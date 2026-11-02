"""路径、配置、run 状态、gh 调用、输入校验。

不依赖外部 jq：取 JSON 一律用 gh 的 --json 后在 Python 里解析。
不依赖 git 算 blob sha：hashlib 直接算 GitHub 的 git object hash。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import ui
from .ui import GhaError, NotAuthorized

# ------------------------------------------------------------------ 路径

# skill 根目录 = 本包目录的父目录
GHA_HOME: Path = Path(__file__).resolve().parent.parent
BIN_DIR: Path = GHA_HOME / "bin"
CONFIG_DIR: Path = GHA_HOME / "config"
TEMPLATE: Path = GHA_HOME / "templates" / "agent-dispatch.yml"
WORKFLOW_NAME = "agent-dispatch.yml"

# 调用方启动时的 cwd —— 结果要落回这里，不是 skill 目录
CWD: Path = Path(os.environ.get("GHA_CWD") or Path.cwd()).resolve()

RUNS_DIR: Path = Path(os.environ.get("GHA_RUNS_DIR") or (CWD / ".gha-runs")).resolve()

# dispatch 总 payload 硬上限 65535 字符，留余量给其余字段
INLINE_B64_LIMIT = int(os.environ.get("GHA_INLINE_B64_LIMIT", "60000"))
BUNDLE_WARN_BYTES = int(os.environ.get("GHA_BUNDLE_WARN_BYTES", str(100 * 1024 * 1024)))

DEFAULT_RUNNER = "ubuntu-latest"
DEFAULT_TIMEOUT_MINUTES = 360
MAX_TIMEOUT_MINUTES = 360          # GitHub 单 job 硬上限 6 小时
DEFAULT_RETENTION_DAYS = 7
DEFAULT_WAIT_TIMEOUT = 600
DEFAULT_WAIT_INTERVAL = 15
MIN_WAIT_INTERVAL = 3              # 别把 API 打成筛子

# 凭证传递围栏（见 credinject.py 与 SKILL.md）：仓库里只存这一个约定名的 secret，
# 值是 JSON 对象（键 = 任务里用的 env 名，值 = 凭证）。模板一次映射永久生效。
SECRET_DEFAULT_NAME = "GHA_TASK_SECRETS"

VALID_RUNNERS = (
    "ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04",
    "macos-latest", "macos-14", "windows-latest",
)
VALID_SHELLS = ("auto", "bash", "python3", "node")

# 默认纳入缓存的常见工具缓存路径（相对 $HOME），只缓存真实存在的
DEFAULT_CACHE_SUBDIRS = (
    ".cache/pip", ".npm", ".cache/uv", ".cargo/registry",
    ".cache/go-build", ".m2", ".gradle/caches", ".cache/yarn",
)
STATE_DIR_NAME = ".gha-state"      # $HOME/.gha-state


# ------------------------------------------------------------------ 小工具

def now_epoch() -> int:
    return int(time.time())


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_text_file(path: Path) -> str:
    """读文本文件；不存在返回空串。newline 交给 universal newlines 处理。"""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def write_text_file(path: Path, text: str) -> None:
    """写文本文件。newline='\n' 是刻意的：Windows 上也不能让 CRLF 污染
    run 状态与 config，否则 head -1 / 字符串比对会出错。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text if text.endswith("\n") else text + "\n")


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def git_blob_sha(data: bytes) -> str:
    """GitHub contents API 返回的 sha 就是 git blob sha，可以直接算，不需要 git。"""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ------------------------------------------------------------------ config

def cfg_path(name: str) -> Path:
    return CONFIG_DIR / name


def cfg_get(name: str) -> str:
    return read_text_file(cfg_path(name)).strip()


def cfg_set(name: str, value: str) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    write_text_file(cfg_path(name), value)
    try:
        os.chmod(cfg_path(name), 0o600)
    except OSError:
        pass    # Windows 上 chmod 语义不同，失败无所谓


def cfg_repo() -> str:
    return cfg_get("repo")


def cfg_visibility() -> str:
    return cfg_get("visibility")


def need_repo() -> str:
    """返回配置的仓库；未初始化就抛错。

    bash 版这里有个 bug：把 die 放在 $( ) 里，exit 传不出来，校验形同虚设。
    异常模型下不可能复发。
    """
    r = cfg_repo()
    if not r:
        raise GhaError(
            "尚未初始化 —— 先跑：./gha init --create --repo <owner>/<name> --yes"
            "（Windows: gha.cmd init ...）"
        )
    return r


# ------------------------------------------------------------------ run 状态

def run_dir(task_id: str, out: Optional[str] = None) -> Path:
    """结果目录。--out 给了就用它（解析成绝对路径），否则 <cwd>/.gha-runs/<task_id>。"""
    if out:
        return Path(out).expanduser().resolve()
    return RUNS_DIR / task_id


def run_set(task_id: str, key: str, value: str, out: Optional[str] = None) -> None:
    d = run_dir(task_id, out)
    d.mkdir(parents=True, exist_ok=True)
    write_text_file(d / key, value)


def run_get(task_id: str, key: str, out: Optional[str] = None) -> str:
    return read_text_file(run_dir(task_id, out) / key).strip()


def resolve_run_id(arg: str, out: Optional[str] = None) -> str:
    """把 task_id 或 run_id 归一成 run_id。

    task_id 本身可能就是纯数字，所以先查本地映射，查不到再把纯数字当 run_id。
    bash 版这里的 case 模式写反了（''*[!0-9]* 匹配的是"含非数字"），有单测守着。
    """
    mapped = run_get(arg, "run_id", out)
    if mapped:
        return mapped
    if arg.isdigit():
        return arg
    raise GhaError(f"找不到 run_id：{arg}（本地 .gha-runs 里没有这个 task_id 的记录？）")


def resolve_task_id(arg: str, out: Optional[str] = None) -> str:
    """把 task_id 或 run_id 归一成 task_id（用于定位结果目录与 artifact 名）。"""
    if (run_dir(arg, out) / "run_id").is_file():
        return arg
    if arg.isdigit():
        f = RUNS_DIR / "by-run" / arg / "task_id"
        if f.is_file():
            v = read_text_file(f).strip()
            if v:
                return v
    return arg


# ------------------------------------------------------------------ gh 定位与调用

class GhResult:
    __slots__ = ("rc", "stdout", "stderr")

    def __init__(self, rc: int, stdout: str, stderr: str) -> None:
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.rc == 0


_GH_PATH: Optional[str] = None


def _local_bin_gh() -> Optional[Path]:
    name = "gh.exe" if os.name == "nt" else "gh"
    p = BIN_DIR / name
    return p if p.is_file() and os.access(p, os.X_OK) else None


def resolve_gh(force: bool = False) -> Optional[str]:
    """定位 gh 可执行文件。

    顺序：$GHA_GH_BIN → 系统 PATH → <skill>/bin/gh。
    系统 gh 优先：它由用户/包管理器维护更新，不会像 bin/gh 那样变成陈旧副本。

    必须用 shutil.which —— 它只查 PATH 上的可执行文件。
    bash 版用 `command -v gh` 时踩过大坑：如果存在名为 gh 的 shell 函数，
    command -v 返回的是函数名 "gh" 而不是路径，再执行就变成递归调用自己直到段错误。
    shutil.which 结构上不可能有这个问题。
    """
    global _GH_PATH
    if _GH_PATH and not force:
        return _GH_PATH

    explicit = os.environ.get("GHA_GH_BIN")
    if explicit and Path(explicit).is_file():
        _GH_PATH = explicit
        return _GH_PATH

    found = shutil.which("gh")
    if found:
        _GH_PATH = found
        return _GH_PATH

    local = _local_bin_gh()
    if local:
        _GH_PATH = str(local)
        return _GH_PATH

    _GH_PATH = None
    return None


def require_gh() -> str:
    gh = resolve_gh()
    if not gh:
        raise GhaError("gh CLI 不可用 —— 先跑：./gha setup --yes（B 类安装，需用户同意）")
    return gh


def run_gh(args: Sequence[str], *, stdin_text: Optional[str] = None,
           repo: Optional[str] = None, allow_fail: bool = True) -> GhResult:
    """调用 gh。allow_fail=False 时在非零退出上抛 GhaError。"""
    gh = require_gh()
    cmd: List[str] = [gh]
    if repo:
        cmd += ["-R", repo]
    cmd += list(args)

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_text.encode("utf-8") if stdin_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as e:
        raise GhaError(f"无法执行 gh：{e}")

    res = GhResult(
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )
    if not res.ok and not allow_fail:
        detail = (res.stderr or res.stdout).strip()[:800]
        raise GhaError(f"gh {' '.join(args[:2])} 失败 (rc={res.rc})：{detail}")
    return res


def gh_json(args: Sequence[str], *, repo: Optional[str] = None) -> Any:
    """跑 gh ... --json ... 并解析。失败或非法 JSON 返回 None（调用方自行判断）。

    注意：gh api 遇到 404 会把错误 JSON 打到 stdout（"gh: Not Found" 才走 stderr），
    所以判成功不能只看 stdout 非空 —— 必须确认目标字段真的存在。
    bash 版在 billing 查询上踩过这个坑，报出 "已用 ? / 含 ?"。
    """
    res = run_gh(list(args), repo=repo)
    if not res.ok or not res.stdout.strip():
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        return None


def gh_version() -> str:
    res = run_gh(["--version"])
    return res.stdout.splitlines()[0] if res.ok and res.stdout else ""


def gh_version_tuple() -> Tuple[int, int]:
    m = re.search(r"(\d+)\.(\d+)", gh_version())
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def gh_supports_run_url() -> bool:
    """gh >= 2.87 才会从 workflow run 打印 run URL（对应 API 开始返回 workflow_run_id）。"""
    maj, minor = gh_version_tuple()
    return (maj, minor) >= (2, 87)


# ------------------------------------------------------------------ 输入校验与净化

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NON_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")
_DASH_RUN_RE = re.compile(r"-{2,}")
# 凭证白名单的键 = 任务里要 export 的 env 名，按 shell 变量名的规矩来
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# gh secret / GitHub Actions 的 secret 名允许字母数字下划线，≤64 字符
_SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")


def valid_task_id(s: str) -> bool:
    return bool(_TASK_ID_RE.match(s))


def derive_task_id(task_dir: Path) -> str:
    """从任务目录名派生 task_id。

    目录名全是非 ASCII（如中文）时净化后会是空串 —— bash 版这里真的返回过空值，
    导致后续 valid_task_id 失败。用路径 CRC32 兜底，保证不同目录不会塌成同名而互相覆盖结果。
    """
    p = Path(task_dir).expanduser().resolve()
    sanitized = _DASH_RUN_RE.sub("-", _NON_SAFE_RE.sub("-", p.name)).strip("-")[:64]
    if sanitized:
        return sanitized
    return "task-%d" % (zlib.crc32(str(p).encode("utf-8")) & 0xFFFFFFFF)


def valid_runner(s: str) -> bool:
    return s in VALID_RUNNERS


def valid_shell(s: str) -> bool:
    return s in VALID_SHELLS


def valid_repo_slug(s: str) -> bool:
    return bool(_REPO_SLUG_RE.match(s))


def valid_timeout_minutes(v: str) -> bool:
    return v.isdigit() and 1 <= int(v) <= MAX_TIMEOUT_MINUTES


def valid_env_name(s: str) -> bool:
    """凭证白名单里的键 = 任务里要 export 的 env 名，按 POSIX 变量名校验。"""
    return bool(_ENV_NAME_RE.match(s or ""))


def valid_secret_name(s: str) -> bool:
    """GitHub secret 名字符集（A-Z a-z 0-9 下划线）；同时避开 URL 拼接问题。"""
    return bool(_SECRET_NAME_RE.match(s or ""))


def b64encode_file(path: Path) -> str:
    """文件 → 单行 base64。字符集天然落在 [A-Za-z0-9+/=]，进 JSON 不需要转义。"""
    return base64.b64encode(path.read_bytes()).decode("ascii")


def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ------------------------------------------------------------------ B 类闸门

def confirm_b(desc: str, fn, *, authorized: bool, show: str = "") -> Any:
    """B 类写操作闸门。

    未授权时打印"将执行的命令"然后抛 NotAuthorized（exit 125），**绝不执行**。
    一次授权只覆盖这一次这一个动作，不是长期许可。

    desc: 给人看的一句话说明
    fn:   无参可调用（通常传 lambda），authorized 为真时才执行
    show: 未授权时展示的命令文本；不给就用 desc
    """
    if authorized:
        ui.info(desc)
        return fn()
    ui.st_install(f"B 类操作未执行（缺 --yes）：{desc}")
    ui.note(f"将执行: {show or desc}")
    raise NotAuthorized(f"需要 --yes 才能执行：{desc}")
