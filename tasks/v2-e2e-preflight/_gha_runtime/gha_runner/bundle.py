"""任务包打包与入口探测。

用 tarfile 取代外部 tar：省掉一个依赖，而且排除规则写在 filter 里，
比 bash 版靠 COPYFILE_DISABLE 环境变量 + --exclude 更可靠。

凭证传递围栏（见 credinject.py 与 SKILL.md）：打包时向包内注入 `_gha/` 目录 ——
credinject.py 与 secrets.py 的自身副本 + declared.json 白名单。注入只进 bundle，
绝不在用户任务目录里落任何文件。
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from pathlib import Path
from typing import List, Optional, Tuple

from . import core
from .ui import GhaError

# 入口文件名 → 解释器
ENTRY_BY_SHELL = {"bash": "task.sh", "python3": "task.py", "node": "task.js"}
# 自动探测顺序
ENTRY_ORDER = ("task.sh", "task.py", "task.js")

# 围栏支持目录在包内的名字；_PKG_DIR 是本包源码目录（副本的来源）
SUPPORT_DIR = "_gha"
_PKG_DIR = Path(__file__).resolve().parent


def _should_exclude(name: str) -> bool:
    """排除 macOS 的元数据垃圾。name 是相对路径（posix 分隔）。"""
    base = name.rsplit("/", 1)[-1]
    return base == ".DS_Store" or base.startswith("._")


def support_files(declared: List[str]) -> List[Tuple[str, bytes]]:
    """要注入 `_gha/` 的文件：credinject.py 与 secrets.py 的自身副本 + declared.json 白名单。

    副本会被解到云端任务目录里独立运行 —— 这两个源模块因此不得有相对导入。
    declared.json 只含键名（任务自己声明的 env 名），不含任何凭证值。
    """
    whitelist = sorted(set(declared or []))
    payload = json.dumps(whitelist, ensure_ascii=False, indent=2) + "\n"
    return [
        ("credinject.py", (_PKG_DIR / "credinject.py").read_bytes()),
        ("secrets.py", (_PKG_DIR / "secrets.py").read_bytes()),
        ("declared.json", payload.encode("utf-8")),
    ]


RUNTIME_SUPPORT_DIR = "_gha_runtime"
_REPO_ROOT = _PKG_DIR.parent


def runtime_support_files() -> List[Tuple[str, bytes]]:
    """Interactive Runtime 运行副本；只含代码与静态资源，不含任何配置或密钥。"""
    files: List[Tuple[str, bytes]] = []
    runtime_root = _REPO_ROOT / "interactive_runtime"
    for p in sorted(runtime_root.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        if p.suffix not in (".py", ".sh", ".js", ".html", ".txt"):
            continue
        files.append((p.relative_to(_REPO_ROOT).as_posix(), p.read_bytes()))
    for rel in (
        "gha_runner/__init__.py",
        "gha_runner/interactive_config.py",
        "gha_runner/interactive_client.py",
        "gha_runner/state_client.py",
        "gha_runner/state_envelope.py",
        "gha_runner/vault.py",
    ):
        files.append((rel, (_REPO_ROOT / rel).read_bytes()))
    return files


def write_runtime_support_files(dest: Path) -> None:
    """把 Interactive Runtime 写入投递副本的独立目录。"""
    root = Path(dest) / RUNTIME_SUPPORT_DIR
    for rel, data in runtime_support_files():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)


def _add_runtime_support_entries(tf: tarfile.TarFile) -> None:
    for rel, data in runtime_support_files():
        ti = tarfile.TarInfo("./%s/%s" % (RUNTIME_SUPPORT_DIR, rel))
        ti.size = len(data)
        ti.mode = 0o755 if rel.endswith(".sh") else 0o644
        ti.mtime = 0
        tf.addfile(ti, io.BytesIO(data))


def _add_support_entries(tf: tarfile.TarFile, declared: List[str]) -> None:
    """以虚拟成员写入 bundle（数据在内存里，不落用户目录）。

    mtime=0 是刻意的：支持文件内容固定，时间戳归零让产物保持确定性。
    """
    d = tarfile.TarInfo("./" + SUPPORT_DIR + "/")
    d.type = tarfile.DIRTYPE
    d.mode = 0o755
    d.mtime = 0
    tf.addfile(d)
    for name, data in support_files(declared):
        ti = tarfile.TarInfo("./%s/%s" % (SUPPORT_DIR, name))
        ti.size = len(data)
        ti.mode = 0o644
        ti.mtime = 0
        tf.addfile(ti, io.BytesIO(data))


def write_support_files(dest: Path, declared: List[str]) -> None:
    """分支投递：把 `_gha/` 写进**投递副本**（git clone 里待推的目录），不碰用户任务目录。

    分支路径不经 bundle（原始文件入分支），不补一份的话云端的凭证围栏就空转了。
    这三个文件只有代码与键名，没有任何凭证值，进临时分支是安全的（fetch 后分支即删）。
    """
    d = Path(dest) / SUPPORT_DIR
    d.mkdir(parents=True, exist_ok=True)
    for name, data in support_files(declared):
        with open(d / name, "wb") as f:
            f.write(data)


def pack_bundle(src: Path, out: Path, declared: Optional[List[str]] = None,
                interactive: bool = False) -> None:
    """把任务目录打成 tar.gz，并注入 _gha/ 支持目录（见 support_files）。

    arcname 用 './<相对路径>' 形式，与 `tar czf out -C dir .` 的产物一致 ——
    runner 侧用 tar xzf 解包，两边行为要能对上。
    条目排序是为了产物确定性（bash 的 tar 是 readdir 顺序，不稳定）。
    """
    src = Path(src).expanduser().resolve()
    if not src.is_dir():
        raise GhaError(f"任务目录不存在：{src}")

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    entries: List[Path] = sorted(p for p in src.rglob("*"))

    def filt(ti: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
        # ti.name 形如 './sub/file'
        rel = ti.name[2:] if ti.name.startswith("./") else ti.name
        if rel and _should_exclude(rel):
            return None
        return ti

    with tarfile.open(out, "w:gz") as tf:
        # 根条目，对应 tar 的 './'
        root = tarfile.TarInfo("./")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = int(src.stat().st_mtime)
        tf.addfile(root)

        for p in entries:
            rel = p.relative_to(src).as_posix()
            if _should_exclude(rel):
                continue
            # _gha/ 与 _gha_runtime/ 归本工具所有：用户目录同名内容不进包
            if rel == SUPPORT_DIR or rel.startswith(SUPPORT_DIR + "/"):
                continue
            if rel == RUNTIME_SUPPORT_DIR or rel.startswith(RUNTIME_SUPPORT_DIR + "/"):
                continue
            tf.add(p, arcname="./" + rel, recursive=False, filter=filt)

        _add_support_entries(tf, list(declared or []))
        if interactive:
            _add_runtime_support_entries(tf)

    if not out.is_file() or out.stat().st_size == 0:
        raise GhaError(f"打包产物为空：{out}")


def list_bundle(path: Path) -> List[str]:
    """列出包内条目名（等价 tar tzf），供差分测试用。"""
    with tarfile.open(path, "r:gz") as tf:
        return sorted(tf.getnames())


def extract_bundle(path: Path, dest: Path) -> None:
    """安全解包。

    不能依赖 tarfile 的 filter= 参数：它是 Python 3.12 才加、3.9.17/3.10.12/3.11.4
    才回补的（CVE-2007-4559）。本包底线是 3.9，在 3.9.6 这种版本上 filter= 会抛
    TypeError —— 如果回落到裸 extractall，`../` 条目就能写出目录之外。
    所以这里手工逐条校验，与 Python 版本无关。
    """
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    with tarfile.open(path, "r:gz") as tf:
        for m in tf.getmembers():
            _assert_safe_member(m, dest)
            tf.extract(m, dest)


def _assert_safe_member(m: tarfile.TarInfo, dest: Path) -> None:
    """拒绝绝对路径、`..` 穿越、以及指向外部的符号/硬链接。"""
    name = m.name.replace("\\", "/")

    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise GhaError(f"任务包内含绝对路径条目，拒绝解包：{m.name}")

    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise GhaError(f"任务包内含路径穿越条目，拒绝解包：{m.name}")

    target = (dest / "/".join(parts)).resolve() if parts else dest
    try:
        target.relative_to(dest)
    except ValueError:
        raise GhaError(f"任务包条目解析后越界，拒绝解包：{m.name}")

    if m.issym() or m.islnk():
        link = m.linkname.replace("\\", "/")
        if link.startswith("/") or re.match(r"^[A-Za-z]:", link):
            raise GhaError(f"任务包内链接指向绝对路径，拒绝解包：{m.name} -> {m.linkname}")
        resolved = (target.parent / link).resolve()
        try:
            resolved.relative_to(dest)
        except ValueError:
            raise GhaError(f"任务包内链接指向目录之外，拒绝解包：{m.name} -> {m.linkname}")


def find_entry(task_dir: Path, shell: str = "auto") -> Optional[str]:
    """找任务入口文件名。找不到返回 None（调用方决定怎么报错）。"""
    task_dir = Path(task_dir)
    if shell in ENTRY_BY_SHELL:
        want = ENTRY_BY_SHELL[shell]
        if (task_dir / want).is_file():
            return want
        return None
    for name in ENTRY_ORDER:
        if (task_dir / name).is_file():
            return name
    return None


def shell_of_entry(entry: str) -> str:
    for shell, name in ENTRY_BY_SHELL.items():
        if name == entry:
            return shell
    return "bash"


def make_b64(bundle: Path, out_b64: Path) -> Tuple[str, int]:
    """bundle → 单行 base64 文件。返回 (base64 字符串, bundle 字节数)。"""
    data = bundle.read_bytes()
    text = core.b64encode_bytes(data)
    out_b64.parent.mkdir(parents=True, exist_ok=True)
    with open(out_b64, "w", encoding="ascii", newline="") as f:
        f.write(text)
    return text, len(data)


def choose_transport(b64_len: int) -> str:
    """内联还是分支投递。

    dispatch 的 inputs 总 payload 硬上限是 65535 字符，
    内联阈值取 60000 留余量给其余 7 个字段。
    """
    return "inline" if b64_len <= core.INLINE_B64_LIMIT else "branch"
