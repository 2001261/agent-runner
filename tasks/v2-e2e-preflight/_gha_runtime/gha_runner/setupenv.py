"""环境自举：11 项检测状态机 + gh 下载安装 + 认证引导。

授权边界（这是本模块存在的理由）：
  A 只读检测   —— 自主执行
  B 写操作     —— 装 gh 等；必须 --yes，且 agent 每次都要先取得用户同意
  C 必须真人   —— gh auth login / auth refresh / SSO / 网页开关；只打印命令并停下等待
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple

from . import core, remote, ui
from .ui import EXIT_FAIL, EXIT_NEEDS_USER, EXIT_OK

GH_RELEASES_API = "https://api.github.com/repos/cli/cli/releases/latest"
API_PROBE = "https://api.github.com"
DEVICE_LOGIN_URL = "https://github.com/login/device"
TOKEN_URL = "https://github.com/settings/tokens"

REQUIRED_BASE_TOOLS = ("git",)          # 只有 git 是硬性外部依赖（且仅分支投递用）
PROBE_BASE_TOOLS = ("curl", "tar", "base64", "find", "sed", "grep")   # 仅报告，不阻塞

AUTH_INSTRUCTIONS = f"""
  ── 需要 GitHub 认证（C 类：必须你亲手完成，gha 不会代做）──

  为什么需要：建仓库、推分支、触发 workflow、下载 artifact 都要认证。
  必需 scope：repo + workflow

  路径 A（推荐，本机有浏览器）：
      gh auth login --hostname github.com --git-protocol https --web
    终端会打印一次性 8 位 code → 浏览器打开 {DEVICE_LOGIN_URL}
    输入 code → 勾选授权 repo 与 workflow → 完成

  路径 B（无浏览器 / CI）：
    1. 打开 {TOKEN_URL} 创建 classic PAT，勾选 repo + workflow
    2. 然后二选一：
         gh auth login --hostname github.com --with-token    # 粘贴 token
         export GH_TOKEN=<你的 PAT>                           # 或走环境变量
       Windows PowerShell 用：$env:GH_TOKEN="<你的 PAT>"

  注意：gh run watch 不支持 fine-grained PAT（需要 checks:read，而 fine-grained PAT
        授予不了）。本 skill 因此不用 gh run watch，改成自己轮询 gh run view --json，
        但仍建议用 OAuth 登录或 classic PAT。

  完成后重新跑 `./gha doctor` 验证 —— 不要只凭"我登录好了"就往下走。
"""

SCOPE_INSTRUCTIONS = """
  ── scope 不足（C 类：必须你亲手完成）──

  补齐 repo 与 workflow：
      gh auth refresh -h github.com -s repo -s workflow
  同样走浏览器 device flow。
"""


# ------------------------------------------------------------------ gh 安装

def gh_asset_name(version: str) -> Optional[str]:
    """按 OS/arch 推导 release asset 名。**不硬编码版本号**。

    实测命名：gh_2.101.0_macOS_arm64.zip / gh_2.101.0_linux_amd64.tar.gz /
              gh_2.101.0_windows_amd64.zip
    """
    system = platform.system()
    machine = (platform.machine() or "").lower()

    if system == "Darwin":
        os_part, ext = "macOS", "zip"
    elif system == "Linux":
        os_part, ext = "linux", "tar.gz"
    elif system == "Windows":
        os_part, ext = "windows", "zip"
    else:
        return None

    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    elif machine.startswith("armv6"):
        arch = "armv6"
    elif machine.startswith("armv7"):
        arch = "armv6"      # gh 的 armv7 包也叫 armv6
    else:
        return None

    if os_part == "linux" and arch == "386":
        ext = "tar.gz"
    return f"gh_{version}_{os_part}_{arch}.{ext}"


def fetch_latest_gh_version(timeout: int = 30) -> str:
    """查 gh 最新版本号。该端点无需认证。"""
    req = urllib.request.Request(GH_RELEASES_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "gha-runner-setup",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        raise ui.GhaError(f"无法获取 gh 最新版本号（网络或 API 限流？）：{e}")
    tag = str(data.get("tag_name") or "").lstrip("v")
    if not re.match(r"^\d+\.\d+", tag):
        raise ui.GhaError(f"releases/latest 返回的 tag_name 不可识别：{tag!r}")
    return tag


def _download(url: str, dest: Path, timeout: int = 300) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "gha-runner-setup"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
    except (urllib.error.URLError, OSError) as e:
        raise ui.GhaError(f"下载失败：{url}\n    {e}")


def _extract_gh_binary(pkg: Path, workdir: Path) -> Optional[Path]:
    """从 zip 或 tar.gz 里找出 gh 可执行文件。"""
    exe = "gh.exe" if os.name == "nt" else "gh"
    if pkg.name.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(pkg) as zf:
            zf.extractall(workdir)
    else:
        import tarfile
        with tarfile.open(pkg, "r:gz") as tf:
            tf.extractall(workdir)

    # 优先 bin/ 下的，其次任何位置
    for cand in sorted(workdir.rglob(exe)):
        if cand.parent.name == "bin":
            return cand
    for cand in sorted(workdir.rglob(exe)):
        return cand
    return None


def install_gh_local() -> None:
    """把 gh 装进 <skill>/bin/ —— 不写系统目录、不需要 sudo。"""
    version = fetch_latest_gh_version()
    ui.info(f"gh 最新版本：{version}")

    asset = gh_asset_name(version)
    if not asset:
        raise ui.GhaError(
            f"无法为 {platform.system()}/{platform.machine()} 推导 gh 包名 ——\n"
            f"    请改用系统包管理器安装，见 references/setup.md"
        )
    url = f"https://github.com/cli/cli/releases/download/v{version}/{asset}"
    ui.info(f"下载 {asset}")
    ui.note(url)

    tmp = Path(tempfile.mkdtemp(prefix="gha-gh-install-"))
    try:
        pkg = tmp / asset
        _download(url, pkg)

        workdir = tmp / "x"
        workdir.mkdir()
        found = _extract_gh_binary(pkg, workdir)
        if not found:
            raise ui.GhaError(f"解包后找不到 gh 二进制（{asset}）")

        core.BIN_DIR.mkdir(parents=True, exist_ok=True)
        dest = core.BIN_DIR / found.name
        shutil.copy2(found, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        # macOS 从网上下载的二进制带 quarantine 属性，会被 Gatekeeper 拦
        if platform.system() == "Darwin" and shutil.which("xattr"):
            subprocess.run(["xattr", "-d", "com.apple.quarantine", str(dest)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        core.resolve_gh(force=True)
        gh = core.resolve_gh()
        if gh and Path(gh).is_file():
            res = core.run_gh(["--version"])
            ver = res.stdout.splitlines()[0] if res.ok and res.stdout else "?"
            ui.st_ok(f"gh 已安装到 {dest}（{ver}）")
            return
        raise ui.GhaError(f"安装后 gh 仍不可执行：{dest} —— 可能是架构不匹配或 Gatekeeper 拦截")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


SYSTEM_INSTALL_HINTS = """    本地安装（不写系统目录、不需 sudo）: ./gha setup --yes
    或系统包管理器（B 类，会写系统目录 / 可能需要 sudo）:
      macOS      brew install gh
      Windows    winget install --id GitHub.cli   /   scoop install gh   /   choco install gh
      Debian     sudo apt install gh              （需先加官方 apt 源）
      Fedora     sudo dnf install gh
      Arch       sudo pacman -S github-cli
    详见 references/setup.md"""


# ------------------------------------------------------------------ 认证与 scope

def auth_status() -> Tuple[bool, str, str]:
    """返回 (是否已登录, 账号名, scopes 原文)。"""
    gh = core.resolve_gh()
    if not gh:
        return False, "", ""
    try:
        r = subprocess.run([gh, "auth", "status"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError:
        return False, "", ""
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode != 0:
        return False, "", out

    acct = ""
    m = re.search(r"Logged in to [^\n]*?account[:\s]+([^\s(]+)", out)
    if m:
        acct = m.group(1)
    scopes = ""
    m = re.search(r"Token scopes:\s*(.+)", out)
    if m:
        scopes = m.group(1).strip()
    return True, acct, scopes


def scopes_sufficient(scopes: str) -> Tuple[bool, List[str]]:
    """检查 scope 是否含 repo 与 workflow。返回 (是否足够, 缺失列表)。

    scopes 形如：'delete_repo', 'gist', 'read:org', 'repo', 'workflow'
    注意 'delete_repo' 里含 "repo" 子串，必须按引号内的完整 token 比对。
    """
    if not scopes:
        return False, ["repo", "workflow"]      # fine-grained PAT 不列 scopes
    tokens = {t.strip().strip("'\"") for t in scopes.split(",")}
    missing = [s for s in ("repo", "workflow") if s not in tokens]
    return not missing, missing


# ------------------------------------------------------------------ 网络探测

def probe_network(timeout: int = 15) -> Tuple[bool, str]:
    try:
        req = urllib.request.Request(API_PROBE, headers={"User-Agent": "gha-runner-doctor"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, str(resp.status)
    except urllib.error.HTTPError as e:
        # 401/403 也说明网络通（api.github.com 根路径本就要求认证）
        return e.code in (200, 401, 403), str(e.code)
    except (urllib.error.URLError, OSError) as e:
        return False, str(e)


# ------------------------------------------------------------------ 状态机

def cmd_setup(check_only: bool = True, yes: bool = False) -> int:
    """11 项幂等检测。返回退出码：0 全绿 / 1 有 fail / 3 有 needs-user。"""
    fails = 0
    needs_user = 0

    mode = "只读" if check_only else "可执行 B 类安装"
    ui.section(f"环境自举检测（{mode}）")
    ui.note(f"skill 目录: {core.GHA_HOME}")
    ui.note(f"python:    {sys.version.split()[0]} ({platform.python_implementation()})")

    # --- 0. 含空格路径自检（本 skill 的开发目录路径就带空格）
    if any(c.isspace() for c in str(core.GHA_HOME)):
        ui.st_ok(f"路径含空格自检：已正确处理（{core.GHA_HOME}）")
    else:
        ui.st_ok("路径自检通过")

    # --- 1. OS / arch
    ui.st_ok(f"OS/arch: {platform.system()} / {platform.machine()}")

    # --- 2. 外部工具
    missing_hard = [t for t in REQUIRED_BASE_TOOLS if not shutil.which(t)]
    if missing_hard:
        ui.st_fail(f"缺必需工具: {' '.join(missing_hard)} —— 分支投递路径需要 git")
        fails += 1
    else:
        ui.st_ok("git: " + (_tool_version("git") or "已安装"))

    present = [t for t in PROBE_BASE_TOOLS if shutil.which(t)]
    absent = [t for t in PROBE_BASE_TOOLS if not shutil.which(t)]
    if absent:
        # Python 版不再依赖这些，只作报告
        ui.st_skip(f"这些 POSIX 工具不存在，但 Python 版不需要它们: {' '.join(absent)}")
    if present:
        ui.st_ok(f"可选 POSIX 工具（Python 版不依赖）: {' '.join(present)}")

    # --- 3. jq / python3（可选）
    if shutil.which("jq"):
        ui.st_ok(f"jq: {_tool_version('jq')}（可选，本 skill 用 json.loads 解析）")
    else:
        ui.st_skip("无 jq —— 不影响，取 JSON 走 gh --json + json.loads")

    # --- 4. gh CLI
    gh = core.resolve_gh(force=True)
    if gh:
        ui.st_ok(f"gh: {core.gh_version()}  [{gh}]")
        if not core.gh_supports_run_url():
            ui.warn("gh 版本 < 2.87 —— run_id 解析会走列表反查的回退路径（仍可用）")
    else:
        if check_only or not yes:
            needs_user += 1
            ui.st_install("gh CLI 未安装")
            for line in SYSTEM_INSTALL_HINTS.splitlines():
                ui.note(line)
        else:
            try:
                install_gh_local()
                gh = core.resolve_gh()
            except ui.GhaError as e:
                ui.st_fail(f"gh 本地安装失败：{e}")
                ui.note("改用系统包管理器，见 references/setup.md")
                fails += 1

    if not gh:
        ui.section("结论")
        ui.err("gh CLI 不可用，后续检查无法进行。")
        if check_only:
            ui.note("跑 `./gha setup --yes`（已获用户同意）来本地安装 gh。")
        return EXIT_FAIL

    # --- 5/6. 认证与 scope
    logged_in, acct, scopes = auth_status()
    if not logged_in:
        needs_user += 1
        ui.st_user("gh 未认证")
        ui.log(AUTH_INSTRUCTIONS)
    else:
        ui.st_ok(f"gh 已认证{('：' + acct) if acct else ''}")
        if scopes:
            enough, missing = scopes_sufficient(scopes)
            if enough:
                ui.st_ok("scope 含 repo + workflow")
            else:
                needs_user += 1
                ui.st_user(f"scope 不足，缺: {' '.join(missing)}")
                ui.note(f"当前: {scopes}")
                ui.log(SCOPE_INSTRUCTIONS)
        else:
            ui.st_skip("无法识别 token scope（可能是 fine-grained PAT）—— "
                       "若后续 API 调用报权限错误，请改用 OAuth 登录或 classic PAT")

    # --- 7. git commit 身份
    if shutil.which("git"):
        name = remote._git_config("user.name")
        email = remote._git_config("user.email")
        if name and email:
            ui.st_ok(f"git commit 身份: {name} <{email}>")
        else:
            derived = remote.derive_git_identity()
            if derived:
                ui.st_install("git commit 身份未设置 —— 将从 GitHub 账号推导，"
                              "并用 git -c 局部覆盖，不改全局配置")
                ui.note(f"user.name  = {derived[0]}")
                ui.note(f"user.email = {derived[1]}")
                ui.note("推分支前会再向你确认一次这个身份")
            else:
                needs_user += 1
                ui.st_user("git commit 身份未设置，且无法从 gh 账号推导")
                ui.note("手工设置（只影响本仓库，不动全局）: "
                        "git config user.name <名字> && git config user.email <邮箱>")

    # --- 8. 网络连通
    ok, detail = probe_network()
    if ok:
        ui.st_ok(f"网络: api.github.com 可达 (HTTP {detail})")
    else:
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "未设置"
        ui.st_fail(f"网络: 无法连接 api.github.com（{detail}）—— 检查代理 HTTPS_PROXY={proxy} 或防火墙")
        fails += 1

    # --- 9/10/11. 仓库相关
    repo = core.cfg_repo()
    if not repo:
        ui.st_skip("仓库未初始化 —— 跑 `./gha init --create --repo <owner>/<name>`（默认 public）")
    else:
        ui.section(f"仓库状态: {repo}")
        vis = remote.repo_visibility(repo)
        if not vis:
            ui.st_fail(f"仓库不可访问: {repo} —— 检查名字、权限，或重跑 ./gha init")
            fails += 1
        else:
            br = remote.default_branch(repo)
            ui.st_ok(f"仓库可访问，可见性={vis.upper()}，默认分支={br}")
            if vis == "public":
                ui.note("公开仓库：4 vCPU / 16 GB，标准 runner 分钟数免费不限量 —— 符合默认策略")
                ui.note("代价：任务脚本进 git 历史且公开可见，artifact 任何人可下载。submit 有凭据扫描兜底。")
            else:
                ui.warn("私有仓库：ubuntu-latest 只有 2 vCPU / 8 GB，且消耗分钟数配额（Free 2,000/月）")

            cfgvis = core.cfg_visibility()
            if cfgvis and cfgvis != vis:
                ui.warn(f"config/visibility={cfgvis} 与实际={vis} 不一致 —— 重跑 ./gha init 同步")

            enabled = remote.actions_enabled(repo)
            if enabled is True:
                ui.st_ok("Actions 已启用")
            elif enabled is False:
                needs_user += 1
                ui.st_user(f"Actions 未启用 —— 去 https://github.com/{repo}/settings/actions 打开（C 类，网页操作）")
            else:
                ui.st_skip("无法查询 Actions 开关状态（权限不足？）")

            if remote.workflow_present(repo):
                ui.st_ok(f"dispatcher 工作流已在仓库: {core.WORKFLOW_NAME}")
                if remote.dispatcher_up_to_date(repo):
                    ui.st_ok("dispatcher 与本地模板一致（git blob sha）")
                else:
                    ui.st_install("dispatcher 与本地模板不一致 —— 跑 `./gha init --yes` 更新")
            else:
                ui.st_install(f"dispatcher 工作流未就绪 —— 跑 `./gha init --yes` 推送")

            bill = remote.billing_actions(repo.split("/")[0])
            if bill:
                ui.st_ok(f"本月 Actions 分钟数：已用 {bill['used']} / 含 {bill['included']}")
            else:
                ui.st_skip("查不到计费信息（该端点需要 user scope）—— 公开仓库分钟数免费不限量，通常无需关心")

    # --- 模板自检
    if core.TEMPLATE.is_file():
        ui.st_ok(f"dispatcher 模板存在: {core.TEMPLATE.relative_to(core.GHA_HOME)}")
    else:
        ui.st_fail(f"缺模板: {core.TEMPLATE}")
        fails += 1

    # --- Python 底线自检
    if sys.version_info < (3, 9):
        ui.st_fail(f"Python {sys.version.split()[0]} 低于底线 3.9")
        fails += 1
    else:
        ui.st_ok(f"Python {sys.version.split()[0]} ≥ 3.9")

    ui.section("结论")
    if fails:
        ui.err(f"{fails} 项失败，需先修复")
        return EXIT_FAIL
    if needs_user:
        ui.warn(f"有 {needs_user} 项需要用户亲手完成（C 类）—— 见上方提示，完成后重跑 ./gha doctor")
        return EXIT_NEEDS_USER
    ui.st_ok("环境就绪")
    return EXIT_OK


def _tool_version(tool: str) -> str:
    try:
        r = subprocess.run([tool, "--version"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=10)
        first = r.stdout.decode("utf-8", "replace").splitlines()
        return first[0].strip() if first else ""
    except (OSError, subprocess.SubprocessError):
        return ""
