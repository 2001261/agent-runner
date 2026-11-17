"""Interactive Runtime 严格环境预检（setup/verify.sh 的判定核心）。

规则：
- 缺任何必需组件一律失败（exit 1），绝不降级、绝不模拟成功；
- 只输出组件名与路径，绝不回显 Token / Secret 的值；
- Tunnel 配置只看 ``env``（该参数由调用方显式传入；命令行直接运行时取
  ``os.environ``），不会回退去读 ``~/.cloudflared`` 等用户已有配置；
- Named 与 Quick 分开判定，绝不拿其中一项顶替另一项。
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import sys
from typing import Dict, List, Mapping, Optional

# (显示名, 命令)
REQUIRED_COMMANDS = [
    ("Xvfb", "Xvfb"),
    ("Openbox", "openbox"),
    ("D-Bus", "dbus-launch"),
    ("D-Bus daemon", "dbus-daemon"),
    ("D-Bus send", "dbus-send"),
    ("FFmpeg", "ffmpeg"),
    ("cloudflared", "cloudflared"),
    ("GUI input", "xdotool"),
    ("Window manager", "wmctrl"),
    ("Screenshot", "scrot"),
    ("agent-desktop", "agent-desktop"),
    ("VNC", "x11vnc"),
    ("WebSocket bridge", "websockify"),
    ("Python", "python3"),
]

REQUIRED_MODULES = ("aiohttp", "playwright", "cryptography", "yaml")
# jsdom 只在自查站（模拟系统弹窗的宿主）里用，不进生产依赖；心跳续租用标准库。
SELFTEST_MODULES = ("requests",)
# Ubuntu 把 AT-SPI launcher 放在 /usr/libexec，而不是 PATH。
ATSPI_LAUNCHER = "/usr/libexec/at-spi-bus-launcher"

TUNNEL_TOKEN_ENV = "GHA_TUNNEL_TOKEN"
TUNNEL_HOSTNAME_ENV = "GHA_TUNNEL_HOSTNAME"
RENDEZVOUS_ENDPOINT_ENV = "GHA_RENDEZVOUS_ENDPOINT"
RENDEZVOUS_TOKEN_ENV = "GHA_RENDEZVOUS_TOKEN"
# 非敏感传输偏好：main.py 读取后交给 QuickTunnelProvider；Named 不接受该变量。
TUNNEL_PROTOCOL_ENV = "GHA_TUNNEL_PROTOCOL"
TUNNEL_PROTOCOLS = ("http2", "quic")
# 已配置 Provider 的离线闭环验证：只校验组件，不要求 Tunnel 凭证。
# 只有 GITHUB_ACTIONS 非 true（即自查/自测，而不是真实 dispatch）时才可能生效；
# 真实 Runner 上拒收该变量，避免把“无 Tunnel”误当成可交付形态。
LOOPBACK_ENV = "GHA_PREFLIGHT_LOOPBACK"

HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")


def _usable_secret(value: Optional[str]) -> bool:
    """与 tunnel._token_shape_ok 同一判定（单行、长度足够）；只看形状，绝不输出值。

    不导入 tunnel 模块：本文件要能被 `python3 -I preflight.py` 以脚本方式直接执行。
    """
    text = (value or "").strip()
    return len(text) >= 16 and not any(ch.isspace() for ch in text)


def site_packages(venv: str, subdir: str = "lib") -> str:
    """venv 里的 site-packages（``lib`` / ``lib64`` / Windows 的 ``Lib``）；
    不依赖 pyvenv.cfg 的解析结果。"""
    root = os.path.join(venv, subdir) if venv else ""
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return ""
    # Windows venv 没有 pythonX.Y 层：site-packages 直接位于 Lib/ 下（与大小写无关比较）。
    if subdir.lower() == "lib":
        for name in entries:
            if name.lower() == "site-packages" and os.path.isdir(os.path.join(root, name)):
                return os.path.join(root, name)
    for name in entries:
        if name.startswith("python3"):
            candidate = os.path.join(root, name, "site-packages")
            if os.path.isdir(candidate):
                return candidate
    return ""


def venv_site_dirs(venv: str) -> List[str]:
    """venv 的库目录按存在顺序排列；Linux 上只会命中 ``lib``/``lib64`` 中的一个。"""
    dirs: List[str] = []
    for subdir in ("lib", "lib64", "Lib"):
        path = site_packages(venv, subdir)
        if path and path not in dirs:
            dirs.append(path)
    return dirs


def native_binary_dirs(agent_desktop_cmd: str) -> List[str]:
    """agent-desktop 原生 Linux 二进制可能的所在目录（沿用 install-linux.sh 的解析顺序）。"""
    dirs: List[str] = []
    try:
        resolved = os.path.realpath(agent_desktop_cmd)
    except OSError:
        resolved = agent_desktop_cmd
    dirs.append(os.path.dirname(resolved))
    npm = shutil.which("npm")
    if npm:
        try:
            import subprocess

            root = subprocess.run([npm, "root", "-g"], capture_output=True, text=True,
                                  timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            root = ""
        if root:
            dirs.append(os.path.join(root, "agent-desktop", "bin"))
    return dirs


def _check_novnc(env: Mapping[str, str], errors: List[str], ok: List[str]) -> None:
    base = env.get("GHA_NOVNC_DIR", "")
    candidates: List[str] = []
    if base:
        candidates.append(base)
    else:
        # 任务包与 workflow 之间工作副本可能不同步：环境变量没写进 GITHUB_ENV 时，
        # 按 install-linux.sh 的同一安装位置（npm 全局根）复核，而不是误报缺失。
        try:
            import subprocess

            root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True,
                                  timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            root = ""
        if root:
            candidates.append(os.path.join(root, "@novnc", "novnc"))
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "core", "rfb.js")):
            ok.append(f"noVNC: {candidate}" + ("" if base else "（按 npm 全局根解析）"))
            return
    if not candidates:
        errors.append("缺少 GHA_NOVNC_DIR（install-linux.sh 未导出 noVNC 目录）")
        return
    errors.append(f"noVNC 资源缺失：$GHA_NOVNC_DIR 下找不到 core/rfb.js（{candidates[-1]}）")


def _required_modules(env: Mapping[str, str]) -> tuple:
    if (env.get(LOOPBACK_ENV) or "").strip() == "1":
        return REQUIRED_MODULES + SELFTEST_MODULES
    return REQUIRED_MODULES


def _check_node(env: Mapping[str, str], errors: List[str], ok: List[str]) -> None:
    """jsdom 真实链路自查里的原生弹窗走 Node + jsdom（交互运行时本身不需要 Node）。"""
    if (env.get(LOOPBACK_ENV) or "").strip() != "1":
        return
    node = shutil.which("node")
    if not node:
        errors.append(f"缺少自查用的 node（{LOOPBACK_ENV}=1 时需要跑 jsdom 弹窗宿主）")
        return
    try:
        import subprocess

        res = subprocess.run([node, "-e", "require.resolve('jsdom')"],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        res = None
    if res is None or res.returncode != 0:
        errors.append("自查用的 jsdom 未安装（node -e require.resolve('jsdom') 失败）")
        return
    ok.append("jsdom 弹窗宿主：node 可用")


def _check_tunnel(env: Mapping[str, str], errors: List[str], ok: List[str]) -> str:
    """返回命中的 Tunnel 模式：named / quick / both / none（both 与 none 都是错误配置）。"""
    hostname = (env.get(TUNNEL_HOSTNAME_ENV) or "").strip()
    rendezvous = (env.get(RENDEZVOUS_ENDPOINT_ENV) or "").strip()
    named = quick = False

    loopback = (env.get(LOOPBACK_ENV) or "").strip() == "1"
    if loopback and env.get("GITHUB_ACTIONS") == "true":
        errors.append(f"{LOOPBACK_ENV} 只用于已配置 Provider 的离线闭环验证，真实 Runner 上必须移除")
        return "none"
    if loopback:
        if hostname or rendezvous:
            errors.append(f"{LOOPBACK_ENV} 与任何 Tunnel 配置不能同时出现")
        ok.append(f"离线闭环验证：{LOOPBACK_ENV}=1（不校验 Tunnel，仅本机回环）")
        _check_protocol(env, False, errors, ok)
        return "loopback"

    if hostname:
        named = True
        if not HOSTNAME_RE.match(hostname.lower()):
            errors.append(f"{TUNNEL_HOSTNAME_ENV} 不是合法域名（需形如 debug.example.com，不支持路径/端口）")
        else:
            ok.append(f"Named Tunnel 域名：{hostname.lower()}")
        if not _usable_secret(env.get(TUNNEL_TOKEN_ENV)):
            errors.append(f"Named Tunnel 缺少可用的 {TUNNEL_TOKEN_ENV}（未注入或格式不合法）")
        else:
            ok.append(f"Named Tunnel 凭证：{TUNNEL_TOKEN_ENV} 已注入")
    if rendezvous:
        if not rendezvous.lower().startswith("https://"):
            errors.append(f"{RENDEZVOUS_ENDPOINT_ENV} 必须是 https:// 地址")
        elif not _usable_secret(env.get(RENDEZVOUS_TOKEN_ENV)):
            errors.append(f"Quick Tunnel 缺少私有 Registry 凭证：{RENDEZVOUS_TOKEN_ENV} 未注入")
        else:
            quick = True
            ok.append(f"Quick Tunnel：{RENDEZVOUS_ENDPOINT_ENV} + {RENDEZVOUS_TOKEN_ENV} 已注入")

    if not hostname and not rendezvous:
        errors.append(
            f"未配置任何 Tunnel：Quick 需要 {RENDEZVOUS_ENDPOINT_ENV}+{RENDEZVOUS_TOKEN_ENV}，"
            f"Named 需要 {TUNNEL_HOSTNAME_ENV}+{TUNNEL_TOKEN_ENV}"
        )
    if named and quick:
        errors.append("Named 与 Quick Tunnel 不能同时配置（Runner 只能有一个对外入口）")

    _check_protocol(env, named, errors, ok)
    return "named" if named and not quick else ("quick" if quick and not named else
                                                ("both" if named and quick else "none"))


def _check_protocol(env: Mapping[str, str], named: bool, errors: List[str], ok: List[str]) -> None:
    protocol = (env.get(TUNNEL_PROTOCOL_ENV) or "").strip().lower()
    if protocol:
        if protocol not in TUNNEL_PROTOCOLS:
            errors.append(f"{TUNNEL_PROTOCOL_ENV} 只接受 {' / '.join(TUNNEL_PROTOCOLS)}（未设置 = cloudflared 默认）")
        elif named:
            errors.append(f"{TUNNEL_PROTOCOL_ENV} 仅适用于 Quick Tunnel，Named Tunnel 不支持")
        else:
            ok.append(f"Quick Tunnel 传输协议：{protocol}")


def _venv_python(env: Mapping[str, str]) -> str:
    venv = env.get("GHA_INTERACTIVE_VENV") or os.path.join(env.get("RUNNER_TEMP", ""),
                                                           "gha-interactive-venv")
    if not venv:
        return ""
    # 生产（Linux）只有 bin/python；Windows 布局是 Scripts/python.exe。这里只是让判定
    # 在非 Linux 宿主上落到同一个 venv 上再报平台错误，不改变 Linux Runner 的结果。
    for parts in (("bin", "python"), ("Scripts", "python.exe")):
        candidate = os.path.join(venv, *parts)
        if os.access(candidate, os.X_OK):
            return candidate
    return os.path.join(venv, "bin", "python")


def _module_probe_code(venv: str, modules) -> str:
    """在 venv 里查找模块的一次性探测代码（供子解释器 ``-c`` 执行）。

    继承来的 path 仍保留：没有 X.Y/site-packages 布局的 venv 依赖解释器按 pyvenv.cfg 解析。
    有布局时不能只靠 ``site.addsitedir``：verify.sh 用 ``python3 -I``（含 ``-E``）拉起本模块，
    Python 3.12 下 ``-E`` 会让 ``addsitedir`` 处理 venv 里那行
    ``import _virtualenv`` 的 .pth 失败，和 ``-P`` 一样不再往 sys.path 追加目录 ——
    依赖检查就空转成“未知”。这里用 ``PathFinder.find_spec`` 只查 venv 的 site-packages，
    不让宿主解释器已安装的同名包造成误判。
    """
    tail = ("m=[n for n in %r if importlib.util.find_spec(n) is None];"
            "print(','.join(m));sys.exit(1 if m else 0)" % (tuple(modules),))
    libs = venv_site_dirs(venv)
    if not libs:
        return "import importlib.util,sys;" + tail
    scoped = ("m=[n for n in %r if importlib.machinery.PathFinder.find_spec(n,%r) is None];"
              "print(','.join(m));sys.exit(1 if m else 0)" % (tuple(modules), libs))
    return "import importlib.machinery,sys;" + scoped


def _check_venv(env: Mapping[str, str], errors: List[str], ok: List[str]) -> None:
    venv = env.get("GHA_INTERACTIVE_VENV") or os.path.join(env.get("RUNNER_TEMP", ""),
                                                           "gha-interactive-venv")
    venv_python = _venv_python(env)
    if not venv_python or not os.access(venv_python, os.X_OK):
        errors.append(f"隔离 Python 环境不存在：{venv or '<未设置 GHA_INTERACTIVE_VENV/RUNNER_TEMP>'}")
        return
    # 子解释器查找 venv 依赖，不重复实现版本探测。verify.sh 以 ``python3 -I`` 运行本模块，
    # 而 -I 会让 PYTHONPATH 失效：任务若由 venv 解释器启动，venv 的 site-packages 只在
    # PYTHONPATH 上，这里按路径显式接进子进程。``-s``/``-E`` 只在接管了 venv 库目录时
    # 才加，避免从用户 site-packages 或宿主 PYTHONPATH 误判“依赖完整”。
    import subprocess

    code = _module_probe_code(venv, _required_modules(env))
    flags = ["-s", "-E"] if venv_site_dirs(venv) else []
    try:
        proc = subprocess.run([venv_python] + flags + ["-B", "-c", code],
                              capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        errors.append(f"无法用 {venv_python} 校验隔离依赖")
        return
    if proc.returncode == 0:
        ok.append("Python 隔离依赖完整")
    else:
        missing = (proc.stdout or "").strip() or "未知"
        errors.append(f"隔离 Python 环境缺少模块：{missing}")


def run_preflight(env: Optional[Mapping[str, str]] = None,
                  atspi_launcher: Optional[str] = None) -> int:
    env = os.environ if env is None else env
    if atspi_launcher is None:
        atspi_launcher = env.get("GHA_PREFLIGHT_ATSPI_LAUNCHER") or ATSPI_LAUNCHER
    errors: List[str] = []
    ok: List[str] = []

    platform_ok = env.get("RUNNER_OS", "") == "Linux"
    if not platform_ok:
        errors.append(f"Interactive Runtime 仅支持 Linux Runner，当前为 {env.get('RUNNER_OS') or 'unknown'}")
    else:
        ok.append("平台：Linux")

    found: Dict[str, str] = {}
    for name, cmd in REQUIRED_COMMANDS:
        path = shutil.which(cmd)
        if path:
            found[cmd] = path
            ok.append(f"{name}: {path}")
        else:
            errors.append(f"缺少必需组件 {name}（命令 {cmd} 不可用）")

    if os.access(atspi_launcher, os.X_OK) or shutil.which("at-spi-bus-launcher"):
        ok.append("AT-SPI bus launcher")
    else:
        errors.append("缺少必需组件 AT-SPI（at-spi-bus-launcher 不可用）")

    if "agent-desktop" in found:
        dirs = native_binary_dirs(found["agent-desktop"])
        hit = next((d for d in dirs
                    if os.access(os.path.join(d, "agent-desktop-linux-x64"), os.X_OK)
                    or os.access(os.path.join(d, "agent-desktop-linux-arm64"), os.X_OK)), None)
        if hit:
            ok.append(f"agent-desktop native binary: {hit}")
        else:
            errors.append("agent-desktop 原生 Linux 二进制缺失或不可执行：" + " / ".join(dirs))

    _check_venv(env, errors, ok)
    if _venv_python(env):
        _check_novnc(env, errors, ok)
        _check_node(env, errors, ok)

    # 收尾顺序：先跑完判定并逐行输出 [OK] / 错误，最后才给出汇总与退出码——
    # 失败时输出的最后一行是错误信息，unittest 的 "... FAIL" 才会紧跟结论而不是 [OK] 列表。
    mode = _check_tunnel(env, errors, ok)
    for line in ok:
        print(f"[OK] {line}")
    for line in errors:
        print(f"::error::{line}")
    print(f"[preflight] tunnel_mode={mode} checks_ok={len(ok)} errors={len(errors)}")
    if errors:
        print("::error::Interactive Runtime 环境预检失败，拒绝启动。")
        return 1
    print("=== Interactive Runtime 环境预检通过 ===")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    # verify.sh 以 `python3 -I -B` 调用本模块文件（不依赖 PYTHONPATH、不写 __pycache__），
    # 这里保持零第三方依赖。
    return run_preflight(os.environ)


if __name__ == "__main__":
    sys.exit(main())
