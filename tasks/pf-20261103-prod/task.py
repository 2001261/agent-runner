#!/usr/bin/env python3
"""临时任务（v2-e2e-preflight，非提交）：在真实 Ubuntu GHA Runner 上验证严格预检。

只输出组件状态、退出码与“键名是否注入”的布尔，不输出任何 Secret 值。

任务包本身不带 ``_gha_runtime/``：它是 ``gha submit --interactive`` 打包时从主仓
``interactive_runtime/`` 注入的。默认按 workflow 的顺序执行（Setup 步骤已写好
``GHA_INTERACTIVE_VENV`` / ``GHA_NOVNC_DIR``）；``--bootstrap`` 时由本任务先显式准备
隔离环境（venv + 依赖 + noVNC 目录，位置与 install-linux.sh 一致）再跑预检，
用于单独提交任务包的回归。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

TASK_DIR = os.environ.get("GHA_TASK_DIR", os.getcwd())
OUT = os.environ.get("GHA_OUTPUT_DIR", "./output")
RUNTIME_DIR = "_gha_runtime"
VERIFY_REL = os.path.join("interactive_runtime", "setup", "verify.sh")
REQUIREMENTS_REL = os.path.join("interactive_runtime", "requirements.txt")
DEFAULT_VENV = "gha-interactive-venv"
VOWS = ["GHA_TUNNEL_TOKEN", "GHA_TUNNEL_HOSTNAME", "GHA_RENDEZVOUS_ENDPOINT",
        "GHA_RENDEZVOUS_TOKEN", "GHA_STATE_KEY_ID", "GHA_STATE_PUBLIC_KEY"]
LABEL = {v: "named" if "TUNNEL" in v else ("registry" if "RENDEZVOUS" in v else "vault") for v in VOWS}


def runtime_source():
    """注入的运行时：打包器随 interactive 提交注入的 ``_gha_runtime/``。"""
    bundled = os.path.join(TASK_DIR, RUNTIME_DIR)
    if os.path.isfile(os.path.join(bundled, VERIFY_REL)):
        return bundled
    return ""


def python_bin(venv):
    return os.path.join(venv, "bin", "python") if venv else ""


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="在 Linux Runner 上验证严格预检；--bootstrap 可替代 workflow 的 Setup 步骤")
    parser.add_argument("--bootstrap", action="store_true",
                        help="先准备隔离环境（venv + 依赖 + noVNC 目录）再跑预检")
    return parser.parse_args(argv)


def _io(text, limit=500):
    """输出末尾一段；按 UTF-8 解码，绝不让预检报告因宿主编码差异崩掉。"""
    data = text if isinstance(text, bytes) else (text or "").encode("utf-8", "replace")
    return data.decode("utf-8", "replace").strip()[-limit:]


class _Failed(Exception):
    """命令无法执行（不是非零退出）：报告里只留一句可读原因。"""


def _run(argv, timeout):
    try:
        return subprocess.run(argv, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _Failed(_io("%s: %s" % (argv[0], exc))) from exc


def bootstrap_venv():
    """显式准备隔离 Python 环境：与 install-linux.sh 的安装位置、依赖清单保持一致。"""
    venv = os.environ.get("GHA_INTERACTIVE_VENV") or os.path.join(
        os.environ.get("RUNNER_TEMP") or "", DEFAULT_VENV)
    record = {"path": venv, "created": False, "reused": False, "install_rc": None}
    if not os.access(python_bin(venv), os.X_OK):
        python3 = shutil.which("python3")
        if not python3:
            record["error"] = "python3 不可用，无法创建隔离 venv"
            return venv, record
        try:
            proc = _run([python3, "-m", "venv", venv], 300)
        except _Failed as exc:
            record["error"] = str(exc)
            return venv, record
        if proc.returncode != 0:
            record["error"] = _io(proc.stderr or proc.stdout)
            return venv, record
        record["created"] = True
    else:
        record["reused"] = True
    source = runtime_source()
    req = os.path.join(source, REQUIREMENTS_REL) if source else ""
    if req and os.path.isfile(req):
        # 与 install-linux.sh 一致：在 venv 内升级 pip，再按同一清单安装。
        try:
            _run([python_bin(venv), "-m", "pip", "install", "--quiet", "--upgrade", "pip"], 600)
            proc = _run([python_bin(venv), "-m", "pip", "install", "--quiet", "-r", req], 900)
        except _Failed as exc:
            record["error"] = str(exc)
            return venv, record
        record["install_rc"] = proc.returncode
        if proc.returncode != 0:
            record["error"] = _io(proc.stderr or proc.stdout)
    os.environ["GHA_INTERACTIVE_VENV"] = venv
    return venv, record


def bootstrap_novnc():
    """与 install-linux.sh 一致：``npm root -g`` 下的 @novnc/novnc。"""
    if os.environ.get("GHA_NOVNC_DIR"):
        return os.environ["GHA_NOVNC_DIR"]
    try:
        root = _io(_run(["npm", "root", "-g"], 60).stdout, 4096)
    except _Failed:
        root = ""
    if root:
        os.environ["GHA_NOVNC_DIR"] = os.path.join(root, "@novnc", "novnc")
    return os.environ.get("GHA_NOVNC_DIR", "")


def _missing_runtime_hint():
    """注入的运行时缺失时给出可执行的解释，而不是让报告静默停在 runtime_present=false。"""
    return ("任务包内缺少 _gha_runtime/interactive_runtime/setup/verify.sh："
            "打包器只在 interactive 提交时注入运行时；请用支持 Interactive Runtime 的 "
            "gha submit --interactive 重新打包")


def run(label, env, verify):
    """执行一次 verify.sh；只保留组件状态与退出码，不回显输出里的凭证值。"""
    try:
        # 不按 UTF-8 严格解码：宿主编码不同的报错文字不能让整份报告崩掉。
        proc = _run(["bash", verify], 300)
    except _Failed as exc:
        return {"label": label, "rc": None, "error": str(exc), "error_lines": [], "ok_count": 0,
                "mode_line": "", "leaked_vows": []}
    text = _io((proc.stdout or b"") + (proc.stderr or b""), 200000)
    return {
        "label": label,
        "rc": proc.returncode,
        "error_lines": [ln for ln in text.splitlines() if "::error::" in ln][:12],
        "ok_count": text.count("[OK]"),
        "mode_line": next((ln for ln in text.splitlines() if ln.startswith("[preflight]")), ""),
        "leaked_vows": [LABEL[v] for v in VOWS if os.environ.get(v) and os.environ[v] in text],
    }


def cases(base, verify):
    """六个用例：原样 / 空 PATH / 缺 agent-desktop / 缺 noVNC / 两种残缺 Tunnel。"""
    out = [run("as-is", base, verify)]

    stripped = dict(base)
    stripped["PATH"] = "/runner-tools-only"
    out.append(run("empty-PATH", stripped, verify))

    shim = os.path.join(base.get("RUNNER_TEMP") or "/tmp", "gha-pf-shim")
    os.makedirs(shim, exist_ok=True)
    for name in ("Xvfb", "openbox", "dbus-launch", "dbus-daemon", "dbus-send", "ffmpeg",
                 "cloudflared", "xdotool", "wmctrl", "scrot", "x11vnc", "websockify",
                 "python3", "npm"):
        path = os.path.join(shim, name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)
    shim_env = dict(base)
    shim_env["PATH"] = shim
    out.append(run("no-agent-desktop", shim_env, verify))

    novnc_env = dict(base)
    novnc_env["GHA_NOVNC_DIR"] = shim
    out.append(run("no-novnc", novnc_env, verify))

    for label in ("quick-endpoint-only", "named-hostname-only"):
        env = dict(base)
        for key in ("GHA_RENDEZVOUS_ENDPOINT", "GHA_RENDEZVOUS_TOKEN",
                    "GHA_TUNNEL_HOSTNAME", "GHA_TUNNEL_TOKEN"):
            env.pop(key, None)
        if label.startswith("quick"):
            env["GHA_RENDEZVOUS_ENDPOINT"] = "https://registry.invalid"
        else:
            env["GHA_TUNNEL_HOSTNAME"] = "debug.invalid.example"
        out.append(run(label, env, verify))
    return out


def main(argv=None):
    args = parse_args(argv)
    source = runtime_source()
    verify = os.path.join(source, VERIFY_REL) if source else ""
    report = {
        "runner": {"os": os.environ.get("RUNNER_OS"), "image": os.environ.get("ImageOS"),
                   "label": os.environ.get("RUNNER_NAME", "")[:24]},
        "runtime_present": bool(source) and os.path.isfile(verify),
        "runtime_root": source,
        "bootstrap": None,
        "venv": os.environ.get("GHA_INTERACTIVE_VENV"),
        "novnc": bool(os.environ.get("GHA_NOVNC_DIR")),
        "vow_present": {v: bool(os.environ.get(v)) for v in VOWS},
        "censor_word_in_vow": any(os.environ.get(v) == "***" for v in VOWS),
        "cases": [],
    }
    if args.bootstrap:
        venv, venv_record = bootstrap_venv()
        report["bootstrap"] = {"venv": venv_record, "novnc": bootstrap_novnc()}
        report["venv"] = venv
        report["novnc"] = bool(os.environ.get("GHA_NOVNC_DIR"))
    base = dict(os.environ)
    if not base.get("PYTHONIOENCODING"):
        base["PYTHONIOENCODING"] = "utf-8"
    # 生产链路（workflow → verify.sh → python3 -I → preflight.py）必须原样跑：
    # 预检自己按 GHA_INTERACTIVE_VENV 解析 venv 的 site-packages，不靠 GHA_PREFLIGHT_PY。
    base.pop("GHA_PREFLIGHT_PY", None)

    if not report["runtime_present"]:
        report["error"] = _missing_runtime_hint()
    else:
        report["cases"] = cases(base, verify)

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "preflight.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["runtime_present"] else 1


if __name__ == "__main__":
    sys.exit(main())
