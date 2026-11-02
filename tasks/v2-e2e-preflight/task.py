#!/usr/bin/env python3
"""临时任务（v2-e2e-preflight，非提交）：在真实 Ubuntu GHA Runner 上验证严格预检。

只输出组件状态、退出码与“键名是否注入”的布尔，不输出任何 Secret 值。
"""
import json
import os
import shutil
import subprocess
import sys

TASK_DIR = os.environ.get("GHA_TASK_DIR", os.getcwd())
OUT = os.environ.get("GHA_OUTPUT_DIR", "./output")
os.makedirs(OUT, exist_ok=True)
RUNTIME = os.path.join(TASK_DIR, "_gha_runtime", "interactive_runtime")
VERIFY = os.path.join(RUNTIME, "setup", "verify.sh")
VOWS = ["GHA_TUNNEL_TOKEN", "GHA_TUNNEL_HOSTNAME", "GHA_RENDEZVOUS_ENDPOINT",
        "GHA_RENDEZVOUS_TOKEN", "GHA_STATE_KEY_ID", "GHA_STATE_PUBLIC_KEY"]
LABEL = {v: "named" if "TUNNEL" in v else ("registry" if "RENDEZVOUS" in v else "vault") for v in VOWS}


def run(label, env):
    proc = subprocess.run(["bash", VERIFY], capture_output=True, text=True, env=env, timeout=300)
    text = proc.stdout + proc.stderr
    return {
        "label": label,
        "rc": proc.returncode,
        "error_lines": [ln for ln in text.splitlines() if "::error::" in ln][:12],
        "ok_count": text.count("[OK]"),
        "mode_line": next((ln for ln in text.splitlines() if ln.startswith("[preflight]")), ""),
        "leaked_vows": [LABEL[v] for v in VOWS if os.environ.get(v) and os.environ[v] in text],
    }


def main():
    report = {
        "runner": {"os": os.environ.get("RUNNER_OS"), "image": os.environ.get("ImageOS"),
                   "label": os.environ.get("RUNNER_NAME", "")[:24]},
        "runtime_present": os.path.isfile(VERIFY) and os.path.isfile(
            os.path.join(RUNTIME, "preflight.py")),
        "vow_present": {v: bool(os.environ.get(v)) for v in VOWS},
        "censor_word_in_vow": any(os.environ.get(v) == "***" for v in VOWS),
        "venv": os.environ.get("GHA_INTERACTIVE_VENV"),
        "novnc": bool(os.environ.get("GHA_NOVNC_DIR")),
    }
    base = dict(os.environ)
    report["cases"] = []

    # 1) 原样环境：应当通过（Tunnel 配置由 case 5/6 单独判定）
    report["cases"].append(run("as-is", base))

    # 2) 缺一个二进制：必须失败
    stripped = dict(base)
    stripped["PATH"] = "/runner-tools-only"
    report["cases"].append(run("empty-PATH", stripped))

    # 3) 缺 agent-desktop 命令
    shim = os.environ.get("RUNNER_TEMP", "/tmp") + "/gha-pf-shim"
    os.makedirs(shim, exist_ok=True)
    for name in ("Xvfb", "openbox", "dbus-launch", "dbus-daemon", "dbus-send", "ffmpeg", "cloudflared",
                 "xdotool", "wmctrl", "scrot", "x11vnc", "websockify", "python3", "npm"):
        path = os.path.join(shim, name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)
    shim_env = dict(base)
    shim_env["PATH"] = shim
    report["cases"].append(run("no-agent-desktop", shim_env))

    # 4) 缺 noVNC 资源
    novnc_env = dict(base)
    novnc_env["GHA_NOVNC_DIR"] = shim
    report["cases"].append(run("no-novnc", novnc_env))

    # 5) Quick 只有 endpoint 没 Token；6) Named 只有 hostname 没 Token
    for label, key in (("quick-endpoint-only", "GHA_RENDEZVOUS_TOKEN"),
                       ("named-hostname-only", "GHA_TUNNEL_TOKEN")):
        env = {k: v for k, v in base.items() if k not in (
            "GHA_RENDEZVOUS_TOKEN", "GHA_RENDEZVOUS_ENDPOINT" if label.startswith("named") else "",)}
        if label.startswith("quick"):
            env["GHA_RENDEZVOUS_ENDPOINT"] = "https://registry.invalid"
        else:
            env["GHA_TUNNEL_HOSTNAME"] = "debug.invalid.example"
        report["cases"].append(run(label, env))

    with open(os.path.join(OUT, "preflight.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
