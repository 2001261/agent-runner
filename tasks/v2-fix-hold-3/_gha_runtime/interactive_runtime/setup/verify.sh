#!/usr/bin/env bash
# Interactive Runtime 启动前硬门禁：缺任何必需组件即失败，禁止静默降级为 mock。
set -uo pipefail

missing=0
if [ "${RUNNER_OS:-}" != "Linux" ]; then
  echo "::error::Interactive Runtime 仅支持 Linux Runner，当前为 ${RUNNER_OS:-unknown}。"
  exit 1
fi

check_cmd() {
  local name="$1" cmd="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    echo "  [OK] $name: $(command -v "$cmd")"
  else
    echo "::error::缺少必需组件 $name（命令 $cmd 不可用）"
    missing=1
  fi
}

for pair in \
  "Xvfb:Xvfb" "Openbox:openbox" "D-Bus:dbus-launch" \
  "FFmpeg:ffmpeg" "cloudflared:cloudflared" \
  "GUI input:xdotool" "Window manager:wmctrl" "Screenshot:scrot" \
  "agent-desktop:agent-desktop" \
  "VNC:x11vnc" "WebSocket bridge:websockify" "Python:python3"; do
  check_cmd "${pair%%:*}" "${pair#*:}"
done

VENV="${GHA_INTERACTIVE_VENV:-$RUNNER_TEMP/gha-interactive-venv}"
if [ ! -x "$VENV/bin/python" ]; then
  echo "::error::隔离 Python 环境不存在：$VENV"
  missing=1
else
  "$VENV/bin/python" - <<'PY'
import importlib.util
import sys
missing = [name for name in ("aiohttp", "playwright", "cryptography", "yaml")
           if importlib.util.find_spec(name) is None]
if missing:
    print("::error::隔离 Python 环境缺少模块：" + ", ".join(missing))
    sys.exit(1)
print("  [OK] Python 隔离依赖完整")
PY
  if [ $? -ne 0 ]; then missing=1; fi
fi

if [ -z "${GHA_RENDEZVOUS_ENDPOINT:-}" ] && [ -z "${GHA_TUNNEL_HOSTNAME:-}" ]; then
  echo "::error::Quick Tunnel 必须配置 GHA_RENDEZVOUS_ENDPOINT 用于私有会话发现；Named Tunnel 必须配置 GHA_TUNNEL_HOSTNAME。"
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  echo "::error::Interactive Runtime 环境预检失败，拒绝启动。"
  exit 1
fi
echo "=== Interactive Runtime 环境预检通过 ==="
