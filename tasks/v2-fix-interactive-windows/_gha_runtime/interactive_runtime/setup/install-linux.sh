#!/usr/bin/env bash
# Ubuntu 24.04 GitHub-hosted Runner：安装 Interactive Runtime 系统依赖与隔离 Python 环境。
set -euo pipefail

if [ "${RUNNER_OS:-}" != "Linux" ]; then
  echo "::error::Interactive Runtime 首发仅支持 Linux Runner；当前为 ${RUNNER_OS:-unknown}。"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y \
  xvfb openbox dbus-x11 at-spi2-core x11-utils xdotool wmctrl scrot \
  ffmpeg x11vnc websockify curl tar zstd ca-certificates

# cloudflared 只用于 Runner 主动出站连接；日志由 Runtime 私密读取。
if ! command -v cloudflared >/dev/null 2>&1; then
  curl -fsSL -o /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i /tmp/cloudflared.deb
  rm -f /tmp/cloudflared.deb
fi

VENV="${GHA_INTERACTIVE_VENV:-$RUNNER_TEMP/gha-interactive-venv}"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet \
  -r "$GHA_TASK_DIR/_gha_runtime/interactive_runtime/requirements.txt"
"$VENV/bin/playwright" install --with-deps chromium

echo "GHA_INTERACTIVE_VENV=$VENV" >> "$GITHUB_ENV"
