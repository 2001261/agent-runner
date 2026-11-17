#!/usr/bin/env bash
# Ubuntu 24.04 GitHub-hosted Runner：安装 Interactive Runtime 系统依赖与隔离 Python 环境。
set -euo pipefail

if [ "${RUNNER_OS:-}" != "Linux" ]; then
  echo "::error::Interactive Runtime 首发仅支持 Linux Runner；当前为 ${RUNNER_OS:-unknown}。"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
# dbus-x11 提供 dbus-launch / dbus-send / dbus-daemon；at-spi2-core 提供
# org.a11y.Bus 与 at-spi-bus-launcher。两者缺一，agent-desktop 的窗口快照
# 就只能返回 WINDOW_NOT_FOUND。
sudo apt-get install -y \
  xvfb openbox dbus-x11 dbus at-spi2-core x11-utils xdotool wmctrl scrot \
  ffmpeg x11vnc websockify curl tar zstd ca-certificates

# cloudflared 只用于 Runner 主动出站连接；日志由 Runtime 私密读取。
if ! command -v cloudflared >/dev/null 2>&1; then
  curl -fsSL -o /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i /tmp/cloudflared.deb
  rm -f /tmp/cloudflared.deb
fi

npm install -g agent-desktop@1.0.2
npm install -g @novnc/novnc@1.7.0

# agent-desktop 的 npm 安装脚本失效时会退回 Node 启动器；Linux 原生二进制与
# 剪贴板 helper 必须可执行，否则 AT-SPI 快照无法工作。
AGENT_DESKTOP_BIN="$(command -v agent-desktop || true)"
if [ -z "$AGENT_DESKTOP_BIN" ]; then
  echo "::error::agent-desktop 未安装到 PATH（npm root -g: $(npm root -g)）"
  exit 1
fi
# npm 全局安装时 /usr/local/bin/agent-desktop 是指向包内启动器的符号链接，
# 真正做 AT-SPI 访问的原生二进制位于链接目标的同一目录。
AGENT_DESKTOP_DIR="$(dirname "$(readlink -f "$AGENT_DESKTOP_BIN")")"
if [ ! -d "$AGENT_DESKTOP_DIR" ] || [ ! -e "$AGENT_DESKTOP_DIR/agent-desktop-linux-x64" ]; then
  AGENT_DESKTOP_DIR="$(npm root -g)/agent-desktop/bin"
fi
AGENT_DESKTOP_NATIVE="$AGENT_DESKTOP_DIR/agent-desktop-linux-x64"
if [ ! -f "$AGENT_DESKTOP_NATIVE" ]; then
  AGENT_DESKTOP_NATIVE="$AGENT_DESKTOP_DIR/agent-desktop-linux-arm64"
fi
if [ ! -x "$AGENT_DESKTOP_NATIVE" ]; then
  chmod 755 "$AGENT_DESKTOP_DIR" "$AGENT_DESKTOP_NATIVE" 2>/dev/null || true
fi
if [ ! -x "$AGENT_DESKTOP_NATIVE" ]; then
  echo "::error::agent-desktop 原生二进制缺失或不可执行：$AGENT_DESKTOP_NATIVE"
  exit 1
fi
for helper in "$AGENT_DESKTOP_DIR"/agent-desktop-linux-clipboard-owner*; do
  [ -f "$helper" ] && chmod 755 "$helper"
done

VENV="${GHA_INTERACTIVE_VENV:-$RUNNER_TEMP/gha-interactive-venv}"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet \
  -r "$GHA_TASK_DIR/_gha_runtime/interactive_runtime/requirements.txt"
"$VENV/bin/playwright" install --with-deps chromium

echo "GHA_INTERACTIVE_VENV=$VENV" >> "$GITHUB_ENV"
echo "GHA_NOVNC_DIR=$(npm root -g)/@novnc/novnc" >> "$GITHUB_ENV"
