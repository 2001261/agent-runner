#!/usr/bin/env bash
# 启动 Xvfb, Openbox, D-Bus session
set -euo pipefail

DISPLAY_NUM="${1:-:99}"
RESOLUTION="${2:-1280x800x24}"

echo "启动虚拟显示器 $DISPLAY_NUM 分辨率 $RESOLUTION ..."
Xvfb "$DISPLAY_NUM" -screen 0 "$RESOLUTION" -ac +extension RANDR >/dev/null 2>&1 &
XVFB_PID=$!
sleep 1

export DISPLAY="$DISPLAY_NUM"

# 启动 D-Bus 会话
if command -v dbus-launch >/dev/null 2>&1; then
  eval "$(dbus-launch --sh-syntax)"
  export DBUS_SESSION_BUS_ADDRESS
fi

# 启动 Openbox
if command -v openbox >/dev/null 2>&1; then
  openbox >/dev/null 2>&1 &
fi

echo "图形环境已就绪: DISPLAY=$DISPLAY_NUM, DBUS=$DBUS_SESSION_BUS_ADDRESS"
