#!/usr/bin/env bash
# 让 Runtime 在宿主机完成浏览器/Handoff/State 操作前保持存活。
set -uo pipefail
seconds="${GHA_DEMO_HOLD_SECONDS:-300}"
echo "interactive hold: ${seconds}s（不输出任何会话地址或令牌）"
mkdir -p "$GHA_OUTPUT_DIR"
sleep "$seconds"
printf 'hold=ok\n' > "$GHA_OUTPUT_DIR/_outputs.env"
