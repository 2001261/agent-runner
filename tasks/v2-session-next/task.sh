#!/usr/bin/env bash
# 供真实 Interactive Runtime 验收：长驻并持续更新可恢复的 TASK 状态。
set -uo pipefail
seconds="${GHA_DEMO_HOLD_SECONDS:-1800}"
mkdir -p "$GHA_OUTPUT_DIR" "$GHA_TASK_DIR/state"
echo "interactive session: ${seconds}s（不输出任何会话地址或令牌）"
for ((i=0; i<seconds; i+=5)); do
  printf '{"iteration":%d,"total_seconds":%d,"status":"running"}\n' "$i" "$seconds" > "$GHA_TASK_DIR/state/progress.json.tmp"
  mv "$GHA_TASK_DIR/state/progress.json.tmp" "$GHA_TASK_DIR/state/progress.json"
  sleep 5
done
printf '{"iteration":%d,"total_seconds":%d,"status":"completed"}\n' "$seconds" "$seconds" > "$GHA_TASK_DIR/state/progress.json"
printf 'session=ok\n' > "$GHA_OUTPUT_DIR/_outputs.env"
