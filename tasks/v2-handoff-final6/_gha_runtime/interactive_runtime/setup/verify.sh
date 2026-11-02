#!/usr/bin/env bash
# Interactive Runtime 启动前硬门禁：缺任何必需组件即失败，禁止静默降级为 mock。
#
# 严格语义：
#  - 任何一项缺失（含 agent-desktop 命令不存在、noVNC 资源缺失、依赖模块缺失）都以
#    ::error:: + exit 1 结束，绝不“部分通过”；
#  - Tunnel 只接受完整配置：Quick = GHA_RENDEZVOUS_ENDPOINT(https) + GHA_RENDEZVOUS_TOKEN；
#    Named = GHA_TUNNEL_HOSTNAME + GHA_TUNNEL_TOKEN；两者不可同时配置；
#  - 本脚本只打印组件名/路径与“已注入/未注入”，绝不回显 Token 或 Secret 的值。
#
# 判定逻辑在 interactive_runtime/preflight.py（用脚本同目录解析，不依赖 PYTHONPATH），
# 便于单测覆盖；本脚本只负责找到新 Runner 自带的系统 Python 并原样传播退出码。
set -uo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
preflight="$here/../preflight.py"
if [ ! -f "$preflight" ]; then
  echo "::error::Interactive Runtime 预检脚本缺失：$preflight（任务包不完整）"
  exit 1
fi

# GHA_PREFLIGHT_PY：仅供测试注入替身解释器；生产不设置，走 Runner 自带的 python3。
PY=""
for candidate in "${GHA_PREFLIGHT_PY:-}" python3 /usr/bin/python3; do
  [ -n "$candidate" ] || continue
  if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
if [ -z "$PY" ]; then
  echo "::error::Runner 上没有系统 python3，无法执行 Interactive Runtime 预检"
  exit 1
fi

# 预检前从任务包重新注入声明过的凭证，避免 Setup/安装步骤之间的环境差异。
credinject="$here/../../../_gha/credinject.py"
if [ -n "${GHA_TASK_SECRETS:-}" ] && [ -f "$credinject" ]; then
  eval "$("$PY" "$credinject" --emit-export)"
fi

# -I：隔离模式，避免 PYTHONPATH / 用户 site-packages 影响判定（预检只要求标准库）。
"$PY" -I -B "$preflight"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "::error::Interactive Runtime 环境预检失败（exit=$rc），拒绝启动。"
  exit "$rc"
fi
exit 0
