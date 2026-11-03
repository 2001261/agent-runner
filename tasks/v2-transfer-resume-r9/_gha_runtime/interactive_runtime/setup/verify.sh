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
# 用 bash 自己的字符串运算拼接：dirname / cd 这些外部工具在精简 PATH 里可能不存在，
# 那条分支会把“脚本缺失”误报成任务包不完整。
preflight="${here%/setup}/preflight.py"
if [ ! -f "$preflight" ]; then
  echo "::error::Interactive Runtime 预检脚本缺失：$preflight（任务包不完整）"
  exit 1
fi

# GHA_PREFLIGHT_PY：仅供测试注入替身解释器；生产不设置，走 Runner 自带的 python3。
# GHA_PREFLIGHT_PY 非空时属于显式选择（与 Bun 的 BUN_BE_BUN 同理），按路径直接执行，
# 不再过 `command -v`：替身不必在 PATH 里，精简 PATH 的用例也不会误落到系统 python3。
PY="${GHA_PREFLIGHT_PY:-}"
if [ -z "$PY" ]; then
  for candidate in python3 /usr/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
  done
fi
if [ -z "$PY" ]; then
  echo "::error::Runner 上没有系统 python3，无法执行 Interactive Runtime 预检"
  exit 1
fi

# -I：隔离模式，避免 PYTHONPATH / 用户 site-packages 影响判定（预检只要求标准库）。
# 变量紧贴引号（"${rc}"）而不是（$rc）：部分 bash（如 macOS 自带 3.2）紧贴在多字节
# 字符前的 $var 会按字节混切，输出变成乱码。
"$PY" -I -B "$preflight"
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "::error::Interactive Runtime 环境预检失败（exit=${rc}），拒绝启动。"
  exit "$rc"
fi
exit 0
