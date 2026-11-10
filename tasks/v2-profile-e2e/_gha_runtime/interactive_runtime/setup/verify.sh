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

# 用 bash 纯内建定位脚本目录，不依赖 dirname：实测 run 42610101171 的 empty-PATH 下
# `$(dirname ...)` 输出为空，here 退化成任务根目录（cd "" 等于不动），于是把
# preflight.py 找成任务根下的同名文件并误报缺失。
# 步骤：取 BASH_SOURCE[0] 最后一个 '/' 之前的目录部分（不含 '/' 即 ./）→ 去掉结尾的
# '/'（根目录保留）→ cd/pwd 得到规范绝对路径。只用到 ${v%pat}/${v#pat} 参数展开，
# macOS 自带 bash 3.2 也能执行。
self="${BASH_SOURCE[0]}"
script_dir="${self%/*}"
[ "$script_dir" = "$self" ] && script_dir=.
# 显式写法调用时这里可能带结尾的 '/'（x/setup//），去掉后 cd 语义不变。
while [ "$script_dir" != "/" ] && [ "${script_dir%/}" != "$script_dir" ]; do
  script_dir="${script_dir%/}"
done
if ! here="$(cd -- "$script_dir" && pwd -P)"; then
  echo "::error::Interactive Runtime 无法定位 verify.sh 所在目录：$script_dir"
  exit 1
fi
[ -n "$here" ] || { echo "::error::Interactive Runtime 无法定位 verify.sh 所在目录：$script_dir"; exit 1; }
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
