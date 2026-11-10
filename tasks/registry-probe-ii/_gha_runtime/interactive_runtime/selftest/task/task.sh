#!/usr/bin/env bash
# 交接闭环自查入口：Runtime 由 task.py 拉起（产品 Supervisor + selftest-handoff）。
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${GHA_PYBIN:-python3}" "$DIR/task.py"
