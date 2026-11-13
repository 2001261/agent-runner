#!/usr/bin/env bash
# 最小 Registry 公网探针：/health + 正式 register/resolve/revoke（按需拉起交互运行时）。
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${GHA_PYBIN:-python3}" "$DIR/task.py"
