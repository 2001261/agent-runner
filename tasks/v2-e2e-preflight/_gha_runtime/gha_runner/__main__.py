"""`python -m gha_runner` 入口。

也支持直接 `python path/to/gha_runner/__main__.py` —— 那种调用方式下包不在
sys.path 上，需要手动把父目录加进去。
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from gha_runner.cli import main
else:
    from .cli import main

if __name__ == "__main__":
    sys.exit(main())
