"""gha-runner —— 把高强度任务卸载到 GitHub Actions 执行并取回结果。

stdlib-only，Python >= 3.9。外部依赖只有 gh CLI（必需）与 git（仅分支投递路径需要）。
"""

__version__ = "2.0.0"

# manifest 契约版本：1 = 无 state 小节；2 = 新增 state 小节（跨次环境复用）
MANIFEST_SCHEMA = 2
SUPPORTED_SCHEMAS = (1, 2)
