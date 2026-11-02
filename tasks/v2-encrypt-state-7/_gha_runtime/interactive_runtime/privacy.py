"""隐私与凭据脱敏过滤器。

遵循《2.0 迭代.md》第十八章「安全与数据隔离」与第五章 5.4。
确保 Tunnel 随机地址、Ticket、Token、Cookie 及私有 Registry 地址不泄露至 GitHub 公开输出。
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Set

# 敏感正则特征
SENSITIVE_PATTERNS = [
    # Cloudflare trycloudflare 域名
    re.compile(r"https?://[a-zA-Z0-9-]+\.trycloudflare\.com[^\s]*", re.IGNORECASE),
    # Token 格式
    re.compile(r"agt_[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"tkt_[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"hmn_[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    # age 密钥
    re.compile(r"AGE-SECRET-KEY-[0-9A-Z]{50,}", re.IGNORECASE),
    # 典型 Bearer / Header 令牌
    re.compile(r"(authorization:\s*bearer\s+)[^\s]+", re.IGNORECASE),
]


class PrivacyFilter:
    """运行期敏感信息过滤器"""

    def __init__(self, custom_secrets: Optional[Iterable[str]] = None):
        self._exact_values: Set[str] = set()
        if custom_secrets:
            for s in custom_secrets:
                if s and len(s) >= 4:
                    self._exact_values.add(s)

    def register_secret(self, secret: str) -> None:
        """注册需要脱敏的精确字符串"""
        if secret and len(secret) >= 4:
            self._exact_values.add(secret)

    def redact_text(self, text: str) -> str:
        """对文本执行深度脱敏替换"""
        if not text:
            return ""

        result = text

        # 1. 精确值字面替换
        for sec in sorted(self._exact_values, key=len, reverse=True):
            if sec in result:
                result = result.replace(sec, "***")

        # 2. 正则特征替换
        for pat in SENSITIVE_PATTERNS:
            result = pat.sub("***", result)

        return result

    def is_clean(self, text: str) -> bool:
        """检查文本是否包含已知敏感信息"""
        if not text:
            return True
        for sec in self._exact_values:
            if sec in text:
                return False
        for pat in SENSITIVE_PATTERNS:
            if pat.search(text):
                return False
        return True
