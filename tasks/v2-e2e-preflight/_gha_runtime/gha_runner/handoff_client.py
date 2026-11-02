"""Handoff 客户端工作流封装。

遵循《2.0 迭代.md》第七章 7.2、第八章 8.2 与第二十一章 21.2。
支持：
- gha handoff request <task-id> --mode browser|desktop
- gha handoff open <task-id>
- gha handoff complete <task-id>
"""

from __future__ import annotations

import webbrowser
from typing import Any, Dict, Optional

from .interactive_client import InteractiveClient


class HandoffClient:
    """人工接管协调客户端"""

    def __init__(self, client: InteractiveClient):
        self.client = client

    def request_handoff(self, mode: str = "browser", timeout_seconds: int = 300) -> Dict[str, Any]:
        """请求人工接管并获取一次性 Ticket"""
        return self.client.post("/v1/handoff/request", {"mode": mode, "timeout_seconds": timeout_seconds})

    def open_portal(self, handoff_url: str) -> bool:
        """在宿主机默认浏览器中打开接管门户"""
        full_url = handoff_url if handoff_url.startswith("http") else f"{self.client.base_url}{handoff_url}"
        try:
            return webbrowser.open(full_url)
        except Exception:
            return False

    def complete_handoff(self) -> Dict[str, Any]:
        """完成人工接管，交还控制权给 Agent"""
        return self.client.post("/v1/handoff/complete")

    def cancel_handoff(self) -> Dict[str, Any]:
        """取消接管请求"""
        return self.client.post("/v1/handoff/cancel")
