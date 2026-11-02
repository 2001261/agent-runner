"""Browser 客户端命令封装。

遵循《2.0 迭代.md》第七章与第二十一章 21.2。
支持：
- gha browser snapshot <task-id>
- gha browser navigate <task-id> <url>
"""

from __future__ import annotations

from typing import Any, Dict

from .interactive_client import InteractiveClient


class BrowserClient:
    """Agent 浏览器控制客户端"""

    def __init__(self, client: InteractiveClient):
        self.client = client

    def _command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        body["generation"] = self.client.session_status()["generation"]
        return self.client.post("/v1/browser/command", body)

    def navigate(self, url: str) -> Dict[str, Any]:
        """导航到指定网址"""
        return self._command({"cmd": "navigate", "url": url})

    def snapshot(self) -> Dict[str, Any]:
        """抓取当前页面 DOM 与无障碍树快照"""
        return self._command({"cmd": "snapshot"})

    def screenshot(self) -> bytes:
        """捕获浏览器页面截图"""
        import json
        import urllib.request
        req = self.client._headers({"Content-Type": "application/json"})
        data = json.dumps({
            "cmd": "screenshot",
            "generation": self.client.session_status()["generation"],
        }).encode("utf-8")
        request = urllib.request.Request(
            self.client.base_url + "/v1/browser/command",
            data=data, headers=req, method="POST")
        with urllib.request.urlopen(request, timeout=self.client.timeout) as resp:
            return resp.read()

    def get_storage_state(self) -> Dict[str, Any]:
        """获取浏览器认证状态"""
        return self._command({"cmd": "storage_state"})
