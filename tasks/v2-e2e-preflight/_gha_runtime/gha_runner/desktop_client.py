"""Desktop 客户端命令封装。

遵循《2.0 迭代.md》第八章与第二十一章 21.2。
支持：
- gha desktop snapshot <task-id>
- gha desktop screenshot <task-id>
"""

from __future__ import annotations

import os
from typing import Any, Dict

from .interactive_client import InteractiveClient


class DesktopClient:
    """Agent 桌面控制客户端"""

    def __init__(self, client: InteractiveClient):
        self.client = client

    def _command(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        body["generation"] = self.client.session_status()["generation"]
        return self.client.post("/v1/agent/command", body)

    def snapshot(self) -> Dict[str, Any]:
        """抓取桌面窗口与无障碍树结构"""
        return self._command({"cmd": "snapshot"})

    def screenshot(self, output_file: Optional[str] = None) -> bytes:
        """捕获虚拟桌面截图并保存至本地文件"""
        url = f"{self.client.base_url}/v1/agent/command"
        req = self.client._headers({"Content-Type": "application/json"})
        import json, urllib.request
        data = json.dumps({
            "cmd": "screenshot",
            "generation": self.client.session_status()["generation"],
        }).encode("utf-8")
        r = urllib.request.Request(url, data=data, headers=req, method="POST")
        with urllib.request.urlopen(r, timeout=self.client.timeout) as resp:
            png_bytes = resp.read()

        if output_file:
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
            with open(output_file, "wb") as f:
                f.write(png_bytes)

        return png_bytes

    def click(self, x: int, y: int, button: int = 1) -> Dict[str, Any]:
        return self._command({"cmd": "click", "x": x, "y": y, "button": button})

    def type_text(self, text: str) -> Dict[str, Any]:
        return self._command({"cmd": "type", "text": text})

    def key(self, key_combination: str) -> Dict[str, Any]:
        return self._command({"cmd": "key", "key": key_combination})
