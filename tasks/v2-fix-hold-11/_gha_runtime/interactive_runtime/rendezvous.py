"""私有会话发现（Rendezvous Provider）。

遵循《2.0 迭代.md》第五章 5.4 与 5.5「随机地址私有发现与 Registry 规范」。
职责：
- Runner 侧将生成的随机 trycloudflare URL 加密/安全提交至私有 Registry 或 HTTPS 回调；
- Agent 侧从 Registry 安全查询当前 session_id / run_id 对应的公网网关入口；
- 绝不在 GitHub Actions Log, Job Summary 或 Artifact 中暴露随机地址。
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class RendezvousClient:
    """私有注册中心通信客户端"""

    def __init__(self, endpoint: Optional[str] = None, auth_token: Optional[str] = None):
        self.endpoint = endpoint
        self.auth_token = auth_token

    async def register_session(
        self,
        session_id: str,
        run_id: str,
        origin: str,
        ttl_seconds: int = 7200,
        agent_token: Optional[str] = None,
    ) -> bool:
        """向私有 Registry 注册会话入口 URL 与受限 Agent Token（仅经认证私有通道）。"""
        if not self.endpoint:
            # 本地开发或 Named Tunnel 可不使用 Registry；GHA Quick 由 Supervisor 强制要求。
            return True

        payload = {
            "session_id": session_id,
            "run_id": run_id,
            "origin": origin,
            "expires_at": int(time.time() + ttl_seconds),
        }
        if agent_token:
            payload["agent_token"] = agent_token
        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "gha-runner/2.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")

        loop = asyncio.get_event_loop()
        try:
            def _post():
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status in (200, 201, 204)
            return await loop.run_in_executor(None, _post)
        except Exception:
            return False

    async def resolve_session(self, session_id: str, run_id: Optional[str] = None) -> Optional[str]:
        """Agent 查询 Registry 获取当前 Session 的网关 URL"""
        if not self.endpoint:
            return None

        url = f"{self.endpoint.rstrip('/')}/v1/sessions/{session_id}"
        headers = {
            "User-Agent": "gha-runner/2.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        req = urllib.request.Request(url, headers=headers, method="GET")
        loop = asyncio.get_event_loop()
        try:
            def _get():
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        return data.get("origin")
                return None
            return await loop.run_in_executor(None, _get)
        except Exception:
            return None

    async def resolve_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """按 GitHub run_id 获取当前会话的私有连接信息。"""
        if not self.endpoint:
            return None
        url = f"{self.endpoint.rstrip('/')}/v1/runs/{run_id}"
        headers = {"User-Agent": "gha-runner/2.0"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        loop = asyncio.get_event_loop()
        try:
            def _get():
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if resp.status == 200:
                        return json.loads(resp.read().decode("utf-8"))
                return None
            return await loop.run_in_executor(None, _get)
        except Exception:
            return None


class InMemoryRegistry:
    """供本地测试与回环演示的模拟 Registry 服务"""

    def __init__(self):
        self._entries: Dict[str, Dict[str, Any]] = {}

    def register(self, session_id: str, run_id: str, origin: str, ttl: int = 3600) -> None:
        self._entries[session_id] = {
            "session_id": session_id,
            "run_id": run_id,
            "origin": origin,
            "expires_at": time.time() + ttl,
        }

    def resolve(self, session_id: str) -> Optional[str]:
        entry = self._entries.get(session_id)
        if entry and time.time() < entry["expires_at"]:
            return entry["origin"]
        return None
