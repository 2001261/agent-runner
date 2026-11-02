"""宿主机按 run_id 发现 Runner Gateway 的 Registry 客户端。"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Tuple

from interactive_runtime.rendezvous import RegistryError, RendezvousClient, SignatureError


class RegistryClient:
    """只读查询：origin + 受限 Agent Token；租户用任务实际提交的仓库。

    Runner 侧登记的租户是 GITHUB_REPOSITORY，宿主必须按同一个值查询，
    否则会像“一边写仓库租户、一边用 default 查”那样永远找不到会话。
    """

    def __init__(self, endpoint: str, auth_token: str, user: str, timeout: float = 15.0):
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.user = user
        self.client = RendezvousClient(endpoint, auth_token, user=user, timeout=timeout)

    async def resolve_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        try:
            return await self.client.resolve_run(str(run_id))
        except (RegistryError, SignatureError):
            return None
        except asyncio.TimeoutError:
            return None

    def resolve_run_blocking(self, run_id: str) -> Optional[Tuple[str, str]]:
        """返回 (origin, agent_token)；未登记或不可达返回 None。"""
        rec = asyncio.run(self.resolve_run(run_id))
        if not rec or not rec.get("origin") or not rec.get("agent_token"):
            return None
        return str(rec["origin"]), str(rec["agent_token"])
