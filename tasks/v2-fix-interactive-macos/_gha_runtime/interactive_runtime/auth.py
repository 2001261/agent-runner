"""权限认证与短期 Ticket 管理。

遵循《2.0 迭代.md》第六章 6.4 权限划分与第九章 9.4 授权规范。
权限范围：AGENT, HUMAN_BROWSER, HUMAN_DESKTOP, STATE_READER, STATE_WRITER。
提供受限 Token 生成、单次兑换 Ticket、超时强制撤销及请求验权。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class Scope(str, Enum):
    AGENT = "AGENT"
    HUMAN_BROWSER = "HUMAN_BROWSER"
    HUMAN_DESKTOP = "HUMAN_DESKTOP"
    STATE_READER = "STATE_READER"
    STATE_WRITER = "STATE_WRITER"


@dataclass
class TokenInfo:
    token: str
    scopes: Set[Scope]
    created_at: float
    expires_at: float
    description: str = ""
    is_revoked: bool = False

    def is_valid(self) -> bool:
        return not self.is_revoked and time.time() < self.expires_at


@dataclass
class HandoffTicket:
    ticket_id: str
    mode: str  # "browser" | "desktop"
    created_at: float
    expires_at: float
    claimed: bool = False

    def is_valid(self) -> bool:
        return not self.claimed and time.time() < self.expires_at


class AuthManager:
    """认证与授权管理器"""

    def __init__(self, master_secret: Optional[str] = None):
        self._secret = master_secret or secrets.token_hex(32)
        self._tokens: Dict[str, TokenInfo] = {}
        self._tickets: Dict[str, HandoffTicket] = {}
        self._session_cookies: Dict[str, TokenInfo] = {}

    def create_agent_token(self, ttl_seconds: int = 86400) -> str:
        """生成具备 AGENT 和 STATE 读写权限的 Agent Token"""
        token = "agt_" + secrets.token_urlsafe(32)
        now = time.time()
        self._tokens[token] = TokenInfo(
            token=token,
            scopes={Scope.AGENT, Scope.STATE_READER, Scope.STATE_WRITER},
            created_at=now,
            expires_at=now + ttl_seconds,
            description="Agent primary control token",
        )
        return token

    def create_handoff_ticket(self, mode: str = "browser", ttl_seconds: int = 300) -> str:
        """生成一次性兑换的接管 Ticket"""
        ticket_id = "tkt_" + secrets.token_urlsafe(24)
        now = time.time()
        self._tickets[ticket_id] = HandoffTicket(
            ticket_id=ticket_id,
            mode=mode,
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        return ticket_id

    def exchange_ticket_for_session(self, ticket_id: str) -> Optional[Tuple[str, Scope]]:
        """兑换接管 Ticket 为专属 session cookie/token，并标记 Ticket 已经失效"""
        ticket = self._tickets.get(ticket_id)
        if not ticket or not ticket.is_valid():
            return None

        ticket.claimed = True
        session_id = "hmn_" + secrets.token_urlsafe(32)
        now = time.time()
        scope = Scope.HUMAN_DESKTOP if ticket.mode == "desktop" else Scope.HUMAN_BROWSER
        token_info = TokenInfo(
            token=session_id,
            scopes={scope},
            created_at=now,
            expires_at=now + 1800,  # 30 分钟会话
            description=f"Human handoff session ({ticket.mode})",
        )
        self._session_cookies[session_id] = token_info
        return session_id, scope

    def verify_token(self, token_or_cookie: str, required_scope: Optional[Scope] = None) -> bool:
        """核验令牌是否有效且包含指定权限"""
        if not token_or_cookie:
            return False

        info = self._tokens.get(token_or_cookie) or self._session_cookies.get(token_or_cookie)
        if not info or not info.is_valid():
            return False

        if required_scope is not None and required_scope not in info.scopes:
            return False

        return True

    def revoke_all(self) -> None:
        """撤销所有凭证"""
        for t in self._tokens.values():
            t.is_revoked = True
        for s in self._session_cookies.values():
            s.is_revoked = True
        self._tickets.clear()
