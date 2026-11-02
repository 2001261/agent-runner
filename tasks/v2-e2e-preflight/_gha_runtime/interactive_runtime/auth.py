"""权限认证与短期 Ticket 管理。

遵循《2.0 迭代.md》第六章 6.4 权限划分与第九章 9.4 授权规范。
权限范围：AGENT, HUMAN_BROWSER, HUMAN_DESKTOP, STATE_READER, STATE_WRITER。
提供受限 Token 生成、单次兑换 Ticket、超时强制撤销及请求验权。

Ticket 兑换是原子的：同一 Ticket 在并发下只有一个兑换能成功，重放一律失败，
失败的重放也不会把首个成功者的会话作废（「先验后删」会踩踏，这里改为 hold/commit）。
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Set, Tuple


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
    session_id: Optional[str] = None

    def is_valid(self) -> bool:
        return not self.claimed and time.time() < self.expires_at


class AuthManager:
    """认证与授权管理器（线程安全；aiohttp 多 worker 与线程池共享同一实例）"""

    def __init__(self, master_secret: Optional[str] = None):
        self._secret = master_secret or secrets.token_hex(32)
        self._tokens: Dict[str, TokenInfo] = {}
        self._tickets: Dict[str, HandoffTicket] = {}
        self._session_cookies: Dict[str, TokenInfo] = {}
        self._lock = threading.RLock()

    def create_agent_token(self, ttl_seconds: int = 86400) -> str:
        """生成具备 AGENT 和 STATE 读写权限的 Agent Token"""
        token = "agt_" + secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
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
        with self._lock:
            self._purge_tickets(now)
            self._tickets[ticket_id] = HandoffTicket(
                ticket_id=ticket_id,
                mode=mode,
                created_at=now,
                expires_at=now + ttl_seconds,
            )
        return ticket_id

    def exchange_ticket_for_session(self, ticket_id: str) -> Optional[Tuple[str, Scope]]:
        """兑换接管 Ticket 为专属 session cookie/token，并标记 Ticket 已经失效"""
        if not ticket_id:
            return None
        now = time.time()
        scope = self._hold_ticket(ticket_id, now)
        if scope is None:
            return None
        session_id = "hmn_" + secrets.token_urlsafe(32)
        token_info = TokenInfo(
            token=session_id,
            scopes={scope},
            created_at=now,
            expires_at=now + 1800,  # 30 分钟会话
            description="Human handoff session",
        )
        with self._lock:
            self._session_cookies[session_id] = token_info
            ticket = self._tickets.get(ticket_id)
            if ticket is not None:
                ticket.session_id = session_id
        return session_id, scope

    def _hold_ticket(self, ticket_id: str, now: float) -> Optional[Scope]:
        """原子地占用 Ticket；并发 / 重放时只有一个线程能拿到 Scope。"""
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None or ticket.claimed or now >= ticket.expires_at:
                return None
            ticket.claimed = True
            return Scope.HUMAN_DESKTOP if ticket.mode == "desktop" else Scope.HUMAN_BROWSER

    def revoke_ticket(self, ticket_id: str) -> bool:
        """撤销 Ticket。已兑换出会话的 Ticket 保留绑定关系，供随后撤销该会话。"""
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return False
            ticket.claimed = True
            ticket.expires_at = 0.0
            if ticket.session_id is None:
                del self._tickets[ticket_id]
        return True

    def revoke_session(self, session_id: str) -> bool:
        """撤销单个会话 Cookie，其余凭证不受影响。"""
        if not session_id:
            return False
        with self._lock:
            info = self._session_cookies.pop(session_id, None)
            if info is None:
                return False
            info.is_revoked = True
            for ticket in self._tickets.values():
                if ticket.session_id == session_id:
                    ticket.session_id = None
        return True

    def revoke_session_for_ticket(self, ticket_id: str) -> bool:
        """按 Ticket 找到其兑换出的会话并撤销。"""
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            session_id = ticket.session_id if ticket is not None else None
        return self.revoke_session(session_id) if session_id else False

    def verify_token(self, token_or_cookie: str, required_scope: Optional[Scope] = None) -> bool:
        """核验令牌是否有效且包含指定权限"""
        if not token_or_cookie:
            return False

        with self._lock:
            info = self._tokens.get(token_or_cookie) or self._session_cookies.get(token_or_cookie)
        if not info or not info.is_valid():
            return False

        if required_scope is not None and required_scope not in info.scopes:
            return False

        return True

    def _purge_tickets(self, now: float) -> None:
        """清理过期且不再绑定有效会话的 Ticket。"""
        dead = [
            tid for tid, t in self._tickets.items()
            if now >= t.expires_at
            and (t.session_id is None or t.session_id not in self._session_cookies)
        ]
        for tid in dead:
            del self._tickets[tid]

    def revoke_all(self) -> None:
        """撤销所有凭证"""
        with self._lock:
            for t in self._tokens.values():
                t.is_revoked = True
            for s in self._session_cookies.values():
                s.is_revoked = True
            self._tokens.clear()
            self._session_cookies.clear()
            self._tickets.clear()
