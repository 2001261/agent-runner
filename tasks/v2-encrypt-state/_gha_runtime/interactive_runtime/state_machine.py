"""Session 状态机与控制权仲裁模块。

遵循《2.0 迭代.md》第九章「Agent 与人工控制权管理」。
实现排他性控制权、control_generation 世代递增防重放，以及严格状态流转。

异常分支都在状态机内自洽处理，不依赖调用方轮询：
- 接管请求超时：``tick()`` / 任一状态查询都会把 HANDOFF_REQUESTED 推进到 HANDOFF_TIMEOUT，
  并撤销当前接管 Ticket（``revoke`` 回调，由 Gateway 绑到 AuthManager）。
- 人工会话过期：超时后就地交还 Agent，并撤销人工会话。
- 控制权丢失：超时 / 故障 / 结束时撤销当前持有者的控制会话（``revoke`` 回调）。
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Callable, List, Optional, Tuple


class SessionState(str, Enum):
    INITIALIZING = "INITIALIZING"
    AGENT_ACTIVE = "AGENT_ACTIVE"
    HANDOFF_REQUESTED = "HANDOFF_REQUESTED"
    HUMAN_ACTIVE = "HUMAN_ACTIVE"
    RESUMING = "RESUMING"
    FINISHING = "FINISHING"
    FINISHED = "FINISHED"

    # 异常分支
    HANDOFF_TIMEOUT = "HANDOFF_TIMEOUT"
    CONNECTION_LOST = "CONNECTION_LOST"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    TASK_CANCELLED = "TASK_CANCELLED"
    RUNTIME_FAILED = "RUNTIME_FAILED"


class ControlRole(str, Enum):
    NONE = "NONE"
    AGENT = "AGENT"
    HUMAN_BROWSER = "HUMAN_BROWSER"
    HUMAN_DESKTOP = "HUMAN_DESKTOP"


CLOSED_STATES = (
    SessionState.FINISHING,
    SessionState.FINISHED,
    SessionState.RUNTIME_FAILED,
    SessionState.TASK_CANCELLED,
)

RevokeCallback = Callable[[str, Optional[int]], None]


class StateMachine:
    """Agent 与人工控制权仲裁状态机"""

    def __init__(self, default_handoff_timeout: int = 300):
        self._state: SessionState = SessionState.INITIALIZING
        self._current_role: ControlRole = ControlRole.NONE
        self._generation: int = 1
        self._handoff_mode: Optional[str] = None  # "browser" | "desktop"
        self._handoff_requested_at: float = 0.0
        self._handoff_timeout: int = default_handoff_timeout
        self._handoff_ticket: Optional[str] = None
        self._control_expires_at: Optional[float] = None
        self._listeners: List[Callable[[SessionState, int], None]] = []
        self._revoke_callbacks: List[RevokeCallback] = []
        self._timer_handle: Optional[asyncio.TimerHandle] = None
        self._timer_deadline: Optional[float] = None

    # ---- 查询与监听

    @property
    def state(self) -> SessionState:
        self._expire_if_due()
        return self._state

    @property
    def current_role(self) -> ControlRole:
        self._expire_if_due()
        return self._current_role

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def handoff_mode(self) -> Optional[str]:
        return self._handoff_mode

    @property
    def handoff_ticket(self) -> Optional[str]:
        return self._handoff_ticket

    @property
    def handoff_deadline(self) -> Optional[float]:
        """当前接管请求（或人工会话）的绝对超时时刻，供定时器对齐。

        纯读取，不推进状态：推进由 ``tick()`` / 状态查询负责，避免在请求刚建立时
        被自身的超时检查提前打翻。
        """
        if self._state == SessionState.HANDOFF_REQUESTED:
            return self._handoff_requested_at + self._handoff_timeout
        if self._state == SessionState.HUMAN_ACTIVE:
            return self._control_expires_at
        return None

    @property
    def is_closed(self) -> bool:
        return self._state in CLOSED_STATES

    def add_listener(self, callback: Callable[[SessionState, int], None]) -> None:
        self._listeners.append(callback)

    def add_revoke_callback(self, callback: RevokeCallback) -> None:
        self._revoke_callbacks.append(callback)

    def _notify(self) -> None:
        for cb in self._listeners:
            try:
                cb(self._state, self._generation)
            except Exception:
                pass

    def _revoke_control(self) -> None:
        if self._current_role == ControlRole.NONE:
            return
        for cb in self._revoke_callbacks:
            try:
                cb(self._current_role.value, self._generation)
            except Exception:
                pass

    def _set(self, state: SessionState, role: ControlRole) -> int:
        self._state = state
        self._current_role = role
        self._generation += 1
        return self._generation

    def _clear_handoff(self) -> None:
        """清空接管上下文（模式、Ticket、超时基线）。"""
        self._handoff_mode = None
        self._handoff_ticket = None
        self._handoff_requested_at = 0.0
        self._control_expires_at = None

    def _expire_if_due(self) -> None:
        now = time.time()
        if self._state == SessionState.HANDOFF_REQUESTED:
            if now - self._handoff_requested_at > self._handoff_timeout:
                ticket = self._handoff_ticket
                self._clear_handoff()
                self._set(SessionState.HANDOFF_TIMEOUT, ControlRole.NONE)
                self._revoke_ticket(ticket)
                self._notify()
        elif self._state == SessionState.HUMAN_ACTIVE:
            if self._control_expires_at is not None and now >= self._control_expires_at:
                self._revoke_control()
                self._clear_handoff()
                self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
                self._notify()

    def _revoke_ticket(self, ticket: Optional[str]) -> None:
        if not ticket:
            return
        for cb in self._revoke_callbacks:
            try:
                cb(ticket, None)
            except Exception:
                pass

    def tick(self) -> bool:
        """推进超时：有状态变化返回 True。可由事件循环定时器或调用方轮询。"""
        before = (self._state, self._generation)
        self._expire_if_due()
        return before != (self._state, self._generation)

    def ensure_handoff_deadline_timer(self) -> None:
        """在运行中的事件循环里挂一个定时器，到点自动 tick（超时不会无限等待）。

        每次控制权变化都重排，保证同一时刻最多一个待触发的定时器。
        """
        handle = self._timer_handle
        if handle is not None:
            handle.cancel()
            self._timer_handle = None
        deadline = self.handoff_deadline
        if deadline is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._timer_deadline = deadline
        self._timer_handle = loop.call_later(max(0.01, deadline - time.time()), self._on_timer)

    def _on_timer(self) -> None:
        self._timer_handle = None
        if self._timer_deadline is not None and time.time() + 0.005 < self._timer_deadline:
            # 定时器被提前唤醒：原定时刻还没到
            self.ensure_handoff_deadline_timer()
            return
        self._expire_if_due()
        self.ensure_handoff_deadline_timer()

    # ---- 状态流转

    def start_agent(self) -> bool:
        """从初始化进入 AGENT_ACTIVE"""
        if self._state != SessionState.INITIALIZING:
            return False
        self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
        self._notify()
        return True

    def request_handoff(self, mode: str = "browser", timeout_seconds: int = 300,
                        ticket: Optional[str] = None) -> Tuple[bool, str]:
        """Agent 请求人工接管"""
        self._expire_if_due()
        if self._state != SessionState.AGENT_ACTIVE:
            return False, f"无法在状态 {self._state.value} 下请求人工接管"
        if timeout_seconds < 0:
            return False, "timeout_seconds 不能为负数"
        if mode not in ("browser", "desktop"):
            return False, f"未知接管模式: {mode}"
        self._handoff_mode = mode
        self._handoff_timeout = timeout_seconds
        self._handoff_requested_at = time.time()
        self._handoff_ticket = ticket
        self._control_expires_at = None
        self._set(SessionState.HANDOFF_REQUESTED, ControlRole.NONE)
        # 有事件循环就挂定时器：即使没人再发请求，到点也会自己超时并撤销 Ticket
        self.ensure_handoff_deadline_timer()
        self._notify()
        return True, "Handoff requested"

    def claim_handoff(self, ticket: Optional[str] = None,
                      session_ttl_seconds: Optional[int] = None) -> Tuple[bool, str]:
        """认领接管控制权。

        认领与 Ticket 单次化在同一同步临界区内完成：并发认领只有一个能成功，
        其余调用看到的状态已是 HUMAN_ACTIVE，直接失败。成功后的世代见 ``generation``。
        """
        self._expire_if_due()
        if self._state != SessionState.HANDOFF_REQUESTED:
            return False, f"当前状态不可认领: {self._state.value}"
        if self._handoff_ticket is not None and (not ticket or ticket != self._handoff_ticket):
            return False, "接管 Ticket 无效"

        role = ControlRole.HUMAN_DESKTOP if self._handoff_mode == "desktop" else ControlRole.HUMAN_BROWSER
        self._handoff_ticket = None
        if session_ttl_seconds is not None:
            self._control_expires_at = time.time() + max(0, session_ttl_seconds)
        self._set(SessionState.HUMAN_ACTIVE, role)
        self.ensure_handoff_deadline_timer()
        self._notify()
        return True, "人工已接管控制权"

    def complete_handoff(self) -> Tuple[bool, str]:
        """人工完成接管，返还控制权给 Agent"""
        self._expire_if_due()
        if self._state != SessionState.HUMAN_ACTIVE:
            return False, f"当前状态不是人工活跃状态: {self._state.value}"

        # 控制权交还后，人工会话 Cookie 立即失效（提交/轮询仍可用，但不再持有控制）
        self._revoke_control()
        self._set(SessionState.RESUMING, ControlRole.NONE)
        self._notify()
        self._clear_handoff()
        self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
        self._notify()
        return True, "控制权已顺利交还 Agent"

    def cancel_handoff(self) -> Tuple[bool, str]:
        """取消人工接管请求，恢复 Agent 控制"""
        self._expire_if_due()
        if self._state == SessionState.HANDOFF_TIMEOUT:
            ticket = self._handoff_ticket
            self._clear_handoff()
            self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
            self._revoke_ticket(ticket)
            self._notify()
            return True, "接管请求已超时，已恢复 Agent"
        if self._state == SessionState.HANDOFF_REQUESTED:
            ticket = self._handoff_ticket
            self._clear_handoff()
            self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
            self._revoke_ticket(ticket)
            self._notify()
            return True, "已取消接管并恢复 Agent"
        if self._state == SessionState.HUMAN_ACTIVE:
            # 人工端断开 / Agent 主动收回：撤销人工会话并交还控制权
            self._revoke_control()
            self._clear_handoff()
            self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
            self._notify()
            return True, "已撤销人工接管并恢复 Agent"
        return False, f"当前状态不可取消接管: {self._state.value}"

    def expire_session(self) -> Tuple[bool, str]:
        """会话到期：撤销一切控制权并进入 SESSION_EXPIRED。"""
        if self._state in CLOSED_STATES:
            return False, f"会话已关闭: {self._state.value}"
        self._revoke_control()
        ticket = self._handoff_ticket
        self._clear_handoff()
        self._set(SessionState.SESSION_EXPIRED, ControlRole.NONE)
        self._revoke_ticket(ticket)
        self._notify()
        return True, "会话已过期"

    def lose_connection(self) -> Tuple[bool, str]:
        """连接丢失：撤销当前持有者。人工端断开时直接交还 Agent，避免控制权悬挂在
        已失效的会话上（Ticket 已一次性用掉，不能再被重新认领）。"""
        if self._state in CLOSED_STATES:
            return False, f"会话已关闭: {self._state.value}"
        if self._state == SessionState.HUMAN_ACTIVE:
            self._revoke_control()
            self._clear_handoff()
            self._set(SessionState.AGENT_ACTIVE, ControlRole.AGENT)
            self._notify()
            return True, "人工连接丢失，控制权已交还 Agent"
        self._revoke_control()
        ticket = self._handoff_ticket
        self._clear_handoff()
        self._set(SessionState.CONNECTION_LOST, ControlRole.NONE)
        self._revoke_ticket(ticket)
        self._notify()
        return True, "连接丢失"

    def begin_finishing(self) -> Tuple[bool, str]:
        """开始结束流程，停止所有 UI 注入"""
        if self._state in (SessionState.FINISHING, SessionState.FINISHED):
            return True, "已经在结束中"
        self.cancel_handoff()
        self._set(SessionState.FINISHING, ControlRole.NONE)
        self._notify()
        return True, "开始结束并保存快照"

    def finish(self) -> Tuple[bool, str]:
        """完成所有清理与回传，终态"""
        if self._state not in CLOSED_STATES:
            self._revoke_control()
            self._clear_handoff()
        self._set(SessionState.FINISHED, ControlRole.NONE)
        self._notify()
        return True, "会话正常结束"

    def fail(self, reason: str = "") -> None:
        """标记运行时故障"""
        self._revoke_control()
        ticket = self._handoff_ticket
        self._clear_handoff()
        self._set(SessionState.RUNTIME_FAILED, ControlRole.NONE)
        self._revoke_ticket(ticket)
        self._notify()

    def verify_action_allowed(self, role: ControlRole, generation: Optional[int] = None) -> Tuple[bool, str]:
        """
        排他控制校验（第九章 9.2 & 9.3）：
        1. 检查调用方 generation 是否与当前 generation 一致（缺省或过期即拒绝）；
        2. 检查调用方 role 是否具有当前活跃控制权。
        控制权一旦过期、撤销或会话关闭，任何输入都会被拒绝。
        """
        self._expire_if_due()

        if self._state in CLOSED_STATES or self._state == SessionState.SESSION_EXPIRED:
            return False, "SESSION_CLOSED"

        if generation is None or generation != self._generation:
            return False, "CONTROL_NOT_HELD"

        if self._current_role != role:
            return False, "CONTROL_NOT_HELD"

        return True, "OK"
