"""Session 状态机与控制权仲裁模块。

遵循《2.0 迭代.md》第九章「Agent 与人工控制权管理」。
实现排他性控制权、control_generation 世代递增防重放，以及严格状态流转。
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
        self._listeners: List[Callable[[SessionState, int], None]] = []
        try:
            asyncio.get_running_loop()
            self._lock = asyncio.Lock()
        except RuntimeError:
            self._lock = None

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def current_role(self) -> ControlRole:
        return self._current_role

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def handoff_mode(self) -> Optional[str]:
        return self._handoff_mode

    def add_listener(self, callback: Callable[[SessionState, int], None]) -> None:
        self._listeners.append(callback)

    def _notify(self) -> None:
        for cb in self._listeners:
            try:
                cb(self._state, self._generation)
            except Exception:
                pass

    def start_agent(self) -> bool:
        """从初始化进入 AGENT_ACTIVE"""
        if self._state != SessionState.INITIALIZING:
            return False
        self._state = SessionState.AGENT_ACTIVE
        self._current_role = ControlRole.AGENT
        self._generation += 1
        self._notify()
        return True

    def request_handoff(self, mode: str = "browser", timeout_seconds: int = 300, ticket: Optional[str] = None) -> Tuple[bool, str]:
        """Agent 请求人工接管"""
        if self._state != SessionState.AGENT_ACTIVE:
            return False, f"无法在状态 {self._state.value} 下请求人工接管"
        self._state = SessionState.HANDOFF_REQUESTED
        self._current_role = ControlRole.NONE
        self._handoff_mode = mode
        self._handoff_timeout = timeout_seconds
        self._handoff_requested_at = time.time()
        self._handoff_ticket = ticket
        self._generation += 1
        self._notify()
        return True, "Handoff requested"

    def claim_handoff(self, ticket: Optional[str] = None) -> Tuple[bool, str]:
        """授权用户认领接管控制权"""
        # 检查超时
        if self._state == SessionState.HANDOFF_REQUESTED:
            if time.time() - self._handoff_requested_at > self._handoff_timeout:
                self._state = SessionState.HANDOFF_TIMEOUT
                self._current_role = ControlRole.NONE
                self._generation += 1
                self._notify()
                return False, "接管请求已超时"

        if self._state != SessionState.HANDOFF_REQUESTED:
            return False, f"当前状态不可认领: {self._state.value}"

        if self._handoff_ticket and ticket != self._handoff_ticket:
            return False, "接管 Ticket 无效"

        self._state = SessionState.HUMAN_ACTIVE
        if self._handoff_mode == "desktop":
            self._current_role = ControlRole.HUMAN_DESKTOP
        else:
            self._current_role = ControlRole.HUMAN_BROWSER
        self._generation += 1
        self._notify()
        return True, "人工已接管控制权"

    def complete_handoff(self) -> Tuple[bool, str]:
        """人工完成接管，返还控制权给 Agent"""
        if self._state != SessionState.HUMAN_ACTIVE:
            return False, f"当前状态不是人工活跃状态: {self._state.value}"

        self._state = SessionState.RESUMING
        self._current_role = ControlRole.NONE
        self._generation += 1
        self._notify()

        # 紧接着恢复 AGENT_ACTIVE
        self._state = SessionState.AGENT_ACTIVE
        self._current_role = ControlRole.AGENT
        self._handoff_mode = None
        self._handoff_ticket = None
        self._generation += 1
        self._notify()
        return True, "控制权已顺利交还 Agent"

    def cancel_handoff(self) -> Tuple[bool, str]:
        """取消人工接管请求，恢复 Agent 控制"""
        if self._state not in (SessionState.HANDOFF_REQUESTED, SessionState.HANDOFF_TIMEOUT):
            return False, f"当前状态不可取消接管: {self._state.value}"
        self._state = SessionState.AGENT_ACTIVE
        self._current_role = ControlRole.AGENT
        self._handoff_mode = None
        self._handoff_ticket = None
        self._generation += 1
        self._notify()
        return True, "已取消接管并恢复 Agent"

    def begin_finishing(self) -> Tuple[bool, str]:
        """开始结束流程，停止所有 UI 注入"""
        if self._state in (SessionState.FINISHING, SessionState.FINISHED):
            return True, "已经在结束中"
        self._state = SessionState.FINISHING
        self._current_role = ControlRole.NONE
        self._generation += 1
        self._notify()
        return True, "开始结束并保存快照"

    def finish(self) -> Tuple[bool, str]:
        """完成所有清理与回传，终态"""
        self._state = SessionState.FINISHED
        self._current_role = ControlRole.NONE
        self._generation += 1
        self._notify()
        return True, "会话正常结束"

    def fail(self, reason: str = "") -> None:
        """标记运行时故障"""
        self._state = SessionState.RUNTIME_FAILED
        self._current_role = ControlRole.NONE
        self._generation += 1
        self._notify()

    def verify_action_allowed(self, role: ControlRole, generation: Optional[int] = None) -> Tuple[bool, str]:
        """
        排他控制校验（第九章 9.2 & 9.3）：
        1. 检查调用方 generation 是否与当前 generation 一致；
        2. 检查调用方 role 是否具有当前活跃控制权。
        """
        if self._state in (SessionState.FINISHING, SessionState.FINISHED, SessionState.RUNTIME_FAILED):
            return False, "SESSION_CLOSED"

        if generation is None or generation != self._generation:
            return False, "CONTROL_NOT_HELD"

        if self._current_role != role:
            return False, "CONTROL_NOT_HELD"

        return True, "OK"
