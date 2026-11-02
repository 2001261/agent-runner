"""运行时会话上下文管理。

聚合会话元数据、状态机、认证管理器、以及当前活跃的 Tunnel 信息。
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from gha_runner.interactive_config import InteractiveConfig
from .auth import AuthManager
from .state_machine import StateMachine


@dataclass
class SessionContext:
    session_id: str
    run_id: str
    config: InteractiveConfig
    auth: AuthManager
    state_machine: StateMachine
    created_at: float = field(default_factory=time.time)
    tunnel_url: Optional[str] = None
    rendezvous_published: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, run_id: Optional[str] = None, config: Optional[InteractiveConfig] = None) -> "SessionContext":
        cfg = config or InteractiveConfig()
        s_id = "ses_" + secrets.token_hex(12)
        r_id = run_id or os.environ.get("GITHUB_RUN_ID", "local-run-001")
        auth_mgr = AuthManager()
        sm = StateMachine(default_handoff_timeout=cfg.handoff.timeout_seconds)
        return cls(
            session_id=s_id,
            run_id=r_id,
            config=cfg,
            auth=auth_mgr,
            state_machine=sm,
        )

    def to_status_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "run_id": self.run_id,
            "state": self.state_machine.state.value,
            "current_role": self.state_machine.current_role.value,
            "generation": self.state_machine.generation,
            "handoff_mode": self.state_machine.handoff_mode,
            "created_at": self.created_at,
            "uptime_seconds": time.time() - self.created_at,
            "rendezvous_published": self.rendezvous_published,
        }
