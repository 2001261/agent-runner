"""Browser Handoff 实时画面推流与输入中继。

遵循《2.0 迭代.md》第七章 7.2 规范。
建立 WebSocket 双向连接：
- 向客户端推流浏览器画面帧；
- 接收客户端注入的鼠标与键盘输入事件并转发至 BrowserManager。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Optional, Set

from .auth import Scope
from .browser import BrowserManager
from .state_machine import ControlRole, StateMachine


class BrowserStreamRelay:
    """浏览器实时流与交互中继器"""

    def __init__(self, browser: BrowserManager, state_machine: StateMachine):
        self.browser = browser
        self.state_machine = state_machine
        self._active_connections: Set[Any] = set()
        self._streaming_task: Optional[asyncio.Task] = None
        self._fps: int = 5

    def add_connection(self, ws: Any) -> None:
        self._active_connections.add(ws)
        if not self._streaming_task or self._streaming_task.done():
            self._streaming_task = asyncio.create_task(self._broadcast_loop())

    def remove_connection(self, ws: Any) -> None:
        self._active_connections.discard(ws)
        if not self._active_connections and self._streaming_task:
            self._streaming_task.cancel()

    async def _broadcast_loop(self) -> None:
        """定时抓取页面截图并通过 WebSocket 广播为二进制或 base64 帧"""
        interval = 1.0 / self._fps
        while self._active_connections:
            try:
                frame_bytes = await self.browser.screenshot()
                if frame_bytes:
                    dead = []
                    for ws in self._active_connections:
                        try:
                            # 发送二进制图片帧
                            await ws.send_bytes(frame_bytes)
                        except Exception:
                            dead.append(ws)
                    for d in dead:
                        self.remove_connection(d)
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(interval)

    async def handle_client_message(self, ws: Any, message_str: str) -> Dict[str, Any]:
        """
        处理客户端发来的操作消息。
        必须校验当前控制权（人类活跃且模式匹配）与 generation。
        """
        try:
            data = json.loads(message_str)
        except Exception:
            return {"error": "Invalid JSON"}

        gen = data.get("generation")
        ok, reason = self.state_machine.verify_action_allowed(ControlRole.HUMAN_BROWSER, generation=gen)
        if not ok:
            return {"status": "rejected", "reason": reason}

        event_type = data.get("type")
        if event_type == "mouse":
            m_type = data.get("event")  # click, move, down, up
            x = int(data.get("x", 0))
            y = int(data.get("y", 0))
            button = data.get("button", "left")
            await self.browser.dispatch_mouse(m_type, x, y, button=button)
            return {"status": "dispatched"}

        elif event_type == "key":
            k_type = data.get("event")  # press, type, down, up
            key = str(data.get("key", ""))
            text = data.get("text")
            await self.browser.dispatch_key(k_type, key, text=text)
            return {"status": "dispatched"}

        return {"status": "ignored"}
