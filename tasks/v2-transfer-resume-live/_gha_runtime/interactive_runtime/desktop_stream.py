"""Desktop Handoff 实时桌面流（x11vnc + websockify + noVNC）管理。

遵循《2.0 迭代.md》第八章 8.2、8.3「按需启动」规范。
x11vnc 与 websockify 仅在完整桌面接管被启用时启动，其余时间关闭以节约资源。
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from typing import Optional


class DesktopStreamManager:
    """按需启动与管理 VNC 及 WebSocket 桥接"""

    def __init__(
        self,
        display: str = ":99",
        vnc_port: int = 5900,
        ws_port: int = 6080,
        force_mock: bool = False,
        ready_timeout: float = 15.0,
    ):
        self.display = display
        self.vnc_port = vnc_port
        self.ws_port = ws_port
        self.force_mock = force_mock
        self.ready_timeout = ready_timeout

        self._x11vnc_proc: Optional[subprocess.Popen] = None
        self._websockify_proc: Optional[subprocess.Popen] = None
        self._is_active: bool = False
        # 上次启动失败的原因（只看异常类型，不带路径或凭证）
        self.last_error: str = ""

    @property
    def is_active(self) -> bool:
        return self._is_active

    @staticmethod
    def _port_open(port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            return False

    def _wait_ready(self) -> bool:
        """Popen 返回不代表已经能服务：等 x11vnc 与 websockify 都真正开始监听。

        handoff_request 之后人工端会立刻连 /v1/live/desktop，端口没起来时 Gateway
        只能把上游连接失败表现成一个 close frame，与网络故障无法区分。
        """
        deadline = time.time() + self.ready_timeout
        while time.time() < deadline:
            for name, proc in (("x11vnc", self._x11vnc_proc), ("websockify", self._websockify_proc)):
                if proc is not None and proc.poll() is not None:
                    self.last_error = f"{name} exited with code {proc.returncode}"
                    return False
            if self._port_open(self.vnc_port) and self._port_open(self.ws_port):
                return True
            time.sleep(0.05)
        self.last_error = (f"stream ports not listening within {self.ready_timeout}s "
                           f"(vnc={self.vnc_port} ws={self.ws_port})")
        return False

    def start_streaming(self) -> bool:
        """按需启动 x11vnc 与 websockify"""
        if self._is_active:
            return True

        self.last_error = ""
        if self.force_mock:
            self._is_active = True
            return True
        missing = [n for n in ("x11vnc", "websockify") if not shutil.which(n)]
        if missing:
            self.last_error = "missing: " + ",".join(missing)
            return False

        env = os.environ.copy()
        env["DISPLAY"] = self.display

        # 启动 x11vnc（仅 localhost；外部必须经过 Gateway 鉴权）
        try:
            self._x11vnc_proc = subprocess.Popen(
                [
                    "x11vnc",
                    "-display", self.display,
                    "-localhost",
                    "-rfbport", str(self.vnc_port),
                    "-forever",
                    "-shared",
                    "-nopw",
                    "-quiet",
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._websockify_proc = subprocess.Popen(
                [
                    "websockify",
                    f"127.0.0.1:{self.ws_port}",
                    f"127.0.0.1:{self.vnc_port}",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            self.stop_streaming()
            return False

        if not self._wait_ready():
            self.stop_streaming()
            return False

        self._is_active = True
        return True

    def stop_streaming(self) -> None:
        """关闭流服务以回收资源"""
        if self._websockify_proc:
            try:
                self._websockify_proc.terminate()
                self._websockify_proc.wait(timeout=2)
            except Exception:
                try:
                    self._websockify_proc.kill()
                except Exception:
                    pass
            self._websockify_proc = None

        if self._x11vnc_proc:
            try:
                self._x11vnc_proc.terminate()
                self._x11vnc_proc.wait(timeout=2)
            except Exception:
                try:
                    self._x11vnc_proc.kill()
                except Exception:
                    pass
            self._x11vnc_proc = None

        self._is_active = False
