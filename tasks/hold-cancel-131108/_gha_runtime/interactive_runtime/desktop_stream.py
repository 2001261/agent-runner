"""Desktop Handoff 实时桌面流（x11vnc + websockify + noVNC）管理。

遵循《2.0 迭代.md》第八章 8.2、8.3「按需启动」规范。
x11vnc 与 websockify 仅在完整桌面接管被启用时启动，其余时间关闭以节约资源。
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Dict, Optional

from .privacy import PrivacyFilter


class DesktopStreamManager:
    """按需启动与管理 VNC 及 WebSocket 桥接"""

    def __init__(
        self,
        display: str = ":99",
        vnc_port: int = 5900,
        ws_port: int = 6080,
        force_mock: bool = False,
        ready_timeout: float = 15.0,
        log_dir: Optional[str] = None,
    ):
        self.display = display
        self.vnc_port = vnc_port
        self.ws_port = ws_port
        self.force_mock = force_mock
        self.ready_timeout = ready_timeout
        # 子进程日志只落私有目录（默认 RUNNER_TEMP），0600，不进任务输出目录。
        self.log_dir = log_dir

        self._x11vnc_proc: Optional[subprocess.Popen] = None
        self._websockify_proc: Optional[subprocess.Popen] = None
        self._log_files: Dict[str, object] = {}
        self._log_paths: Dict[str, str] = {}
        self._last_exit: Dict[str, Optional[int]] = {}
        self._is_active: bool = False
        # 上次启动失败的原因（只看异常类型，不带路径或凭证）
        self.last_error: str = ""

    @property
    def is_active(self) -> bool:
        return self._is_active

    def _log_root(self) -> str:
        base = self.log_dir or os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
        path = os.path.join(base, "gha-desktop-stream")
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        return path

    def _open_log(self, name: str):
        path = os.path.join(self._log_root(), f"{name}.log")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._log_paths[name] = path
        return os.fdopen(fd, "ab", buffering=0), path

    def _close_logs(self) -> None:
        for handle in self._log_files.values():
            try:
                handle.close()
            except OSError:
                pass
        self._log_files = {}

    def _tail(self, name: str, limit: int = 1200) -> str:
        path = self._log_paths.get(name)
        if not path:
            return ""
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 4096))
                raw = fh.read().decode("utf-8", "replace")
        except OSError:
            return ""
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()][-10:]
        text = PrivacyFilter().redact_text(" | ".join(lines))
        return text[-limit:]

    def diagnose(self) -> Dict[str, object]:
        """谁还活着、谁以什么码退出，以及脱敏后的日志尾部（可安全写进公开日志）。"""
        state: Dict[str, object] = {}
        for name, proc in (("x11vnc", self._x11vnc_proc), ("websockify", self._websockify_proc)):
            code = None
            if proc is not None:
                code = proc.poll()
            if code is None:
                code = self._last_exit.get(name)
            state[name] = {"running": proc is not None and code is None, "exit_code": code}
        state["log_tail"] = {name: self._tail(name) for name in ("x11vnc", "websockify")}
        return state

    def diagnose_summary(self) -> str:
        state = self.diagnose()
        parts = []
        for name in ("x11vnc", "websockify"):
            info = state[name]
            if info["running"]:
                parts.append(f"{name}=running")
            elif info["exit_code"] is None:
                parts.append(f"{name}=absent")
            else:
                parts.append(f"{name}=exited({info['exit_code']})")
            tail = state["log_tail"][name]
            if tail:
                parts.append(f"{name}_log={tail[:400]!r}")
        return " ".join(parts)

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
                    self.last_error = (f"{name} exited with code {proc.returncode}; "
                                       f"{self.diagnose_summary()}")
                    return False
            if self._port_open(self.vnc_port) and self._port_open(self.ws_port):
                return True
            time.sleep(0.05)
        self.last_error = (f"stream ports not listening within {self.ready_timeout}s "
                           f"(vnc={self.vnc_port} ws={self.ws_port}); {self.diagnose_summary()}")
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
            x11vnc_out, _ = self._open_log("x11vnc")
            self._log_files["x11vnc"] = x11vnc_out
            self._x11vnc_proc = subprocess.Popen(
                [
                    "x11vnc",
                    "-display", self.display,
                    "-localhost",
                    "-rfbport", str(self.vnc_port),
                    "-forever",
                    "-shared",
                    "-nopw",
                    # 保留详细日志：客户端断开原因只出现在 verbose 输出里
                    "-v",
                ],
                env=env,
                stdout=x11vnc_out,
                stderr=subprocess.STDOUT,
            )
            ws_out, _ = self._open_log("websockify")
            self._log_files["websockify"] = ws_out
            self._websockify_proc = subprocess.Popen(
                [
                    "websockify",
                    "-v",
                    f"127.0.0.1:{self.ws_port}",
                    f"127.0.0.1:{self.vnc_port}",
                ],
                stdout=ws_out,
                stderr=subprocess.STDOUT,
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
            self._last_exit["websockify"] = self._websockify_proc.poll()
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
            self._last_exit["x11vnc"] = self._x11vnc_proc.poll()
            self._x11vnc_proc = None

        self._close_logs()
        self._is_active = False
