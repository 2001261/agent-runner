"""Cloudflare Named/Quick Tunnel Provider。

生产环境 fail-closed：缺依赖、进程退出或 URL 获取超时都返回失败，
只有显式 force_mock 的单元测试才允许使用模拟地址。
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class TunnelProvider(ABC):
    @abstractmethod
    async def start(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def status(self) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_public_url(self) -> Optional[str]:
        raise NotImplementedError


class NamedTunnelProvider(TunnelProvider):
    def __init__(self, hostname: str, token_secret_or_file: str,
                 gateway_url: str = "http://127.0.0.1:8765"):
        self.hostname = hostname
        self.token_secret_or_file = token_secret_or_file
        self.gateway_url = gateway_url
        self._proc: Optional[subprocess.Popen] = None
        self._is_connected = False
        self._tmp_token: Optional[str] = None

    async def start(self) -> bool:
        binary = shutil.which("cloudflared")
        if not binary:
            return False
        token_file = self.token_secret_or_file
        if not os.path.isfile(token_file):
            token = os.environ.get(token_file, self.token_secret_or_file).strip()
            if not token:
                return False
            private_dir = os.environ.get("RUNNER_TEMP", tempfile.gettempdir())
            fd, self._tmp_token = tempfile.mkstemp(prefix=".gha-cf-token-", dir=private_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(token)
            os.chmod(self._tmp_token, 0o600)
            token_file = self._tmp_token
        try:
            self._proc = subprocess.Popen(
                [binary, "tunnel", "run", "--url", self.gateway_url,
                 "--token-file", token_file],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.sleep(1.0)
            self._is_connected = self._proc.poll() is None
            return self._is_connected
        except Exception:
            self._is_connected = False
            return False

    async def status(self) -> Dict[str, Any]:
        running = self._is_connected if self._proc is None else self._proc.poll() is None
        return {"provider": "named", "hostname": self.hostname, "connected": running}

    async def stop(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        self._is_connected = False
        if self._tmp_token:
            try:
                os.remove(self._tmp_token)
            except OSError:
                pass
            self._tmp_token = None

    def get_public_url(self) -> Optional[str]:
        return f"https://{self.hostname}" if self._is_connected else None


class QuickTunnelProvider(TunnelProvider):
    URL_PATTERN = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")

    def __init__(self, gateway_url: str = "http://127.0.0.1:8765", force_mock: bool = False):
        self.gateway_url = gateway_url
        self.force_mock = force_mock
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._drain_task: Optional[asyncio.Task] = None
        self._url: Optional[str] = None
        self._is_connected = False

    async def start(self) -> bool:
        if self.force_mock:
            self._url = "https://mock-ephemeral-tunnel.trycloudflare.com"
            self._is_connected = True
            return True
        binary = shutil.which("cloudflared")
        if not binary:
            return False
        try:
            self._proc = await asyncio.create_subprocess_exec(
                binary, "tunnel", "--url", self.gateway_url,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )

            async def drain_output():
                # 找到 URL 后仍须持续 drain，避免 cloudflared 因 stderr 管道写满而卡死。
                while self._proc and self._proc.stderr:
                    line = await self._proc.stderr.readline()
                    if not line:
                        break
                    if not self._url:
                        match = self.URL_PATTERN.search(line.decode("utf-8", "replace"))
                        if match:
                            self._url = match.group(0)
                            self._is_connected = True

            self._drain_task = asyncio.create_task(drain_output())
            for _ in range(40):
                if self._url:
                    return True
                if self._proc.returncode is not None:
                    break
                await asyncio.sleep(0.5)
            await self.stop()
            return False
        except Exception:
            await self.stop()
            return False

    async def status(self) -> Dict[str, Any]:
        running = self._is_connected
        if self._proc is not None and self._proc.returncode is not None:
            running = False
        return {"provider": "quick", "connected": running, "has_url": self._url is not None}

    async def stop(self) -> None:
        if self._drain_task:
            self._drain_task.cancel()
            try:
                await self._drain_task
            except (asyncio.CancelledError, Exception):
                pass
            self._drain_task = None
        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=3.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        self._is_connected = False
        self._url = None

    def get_public_url(self) -> Optional[str]:
        return self._url if self._is_connected else None
