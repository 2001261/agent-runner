"""Cloudflare Named/Quick Tunnel Provider。

生产环境 fail-closed：缺依赖、进程退出或 URL 获取超时都返回失败，
只有显式 force_mock 的单元测试才允许使用模拟地址。

Named Tunnel 的 Token 只允许经 Secret 环境变量或 ``--token-file`` 传入：
- 绝不把 Token 拼进命令行（``ps`` 可见）或日志；
- Secret 形式一律先落到 0600 临时文件，再用 ``--token-file`` 启动；
- 固定域名不等于固定身份，Gateway 仍须逐次核验 session_id / Agent Token。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple


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


def _private_tmpdir() -> str:
    """Token 临时文件目录：优先 RUNNER_TEMP，不可用时退回系统临时目录。"""
    candidate = os.environ.get("RUNNER_TEMP", "")
    if candidate and os.path.isdir(candidate):
        return candidate
    return tempfile.gettempdir()


def _token_shape_ok(token: str) -> bool:
    return len(token) >= 16 and not any(ch.isspace() for ch in token)


def read_token(spec: str) -> Optional[str]:
    """把 ``token_file 路径`` 或 ``Secret 环境变量名`` 统一解析成 Token 文本。

    Token 必须是单行、长度足够的 base64url 串；不满足就当作配置错误，
    由调用方 fail-closed（不启动连接器）。

    不认识的 ``spec`` 一律当作“未配置”，绝不回退去读用户的
    ``~/.cloudflared/config.yml`` / 系统凭据 —— 那会让“Secret 没注入”看起来像成功。
    """
    if not spec:
        return None
    if os.path.isfile(spec):
        try:
            with open(spec, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError:
            return None
    elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", spec):
        token = os.environ.get(spec, "").strip()
    else:
        return None
    if not _token_shape_ok(token):
        return None
    return token


class NamedTunnelProvider(TunnelProvider):
    """固定域名 Tunnel：``cloudflared tunnel --url <gateway> --token-file <0600 临时文件>``。"""

    # 单次 RTT：确认隧道入口上真的有这个 cloudflared 的请求进来。
    PROBE_TIMEOUT_SECONDS = 15.0
    # cloudflared 完成注册需要一点时间；进程提前退出说明配置有问题。
    DEFAULT_PROBE_SECONDS = 3.0
    # 探针结束后再等一小段，兜住“子进程已退出但 poll() 还没看到”的窗口
    # （Popen 返回时可能尚未 exec；wait() 由 SIGCHLD 触发，比 poll() 可靠）。
    EXIT_SETTLE_SECONDS = 0.5

    def __init__(self, hostname: str, token_secret_or_file: str,
                 gateway_url: str = "http://127.0.0.1:8765",
                 force_mock: bool = False,
                 probe_seconds: Optional[float] = None,
                 public_url: Optional[str] = None):
        self.hostname = (hostname or "").strip().lower()
        self.token_secret_or_file = token_secret_or_file
        self.gateway_url = gateway_url
        # 入口上对用户真正生效的 origin（可带路径，如 https://debug.example.com/run/<id>）。
        # cloudflared 只负责把固定域名送到本地 Gateway，路径/会话仍由 Registry 与管理端决定。
        self.public_url = (public_url or "").strip() or (f"https://{self.hostname}" if self.hostname else "")
        self.force_mock = force_mock
        self._proc: Optional[subprocess.Popen] = None
        self._is_connected = False
        self._tmp_token: Optional[str] = None
        self._started_at: Optional[float] = None
        self._probe_id: Optional[str] = None
        self._probe_seen = False
        self.probe_seconds = self.DEFAULT_PROBE_SECONDS if probe_seconds is None else float(probe_seconds)
        self.last_error: Optional[str] = None

    async def start(self) -> bool:
        self.last_error = None
        self._is_connected = False
        if self.force_mock:
            self._is_connected = True
            return True
        if not self.hostname or not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", self.hostname):
            self.last_error = "hostname 不合法"
            return False
        if not self.public_url.lower().startswith("https://"):
            # Registry 只接受 https origin；入口 URL 非法时绝不上报，避免“看起来注册成功”。
            self.last_error = "public_url 必须是 https:// 地址"
            return False

        binary = shutil.which("cloudflared")
        if not binary:
            # 缺依赖必须 fail-closed，绝不退回 mock 地址。
            self.last_error = "未找到 cloudflared"
            return False

        token = read_token(self.token_secret_or_file)
        if token is None:
            self.last_error = "Named Tunnel Token 未配置或格式不合法"
            return False
        if os.path.isfile(self.token_secret_or_file):
            # 调用方自带 Token 文件：直接使用，但必须已收紧到 0600，避免同机他人可读。
            mode = stat.S_IMODE(os.stat(self.token_secret_or_file).st_mode)
            if os.name == "posix" and mode & 0o077:
                self.last_error = "Token 文件权限过宽（需 0600）"
                return False
            token_file, error = self.token_secret_or_file, None
        else:
            token_file, error = self._write_token_file(token)
        if error:
            self.last_error = error
            return False

        self._probe_id = uuid.uuid4().hex
        self._probe_seen = False
        try:
            self._proc = subprocess.Popen(
                [binary, "tunnel", "run", "--url", self.gateway_url,
                 "--token-file", str(token_file),
                 "--header", f"X-GHA-Tunnel-Probe: {self._probe_id}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            self.last_error = f"cloudflared 启动失败：{exc.__class__.__name__}"
            await self._cleanup_token_file()
            return False

        loop = asyncio.get_event_loop()
        deadline = loop.time() + max(0.0, self.probe_seconds)
        while True:
            if self._proc.poll() is not None:
                self.last_error = "cloudflared 提前退出（Token、Tunnel 或 hostname 不匹配）"
                await self.stop()
                return False
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(0.25, remaining))
        # 假 cloudflared（以及启动极快的真实进程）会 echo 完就 exit：接管终端后
        # 才收到 SIGCHLD。只 poll 一次会把“探针窗口内已退出”误判为成功。
        await self._exited_within(self.EXIT_SETTLE_SECONDS)
        if self._proc.poll() is not None:
            self.last_error = "cloudflared 提前退出（Token、Tunnel 或 hostname 不匹配）"
            await self.stop()
            return False

        # 进程存活 ≠ 隧道可用：再看固定域名是否真的把请求送到了本地 Gateway。
        error = await self.verify_ingress()
        if error:
            self.last_error = error
            await self.stop()
            return False
        self._is_connected = True
        self._started_at = loop.time()
        return True

    async def verify_ingress(self) -> Optional[str]:
        """经固定域名请求 Gateway ``/health``，确认入站确实落到本进程的 Gateway。

        用一次性 ``X-GHA-Tunnel-Probe`` 头 + Gateway 侧回显判定：只比较“有没有回显
        本次随机串”，不需要回显任何凭证。成功返回 ``None``，失败返回简短原因
        （不含 Token、不含入口 URL）。
        """
        if self.force_mock:
            return None
        if not self.public_url:
            return "缺少 public_url"
        try:
            import urllib.request

            def _fetch() -> str:
                # 探针只打自有路径：public_url 带子路径（如 /run/<id>）时，
                # 依赖该路径把 /health 原样转给本 Gateway；否则返回的是别的页面。
                req = urllib.request.Request(self.public_url.rstrip("/") + "/health", headers={
                    "X-GHA-Tunnel-Probe": self._probe_id or "",
                    "Cache-Control": "no-store",
                })
                with urllib.request.urlopen(req, timeout=self.PROBE_TIMEOUT_SECONDS) as resp:
                    return resp.read(8192).decode("utf-8", "replace")

            body = await asyncio.get_event_loop().run_in_executor(None, _fetch)
        except Exception as exc:  # noqa: BLE001 - 任何异常都视为入站未就绪
            return f"固定域名入站探针失败：{exc.__class__.__name__}"
        try:
            payload = json.loads(body)
        except ValueError:
            return "固定域名入站探针失败：/health 返回非 JSON"
        if not isinstance(payload, dict) or not payload.get("ingress_probe_ok"):
            return "固定域名入站探针失败：请求未落到本 Runner 的 Gateway"
        if not self._probe_id or payload.get("probe") != hashlib.sha256(self._probe_id.encode()).hexdigest()[:16]:
            return "固定域名入站探针失败：Gateway 回显与本次探针不一致（可能路由到其它 Runner）"
        return None

    async def _wait_exited(self) -> None:
        await asyncio.get_event_loop().run_in_executor(None, self._proc.wait)

    async def _exited_within(self, seconds: float) -> bool:
        """``seconds`` 内子进程是否已退出（``wait()`` 由 SIGCHLD 驱动，比轮询 poll() 可靠）。"""
        task = asyncio.ensure_future(self._wait_exited())
        try:
            await asyncio.wait({task}, timeout=max(0.0, seconds))
        finally:
            task.cancel()

    def _write_token_file(self, token: str) -> Tuple[Optional[str], Optional[str]]:
        """Token 一律落 0600 临时文件后经 ``--token-file`` 传入，绝不进命令行/日志。"""
        try:
            fd, path = tempfile.mkstemp(prefix=".gha-cf-token-", dir=_private_tmpdir())
        except OSError as exc:
            return None, f"无法创建 Token 临时文件：{exc.__class__.__name__}"
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(token)
            os.chmod(path, 0o600)
        except OSError:
            try:
                os.remove(path)
            except OSError:
                pass
            return None, "无法写入 Token 临时文件"
        self._tmp_token = path
        return path, None

    async def status(self) -> Dict[str, Any]:
        running = self._is_connected
        if self._proc is not None and self._proc.poll() is not None:
            running = False
            self._is_connected = False
        uptime = None
        if running and self._started_at is not None:
            uptime = round(asyncio.get_event_loop().time() - self._started_at, 1)
        return {
            "provider": "named",
            "hostname": self.hostname,
            "connected": running,
            "pid": self._proc.pid if (self._proc and running) else None,
            "uptime_seconds": uptime,
            # 只报告文件是否托管，绝不回显路径或 Token 内容。
            "token_file_managed": self._tmp_token is not None,
            "error": self.last_error,
        }

    async def stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    await asyncio.get_event_loop().run_in_executor(None, self._reap, proc)
            except Exception:
                try:
                    proc.kill()
                except OSError:
                    pass
        self._is_connected = False
        self._started_at = None
        await self._cleanup_token_file()

    @staticmethod
    def _reap(proc: subprocess.Popen) -> None:
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass

    async def _cleanup_token_file(self) -> None:
        if not self._tmp_token:
            return
        path, self._tmp_token = self._tmp_token, None
        try:
            os.remove(path)
        except OSError:
            pass

    def get_public_url(self) -> Optional[str]:
        return self.public_url if (self._is_connected and self.public_url) else None


class QuickTunnelProvider(TunnelProvider):
    URL_PATTERN = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")

    def __init__(self, gateway_url: str = "http://127.0.0.1:8765", force_mock: bool = False):
        self.gateway_url = gateway_url
        self.force_mock = force_mock
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._drain_task: Optional[asyncio.Task] = None
        self._url: Optional[str] = None
        self._is_connected = False
        self.last_error: Optional[str] = None

    async def start(self) -> bool:
        self.last_error = None
        if self.force_mock:
            self._url = "https://mock-ephemeral-tunnel.trycloudflare.com"
            self._is_connected = True
            return True
        binary = shutil.which("cloudflared")
        if not binary:
            self.last_error = "未找到 cloudflared"
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
            self.last_error = "cloudflared 未在超时内返回 URL"
            await self.stop()
            return False
        except Exception:
            self.last_error = "cloudflared 启动失败"
            await self.stop()
            return False

    async def status(self) -> Dict[str, Any]:
        running = self._is_connected
        if self._proc is not None and self._proc.returncode is not None:
            running = False
        return {"provider": "quick", "connected": running, "has_url": self._url is not None,
                "error": self.last_error}

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
