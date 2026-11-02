"""Runtime Supervisor（运行时进程管理器）。

遵循《2.0 迭代.md》第四章 4.2 与第十九章「Session 生命周期」。
管理：
- Xvfb 虚拟屏幕；
- Openbox 窗口管理器；
- D-Bus 会话总线；
- Chromium 浏览器；
- Secure Gateway 服务；
- Cloudflare Tunnel；
- 私有会话注册；
- 任务执行与终态清理。
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import subprocess
import time
from typing import Optional

from aiohttp import web
from gha_runner.interactive_config import InteractiveConfig
from .browser import BrowserManager
from .cleanup import RuntimeCleaner
from .desktop import DesktopManager
from .desktop_stream import DesktopStreamManager
from .gateway import GatewayApp
from .recording import DesktopRecorder
from .rendezvous import RendezvousClient
from .session import SessionContext
from .state_export import StateExporter
from .state_import import StateImporter
from .transfer import ChunkedTransferEngine
from .tunnel import NamedTunnelProvider, QuickTunnelProvider, TunnelProvider


class RuntimeSupervisor:
    """交互运行时主控进程"""

    def __init__(self, config: Optional[InteractiveConfig] = None, run_id: Optional[str] = None):
        self.config = config or InteractiveConfig()
        self.run_id = run_id or os.environ.get("GITHUB_RUN_ID", "local-test-run")

        self.display = self.config.graphical.display
        self.runner_temp = os.environ.get("RUNNER_TEMP", "/tmp")
        self.storage_dir = os.path.join(self.runner_temp, "gha-interactive-private")
        os.makedirs(self.storage_dir, exist_ok=True)

        self._xvfb_proc: Optional[subprocess.Popen] = None
        self._openbox_proc: Optional[subprocess.Popen] = None

        # 核心上下文与子系统
        self.session_ctx = SessionContext.create(run_id=self.run_id, config=self.config)
        self.browser_mgr = BrowserManager(
            cdp_port=self.config.browser.cdp_port,
            display=self.display,
        )
        self.desktop_mgr = DesktopManager(display=self.display)
        self.transfer_engine = ChunkedTransferEngine(storage_dir=os.path.join(self.storage_dir, "transfers"))
        self.exporter = StateExporter(
            transfer_engine=self.transfer_engine,
            browser_mgr=self.browser_mgr,
            desktop_mgr=self.desktop_mgr,
            storage_dir=os.path.join(self.storage_dir, "exports"),
        )
        self.importer = StateImporter(
            transfer_engine=self.transfer_engine,
            browser_mgr=self.browser_mgr,
        )
        self.desktop_stream = DesktopStreamManager(display=self.display)
        self.recorder = DesktopRecorder(
            output_dir=os.path.join(self.storage_dir, "recordings"),
            display=self.display,
            segment_seconds=self.config.persistence.desktop_video.segment_seconds,
        )

        # Tunnel Provider 实例化
        if self.config.tunnel.provider == "named" and self.config.tunnel.hostname:
            self.tunnel: TunnelProvider = NamedTunnelProvider(
                hostname=self.config.tunnel.hostname,
                token_secret_or_file=self.config.tunnel.token_secret or "",
                gateway_url=f"http://{self.config.gateway.bind}:{self.config.gateway.port}",
            )
        else:
            self.tunnel = QuickTunnelProvider(
                gateway_url=f"http://{self.config.gateway.bind}:{self.config.gateway.port}",
            )

        self.gateway_app = GatewayApp(
            session_ctx=self.session_ctx,
            browser_mgr=self.browser_mgr,
            desktop_mgr=self.desktop_mgr,
            transfer_engine=self.transfer_engine,
            state_exporter=self.exporter,
            state_importer=self.importer,
            desktop_stream_mgr=self.desktop_stream,
        )

        self.rendezvous = RendezvousClient(
            endpoint=self.config.rendezvous.endpoint,
            auth_token=self.config.rendezvous.auth_token,
        )

        self.cleaner = RuntimeCleaner(
            auth_mgr=self.session_ctx.auth,
            tunnel=self.tunnel,
            browser=self.browser_mgr,
            desktop_stream=self.desktop_stream,
            recorder=self.recorder,
            private_dirs=[self.storage_dir],
        )

        self._site: Optional[web.TCPSite] = None
        self._runner_runner: Optional[web.AppRunner] = None

    def start_graphical_environment(self) -> None:
        """启动共享 D-Bus、Xvfb 与 Openbox（所有 GUI 子进程继承同一环境）"""
        res = self.config.graphical.resolution
        res_str = f"{res[0]}x{res[1]}x{self.config.graphical.depth}"

        xdg_dir = os.path.join(self.storage_dir, "xdg-runtime")
        os.makedirs(xdg_dir, exist_ok=True)
        os.chmod(xdg_dir, 0o700)
        os.environ["XDG_RUNTIME_DIR"] = xdg_dir

        # agent-desktop 的 AT-SPI 依赖会话总线；没有它只能得到 WINDOW_NOT_FOUND。
        if not os.environ.get("DBUS_SESSION_BUS_ADDRESS") and shutil.which("dbus-launch"):
            try:
                res_dbus = subprocess.run(
                    ["dbus-launch", "--sh-syntax"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in res_dbus.stdout.splitlines():
                    if line.startswith("DBUS_SESSION_BUS_ADDRESS="):
                        value = line.split("=", 1)[1].strip().rstrip(";")
                        os.environ["DBUS_SESSION_BUS_ADDRESS"] = value.strip("'\"") 
            except Exception:
                pass

        # 启动 Xvfb
        if shutil.which("Xvfb"):
            try:
                self._xvfb_proc = subprocess.Popen(
                    ["Xvfb", self.display, "-screen", "0", res_str, "-ac", "+extension", "RANDR"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.5)
            except Exception:
                pass

        # 启动 Openbox
        if shutil.which("openbox"):
            env = os.environ.copy()
            env["DISPLAY"] = self.display
            try:
                self._openbox_proc = subprocess.Popen(
                    ["openbox"],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

    async def start(self) -> str:
        """启动完整运行时栈，并返回 Agent Token"""
        # 1. 图形环境
        self.start_graphical_environment()

        # 2. 浏览器启动（正式环境不允许用 mock 冒充启动成功）
        if self.config.browser.enabled:
            if not await self.browser_mgr.start():
                raise RuntimeError(f"Chromium / Playwright 启动失败: {self.browser_mgr.last_error}")

        # 3. 启动 Gateway HTTP 服务
        self._runner_runner = web.AppRunner(self.gateway_app.app)
        await self._runner_runner.setup()
        self._site = web.TCPSite(
            self._runner_runner,
            host=self.config.gateway.bind,
            port=self.config.gateway.port,
        )
        await self._site.start()

        # 4. 生成 Agent 主凭证
        agent_token = self.session_ctx.auth.create_agent_token()

        # 5. 启动 Cloudflare Tunnel
        if not await self.tunnel.start():
            raise RuntimeError("Cloudflare Tunnel 启动失败")
        public_url = self.tunnel.get_public_url()
        if not public_url:
            raise RuntimeError("Cloudflare Tunnel 未返回可用入口")
        self.session_ctx.tunnel_url = public_url

        # 6. 私有会话注册（Quick Tunnel 在 GHA 必须配置私有 Registry）
        if (os.environ.get("GITHUB_ACTIONS") == "true"
                and self.config.tunnel.provider == "quick"
                and not self.config.rendezvous.endpoint):
            raise RuntimeError("Quick Tunnel 未配置 rendezvous.endpoint，拒绝公开地址或仅本地假成功")
        ok = await self.rendezvous.register_session(
            session_id=self.session_ctx.session_id,
            run_id=self.session_ctx.run_id,
            origin=public_url,
            agent_token=agent_token,
        )
        self.session_ctx.rendezvous_published = ok
        if not ok:
            raise RuntimeError("私有会话注册失败")

        # 7. 开启录像（若配置开启）
        if self.config.persistence.desktop_video.enabled:
            if not self.recorder.start():
                raise RuntimeError("FFmpeg 桌面录像启动失败")

        # 8. 激活 Agent 状态机
        self.session_ctx.state_machine.start_agent()

        return agent_token

    async def stop(self) -> None:
        """关闭运行时并清理资源"""
        await self.cleaner.cleanup_all()

        if self._runner_runner:
            try:
                await self._runner_runner.cleanup()
            except Exception:
                pass

        if self._openbox_proc:
            try:
                self._openbox_proc.terminate()
            except Exception:
                pass

        if self._xvfb_proc:
            try:
                self._xvfb_proc.terminate()
            except Exception:
                pass
