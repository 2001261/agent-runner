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
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout, web
from gha_runner.interactive_config import InteractiveConfig
from .browser import BrowserManager, BrowserRestartExhausted
from .cleanup import RuntimeCleaner
from .desktop import DesktopManager
from .desktop_stream import DesktopStreamManager
from .gateway import GatewayApp
from .preflight import TUNNEL_PROTOCOL_ENV, TUNNEL_PROTOCOLS
from .recording import DesktopRecorder
from .rendezvous import RendezvousClient
from .session import SessionContext
from .state_export import StateExporter
from .state_import import StateImporter
from .transfer import ChunkedTransferEngine
from .tunnel import NamedTunnelProvider, QuickTunnelProvider, TunnelProvider

logger = logging.getLogger(__name__)

# 运行期健康检查里视为正常的组件状态；其余（down / unhealthy / failed）一律如实标记。
_HEALTHY_STATES = frozenset({"ok", "recovered", "disabled", "unchecked"})

# 会话总线由 dbus-launch 拉起时的环境变量名（它与 DBUS_SESSION_BUS_ADDRESS 指同一条总线）
_LAUNCH_PID_ENV = "DBUS_SESSION_BUS_PID"
_LAUNCH_ADDRESS_ENV = "DBUS_SESSION_BUS_ADDRESS"
# at-spi-bus-launcher 读这两个变量；设置后不再依赖它从会话总线里取地址。
_ATSPI_ADDRESS_ENV = "AT_SPI_BUS_ADDRESS"


def parse_bus_address(output: str) -> Dict[str, str]:
    """解析 `dbus-launch --sh-syntax` 输出，返回环境变量字典。

    兼容三种写法：`NAME='v';`、`NAME=v;`、`NAME="v"`，忽略 `export ` 前缀与注释。
    只接受形如 `unix:...` / `tcp:...` 的合法地址，其余变量原样返回。
    """
    env: Dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        name, raw = line.split("=", 1)
        name = name.strip()
        raw = raw.strip().rstrip(";").strip()
        if not name or not raw:
            continue
        if raw[0] in "'\"":
            try:
                parts = shlex.split(raw)
            except ValueError:
                continue
            if len(parts) != 1:
                continue
            value = parts[0]
        else:
            value = raw
        if name in (_LAUNCH_ADDRESS_ENV, _ATSPI_ADDRESS_ENV) and not re.match(
            r"^[A-Za-z][A-Za-z0-9_-]*:", value
        ):
            continue
        env[name] = value
    return env


def _address_paths(address: str) -> List[str]:
    """提取 D-Bus 地址中 unix:path= 指向的套接字路径。"""
    paths: List[str] = []
    for part in address.split(";"):
        if not part.startswith("unix:"):
            continue
        for kv in part[len("unix:"):].split(","):
            if kv.startswith("path="):
                paths.append(kv[len("path="):])
    return paths


def bus_address_alive(address: Optional[str]) -> bool:
    """粗检会话总线是否仍可用：unix 套接字地址必须指向存在的套接字文件。

    tcp/abstract 等地址无法廉价验证，按“可用”处理，由 agent-desktop 自己去连。
    """
    if not address:
        return False
    paths = _address_paths(address)
    if not paths:
        return True
    if any(os.path.exists(p) for p in paths):
        return True
    # 套接字在抽象命名空间（@xxx）时没有文件路径
    return all(p.startswith("@") for p in paths)


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
        self._dbus_proc: Optional[subprocess.Popen] = None
        self._dbus_pid: Optional[int] = None
        self._dbus_owned = False
        self.graphics_report: Dict[str, str] = {}

        # 核心上下文与子系统
        self.session_ctx = SessionContext.create(run_id=self.run_id, config=self.config)
        persistence = self.config.persistence
        browser_video = persistence.browser_video
        self.browser_mgr = BrowserManager(
            cdp_port=self.config.browser.cdp_port,
            display=self.display,
            video_enabled=browser_video.enabled,
            video_dir=os.path.join(self.storage_dir, "browser-video"),
            video_size=tuple(browser_video.max_resolution) if browser_video.enabled else None,
            video_fps=browser_video.max_fps,
            trace_enabled=persistence.traces,
            trace_dir=os.path.join(self.storage_dir, "browser-trace"),
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
        # DESKTOP checkpoint 需要把录像片段一起注册回传（未启用录像时 recorder 从不启动）
        self.exporter.recorder = self.recorder

        # Tunnel Provider 实例化
        if self.config.tunnel.provider == "named" and self.config.tunnel.hostname:
            self.tunnel: TunnelProvider = NamedTunnelProvider(
                hostname=self.config.tunnel.hostname,
                token_secret_or_file=self.config.tunnel.token_secret or "",
                gateway_url=f"http://{self.config.gateway.bind}:{self.config.gateway.port}",
                public_url=os.environ.get("GHA_TUNNEL_PUBLIC_URL") or None,
            )
        else:
            self.tunnel = QuickTunnelProvider(
                gateway_url=f"http://{self.config.gateway.bind}:{self.config.gateway.port}",
                # 非敏感传输偏好：配置或环境变量 GHA_TUNNEL_PROTOCOL 显式给出 http2 时才覆盖
                # cloudflared 默认；非法值已由 preflight fail-closed，这里不再兜底。
                protocol=self.config.tunnel.protocol or os.environ.get(TUNNEL_PROTOCOL_ENV) or None,
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

        # 运行期健康监控（Tunnel / Gateway / Chromium）：只做有界恢复，失败如实标记。
        health = self.config.health
        self.health_check_interval = max(0.05, float(health.check_interval_seconds))
        self.health_check_timeout = max(0.05, float(health.check_timeout_seconds))
        self.tunnel_max_restarts = max(0, int(health.tunnel_max_restarts))
        self.tunnel_restart_backoff = max(0.0, float(health.tunnel_restart_backoff_seconds))
        self.chromium_max_restarts = max(0, int(health.chromium_max_restarts))
        # 上限是“最近一个窗口内”的次数：窗口滑过后重新获得有限的恢复机会，
        # 而不是在长时间任务里永久锁定为不可恢复。
        self.health_window_seconds = max(0.0, float(health.restart_window_seconds))
        self._tunnel_restart_times: List[float] = []
        self._browser_restart_times: List[float] = []
        self._health_stop = asyncio.Event()
        self._health_task: Optional[asyncio.Task] = None
        self._gateway_session: Optional[ClientSession] = None
        self._tunnel_down_count = 0
        self.tunnel_restarts = 0
        self.browser_restarts = 0
        self._degraded_announced = False
        self.health_state: Dict[str, Any] = {"overall": "disabled"}

    def _runtime_dir(self) -> str:
        """XDG_RUNTIME_DIR：模式必须为 0700，否则各组件会忽略或拒绝它。

        若外部已提供一个存在且权限正确的目录则沿用（例如用户自己的会话），
        否则使用 Runner 私有目录，避免在共享主机上删掉别人的套接字。
        """
        candidate = os.environ.get("XDG_RUNTIME_DIR")
        if candidate and os.path.isdir(candidate):
            try:
                if (os.stat(candidate).st_mode & 0o777) == 0o700:
                    return candidate
            except OSError:
                pass
        xdg_dir = os.path.join(self.storage_dir, "xdg-runtime")
        os.makedirs(xdg_dir, mode=0o700, exist_ok=True)
        os.chmod(xdg_dir, 0o700)
        return xdg_dir

    def _start_session_bus(self) -> None:
        """确保 DBUS_SESSION_BUS_ADDRESS 可用，且该总线随运行时进程一起退出。

        GHA Runner 没有用户会话总线；不启动它时 agent-desktop 的 AT-SPI 连接
        会报 “No D-Bus session bus is reachable”，窗口快照只剩 WINDOW_NOT_FOUND。
        """
        current = os.environ.get(_LAUNCH_ADDRESS_ENV)
        if current and bus_address_alive(current):
            self.graphics_report["dbus"] = "reused"
            return
        if current:
            logger.warning("忽略失效的 DBUS_SESSION_BUS_ADDRESS: %s", current)
            self.graphics_report["dbus"] = "stale"
            os.environ.pop(_LAUNCH_ADDRESS_ENV, None)
            os.environ.pop(_LAUNCH_PID_ENV, None)
            os.environ.pop(_ATSPI_ADDRESS_ENV, None)

        dbus_launch = shutil.which("dbus-launch")
        daemon = shutil.which("dbus-daemon")
        if dbus_launch:
            try:
                # --exit-with-x11：由 dbus-launch 的 babysitter 监视本 DISPLAY，
                # X 服务器消失即关闭这条总线。不能用 --exit-with-session——它会在
                # 连不上 X 时改为监听本进程 stdin，对后台 Supervisor 无意义。
                res = subprocess.run(
                    [dbus_launch, "--sh-syntax", "--exit-with-x11"],
                    capture_output=True, text=True, timeout=10,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("dbus-launch 启动失败: %s", exc)
                res = None
            if res is not None and res.returncode == 0:
                parsed = parse_bus_address(res.stdout)
                address = parsed.get(_LAUNCH_ADDRESS_ENV, "")
                if address and bus_address_alive(address):
                    for name in (_LAUNCH_ADDRESS_ENV, _ATSPI_ADDRESS_ENV, "DBUS_SESSION_BUS_STARTER"):
                        if parsed.get(name):
                            os.environ[name] = parsed[name]
                    pid = parsed.get(_LAUNCH_PID_ENV, "")
                    # 是我们拉起的总线，就由我们负责在 stop() 时回收。
                    self._dbus_owned = True
                    if pid.isdigit() and int(pid) > 0:
                        os.environ[_LAUNCH_PID_ENV] = pid
                        self._dbus_pid = int(pid)
                    else:
                        logger.warning("dbus-launch 未返回 DBUS_SESSION_BUS_PID，仅依赖 --exit-with-x11 回收")
                    self.graphics_report["dbus"] = "launched"
                    return
                detail = (res.stderr or res.stdout or "").strip()[:200]
                logger.warning("dbus-launch 未返回可用地址: %s", detail)
                self.graphics_report["dbus"] = "launch_failed"
            elif res is not None:
                logger.warning(
                    "dbus-launch 退出码 %s: %s", res.returncode,
                    (res.stderr or res.stdout or "").strip()[:200],
                )
                self.graphics_report["dbus"] = "launch_failed"

        if daemon:
            # 兜底：直接拉起会话总线守护进程（dbus-x11 缺失时仍可工作）。
            address = "unix:path=%s" % os.path.join(self._runtime_dir(), "bus")
            try:
                proc = subprocess.Popen(
                    [daemon, "--session", "--nofork", "--nopidfile", "--address=%s" % address],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError as exc:
                logger.warning("dbus-daemon 启动失败: %s", exc)
                self.graphics_report["dbus"] = "unavailable"
                return
            for _ in range(50):
                if bus_address_alive(address) or proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None and bus_address_alive(address):
                self._dbus_proc = proc
                self._dbus_owned = True
                os.environ[_LAUNCH_ADDRESS_ENV] = address
                os.environ[_LAUNCH_PID_ENV] = str(proc.pid)
                self.graphics_report["dbus"] = "daemon"
                return
            try:
                proc.terminate()
            except OSError:
                pass
            logger.warning("dbus-daemon 未能提供可用总线")
            self.graphics_report["dbus"] = "unavailable"
            return

        logger.warning("系统缺少 dbus-launch / dbus-daemon，AT-SPI 不可用")
        self.graphics_report["dbus"] = "unavailable"

    def _start_xvfb(self, res_str: str) -> bool:
        xvfb = shutil.which("Xvfb")
        if not xvfb:
            self.graphics_report["xvfb"] = "missing"
            return False
        try:
            self._xvfb_proc = subprocess.Popen(
                [xvfb, self.display, "-screen", "0", res_str, "-ac", "+extension", "RANDR"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.warning("Xvfb 启动失败: %s", exc)
            self.graphics_report["xvfb"] = "failed"
            return False
        # 等待套接字就绪，而不是固定 sleep
        sock = "/tmp/.X11-unix/X%s" % self.display.lstrip(":").split(".")[0]
        for _ in range(50):
            if self._xvfb_proc.poll() is not None:
                break
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        if self._xvfb_proc.poll() is not None:
            self._xvfb_proc = None
            # 该 display 已被外部 Xvfb 占用时 Xvfb 会直接退出；套接字存在就沿用
            # 既有服务器，而不是让整个图形环境失败。
            if os.path.exists(sock):
                self.graphics_report["xvfb"] = "external"
                return True
            self.graphics_report["xvfb"] = "exited"
            return False
        self.graphics_report["xvfb"] = "running"
        return True

    def _start_openbox(self) -> None:
        openbox = shutil.which("openbox")
        if not openbox:
            self.graphics_report["openbox"] = "missing"
            return
        try:
            self._openbox_proc = subprocess.Popen(
                [openbox],
                env=self.shared_gui_env(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.warning("Openbox 启动失败: %s", exc)
            self.graphics_report["openbox"] = "failed"
            return
        self.graphics_report["openbox"] = "running"

    def _seed_atspi_bus(self, attempts: int = 3) -> None:
        """提前调用 org.a11y.Bus.GetAddress，让 AT-SPI 总线与 registry 先于应用就绪。

        agent-desktop 自身也会自动拉起，但应用若在总线出现之前启动就永远不会注册，
        只会表现为 WINDOW_NOT_FOUND。首次调用由 D-Bus 激活 at-spi-bus-launcher，
        冷启动可能慢于 10s，故重试几次再判定不可用。
        """
        dbus_send = shutil.which("dbus-send")
        if not dbus_send:
            self.graphics_report["atspi"] = "dbus-send-missing"
            return
        env = self.shared_gui_env()
        detail = ""
        for attempt in range(max(1, attempts)):
            try:
                res = subprocess.run(
                    [
                        dbus_send, "--session", "--print-reply",
                        "--dest=org.a11y.Bus", "/org/a11y/bus",
                        "org.a11y.Bus.GetAddress",
                    ],
                    env=env, capture_output=True, text=True, timeout=10,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                logger.warning("AT-SPI 总线预热失败: %s", exc)
                self.graphics_report["atspi"] = "error"
                return
            if res.returncode == 0:
                break
            detail = (res.stderr or res.stdout or "").strip()[:200]
            if attempt + 1 < attempts:
                time.sleep(0.5)
        else:
            self.graphics_report["atspi"] = "unavailable"
            logger.warning("AT-SPI 总线不可用（检查 at-spi2-core）: %s", detail)
            return
        # 把地址同步给后续应用，避免每个进程各拉一条总线；registry 由 launcher 负责。
        address = re.search(r'string "(.*)"', res.stdout)
        if address and bus_address_alive(address.group(1)):
            os.environ[_ATSPI_ADDRESS_ENV] = address.group(1)
            self.graphics_report["atspi"] = "ready"
        else:
            self.graphics_report["atspi"] = "ready-unparsed"

    def shared_gui_env(self) -> Dict[str, str]:
        """所有 GUI 子进程共用的环境：同一 DISPLAY、同一会话总线、同一运行目录。"""
        env = os.environ.copy()
        env["DISPLAY"] = self.display
        for name in (_LAUNCH_ADDRESS_ENV, _LAUNCH_PID_ENV, _ATSPI_ADDRESS_ENV):
            if os.environ.get(name):
                env[name] = os.environ[name]
        # 无桌面设置守护进程时 toolkit-accessibility 默认是 false，Chromium 等
        # GTK 应用会因此不注册到 AT-SPI 总线。
        env["GTK_MODULES"] = (env.get("GTK_MODULES", "") + ":gail:atk-bridge").strip(":")
        env["NO_AT_BRIDGE"] = "0"
        return env

    def start_graphical_environment(self) -> None:
        """启动共享 Xvfb、D-Bus 与 Openbox（所有 GUI 子进程继承同一环境）

        顺序有意义：Xvfb 先起，`dbus-launch --exit-with-x11` 才能监视这个 X
        display 并在其消失时一并关闭总线；总线先于 Openbox 和 AT-SPI 就绪，
        应用才不会在总线出现之前启动而永远无法注册。
        """
        res = self.config.graphical.resolution
        res_str = f"{res[0]}x{res[1]}x{self.config.graphical.depth}"
        self.graphics_report = {}

        os.environ["XDG_RUNTIME_DIR"] = self._runtime_dir()
        self.graphics_report["xdg_runtime_dir"] = os.environ["XDG_RUNTIME_DIR"]

        # Wayland 变量必须清掉：agent-desktop 优先选择能连上的 Wayland 套接字，
        # 残留的旧会话会把工具引到另一台桌面上，X11 窗口就永远 WINDOW_NOT_FOUND。
        os.environ.pop("WAYLAND_DISPLAY", None)
        os.environ["DISPLAY"] = self.display

        if not self._start_xvfb(res_str):
            return

        if self.config.desktop.enabled:
            self._start_session_bus()

        self._start_openbox()
        if self.config.desktop.enabled:
            self._seed_atspi_bus()
            self.graphics_report["agent_desktop"] = self.desktop_mgr.refresh_tools()
            # 门禁：桌面自动化已启用、工具已安装，但 AT-SPI 不可用时快照只会报
            # WINDOW_NOT_FOUND。此处明确失败，而不是让 Agent 误以为桌面是空的。
            if (getattr(self.desktop_mgr, "has_agent_desktop", False)
                    and self.graphics_report.get("atspi") not in ("ready", "ready-unparsed")):
                raise RuntimeError(
                    "AT-SPI 无障碍总线不可用（%s），桌面快照必然失败；"
                    "请检查 dbus-x11 / at-spi2-core 与 DBUS_SESSION_BUS_ADDRESS"
                    % self.graphics_report.get("atspi", "unknown")
                )

    async def _start_gateway_runner(self) -> None:
        # aiohttp 的 AppRunner.setup() 与 TCPSite.start() 都是协程，必须等待；
        # 否则 TCPSite 直接抛 "Call runner.setup() before making a site"（实测 aiohttp 3.12.15 必现）。
        runner = web.AppRunner(self.gateway_app.app)
        self._runner_runner = runner
        await runner.setup()
        # 端口冲突时 aiohttp 会换临时端口；任务与配置都以固定端口为准，必须拒绝这种静默降级。
        conflicts = [a for a in (runner.addresses or []) if isinstance(a, tuple) and len(a) >= 2
                     and int(a[1]) != int(self.config.gateway.port)]
        if conflicts:
            await runner.cleanup()
            self._runner_runner = None
            raise RuntimeError("Gateway 端口 %d 被占用，aiohttp 改绑到 %s；拒绝继续"
                               % (self.config.gateway.port, conflicts))
        try:
            self._site = web.TCPSite(
                runner,
                host=self.config.gateway.bind,
                port=self.config.gateway.port,
            )
            await self._site.start()
        except BaseException:
            self._site = None
            try:
                runner.cleanup()
            except Exception:
                pass
            raise

    async def _close_gateway_runner(self) -> None:
        runner, self._runner_runner = self._runner_runner, None
        self._site = None
        if runner is not None:
            await runner.cleanup()

    async def start(self) -> str:
        """启动完整运行时栈，并返回 Agent Token"""
        # 1. 图形环境
        self.start_graphical_environment()

        # 2. 浏览器启动（正式环境不允许用 mock 冒充启动成功）
        if self.config.browser.enabled:
            if not await self.browser_mgr.start():
                raise RuntimeError(f"Chromium / Playwright 启动失败: {self.browser_mgr.last_error}")

        # 3. 启动 Gateway HTTP 服务
        await self._start_gateway_runner()

        # 4. 生成 Agent 主凭证
        agent_token = self.session_ctx.auth.create_agent_token()

        # 5. 启动 Cloudflare Tunnel
        named = self.config.tunnel.provider == "named"
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
        # Named 固定域名必须把 hostname 交给 Registry 做跨用户互斥，
        # 否则同一域名下的两个 Runner 会被错误路由。
        ok = await self.rendezvous.register_session(
            session_id=self.session_ctx.session_id,
            run_id=self.session_ctx.run_id,
            origin=public_url,
            agent_token=agent_token,
            hostname=self.config.tunnel.hostname if named else None,
        )
        self.session_ctx.rendezvous_published = ok
        print(f"[runtime] registry_register_ok={ok} last_error={self.rendezvous.last_error}", flush=True)
        if not ok:
            raise RuntimeError(f"私有会话注册失败: {self.rendezvous.last_error or 'unknown'}")

        # 7. 开启录像（若配置开启）
        if self.config.persistence.desktop_video.enabled:
            if not self.recorder.start():
                raise RuntimeError("FFmpeg 桌面录像启动失败")

        # 8. 激活 Agent 状态机
        self.session_ctx.state_machine.start_agent()

        # 9. 运行期健康监控：Tunnel 断开、Gateway 不健康、Chromium 崩溃都如实标记，
        #    只在本架构能安全恢复时做有界重启/重连。
        if self.config.health.enabled:
            self._health_stop.clear()
            self._health_task = asyncio.ensure_future(self._health_loop())

        return agent_token

    # ------------------------------------------------------------------
    # 运行期健康监控与有界恢复
    #
    # 本架构下能安全恢复的有两类：cloudflared 退出（重启并重新做入站探针；Quick
    # Tunnel 换域名后重新向 Registry 注册）与 Chromium 崩溃（同一 user_data_dir
    # 有界重启）。Gateway 的 aiohttp 回调与 Session 深度绑定，原地重建只会得到半死
    # 的服务，因此不健康的 Gateway 只如实标记，由宿主据实上报。
    # ------------------------------------------------------------------

    def _truncate(self, text: str, limit: int = 200) -> str:
        return " ".join(str(text or "").split())[:limit]

    async def _health_loop(self) -> None:
        """周期检查 Gateway → Chromium → Tunnel；stop() 会取消本任务。"""
        while not self._health_stop.is_set():
            try:
                await self.check_health_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - 单轮异常不能让监控自身静默退出
                logger.warning("运行期健康检查异常: %s", type(exc).__name__)
            try:
                await asyncio.wait_for(self._health_stop.wait(), timeout=self.health_check_interval)
            except asyncio.TimeoutError:
                continue

    async def check_health_once(self) -> Dict[str, Any]:
        """执行一轮健康检查，返回本轮报告（只含状态与脱敏原因）。"""
        gateway = await self._check_gateway()
        chromium = await self._check_chromium()
        tunnel = await self._check_tunnel()
        report: Dict[str, Any] = {"gateway": gateway, "chromium": chromium, "tunnel": tunnel}
        report["healthy"] = all(
            item.get("status") in _HEALTHY_STATES for item in (gateway, chromium, tunnel))
        self._publish_health(report)
        return report

    def health_report(self) -> Dict[str, Any]:
        """最近一轮健康报告（监控未启动时返回 disabled 标记）。"""
        return self.health_state

    async def _get_gateway_session(self) -> ClientSession:
        if self._gateway_session is None or self._gateway_session.closed:
            self._gateway_session = ClientSession(
                timeout=ClientTimeout(total=self.health_check_timeout))
        return self._gateway_session

    async def _check_gateway(self) -> Dict[str, Any]:
        """本地回环 /health：确认 Gateway 仍在监听且服务于本会话。"""
        url = f"http://{self.config.gateway.bind}:{self.config.gateway.port}/health"
        try:
            session = await self._get_gateway_session()
            async with session.get(url) as resp:
                if resp.status != 200:
                    return {"status": "unhealthy", "detail": f"HTTP {resp.status}",
                            "probe_failed": True}
                body = await resp.json(content_type=None)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - 连接失败同样是不健康
            return {"status": "unhealthy", "detail": type(exc).__name__, "probe_failed": True}
        if not isinstance(body, dict) or body.get("status") != "ok":
            return {"status": "unhealthy", "detail": "健康响应格式异常", "probe_failed": True}
        session_id = body.get("session_id")
        if session_id and session_id != self.session_ctx.session_id:
            return {"status": "unhealthy", "detail": "session 不匹配", "probe_failed": True}
        return {"status": "ok", "detail": "", "probe_failed": False}

    async def _public_edge_ok(self) -> bool:
        """经公网入口探一次 /health；连续失败即视为入口已失效（cloudflared 仍连着边缘，
        但隧道本身在边缘侧已不存在 —— 进程活着不代表入口可用）。

        只针对 Quick Tunnel：随机域名被边缘回收是真实故障；Named 固定域名归用户所有，
        其可达性不由本运行时判定。
        """
        if getattr(self.config.tunnel, "provider", "") != "quick":
            return True
        url = (self.session_ctx.tunnel_url or "").rstrip("/") + "/health"
        if not url.startswith("https://"):
            return True
        try:
            session = await self._get_gateway_session()
            async with session.get(url, headers={"Cache-Control": "no-store"}) as resp:
                return resp.status == 200
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - 任何失败都是入口不可用
            return False

    async def _check_tunnel(self) -> Dict[str, Any]:
        """cloudflared 退出即如实标记；在架构允许时做有界重启。"""
        provider = self.tunnel
        status = await provider.status()
        if provider.force_mock:
            return {"status": "unchecked", "detail": "mock provider", "restarts": 0}
        if status.get("connected") and await self._public_edge_ok():
            self._tunnel_down_count = 0
            return {"status": "ok", "detail": "", "restarts": self.tunnel_restarts}
        if status.get("connected"):
            detail = "公网入口 /health 探针连续失败"
            try:
                await provider.stop()
            except Exception:  # noqa: BLE001 - 停止失败不阻断重启
                pass
        else:
            detail = self._truncate(status.get("error") or "tunnel 已断开")
        if len(self._recent(self._tunnel_restart_times)) >= int(self.tunnel_max_restarts):
            return {"status": "down",
                    "detail": detail + "（重启次数用尽）",
                    "restarts": self.tunnel_restarts}
        self._tunnel_down_count += 1
        if self.tunnel_restart_backoff:
            await asyncio.sleep(self.tunnel_restart_backoff * self._tunnel_down_count)
        started = False
        attempted_at = time.monotonic()
        try:
            started = bool(await provider.start())
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tunnel 重启异常: %s", type(exc).__name__)
        # 尝试本身也计入窗口预算：即使失败也不会每次都再 spawn，避免无限重试。
        self._tunnel_restart_times.append(attempted_at)
        new_url = provider.get_public_url() if started else None
        if not started or not new_url:
            last = self._truncate(((await provider.status()) or {}).get("error") or "")
            return {"status": "down",
                    "detail": last or detail + "（重启失败）",
                    "restarts": self.tunnel_restarts}
        self.tunnel_restarts += 1
        self._tunnel_down_count = 0
        if new_url != self.session_ctx.tunnel_url:
            # Quick Tunnel 每次重连都是新域名：旧 Registry 记录已失效，必须重新注册。
            await self._reregister_tunnel(new_url)
        return {"status": "recovered", "detail": detail, "restarts": self.tunnel_restarts}

    async def _reregister_tunnel(self, new_url: str) -> None:
        token = self.session_ctx.auth.create_agent_token()
        try:
            ok = await self.rendezvous.register_session(
                session_id=self.session_ctx.session_id,
                run_id=self.session_ctx.run_id,
                origin=new_url,
                agent_token=token,
                hostname=self.config.tunnel.hostname if self.config.tunnel.provider == "named" else None,
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - 注册失败只影响发布状态，不覆盖入口本身
            ok = False
        self.session_ctx.rendezvous_published = ok
        self.session_ctx.tunnel_url = new_url
        if ok:
            return
        logger.warning("Tunnel 重连后重新注册失败，入口未发布到 Registry")

    async def _check_chromium(self) -> Dict[str, Any]:
        if not self.config.browser.enabled:
            return {"status": "disabled", "detail": "", "restarts": 0}
        reason = self.browser_mgr.check_health()
        if reason is None:
            return {"status": "ok", "detail": "", "restarts": self.browser_restarts}
        if len(self._recent(self._browser_restart_times)) >= int(self.chromium_max_restarts):
            return self._chromium_down(reason + "（重启次数用尽）")

        self._browser_restart_times.append(time.monotonic())
        try:
            ok = await self.browser_mgr.restart()
        except BrowserRestartExhausted as exc:
            return self._chromium_down(str(exc))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - 重启异常同样是失败，不得吞掉
            return self._chromium_down("Chromium 重启异常: %s" % type(exc).__name__)
        if not ok:
            return self._chromium_down("Chromium 重启失败: %s"
                                       % self._truncate(self.browser_mgr.last_error))
        self.browser_restarts += 1
        self._clear_runtime_fault()
        return {"status": "recovered", "detail": reason, "restarts": self.browser_restarts}

    def _recent(self, times: List[float]) -> List[float]:
        """只保留窗口内的记录（原地裁剪）。"""
        if not times:
            return times
        cutoff = time.monotonic() - self.health_window_seconds
        times[:] = [t for t in times if t >= cutoff]
        return times

    def _chromium_down(self, detail: str) -> Dict[str, Any]:
        # 如实写入会话状态：调用方从 /v1/session 就能看到浏览器已不可用，
        # 而不是只能碰到后续命令超时。恢复成功后由 _clear_runtime_fault 撤销。
        self.session_ctx.state_machine.mark_runtime_fault("chromium", detail)
        return {"status": "down", "detail": detail, "restarts": self.browser_restarts}

    def _clear_runtime_fault(self) -> None:
        self.session_ctx.state_machine.clear_runtime_fault()

    def _publish_health(self, report: Dict[str, Any]) -> None:
        """把本轮报告写入会话状态（/v1/session 对已鉴权调用方可见）。"""
        chrome = self.browser_mgr.health() if self.config.browser.enabled else {"status": "disabled"}
        self.health_state = {
            "overall": "ok" if report.get("healthy") else "degraded",
            "tunnel": report.get("tunnel"),
            "gateway": report.get("gateway"),
            "chromium": report.get("chromium"),
            "browser": chrome,
        }
        healthy = bool(report.get("healthy"))
        self.session_ctx.health = self.health_state
        # 只在“由好变坏”时打印一次，避免每轮刷屏；原因已脱敏（不含入口/凭证/Token）。
        if healthy:
            self._degraded_announced = False
            return
        if self._degraded_announced:
            return
        self._degraded_announced = True
        print("[runtime] health degraded tunnel=%s gateway=%s chromium=%s" % (
            (report.get("tunnel") or {}).get("status"),
            (report.get("gateway") or {}).get("status"),
            (report.get("chromium") or {}).get("status")), flush=True)

    async def _stop_health_monitor(self) -> None:
        self._health_stop.set()
        task, self._health_task = self._health_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        session, self._gateway_session = self._gateway_session, None
        if session is not None and not session.closed:
            try:
                await session.close()
            except Exception:
                pass

    async def stop(self) -> None:
        """关闭运行时并清理资源"""
        await self._stop_health_monitor()
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

        self._stop_session_bus()

    def _stop_session_bus(self) -> None:
        """只回收本进程拉起的会话总线，绝不动外部提供的那条。"""
        if not self._dbus_owned:
            return
        if self._dbus_proc is not None:
            try:
                self._dbus_proc.terminate()
                self._dbus_proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    self._dbus_proc.kill()
                except OSError:
                    pass
        elif self._dbus_pid:
            try:
                os.kill(self._dbus_pid, signal.SIGTERM)
            except OSError:
                pass
        self._dbus_proc = None
        self._dbus_pid = None
        self._dbus_owned = False
        for name in (_LAUNCH_ADDRESS_ENV, _LAUNCH_PID_ENV, _ATSPI_ADDRESS_ENV):
            os.environ.pop(name, None)
