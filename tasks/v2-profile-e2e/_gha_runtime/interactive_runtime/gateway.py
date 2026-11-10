"""Secure Session Gateway 实现。

遵循《2.0 迭代.md》第六章。
单一对外入口（127.0.0.1:8765），汇聚五个功能域：
1. Authentication（Token 与单次 Ticket 交换）；
2. Agent Control（GUI 与浏览器高级指令）；
3. Human Handoff（人工接管、认领、交还与取消）；
4. Live Streaming（浏览器画面 WebSocket 与桌面流）；
5. State Transfer（分块传输、Manifest、断点续传与 ACK 确认）。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from aiohttp import ClientSession, WSMsgType, web

from .auth import AuthManager, Scope
from .browser import BrowserManager
from .browser_stream import BrowserStreamRelay
from .desktop import DesktopManager
from .desktop_stream import DesktopStreamManager
from .session import SessionContext
from .state_export import (
    CheckpointConflictError,
    SecretExportError,
    StateExporter,
    TaskStateError,
)
from .state_import import StateImporter
from .state_machine import CLOSED_STATES, ControlRole, SessionState, StateMachine
from .transfer import ChunkedTransferEngine, TransferError

logger = logging.getLogger(__name__)

# Gateway 接受的 checkpoint 类型（CLI --type 的同名集合）
CHECKPOINT_TYPES = ("AUTH", "BROWSER", "DESKTOP", "TASK", "FINAL")


def _parse_byte_range(value: str) -> Optional[tuple]:
    """解析单段 bytes=start-end / bytes=start- / bytes=-suffix；不合法返回 None。"""
    value = value.strip()
    if not value.lower().startswith("bytes="):
        return None
    spec = value[6:].strip()
    if "," in spec or "-" not in spec:
        return None
    start_s, _, end_s = spec.partition("-")
    start_s, end_s = start_s.strip(), end_s.strip()
    if not start_s and not end_s:
        return None
    try:
        if not start_s:
            suffix = int(end_s)
            return (0, suffix - 1) if suffix > 0 else None
        start = int(start_s)
        end = int(end_s) if end_s else None
    except ValueError:
        return None
    if start < 0 or (end is not None and end < start):
        return None
    return start, end if end is not None else (1 << 62)


class CheckpointScheduler:
    """可选的定时检查点（`persistence.checkpoint_interval_seconds > 0` 时启用，默认关闭）。

    - 每个 interval 最多生成一个检查点；tick 串行化，并发触发只会有一次真正创建；
    - 默认生成 AUTH_CHECKPOINT；配置 `persistence.task_state_path` 时改为 TASK_CHECKPOINT，
      定时保存业务中间产物；
    - 单个 tick 失败（例如 Host 公钥未配置、任务状态路径暂时不可读）只记录错误，
      不会终止定时器，也不影响任务的生命周期与最终 FINAL 归档。
    """

    def __init__(
        self,
        exporter: StateExporter,
        interval_seconds: float = 0,
        task_state_path: Optional[str] = None,
        clock: Optional[Any] = None,
        skip_when: Optional[Any] = None,
    ):
        self.exporter = exporter
        self.interval_seconds = max(0.0, float(interval_seconds or 0))
        self.task_state_path = task_state_path or None
        self.checkpoint_type = "TASK" if self.task_state_path else "AUTH"
        self._clock = clock or time.monotonic
        # 会话进入收尾/终态时跳过：FINAL 正在关闭浏览器，定时器不得再碰它
        self._skip_when = skip_when
        self._task: Optional[asyncio.Task] = None
        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Optional[Any] = None
        self._last_tick: Optional[float] = None
        self._seq = 0
        # 已生成的 checkpoint_id 与最近错误；供审计/测试观察，不参与控制流
        self.created: List[str] = []
        self.errors: List[str] = []

    @classmethod
    def from_config(cls, exporter: Any, config: Any, skip_when: Optional[Any] = None) -> "CheckpointScheduler":
        persistence = getattr(config, "persistence", None)
        interval: Any = getattr(persistence, "checkpoint_interval_seconds", 0)
        if not getattr(persistence, "enabled", True):
            interval = 0
        try:
            interval = float(interval or 0)
        except (TypeError, ValueError):
            interval = 0.0
        return cls(
            exporter, interval, getattr(persistence, "task_state_path", None),
            skip_when=skip_when,
        )

    @property
    def enabled(self) -> bool:
        return self.interval_seconds > 0

    def _tick_lock(self) -> asyncio.Lock:
        """按事件循环惰性创建锁：StateExporter 可能在 asyncio.run 之外构造。"""
        loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    async def start(self) -> bool:
        if not self.enabled or self._task is not None:
            return False
        self._task = asyncio.create_task(self._run(), name="gha-checkpoint-timer")
        return True

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:  # 定时器自身异常不阻断关闭流程
            pass

    async def tick(self, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """最多生成一个检查点：距上次触发不足一个 interval 时直接跳过。"""
        if not self.enabled:
            return None
        async with self._tick_lock():
            if self._skip_when is not None:
                try:
                    if self._skip_when():
                        return None
                except Exception:  # 判定函数自身异常不应拖垮定时器
                    logger.exception("定时检查点跳过判定失败")
                    return None
            moment = self._clock() if now is None else now
            if self._last_tick is not None and (moment - self._last_tick) < self.interval_seconds:
                return None
            checkpoint_id = f"periodic-{self._seq + 1:04d}"
            try:
                if self.checkpoint_type == "TASK":
                    record = await self.exporter.create_task_checkpoint(checkpoint_id, self.task_state_path)
                else:
                    record = await self.exporter.create_auth_checkpoint(checkpoint_id)
            except Exception as exc:
                self.errors.append(f"{checkpoint_id}: {type(exc).__name__}: {str(exc)[:200]}")
                del self.errors[:-50]  # 长任务只保留最近 50 条，避免无界增长
                logger.warning("定时检查点 %s 失败：%s", checkpoint_id, exc)
                # 失败也算本间隔已尝试过，避免每个循环都重试造成日志风暴
                self._last_tick = moment
                return None
            self._seq += 1
            self._last_tick = moment
            self.created.append(checkpoint_id)
            return record

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.interval_seconds)
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # tick 已自行兜底，这里只防御未预期异常
                logger.exception("定时检查点循环异常")


class GatewayApp:
    """网关应用服务器"""

    def __init__(
        self,
        session_ctx: SessionContext,
        browser_mgr: BrowserManager,
        desktop_mgr: DesktopManager,
        transfer_engine: ChunkedTransferEngine,
        state_exporter: StateExporter,
        state_importer: StateImporter,
        desktop_stream_mgr: DesktopStreamManager,
        web_static_dir: Optional[str] = None,
    ):
        self.ctx = session_ctx
        self.auth = session_ctx.auth
        self.state_machine = session_ctx.state_machine
        self.browser = browser_mgr
        self.desktop = desktop_mgr
        self.transfer = transfer_engine
        self.exporter = state_exporter
        self.importer = state_importer
        self.desktop_stream = desktop_stream_mgr
        self.browser_stream = BrowserStreamRelay(browser_mgr, self.state_machine)
        self.web_static_dir = web_static_dir or os.path.join(os.path.dirname(__file__), "web")

        # 可选定时的检查点：默认关闭；配置了 interval 时随 Gateway 生命周期启停
        self.checkpoint_scheduler = CheckpointScheduler.from_config(
            self.exporter, self.ctx.config, skip_when=self._periodic_skipped)
        persistence = getattr(self.ctx.config, "persistence", None)
        self.configured_task_state_path = getattr(persistence, "task_state_path", None)

        self.app = web.Application(client_max_size=16 * 1024 * 1024)
        self.app.on_startup.append(self._start_checkpoint_scheduler)
        self.app.on_cleanup.append(self._stop_checkpoint_scheduler)
        self._setup_routes()

    def _periodic_skipped(self) -> bool:
        """收尾/终态阶段跳过定时检查点：此时 FINAL 正在关闭浏览器。"""
        return self.state_machine.state in CLOSED_STATES

    async def _start_checkpoint_scheduler(self, app: web.Application) -> None:
        await self.checkpoint_scheduler.start()

    async def _stop_checkpoint_scheduler(self, app: web.Application) -> None:
        await self.checkpoint_scheduler.stop()

    @staticmethod
    def _novnc_dir() -> str:
        """noVNC 静态文件目录（npm 全局安装，install-linux.sh 写入 GHA_NOVNC_DIR）。

        人工作业机（``gha handoff open``）可以用环境变量指到任意本地 noVNC 1.x 目录。
        npm 全局根目录只查一次：每个 GatewayApp 构造都跑一遍 npm 会拖慢启动。
        """
        env_dir = os.environ.get("GHA_NOVNC_DIR", "")
        if env_dir and os.path.isfile(os.path.join(env_dir, "core", "rfb.js")):
            return env_dir
        for path in GatewayApp._npm_novnc_dirs():
            if os.path.isfile(os.path.join(path, "core", "rfb.js")):
                return path
        return ""

    _NPM_NOVNC_DIRS: Optional[list] = None

    @staticmethod
    def _npm_novnc_dirs() -> list:
        if GatewayApp._NPM_NOVNC_DIRS is None:
            dirs = []
            try:
                root = subprocess.run(
                    ["npm", "root", "-g"], capture_output=True, text=True, timeout=5,
                )
                if root.returncode == 0 and root.stdout.strip():
                    dirs.append(os.path.join(root.stdout.strip(), "@novnc", "novnc"))
            except (OSError, subprocess.SubprocessError):
                pass
            GatewayApp._NPM_NOVNC_DIRS = dirs
        return GatewayApp._NPM_NOVNC_DIRS

    def _setup_routes(self) -> None:
        self.app.router.add_get("/health", self.handle_health)
        self.app.router.add_get("/v1/session", self.handle_get_session)
        self.app.router.add_post("/v1/agent/command", self.handle_agent_command)
        self.app.router.add_post("/v1/browser/command", self.handle_browser_command)

        # Handoff 控制路由
        self.app.router.add_post("/v1/handoff/request", self.handle_handoff_request)
        self.app.router.add_post("/v1/handoff/claim", self.handle_handoff_claim)
        self.app.router.add_post("/v1/handoff/complete", self.handle_handoff_complete)
        self.app.router.add_post("/v1/handoff/cancel", self.handle_handoff_cancel)

        # 实时流路由
        self.app.router.add_get("/v1/live/browser", self.handle_browser_stream_ws)
        self.app.router.add_get("/v1/live/desktop", self.handle_desktop_stream_ws)

        # 状态持久化路由
        self.app.router.add_get("/v1/state/manifest", self.handle_state_manifest)
        self.app.router.add_get("/v1/state/objects/{id}", self.handle_download_object)
        self.app.router.add_get("/v1/state/import/status", self.handle_import_status)
        self.app.router.add_post("/v1/state/import", self.handle_import_object)
        self.app.router.add_post("/v1/state/checkpoint", self.handle_create_checkpoint)
        self.app.router.add_post("/v1/state/ack", self.handle_state_ack)

        # 任务终态控制
        self.app.router.add_post("/v1/task/finish", self.handle_task_finish)

        # 静态文件服务（Handoff UI）。noVNC 必须先于 /web/ 注册：同一路由表里 /web/ 是
        # 前缀通配，先注册的 handler 优先，否则 /web/novnc/core/rfb.js 会被 /web/ 抢走。
        if os.path.isdir(self.web_static_dir):
            novnc_dir = self._novnc_dir()
            if novnc_dir:
                self.app.router.add_static("/web/novnc/", path=novnc_dir, name="novnc")
                # 门户用 `import()` 加载 core/rfb.js，而 npm 包只在包根目录带
                # package.json（"type": "module"）。静态服务只暴露包内文件、不读它，
                # 浏览器会按经典脚本解析 .js 而报 `Unexpected token 'export'`。
                # 这里给 .js 补上 JS MIME，让 ES module 加载成立（只影响静态资源）。
                self.app.router.add_get("/web/novnc/{path:.*\\.js}", self.handle_novnc_module)
            self.app.router.add_static("/web/", path=self.web_static_dir, name="web")
            self.app.router.add_get("/", self.handle_index_html)

    async def handle_novnc_module(self, req: web.Request) -> web.StreamResponse:
        """noVNC 的 .js 以 ES module MIME 下发（见 _setup_routes 里的注册原因）。"""
        root = GatewayApp._novnc_dir()
        if not root:
            return web.Response(status=404)
        rel = req.match_info["path"]
        target = os.path.realpath(os.path.join(root, rel))
        if not target.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(target):
            return web.Response(status=404)
        return web.FileResponse(target, headers={
            "Content-Type": "text/javascript; charset=utf-8",
            "Cache-Control": "no-cache",
        })

    def _extract_auth_token(self, req: web.Request) -> str:
        """只从 Authorization Header 或 HttpOnly Cookie 取 Token，禁止 URL Query 携带。"""
        auth_hdr = req.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        return req.cookies.get("gha_session", "")

    @staticmethod
    def _scope_allowed(auth: Any, token: str, scopes: tuple) -> bool:
        """token 需要至少具备 scopes 中的一个（例如人工会话只持 HUMAN_BROWSER 或 HUMAN_DESKTOP）。"""
        return any(auth.verify_token(token, required_scope=s) for s in scopes)

    @staticmethod
    def _origin_allowed(req: web.Request) -> bool:
        """Origin 必须与 Host 同源。

        页面经 Cloudflare Tunnel 打开时 Host 是 ``xxx.trycloudflare.com``，而 Origin
        也是 https 的同一主机；localhost 调试与 TestServer 走 http。两者都接受，
        避免把合法页面误判成跨站。
        """
        origin = req.headers.get("Origin", "")
        if not origin:
            return True  # 非浏览器 Agent 客户端没有 Origin；浏览器页面由浏览器强制带 Origin
        host = req.host or ""
        return origin in (f"https://{host}", f"http://{host}")

    async def handle_health(self, req: web.Request) -> web.Response:
        """非敏感健康检查。

        Named Tunnel 的入站探针会带一次性的 ``X-GHA-Tunnel-Probe``：只回显它的
        摘要（16 位 hex），供 Runner 确认“固定域名确实路由到了本进程”，不回显原值、
        也不含任何凭证。
        """
        probe = req.headers.get("X-GHA-Tunnel-Probe", "")
        body = {
            "status": "ok",
            "time": time.time(),
            "version": "2.0.0",
            "session_id": self.ctx.session_id,
        }
        if probe:
            body["ingress_probe_ok"] = True
            body["probe"] = hashlib.sha256(probe.encode("utf-8")).hexdigest()[:16]
        return web.json_response(body)

    async def handle_index_html(self, req: web.Request) -> web.Response:
        mode = req.query.get("mode", "browser")
        return self._portal_response(mode)

    def handoff_page(self, mode: str) -> str:
        """两种 Handoff 共用一个门户页面；?mode= 决定认领后展示哪条流。"""
        return "/" if mode not in ("browser", "desktop") else f"/?mode={mode}"

    def _portal_response(self, mode: str) -> web.Response:
        if mode not in ("browser", "desktop"):
            return web.Response(text="Unknown mode", status=400)
        index_file = os.path.join(self.web_static_dir, "index.html")
        if os.path.isfile(index_file):
            resp = web.FileResponse(index_file)
            resp.headers["Cache-Control"] = "no-store"
            return resp
        return web.Response(text="<h1>gha-runner Interactive Gateway</h1>", content_type="text/html")

    async def handle_get_session(self, req: web.Request) -> web.Response:
        """查询当前会话状态"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token):
            return web.json_response({"error": "Unauthorized"}, status=401)

        return web.json_response(self.ctx.to_status_dict())

    async def handle_agent_command(self, req: web.Request) -> web.Response:
        """处理 Agent 发来的原生桌面自动化命令"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, required_scope=Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        gen = body.get("generation")
        ok, reason = self.state_machine.verify_action_allowed(ControlRole.AGENT, generation=gen)
        if not ok:
            return web.json_response({"error": reason, "status": "rejected"}, status=403)

        if not isinstance(body, dict):
            return web.json_response({"error": "Invalid JSON"}, status=400)
        cmd = str(body.get("cmd") or "")
        if cmd == "snapshot":
            snap = self.desktop.snapshot()
            status = "ok" if snap.get("ok", True) else "failed"
            return web.json_response({"status": status, "snapshot": snap})

        handler = self._AGENT_GUI_COMMANDS.get(cmd)
        if handler is not None:
            try:
                result = handler(self, body)
            except (TypeError, ValueError) as exc:
                return web.json_response(
                    {"status": "failed", "error": {"code": "INVALID_ARGS", "message": str(exc)}},
                    status=400,
                )
            res = bool(result) if isinstance(result, bool) else result is not None
            payload: Dict[str, Any] = {"status": "ok" if res else "failed"}
            if not res:
                error = getattr(self.desktop, "last_error_dict", lambda: None)()
                payload["error"] = error or {"code": "ACTION_FAILED", "message": "桌面操作未执行"}
            return web.json_response(payload)
        if cmd == "screenshot":
            png_bytes = self.desktop.screenshot()
            if not png_bytes:
                error = getattr(self.desktop, "last_error_dict", lambda: None)()
                return web.json_response(
                    {"status": "failed", "error": error or {"code": "SCREENSHOT_FAILED", "message": "桌面截图失败"}},
                    status=502,
                )
            return web.Response(body=png_bytes, content_type="image/png")

        return web.json_response({"error": f"Unknown command: {cmd}"}, status=400)

    def _cmd_click(self, body: Dict[str, Any]) -> bool:
        if "x" not in body or "y" not in body:
            raise ValueError("click 需要 x / y 坐标")
        button = body.get("button", 1)
        if isinstance(button, str):
            button = {"left": 1, "middle": 2, "right": 3}.get(button.lower(), button)
        return self.desktop.click(int(body["x"]), int(body["y"]), int(button))

    def _cmd_type(self, body: Dict[str, Any]) -> bool:
        text = body.get("text")
        if not isinstance(text, str) or not text:
            raise ValueError("type 需要非空 text 字段")
        return self.desktop.type_text(text)

    def _cmd_key(self, body: Dict[str, Any]) -> bool:
        key = body.get("key")
        if not isinstance(key, str) or not key.strip():
            raise ValueError("key 需要非空 key 字段，例如 ctrl+c")
        return self.desktop.key_press(key)

    def _cmd_focus(self, body: Dict[str, Any]) -> bool:
        target = body.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("focus 需要 target（窗口标题或窗口 id）")
        return self.desktop.focus_window(target)

    # GUI 命令 -> 参数校验 + 桌面后端调用。非法参数一律 INVALID_ARGS(400)，
    # 绝不把缺失字段当成 (0,0) 之类的默认值去点击。
    _AGENT_GUI_COMMANDS = {
        "click": _cmd_click,
        "type": _cmd_type,
        "key": _cmd_key,
        "focus": _cmd_focus,
    }

    async def handle_browser_command(self, req: web.Request) -> web.Response:
        """处理 Agent 发来的浏览器控制命令"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, required_scope=Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "Invalid JSON"}, status=400)

        gen = body.get("generation")
        ok, reason = self.state_machine.verify_action_allowed(ControlRole.AGENT, generation=gen)
        if not ok:
            return web.json_response({"error": reason, "status": "rejected"}, status=403)

        cmd = body.get("cmd", "")
        if cmd == "navigate":
            url = str(body.get("url", ""))
            res = await self.browser.navigate(url)
            return web.json_response(res)
        elif cmd == "snapshot":
            snap = await self.browser.snapshot()
            return web.json_response({"status": "ok", "snapshot": snap})
        elif cmd == "screenshot":
            png_bytes = await self.browser.screenshot()
            return web.Response(body=png_bytes, content_type="image/png")
        elif cmd == "storage_state":
            st = await self.browser.export_storage_state()
            return web.json_response({"status": "ok", "storage_state": st})
        elif cmd == "set_download_behavior":
            # 让 Chromium 自己持有下载目录偏好：写内存偏好在关闭时落盘进 Profile，
            # 任务端不必自己连 CDP（远端 CDP 端口不对外暴露）。
            directory = body.get("download_directory")
            if not isinstance(directory, str) or not directory.startswith("/"):
                return web.json_response({"error": "download_directory 必须是绝对路径"}, status=400)
            try:
                res = await self.browser.set_download_behavior(
                    directory, str(body.get("behavior") or "allow"))
            except Exception as exc:
                return web.json_response(
                    {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}, status=500)
            return web.json_response({"status": "ok", "cdp": res, "download_directory": directory})

        return web.json_response({"error": f"Unknown browser command: {cmd}"}, status=400)

    # ---- Handoff 流程路由
    async def handle_handoff_request(self, req: web.Request) -> web.Response:
        """Agent 请求人工接管"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, required_scope=Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            body = {}

        mode = body.get("mode", "browser")
        if mode not in ("browser", "desktop"):
            return web.json_response({"error": f"Unknown handoff mode: {mode}"}, status=400)
        try:
            timeout_s = int(body.get("timeout_seconds", 300))
        except (TypeError, ValueError):
            return web.json_response({"error": "timeout_seconds 必须是整数"}, status=400)
        if timeout_s <= 0:
            return web.json_response({"error": "timeout_seconds 必须为正数"}, status=400)
        ticket = self.auth.create_handoff_ticket(mode=mode, ttl_seconds=timeout_s)

        ok, msg = self.state_machine.request_handoff(mode=mode, timeout_seconds=timeout_s, ticket=ticket)
        if not ok:
            return web.json_response({"error": msg}, status=400)

        if mode == "desktop" and not self.desktop_stream.start_streaming():
            self.state_machine.cancel_handoff()
            return web.json_response({
                "error": "Desktop streaming dependencies unavailable",
                "detail": getattr(self.desktop_stream, "last_error", ""),
            }, status=503)

        # Ticket 放在 fragment（#）而不是 Query：fragment 不会随 HTTP 请求发到服务器，
        # 也不会出现在 Gateway / Tunnel 的访问日志里。浏览器/桌面共用一个门户页面，
        # 认领后用返回的 Cookie 按 scope 选择是否连接 noVNC。
        return web.json_response({
            "status": "ok",
            "mode": mode,
            "ticket": ticket,
            "handoff_url": f"{self.handoff_page(mode)}#ticket={ticket}",
            "desktop_stream": mode == "desktop" and self.desktop_stream.is_active,
            "generation": self.state_machine.generation,
        })

    async def handle_handoff_claim(self, req: web.Request) -> web.Response:
        """人工端凭 Ticket 认领控制权并获取专属会话 Cookie"""
        try:
            body = await req.json()
        except Exception:
            body = {}

        ticket = body.get("ticket")
        if not ticket:
            return web.json_response({"error": "Missing ticket"}, status=400)

        ex = self.auth.exchange_ticket_for_session(ticket)
        if not ex:
            return web.json_response({"error": "Invalid or expired ticket"}, status=403)

        session_cookie, scope = ex
        ok, msg = self.state_machine.claim_handoff(ticket=ticket)
        if not ok:
            return web.json_response({"error": msg}, status=400)

        resp = web.json_response({
            "status": "ok",
            "message": "Handoff claimed",
            "mode": self.state_machine.handoff_mode,
            "role": self.state_machine.current_role.value,
            "generation": self.state_machine.generation,
            "page": self.handoff_page(self.state_machine.handoff_mode or "browser"),
        })
        resp.set_cookie("gha_session", session_cookie, httponly=True,
                        secure=(req.scheme == "https"), samesite="Lax")
        return resp

    async def handle_handoff_complete(self, req: web.Request) -> web.Response:
        """人工完成接管，返还控制权给 Agent。

        人工端用认领拿到的 session Cookie（HUMAN_BROWSER / HUMAN_DESKTOP），Agent 用自己的
        Token 也能调用。切回 Agent 时不重启桌面：只关掉 x11vnc/websockify 这条流，
        Xvfb、Openbox、Chromium 与 AT-SPI 原样留给 agent-desktop 继续使用。
        """
        token = self._extract_auth_token(req)
        if not self._scope_allowed(
                self.auth, token, (Scope.HUMAN_BROWSER, Scope.HUMAN_DESKTOP, Scope.AGENT)):
            return web.json_response({"error": "Unauthorized"}, status=401)

        ok, msg = self.state_machine.complete_handoff()
        if not ok:
            return web.json_response({"error": msg}, status=400)

        self.desktop_stream.stop_streaming()

        # 触发接管后即时检查点
        await self.exporter.create_auth_checkpoint(f"after-handoff-{int(time.time())}")

        return web.json_response({
            "status": "ok",
            "message": "Returned control to agent",
            "generation": self.state_machine.generation,
        })

    async def handle_handoff_cancel(self, req: web.Request) -> web.Response:
        """取消接管"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, required_scope=Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        ok, msg = self.state_machine.cancel_handoff()
        self.desktop_stream.stop_streaming()
        if not ok:
            return web.json_response({"error": msg}, status=400)

        return web.json_response({
            "status": "ok",
            "message": "Handoff cancelled",
            "generation": self.state_machine.generation,
        })

    # ---- WebSocket 实时流
    async def handle_browser_stream_ws(self, req: web.Request) -> web.WebSocketResponse:
        """浏览器画面流与输入双向 WebSocket"""
        token = self._extract_auth_token(req)
        if not self._origin_allowed(req):
            return web.Response(status=403)
        if not self._scope_allowed(self.auth, token, (Scope.HUMAN_BROWSER,)):
            return web.Response(status=401)

        ws = web.WebSocketResponse()
        await ws.prepare(req)
        self.browser_stream.add_connection(ws)

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    await self.browser_stream.handle_client_message(ws, msg.data)
                elif msg.type == WSMsgType.ERROR:
                    break
        finally:
            self.browser_stream.remove_connection(ws)

        return ws

    async def handle_desktop_stream_ws(self, req: web.Request) -> web.WebSocketResponse:
        """桌面画面流（noVNC 协议通道，Gateway 鉴权后转发到本机 websockify）"""
        token = self._extract_auth_token(req)
        if not self._origin_allowed(req):
            return web.Response(status=403)
        # noVNC 只认人工桌面会话；Agent Token、Browser 会话都不能接到桌面流上。
        if not self._scope_allowed(self.auth, token, (Scope.HUMAN_DESKTOP,)):
            return web.Response(status=401)
        if not self.desktop_stream.is_active:
            return web.Response(status=409)

        # 人工接管期间 Agent 的桌面输入被状态机挡住，但底层桌面（Xvfb/Chromium/agent-desktop）
        # 全程不重启；接管结束只停流，后续 Agent 指令立即可用。
        ws = web.WebSocketResponse(max_msg_size=0)
        await ws.prepare(req)
        upstream = None
        try:
            async with ClientSession() as session:
                upstream = await session.ws_connect(
                    f"ws://127.0.0.1:{self.desktop_stream.ws_port}")

                async def client_to_upstream():
                    try:
                        async for msg in ws:
                            if msg.type == WSMsgType.TEXT:
                                await upstream.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await upstream.send_bytes(msg.data)
                        # CLOSE/ERROR 会让 aiohttp 结束迭代，方向与关闭码统一在此记录
                        logger.warning("桌面流方向=client->upstream 结束 code=%s", ws.close_code)
                    except Exception as exc:
                        logger.warning("桌面流方向=client->upstream 失败：%s: %s",
                                       type(exc).__name__, exc)
                        raise

                async def upstream_to_client():
                    try:
                        async for msg in upstream:
                            if msg.type == WSMsgType.TEXT:
                                await ws.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await ws.send_bytes(msg.data)
                        logger.warning("桌面流方向=upstream->client 结束 code=%s",
                                       upstream.close_code)
                    except Exception as exc:
                        logger.warning("桌面流方向=upstream->client 失败：%s: %s",
                                       type(exc).__name__, exc)
                        raise

                await asyncio.gather(client_to_upstream(), upstream_to_client())
        except Exception as exc:
            # 上游（本机 websockify）出问题时必须留下原因：否则客户端只看到 close frame，
            # 会被误判成网络故障，产品缺陷就永远查不出来。
            try:
                detail = self.desktop_stream.diagnose_summary()
            except Exception:  # 诊断自身异常不得掩盖原始错误
                detail = ""
            logger.warning("桌面流上游失败：%s: %s; %s", type(exc).__name__, exc, detail)
            if not ws.closed:
                if upstream is None:
                    await ws.close(code=1011, message=b"desktop upstream unavailable")
                else:
                    await ws.close(code=1011, message=b"desktop upstream failed")
        return ws

    # ---- 状态传输路由 (State Transfer)
    async def handle_state_manifest(self, req: web.Request) -> web.Response:
        """获取当前所有状态对象清单"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_READER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        manifest = self.exporter.get_manifest()
        return web.json_response(manifest)

    def _iter_object(self, obj_id: str, offset: int, length: int, total_size: int):
        """按固定块流式读取，单次请求内也不把大对象整体读进内存。"""
        remaining = length
        while remaining > 0:
            block, _, _ = self.transfer.read_chunk(obj_id, offset, min(self.transfer.stream_block, remaining))
            if not block:
                break
            offset += len(block)
            remaining -= len(block)
            yield block

    async def handle_download_object(self, req: web.Request) -> web.StreamResponse:
        """分块下载指定状态对象（支持 Range: bytes=start-end），逐块流式输出"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_READER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        obj_id = req.match_info["id"]
        meta = self.transfer.get_object_metadata(obj_id)
        if not meta:
            return web.json_response({"error": "Object not found"}, status=404)

        total_size = meta["size"]
        range_header = req.headers.get("Range", "")
        offset = 0
        length = total_size

        if range_header:
            span = _parse_byte_range(range_header)
            if span is None or span[0] >= total_size or span[1] < span[0]:
                return web.json_response(
                    {"error": "Range Not Satisfiable"},
                    status=416,
                    headers={"Content-Range": f"bytes */{total_size}"},
                )
            offset = span[0]
            end = min(span[1], total_size - 1)
            length = end - offset + 1

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(length),
            "Content-Range": f"bytes {offset}-{offset + length - 1}/{total_size}",
            "X-SHA256": meta["sha256"],
        }
        resp = web.StreamResponse(status=206 if range_header else 200, headers=headers)
        await resp.prepare(req)
        try:
            for block in self._iter_object(obj_id, offset, length, total_size):
                await resp.write(block)
        except Exception:
            # 文件在声明长度内被截断/读失败：断开连接让 Host 按 Range 重试，绝不补零
            logger.exception("对象 %s 流式读取中断", obj_id)
            await resp.write_eof()
            raise
        await resp.write_eof()
        return resp

    @staticmethod
    def _import_params(req: web.Request) -> Tuple[Optional[str], Optional[int], str, str]:
        obj_id = req.headers.get("X-Object-ID", "")
        try:
            total_size = int(req.headers.get("X-Total-Size", 0))
        except ValueError:
            return None, None, "", ""
        return obj_id, total_size, req.headers.get("X-SHA256", ""), req.headers.get("X-Category", "unknown")

    async def handle_import_status(self, req: web.Request) -> web.Response:
        """查询 Host→Runner 上传的已接收字节（断点续传依据）。

        只接受经身份特征（对象 ID + 总长 + SHA-256 + 类别）匹配的已登记导入对象；
        未登记对象一律 received=0，调用方需从头上传，不能按任意路径读取进度。
        """
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_WRITER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        obj_id, total_size, sha256, category = self._import_params(req)
        if not obj_id or not sha256 or total_size is None or total_size <= 0:
            return self._error_json("INVALID_ARGS", "缺少 X-Object-ID / X-Total-Size / X-SHA256", 400)
        # 返回 Runner 当前代际/会话号；Host 据此拒绝复用跨会话的旧进度。
        try:
            status, mismatch = self.transfer.incoming_status(obj_id, total_size, sha256, category)
        except TransferError as exc:
            return self._error_json(exc.code, str(exc), exc.status)
        if status.get("status") in ("in_progress", "complete"):
            # 进度被 Host 心跳式确认：长传期间不让索引淘汰把这条记录挤掉
            self.transfer.touch_incoming(obj_id)
        return web.json_response(dict(
            status,
            generation=self.state_machine.generation,
            session_id=getattr(self.ctx, "session_id", None),
            mismatch=mismatch,
        ))

    async def handle_import_object(self, req: web.Request) -> web.Response:
        """从 Agent Host 上传状态对象并写入（X-Offset 断点续传，SHA-256 校验通过才恢复）"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_WRITER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        obj_id, total_size, sha256, category = self._import_params(req)
        try:
            offset = int(req.headers.get("X-Offset", 0))
        except ValueError:
            return web.json_response({"error": "Invalid numeric header"}, status=400)
        if total_size is None:
            return web.json_response({"error": "Invalid numeric header"}, status=400)

        if not obj_id or not sha256 or total_size <= 0 or offset < 0 or offset > total_size:
            return web.json_response({"error": "Missing metadata headers"}, status=400)
        # 续传分块的 Content-Length + X-Offset 必须落在总长内，提前拒绝越界
        try:
            content_length = int(req.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return web.json_response({"error": "Invalid numeric header"}, status=400)
        if offset + content_length > total_size:
            return web.json_response({"error": "Upload exceeds declared size"}, status=400)

        if offset == 0:
            # 显式从 0 开始：即使服务端残留旧进度也以本次上传为准
            self.transfer.init_incoming_object(obj_id, total_size, sha256, category)
        else:
            # 断点续传：只允许复用身份特征（ID/总长/SHA-256/类别）完全一致的已登记进度
            if self.transfer.resume_incoming_object(obj_id, total_size, sha256, category) is None:
                status, _ = self.transfer.incoming_status(obj_id, total_size, sha256, category)
                return web.json_response(
                    {
                        "error": f"服务端没有可续传的对象 {obj_id}（{status.get('status')}），请从偏移 0 重新上传",
                        "code": "NO_RESUMABLE_UPLOAD",
                        "received": 0,
                    },
                    status=409,
                )

        if offset == total_size:
            # 空尾块：最后一块的响应在返回路上丢了。已经恢复并校验过的对象幂等回答
            # verified，绝不再重放导入（重复解包/重启浏览器），也不再写任何字节。
            if self.transfer.incoming_verified(obj_id):
                return web.json_response({
                    "status": "completed",
                    "object_id": obj_id,
                    "bytes": total_size,
                    "verified": True,
                    "replayed": True,
                })
            return web.json_response({
                "error": f"对象 {obj_id} 已收满但尚未验证恢复，请先读取 Runner 状态确认",
                "verified": False,
            }, status=409)

        chunk_data = await req.read()
        try:
            received = self.transfer.write_chunk(obj_id, offset, chunk_data)
        except TransferError as exc:
            if exc.code == "OFFSET_MISMATCH":
                status, _ = self.transfer.incoming_status(obj_id, total_size, sha256, category)
                return web.json_response(
                    {"error": str(exc), "code": exc.code, "received": status.get("received", 0)},
                    status=exc.status, headers={"X-GHA-Received": str(status.get("received", 0))},
                )
            return web.json_response({"error": str(exc), "code": exc.code}, status=exc.status)
        if received > total_size:
            return web.json_response({"error": "Upload exceeds declared size"}, status=400)

        if received == total_size:
            compatibility = {}
            if req.headers.get("X-Compatibility"):
                try:
                    compatibility = json.loads(req.headers["X-Compatibility"])
                except Exception:
                    return web.json_response({"error": "Invalid X-Compatibility JSON"}, status=400)
                if not isinstance(compatibility, dict):
                    return web.json_response({"error": "Invalid X-Compatibility JSON"}, status=400)
            try:
                final_path = self.transfer.finalize_incoming_object(obj_id)
            except TransferError as exc:
                return web.json_response({"error": str(exc), "verified": False}, status=400)
            if category == "auth_state":
                restored, message = await self.importer.restore_auth_state(final_path, compatibility)
            elif category == "browser_profile":
                restored, message = await self.importer.restore_profile_archive(final_path, compatibility)
            else:
                restored, message = True, "stored"
            if not restored:
                return web.json_response({"error": message, "verified": False}, status=500)
            self.transfer.mark_incoming_verified(obj_id, message)

            return web.json_response({
                "status": "completed",
                "object_id": obj_id,
                "bytes": received,
                "verified": True,
            })

        return web.json_response({
            "status": "chunk_received",
            "object_id": obj_id,
            "received": received,
        })

    @staticmethod
    def _error_json(code: str, message: str, status: int) -> web.Response:
        return web.json_response({"error": {"code": code, "message": message}}, status=status)

    def _public_checkpoint(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """返回给调用方的记录与 Manifest 同构：不含 Runner 本地路径。"""
        sanitize = getattr(self.exporter, "public_record", None)
        return sanitize(record) if sanitize else record

    async def handle_create_checkpoint(self, req: web.Request) -> web.Response:
        """触发生成检查点（AUTH / BROWSER / DESKTOP / TASK / FINAL）"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            return self._error_json("INVALID_JSON", "请求体必须是 JSON 对象", 400)
        if not isinstance(body, dict):
            return self._error_json("INVALID_JSON", "请求体必须是 JSON 对象", 400)

        raw_type = body.get("type", "AUTH")
        if not isinstance(raw_type, str):
            return self._error_json("INVALID_ARGS", "type 必须是字符串", 400)
        cp_type = raw_type.strip().upper()
        if cp_type not in CHECKPOINT_TYPES:
            return self._error_json(
                "INVALID_ARGS",
                f"Unknown checkpoint type: {raw_type}（可选：{', '.join(CHECKPOINT_TYPES)}）",
                400,
            )

        cp_id = body.get("checkpoint_id", f"cp-{int(time.time() * 1000)}")
        if not isinstance(cp_id, str) or not cp_id.strip():
            return self._error_json("INVALID_ARGS", "checkpoint_id 必须是非空字符串", 400)

        task_state_path = body.get("task_state_path")
        if task_state_path is not None and not isinstance(task_state_path, str):
            return self._error_json("INVALID_ARGS", "task_state_path 必须是字符串", 400)
        if task_state_path is not None and cp_type != "TASK":
            return self._error_json("INVALID_ARGS", "task_state_path 仅适用于 TASK checkpoint", 400)

        try:
            if cp_type == "AUTH":
                rec = await self.exporter.create_auth_checkpoint(cp_id)
            elif cp_type == "BROWSER":
                rec = await self.exporter.create_browser_checkpoint(cp_id)
            elif cp_type == "DESKTOP":
                rec = await self.exporter.create_desktop_checkpoint(cp_id)
            elif cp_type == "FINAL":
                rec = await self.exporter.create_final_checkpoint(cp_id)
            else:
                # 未显式给路径时用配置里的 persistence.task_state_path（CLI 无路径参数也能用）
                path = task_state_path.strip() if task_state_path else self.configured_task_state_path
                rec = await self.exporter.create_task_checkpoint(cp_id, path)
        except TaskStateError as exc:
            return self._error_json(exc.code, str(exc), exc.status)
        except CheckpointConflictError as exc:
            return self._error_json("CHECKPOINT_IN_PROGRESS", str(exc), 409)
        except SecretExportError as exc:
            # 敏感状态无法加密就不回传，也不降级成明文
            return self._error_json("STATE_ENCRYPTION_UNAVAILABLE", str(exc), 503)
        except ValueError as exc:
            return self._error_json("INVALID_ARGS", str(exc), 400)

        return web.json_response({"status": "ok", "checkpoint": self._public_checkpoint(rec)})

    async def handle_state_ack(self, req: web.Request) -> web.Response:
        """接收 Host 确认落盘保存成功的 ACK 消息"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_WRITER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            body = {}

        obj_id = body.get("object_id")
        if not obj_id:
            return web.json_response({"error": "Missing object_id"}, status=400)
        status = body.get("status", "PERSISTED")
        try:
            record = self.transfer.acknowledge_object(obj_id, status)
        except Exception:
            return web.json_response({"error": "Unknown object or invalid state"}, status=404)
        return web.json_response({
            "status": "acknowledged", "object_id": obj_id, "state": status,
            "replay": bool(record.get("acked_replay")),
        })

    async def handle_task_finish(self, req: web.Request) -> web.Response:
        """请求结束任务并触发终态保存"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        self.state_machine.begin_finishing()
        final_cp = await self.exporter.create_final_checkpoint(f"finish-{int(time.time())}")
        self.state_machine.finish()
        return web.json_response({
            "status": "ok",
            "message": "Task finishing completed",
            "final_checkpoint": self._public_checkpoint(final_cp),
        })
