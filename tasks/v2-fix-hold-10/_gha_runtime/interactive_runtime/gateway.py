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
import json
import os
import time
from typing import Any, Dict, Optional

from aiohttp import ClientSession, WSMsgType, web

from .auth import AuthManager, Scope
from .browser import BrowserManager
from .browser_stream import BrowserStreamRelay
from .desktop import DesktopManager
from .desktop_stream import DesktopStreamManager
from .session import SessionContext
from .state_export import StateExporter
from .state_import import StateImporter
from .state_machine import ControlRole, SessionState, StateMachine
from .transfer import ChunkedTransferEngine, TransferError


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

        self.app = web.Application()
        self._setup_routes()

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
        self.app.router.add_post("/v1/state/import", self.handle_import_object)
        self.app.router.add_post("/v1/state/checkpoint", self.handle_create_checkpoint)
        self.app.router.add_post("/v1/state/ack", self.handle_state_ack)

        # 任务终态控制
        self.app.router.add_post("/v1/task/finish", self.handle_task_finish)

        # 静态文件服务（Handoff UI）
        if os.path.isdir(self.web_static_dir):
            self.app.router.add_static("/web/", path=self.web_static_dir, name="web")
            novnc_dir = os.environ.get("GHA_NOVNC_DIR", "")
            if novnc_dir and os.path.isdir(novnc_dir):
                self.app.router.add_static("/web/novnc/", path=novnc_dir, name="novnc")
            self.app.router.add_get("/", self.handle_index_html)

    def _extract_auth_token(self, req: web.Request) -> str:
        """只从 Authorization Header 或 HttpOnly Cookie 取 Token，禁止 URL Query 携带。"""
        auth_hdr = req.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        return req.cookies.get("gha_session", "")

    @staticmethod
    def _origin_allowed(req: web.Request) -> bool:
        origin = req.headers.get("Origin", "")
        if not origin:
            return True  # 非浏览器 Agent 客户端没有 Origin；浏览器页面由浏览器强制带 Origin
        return origin in (f"https://{req.host}", f"http://{req.host}")

    async def handle_health(self, req: web.Request) -> web.Response:
        """非敏感健康检查"""
        return web.json_response({
            "status": "ok",
            "time": time.time(),
            "version": "2.0.0",
        })

    async def handle_index_html(self, req: web.Request) -> web.Response:
        filename = "desktop.html" if req.query.get("mode") == "desktop" else "index.html"
        index_file = os.path.join(self.web_static_dir, filename)
        if os.path.isfile(index_file):
            return web.FileResponse(index_file)
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

        cmd = body.get("cmd", "")
        if cmd == "snapshot":
            snap = self.desktop.snapshot()
            return web.json_response({"status": "ok", "snapshot": snap})
        elif cmd == "click":
            x, y = int(body.get("x", 0)), int(body.get("y", 0))
            btn = int(body.get("button", 1))
            res = self.desktop.click(x, y, btn)
            return web.json_response({"status": "ok" if res else "failed"})
        elif cmd == "type":
            text = str(body.get("text", ""))
            res = self.desktop.type_text(text)
            return web.json_response({"status": "ok" if res else "failed"})
        elif cmd == "key":
            k = str(body.get("key", ""))
            res = self.desktop.key_press(k)
            return web.json_response({"status": "ok" if res else "failed"})
        elif cmd == "focus":
            target = str(body.get("target", ""))
            res = self.desktop.focus_window(target)
            return web.json_response({"status": "ok" if res else "failed"})
        elif cmd == "screenshot":
            png_bytes = self.desktop.screenshot()
            return web.Response(body=png_bytes, content_type="image/png")

        return web.json_response({"error": f"Unknown command: {cmd}"}, status=400)

    async def handle_browser_command(self, req: web.Request) -> web.Response:
        """处理 Agent 发来的浏览器控制命令"""
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
        timeout_s = int(body.get("timeout_seconds", 300))
        ticket = self.auth.create_handoff_ticket(mode=mode, ttl_seconds=timeout_s)

        ok, msg = self.state_machine.request_handoff(mode=mode, timeout_seconds=timeout_s, ticket=ticket)
        if not ok:
            return web.json_response({"error": msg}, status=400)

        if mode == "desktop" and not self.desktop_stream.start_streaming():
            self.state_machine.cancel_handoff()
            return web.json_response({"error": "Desktop streaming dependencies unavailable"}, status=503)

        # Ticket 放在 fragment（#）而不是 Query：fragment 不会随 HTTP 请求发到服务器。
        handoff_url = f"/web/index.html?mode={mode}#ticket={ticket}"
        return web.json_response({
            "status": "ok",
            "mode": mode,
            "ticket": ticket,
            "handoff_url": handoff_url,
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
            "generation": self.state_machine.generation,
        })
        resp.set_cookie("gha_session", session_cookie, httponly=True,
                        secure=(req.scheme == "https"), samesite="Lax")
        return resp

    async def handle_handoff_complete(self, req: web.Request) -> web.Response:
        """人工完成接管，返还控制权给 Agent"""
        token = self._extract_auth_token(req)
        if not (self.auth.verify_token(token, Scope.HUMAN_BROWSER) or
                self.auth.verify_token(token, Scope.HUMAN_DESKTOP) or
                self.auth.verify_token(token, Scope.AGENT)):
            return web.json_response({"error": "Unauthorized"}, status=401)

        ok, msg = self.state_machine.complete_handoff()
        if not ok:
            return web.json_response({"error": msg}, status=400)

        # 若是桌面接管，停止 x11vnc 回收资源
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
        if not self.auth.verify_token(token, Scope.HUMAN_BROWSER):
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
        if not self.auth.verify_token(token, Scope.HUMAN_DESKTOP):
            return web.Response(status=401)
        if not self.desktop_stream.is_active:
            return web.Response(status=409)

        ws = web.WebSocketResponse()
        await ws.prepare(req)
        try:
            async with ClientSession() as session:
                upstream = await session.ws_connect(
                    f"ws://127.0.0.1:{self.desktop_stream.ws_port}")

                async def client_to_upstream():
                    async for msg in ws:
                        if msg.type == WSMsgType.TEXT:
                            await upstream.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await upstream.send_bytes(msg.data)
                        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                            break

                async def upstream_to_client():
                    async for msg in upstream:
                        if msg.type == WSMsgType.TEXT:
                            await ws.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws.send_bytes(msg.data)
                        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                            break

                await asyncio.gather(client_to_upstream(), upstream_to_client())
        except Exception:
            if not ws.closed:
                await ws.close()
        return ws

    # ---- 状态传输路由 (State Transfer)
    async def handle_state_manifest(self, req: web.Request) -> web.Response:
        """获取当前所有状态对象清单"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_READER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        manifest = self.exporter.get_manifest()
        return web.json_response(manifest)

    async def handle_download_object(self, req: web.Request) -> web.StreamResponse:
        """分块下载指定状态对象（支持 Range: bytes=start-end）"""
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

        data, actual_offset, _ = self.transfer.read_chunk(obj_id, offset, length or None)
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(data)),
            "Content-Range": f"bytes {actual_offset}-{actual_offset + len(data) - 1}/{total_size}",
            "X-SHA256": meta["sha256"],
        }
        return web.Response(body=data, headers=headers, status=206 if range_header else 200)

    async def handle_import_object(self, req: web.Request) -> web.Response:
        """从 Agent Host 上传状态对象并写入"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.STATE_WRITER):
            return web.json_response({"error": "Unauthorized"}, status=401)

        obj_id = req.headers.get("X-Object-ID", "")
        try:
            total_size = int(req.headers.get("X-Total-Size", 0))
            offset = int(req.headers.get("X-Offset", 0))
        except ValueError:
            return web.json_response({"error": "Invalid numeric header"}, status=400)
        sha256 = req.headers.get("X-SHA256", "")
        category = req.headers.get("X-Category", "unknown")

        if not obj_id or not sha256 or total_size <= 0 or offset < 0 or offset > total_size:
            return web.json_response({"error": "Missing metadata headers"}, status=400)
        if offset == 0:
            self.transfer.init_incoming_object(obj_id, total_size, sha256, category)

        chunk_data = await req.read()
        try:
            received = self.transfer.write_chunk(obj_id, offset, chunk_data)
        except TransferError as exc:
            return web.json_response({"error": str(exc)}, status=400)
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
                restored, message = await self.importer.restore_auth_state(final_path)
            elif category == "browser_profile":
                restored, message = await self.importer.restore_profile_archive(final_path, compatibility)
            else:
                restored, message = True, "stored"
            if not restored:
                return web.json_response({"error": message, "verified": False}, status=500)

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

    async def handle_create_checkpoint(self, req: web.Request) -> web.Response:
        """触发生成检查点"""
        token = self._extract_auth_token(req)
        if not self.auth.verify_token(token, Scope.AGENT):
            return web.json_response({"error": "Unauthorized"}, status=401)

        try:
            body = await req.json()
        except Exception:
            body = {}

        cp_type = body.get("type", "AUTH").upper()
        cp_id = body.get("checkpoint_id", f"cp-{int(time.time())}")

        if cp_type == "AUTH":
            rec = await self.exporter.create_auth_checkpoint(cp_id)
        elif cp_type == "BROWSER":
            rec = await self.exporter.create_browser_checkpoint(cp_id)
        elif cp_type == "DESKTOP":
            rec = await self.exporter.create_desktop_checkpoint(cp_id)
        elif cp_type == "FINAL":
            rec = await self.exporter.create_final_checkpoint(cp_id)
        else:
            return web.json_response({"error": f"Unknown checkpoint type: {cp_type}"}, status=400)

        return web.json_response({"status": "ok", "checkpoint": rec})

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
            self.transfer.acknowledge_object(obj_id, status)
        except Exception:
            return web.json_response({"error": "Unknown object or invalid state"}, status=404)
        return web.json_response({"status": "acknowledged", "object_id": obj_id, "state": status})

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
            "final_checkpoint": final_cp,
        })
