"""任务内网渠道：任务进程常驻的会话端点，Host 经 Control Gateway 的 `/x` 反代访问。

缺口背景：r9 任务原来只读 `transfers/incoming-index.json`、发 `/v1/state/checkpoint`、
等会话终态；它不监听内网端口、不发布 `v1/channel`、不写 `resume-e2e-uploaded/resumed/
stopped/ack` 消息。驱动因此在 `chan.channel_port()` 超时，也无法在任务退出前确认
「Runner 已看到续传回执」与「重复 ACK 幂等」。

渠道只做「暴露真实引擎状态 + 在两端口之间传消息」，不自建第二套传输协议：

- 上传分块 `PUT /<port>/part?offset=` 直接调用 `ChunkedTransferEngine`（init/resume/
  write_chunk/finalize；偏移必须等于 Runner 磁盘上真实已接收字节数，否则 409）；
- 幂等重放（空尾块）调用 `incoming_verified`，与 Gateway 的 `/v1/state/import` 同语义；
- 断点偏移只取 `engine.incoming_status()` 的真实值，渠道不记自己的进度。

协议（监听 127.0.0.1 随机端口；鉴权 `Authorization: Bearer <Host Token>`，口令来自
secret 环境变量 `GHA_RESUME_HOST_TOKEN`，只保存摘要，不进清单/日志）：

- `GET e2e-channel.json`            渠道清单 `{"port": N, "protocol": ...}`
- `GET <N>/activate?secret=&action=seed|upload&size=&sha256=&category=&limit=&upload_id=`
- `GET <N>/meta?key=&value=`        Host 写消息（value 省略即删除）；返回 `reply`
- `GET <N>/part?offset=`            Runner 真实已接收字节
- `PUT <N>/part?offset=`            分块（同上）
- `GET <N>/note?key=`               Runner 发布的消息
- `GET <N>/state`                   渠道与引擎摘要（不含口令）
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, Optional

from aiohttp import web

HOST_TOKEN_ENV = "GHA_RESUME_HOST_TOKEN"
MANIFEST_PATH = "e2e-channel.json"
PROTOCOL = "resume-e2e/1"
MAX_META_BYTES = 64 * 1024

NOTE_UPLOADED = "resume-e2e-uploaded"
NOTE_RESUMED = "resume-e2e-resumed"
NOTE_STOPPED = "resume-e2e-stopped"
NOTE_CURRENT = "resume-e2e-current"
NOTE_ACK = "resume-e2e-ack"
HOST_RESET = "resume-e2e-reseat"
HOST_STOP = "resume-e2e-stop"


class ChannelState:
    """Host 消息、Runner 消息与激活参数的共享状态（线程安全）。"""

    def __init__(self, run_id: str = ""):
        self.run_id = run_id
        self.lock = threading.RLock()
        self._meta: Dict[str, Any] = {}
        self._notes: Dict[str, Any] = {}
        self.activation: Optional[Dict[str, Any]] = None
        self.activations = 0
        self.stopped: Optional[Dict[str, Any]] = None
        self.host_requests = 0
        self.part_bytes = 0

    def put(self, key: str, value: Any) -> None:
        with self.lock:
            if value is None:
                self._meta.pop(key, None)
            else:
                self._meta[key] = value
            # 与 Runner 消息同一条规则：读回本 key 的最新已存值
            self._notes[key] = self._meta.get(key)

    def get(self, key: str) -> Any:
        with self.lock:
            return self._meta.get(key)

    def note(self, key: str, value: Any) -> None:
        with self.lock:
            self._notes[key] = value

    def reply(self, key: str) -> Any:
        with self.lock:
            return self._notes.get(key)

    def host_seen(self) -> bool:
        with self.lock:
            return self.host_requests > 0

    def mark_stopped(self, reason: str) -> Dict[str, Any]:
        with self.lock:
            if self.stopped is None:
                self.stopped = {"at": time.time(), "reason": reason}
                self._notes[NOTE_STOPPED] = dict(self.stopped)
            return dict(self.stopped)

    def wait_for(self, predicate, timeout: float, poll: float = 0.25) -> bool:
        """线程版等待：任务在自己的线程里推进时用；超时返回 False。"""
        deadline = time.time() + timeout
        while True:
            if predicate():
                return True
            left = deadline - time.time()
            if left <= 0:
                return False
            time.sleep(min(poll, left))

    def snapshot(self, engine=None) -> Dict[str, Any]:
        with self.lock:
            out = {
                "run_id": self.run_id,
                "host_requests": self.host_requests,
                "part_bytes": self.part_bytes,
                "activation": dict(self.activation) if self.activation else None,
                "activations": self.activations,
                "stopped": dict(self.stopped) if self.stopped else None,
                "meta_keys": sorted(self._meta),
                "note_keys": sorted(self._notes),
            }
            act = dict(self.activation) if self.activation else None
        if engine is not None and act and act.get("upload_id"):
            status, _ = engine.incoming_status(act["upload_id"], act["size"],
                                               act["sha256"], act["category"])
            out["upload"] = status
        return out


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_from_env(environ: Optional[Dict[str, str]] = None) -> str:
    return (environ or os.environ).get(HOST_TOKEN_ENV, "")


def random_host_token() -> str:
    """本地演示/测试用：真实 run 的口令由 Host 写进 secret。"""
    return "hst_" + secrets.token_hex(16)


class TaskChannel:
    """在 `bind:port`（默认 127.0.0.1 随机端口）上服务；`publish()` 写清单，`wait()` 推进阶段。"""

    def __init__(self, transfer_engine, host_token: str, run_id: str = "",
                 bind: str = "127.0.0.1", port: int = 0):
        if not host_token:
            raise RuntimeError("任务内网渠道缺少 Host Token（环境变量 %s）" % HOST_TOKEN_ENV)
        self.engine = transfer_engine
        self.state = ChannelState(run_id=run_id)
        self._bind = bind
        self._port = int(port or 0)
        self._digest = _token_digest(host_token)
        # 口令本身从不保存：只留长度供核对 Host 是否注入了同一口令
        self.token_bytes = len(host_token.encode("utf-8"))
        self.manifest: Dict[str, Any] = {}
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.app = self._build_app()

    # ------------------------------------------------------------ 鉴权

    def _authorized(self, req: web.Request) -> bool:
        header = req.headers.get("Authorization", "")
        presented = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not presented:
            presented = req.query.get("secret", "")
        return bool(presented) and hmac.compare_digest(_token_digest(presented), self._digest)

    def _guard(self, req: web.Request) -> Optional[web.Response]:
        if not self._authorized(req):
            return web.json_response({"error": "Unauthorized"}, status=401)
        if int(req.match_info["port"]) != self._port:
            return web.json_response({"error": "unknown channel port"}, status=404)
        with self.state.lock:
            self.state.host_requests += 1
        return None

    def _build_app(self) -> web.Application:
        app = web.Application(client_max_size=16 * 1024 * 1024)
        app.router.add_get("/" + MANIFEST_PATH, self.handle_manifest)
        app.router.add_get("/{port:\\d+}/activate", self.handle_activate)
        app.router.add_get("/{port:\\d+}/meta", self.handle_meta)
        app.router.add_get("/{port:\\d+}/note", self.handle_note)
        app.router.add_get("/{port:\\d+}/part", self.handle_part_get)
        app.router.add_put("/{port:\\d+}/part", self.handle_part_put)
        app.router.add_get("/{port:\\d+}/state", self.handle_state)
        return app

    @property
    def port(self) -> int:
        return self._port

    # ------------------------------------------------------------ handlers

    async def handle_manifest(self, req: web.Request) -> web.Response:
        # 清单只透露端口与协议版本：口令在 Host 手里，见不到清单也无所谓
        secret = req.query.get("secret", "")
        if secret and not self._authorized(req):
            return web.json_response({"error": "Unauthorized"}, status=401)
        if not self.manifest.get("port"):
            return web.json_response({"error": "channel not ready"}, status=503)
        return web.json_response(dict(self.manifest))

    async def handle_activate(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        q = req.query
        try:
            size = int(q.get("size", "0"))
            limit = int(q.get("limit", "1"))
        except ValueError:
            return web.json_response({"error": "size/limit 必须是整数"}, status=400)
        with self.state.lock:
            activation = {
                "action": q.get("action", ""),
                "size": size,
                "sha256": q.get("sha256", ""),
                "category": q.get("category", ""),
                "limit": limit,
                "upload_id": q.get("upload_id", ""),
                "seq": self.state.activations,
            }
            self.state.activation = activation
            self.state.activations += 1
        return web.json_response(dict(activation, accepted=True))

    async def handle_meta(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        key = req.query.get("key", "")
        if not key:
            return web.json_response({"error": "缺少 key"}, status=400)
        if "value" in req.query:
            raw = req.query["value"]
            if len(raw) > MAX_META_BYTES:
                return web.json_response({"error": "value 过大"}, status=413)
            try:
                value = json.loads(raw)
            except ValueError:
                value = raw
            self.state.put(key, value)
        return web.json_response({"key": key, "reply": self.state.reply(key)})

    async def handle_note(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        key = req.query.get("key", "")
        return web.json_response({"key": key, "reply": self.state.reply(key)})

    async def handle_state(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        return web.json_response(self.state.snapshot(self.engine))

    async def handle_part_get(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        act = self.state.activation
        if not act or not act.get("upload_id"):
            return web.json_response({"error": "未激活上传", "code": "NOT_ACTIVATED"}, status=409)
        received = self._received(act)
        return web.json_response({"received": received or 0, "size": act["size"]})

    async def handle_part_put(self, req: web.Request) -> web.Response:
        denied = self._guard(req)
        if denied is not None:
            return denied
        act = self.state.activation
        if not act or act.get("action") != "upload" or not act.get("upload_id"):
            return web.json_response({"error": "未激活可续传上传", "code": "NOT_UPLOAD"}, status=409)
        try:
            offset = int(req.query.get("offset", "-1"))
        except ValueError:
            return web.json_response({"error": "offset 必须是整数"}, status=400)
        data = await req.read()
        obj_id, size = act["upload_id"], act["size"]
        sha, category = act["sha256"], act["category"]
        if offset == 0:
            # 本次上传从 0 开始：即使残留旧进度也以本次为准（与 Gateway 一致）
            self.engine.init_incoming_object(obj_id, size, sha, category)
        elif self._received(act) is None:
            return web.json_response({"error": "没有可续传的对象，请从偏移 0 重新上传",
                                      "code": "NO_RESUMABLE_UPLOAD", "received": 0}, status=409)
        else:
            self.engine.resume_incoming_object(obj_id, size, sha, category)
        if not data:
            # 空尾块：最后一块的响应在返回路上丢了。只在真实校验通过后幂等回答 verified
            return web.json_response({"verified": self.engine.incoming_verified(obj_id),
                                      "received": self._received(act)}, status=200)
        try:
            got = self.engine.write_chunk(obj_id, offset, data)
        except Exception as exc:  # TransferError：偏移与真实字节数不一致等
            return web.json_response({"error": str(exc), "code": getattr(exc, "code", "TRANSFER_ERROR"),
                                      "received": self._received(act) or 0},
                                     status=getattr(exc, "status", 400))
        with self.state.lock:
            self.state.part_bytes += len(data)
        # 进度直接取自引擎返回的真实落盘长度（write_chunk 的返回值），不推算
        self.state.note(NOTE_CURRENT, {"received": got, "at": time.time()})
        finished = got == size
        if finished:
            final = self.engine.finalize_incoming_object(obj_id)
            self.engine.mark_incoming_verified(obj_id, "e2e-channel")
            self.state.note(NOTE_UPLOADED, {
                "at": time.time(), "bytes": got,
                "sha256": self.engine.calculate_sha256(final), "channel": True,
            })
        return web.json_response({"status": "completed" if finished else "chunk_received",
                                  "received": got, "verified": finished})

    # ------------------------------------------------------------ 引擎状态

    def _received(self, act: Dict[str, Any]) -> Optional[int]:
        """Runner 真实已接收字节；对象不存在或特征不符返回 None（绝不推算）。"""
        status, mismatch = self.engine.incoming_status(act["upload_id"], act["size"],
                                                       act["sha256"], act["category"])
        if mismatch is not None or status.get("status") not in ("in_progress", "complete"):
            return None
        return int(status.get("received") or 0)

    # ------------------------------------------------------------ 生命周期

    async def start(self) -> Dict[str, Any]:
        self._runner = web.AppRunner(self.app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self._bind, self._port)
        await self._site.start()
        server = getattr(self._site, "_server", None)
        sockets = getattr(server, "sockets", None) or []
        if sockets:
            self._port = sockets[0].getsockname()[1]
        if not self._port and getattr(self._site, "_port", None):
            self._port = int(self._site._port)
        if not self._port:
            raise RuntimeError("内网渠道未能取得监听端口")
        self.manifest = {
            "port": self._port,
            "protocol": PROTOCOL,
            "manifest": MANIFEST_PATH,
            "token_bytes": self.token_bytes,
        }
        return dict(self.manifest)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    async def _wait_for(self, predicate, timeout: float, poll: float = 0.25) -> bool:
        """等 predicate 成立（靠 notify_all 唤醒），用于渠道自己的事件循环内。"""
        deadline = time.time() + timeout
        while True:
            if predicate():
                return True
            left = deadline - time.time()
            if left <= 0:
                return False
            await asyncio.sleep(min(poll, left))

    async def wait_async(self, upload_timeout: float = 900.0,
                         stop_timeout: float = 7200.0) -> Dict[str, Any]:
        """阻塞推进：Host 接入 → 上传收满 → Host 请求复位 → 放行停止。

        只在真实状态上推进，每一步都有超时；返回值是停止记录（含 reason）。
        必须跑在渠道自己的事件循环上（任务在 EventLoopThread 里等它）。
        """
        st = self.state
        if not await self._wait_for(st.host_seen, upload_timeout):
            return st.mark_stopped("host_not_seen")
        if not await self._wait_for(lambda: NOTE_UPLOADED in st._notes, stop_timeout):
            return st.mark_stopped("upload_timeout")
        act = st.activation or {}
        if await self._wait_for(lambda: isinstance(st.get(HOST_RESET), dict), stop_timeout):
            reseat = st.get(HOST_RESET) or {}
            # 复位是 Host 的意图；resumed 里只放引擎此刻的真实值
            st.note(NOTE_RESUMED, {
                "at": time.time(),
                "reseat": reseat.get("at"),
                "received": self._received(act) if act.get("upload_id") else None,
                "channel_activations": st.activations,
            })
        if await self._wait_for(lambda: st.stopped is not None
                                or (isinstance(st.get(HOST_STOP), dict) and st.host_seen()),
                                stop_timeout):
            return st.mark_stopped("host-request")
        return st.mark_stopped("stop_timeout")
