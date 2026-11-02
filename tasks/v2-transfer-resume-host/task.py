#!/usr/bin/env python3
"""双向续传 E2E 的 Runner 侧任务（由 workflow 以 interactive_runtime.main 包装启动）。

顺序（全部在同一个真实 ubuntu-latest Runner 进程内）：

1. 等 Host 打开 seed 窗（`import_gate` 带对象 ID/总长/SHA-256 —— 只有宿主给的身份）；
2. 上传：Host 分块写到 `upload-resume-e2e`，中途真实断线一次再按 received 续传到底；
3. 索引复位：宿主发 `resume-e2e-reseat` 后，任务只做一次 `incoming-index.json` 移走
   （前先核对索引与磁盘 `.part` 长度一致），并记录引擎随后真实回答；之后永不再复位；
4. Runner 修改：把收到的对象改成 512 MiB（前缀 + 原文 + 填充 + 后缀）并生成 TASK checkpoint；
5. 回传给 Host：Host 按 Range 分块下载，第 1 块中途断线，按已落盘偏移续传，整包摘要一致后 ACK；
6. Host 的 `resume-e2e-ack` 到达后写 output/host.json 并退出 0。

带外消息走任务自己在本地起的极小 HTTP 渠道（127.0.0.1 固定端口），宿主经 Gateway 的
`/e2e-tunnel`（仅测试包补丁提供）反代访问；密钥由宿主在激活消息里下发，只校验不回显。

任何一步超时或摘要不符都写 phase.json（含 traceback）并非零退出，绝不假装成功。
"""
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TASK_DIR = os.environ.get("GHA_TASK_DIR", os.getcwd())
# 任务目录在前：运行时副本里有同名 task.py（selftest），会被当成「本任务」重跑 main()
sys.path.insert(0, TASK_DIR)
sys.path.insert(0, os.path.join(TASK_DIR, "_gha_runtime"))

from gha_runner.interactive_client import InteractiveClient  # noqa: E402

UPLOAD_ID = "upload-resume-e2e-b126b1c6"
CHECKPOINT_ID = "resume-e2e-task-b126b1c6"
WAIT_SECONDS = 1500
POLL_SECONDS = 2
PROGRESS_SAMPLE_SECONDS = 10
MODIFIED_SIZE = 512 * 1024 * 1024
BAND = b"RUNNER-E2E-BAND-0123456789abcdef"
BAND_LEN = 64
CHANNEL_PORT = int(os.environ.get("RESUME_E2E_CHANNEL_PORT") or 18600)
CHANNEL_TAG = os.environ.get("RESUME_E2E_CHANNEL_TAG") or ""

RESULT = {"completed": False}
OUT = os.path.join(os.environ.get("GHA_OUTPUT_DIR", "./output"))
NOTES = {}
CHANNEL_SECRET = ""
CHANNEL_BASE = ""
PENDING_STOP = {}
LAST_NOTE_ERROR = []
RESEAT_DONE = {"done": False}
UPLOAD_OK = {"done": False}


def log(msg):
    print("[resume-host] %s" % msg, flush=True)


def runtime_storage() -> str:
    cfg = os.environ.get("GHA_INTERACTIVE_CONFIG_FILE", "")
    if cfg:
        return os.path.dirname(os.path.abspath(cfg))
    return os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "gha-interactive-private")


def index_path() -> str:
    return os.path.join(runtime_storage(), "transfers", "incoming-index.json")


def upload_entry() -> dict:
    try:
        with open(index_path(), "r", encoding="utf-8") as f:
            return (json.load(f) or {}).get(UPLOAD_ID) or {}
    except (OSError, ValueError):
        return {}


def dump(name, data):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def req_query(path):
    from urllib.parse import parse_qs, urlsplit
    return {k: v[-1] for k, v in parse_qs(urlsplit(path).query).items()}


def raw_path(path):
    return path.split("?", 1)[0].split("#", 1)[0].strip()


class ChannelHandler(BaseHTTPRequestHandler):
    server_version = "gha-resume-e2e/1"

    def _authorized(self):
        return bool(CHANNEL_SECRET) and self.headers.get("X-E2E-Secret") == CHANNEL_SECRET

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            self._route_get()
        except Exception as exc:
            try:
                self._send(500, {"error": type(exc).__name__})
            except Exception:
                pass

    def do_POST(self):
        self._send(405, {"error": "read-only channel"})

    def do_PUT(self):
        self._send(405, {"error": "read-only channel"})

    def _do_activate(self):
        global CHANNEL_SECRET
        q = req_query(self.path)
        try:
            size = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(size) or b"{}")
        except ValueError:
            body = {}
        body = dict(q, **body) if q else body
        CHANNEL_SECRET = str(body.get("secret") or secrets.token_hex(16))
        action = str(body.get("action") or "")
        if action == "seed" and body.get("size"):
            NOTES["import_gate"] = {"action": "import_gate", "phase": "seed", "size": body["size"],
                                    "sha256": body.get("sha256"), "category": body.get("category"),
                                    "limit": body.get("limit") or 1}
        self._send(200, {"status": "ok", "channel": CHANNEL_BASE, "reply": NOTES.get("import_gate")})

    def _route_get(self):
        route = raw_path(self.path)
        if route not in ("/v1/meta", "/v1/channel", "/v1/activate"):
            self._send(404, {"error": "not found"})
            return
        if route == "/v1/activate":
            self._do_activate()
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        if route == "/v1/channel":
            # 渠道清单：宿主据此发现内网端口（不依赖已冻结的 Gateway 路由）
            self._send(200, {"status": "ok", "port": int(CHANNEL_BASE.rsplit(":", 1)[-1]),
                             "pid": os.getpid()})
            return
        q = req_query(self.path)
        key = str(q.get("key") or "")
        if key and "value" in q:
            raw = q["value"]
            try:
                NOTES[key] = json.loads(raw)
            except ValueError:
                NOTES[key] = raw
        if key:
            self._send(200, {"status": "ok", "key": key, "reply": NOTES.get(key)})
            return
        self._send(200, {"status": "ok", "notes": dict(NOTES)})


class ChannelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def handle_error(self, request, client_address):
        pass

    def log_message(self, *args):
        pass


def channel_manifest_path():
    """隔离清单：同一 Runner 池上可能有别的 agent 的任务在跑，文件名带本驱动的 run tag。"""
    return os.path.join(runtime_storage(), "e2e-channel%s.json" % CHANNEL_TAG)


def _write_channel_manifest(port):
    try:
        os.makedirs(runtime_storage(), exist_ok=True)
        with open(channel_manifest_path(), "w", encoding="utf-8") as f:
            json.dump({"port": port, "pid": os.getpid(), "tag": CHANNEL_TAG}, f)
    except OSError:
        pass


def start_channel(port=CHANNEL_PORT):
    """起内网渠道；端口写进私有目录的清单（宿主发现它不能依赖已冻结的 Gateway 路由）。"""
    global CHANNEL_BASE
    try:
        server = ChannelServer(("127.0.0.1", port), ChannelHandler)
    except OSError:
        server = ChannelServer(("127.0.0.1", 0), ChannelHandler)
    CHANNEL_BASE = "http://127.0.0.1:%d" % server.server_address[1]
    _write_channel_manifest(server.server_address[1])
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


class ChannelClient:
    def __init__(self, base=None):
        self.base = base or CHANNEL_BASE

    def _call(self, path, body, headers):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(),
                                     headers=dict(headers, **{"X-E2E-Secret": CHANNEL_SECRET,
                                                              "Connection": "close"}), method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def put(self, key, value):
        return self._call("/v1/meta", {"key": key, "value": value}, {"Content-Type": "application/json"})


def note(key, value):
    try:
        return ChannelClient().put(key, value) or {}
    except Exception as exc:
        msg = "%s: %s" % (type(exc).__name__, str(exc)[:160])
        if msg not in LAST_NOTE_ERROR:
            LAST_NOTE_ERROR.append(msg)
            log("channel(%s) 失败：%s" % (key, msg))
    return {}


def agent_client():
    gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
    token = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
    deadline = time.time() + 300
    while time.time() < deadline:
        if not token:
            try:
                with open(os.path.join(runtime_storage(), ".agent_token"), "r", encoding="utf-8") as f:
                    token = f.read().strip()
            except OSError:
                token = ""
        if token:
            try:
                client = InteractiveClient(gateway, token, timeout=120)
                if client.health().get("status") == "ok":
                    return client
            except Exception:
                pass
        time.sleep(2)
    raise RuntimeError("Runner 私有 .agent_token 不可读或 Gateway 未就绪")


def reseat_once():
    path = index_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            index = (json.load(f) or {}).get(UPLOAD_ID) or {}
    except (OSError, ValueError):
        index = {}
    part = os.path.join(runtime_storage(), "transfers", UPLOAD_ID + ".part")
    disk = os.path.getsize(part) if os.path.exists(part) else 0
    info = {"index_status": bool(index), "index_received": index.get("received_bytes"),
            "disk_bytes": disk, "disk_equals_index": disk == index.get("received_bytes")}
    if os.path.exists(path):
        os.replace(path, path + ".reseat.bak")
    info["moved"] = not os.path.exists(path)
    return info


def build_modified(upload_path):
    target = os.path.join(TASK_DIR, "state", "modified.bin")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    prefix, suffix = b"RUNNER-MODIFIED:", b":RUNNER-END"
    fill_len = MODIFIED_SIZE - len(prefix) - os.path.getsize(upload_path) - len(suffix)
    if fill_len <= 0:
        raise RuntimeError("修改后的对象尺寸上限不足")
    digest = hashlib.sha256()
    band = 2 * BAND
    written = 0
    with open(target, "wb") as out:
        def emit(data):
            nonlocal written
            out.write(data)
            digest.update(data)
            written += len(data)

        emit(prefix)
        with open(upload_path, "rb") as src:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                emit(block)
        left = fill_len
        while left > 0:
            piece = band[:min(BAND_LEN, left)]
            emit(piece)
            left -= len(piece)
        emit(suffix)
    return {"bytes": written, "sha256": digest.hexdigest(), "prefix": prefix.decode(),
            "suffix": suffix.decode(), "fill_bytes": fill_len, "layout": "prefix + upload + filler + suffix",
            "filler": {"pattern": BAND.decode(), "repeats": BAND_LEN}}


def stop_requested():
    return bool(PENDING_STOP.get("at"))


def main():
    os.makedirs(OUT, exist_ok=True)
    try:
        log("本地会话渠道端口 %d" % start_channel())
        log("等待 Host 激活（写渠道清单 %s）" % channel_manifest_path())
        agent = agent_client()
        deadline = time.time() + WAIT_SECONDS
        while time.time() < deadline and not CHANNEL_SECRET:
            if stop_requested():
                log("收到 Runner 退出请求（本 run 结束）")
                RESULT["stopped"] = PENDING_STOP
                dump("phase.json", RESULT)
                return 0
            time.sleep(POLL_SECONDS)
        if not CHANNEL_SECRET:
            raise RuntimeError("等待 Host 激活超时")
        _write_channel_manifest(int(CHANNEL_BASE.rsplit(":", 1)[-1]))
        # 端口已随清单交给宿主：宿主按它访问本渠道
        note("resume-e2e-channel", {"base": CHANNEL_BASE, "pid": os.getpid()})
        log("Host 已激活 seed 窗，等待上传")
        gate = NOTES.get("import_gate") or {}
        headers = {"X-Object-ID": UPLOAD_ID, "X-Total-Size": str(gate.get("size")),
                   "X-SHA256": gate.get("sha256") or "", "X-Category": gate.get("category") or "probe_state"}
        samples = []
        last_sample = 0.0
        entry = {}
        while time.time() < deadline:
            now = time.time()
            if PENDING_STOP.get("at"):
                break
            if now - last_sample >= PROGRESS_SAMPLE_SECONDS:
                entry = upload_entry()
                samples.append({"t": round(now), "received": entry.get("received_bytes"),
                                "size": entry.get("size")})
                last_sample = now
                dump("upload-progress.json", samples)
                log("上传进度 %s / %s" % (entry.get("received_bytes"), entry.get("size")))
                note("resume-e2e-current", {"received": entry.get("received_bytes"),
                                            "size": entry.get("size")})
            wanted_reseat = NOTES.get("resume-e2e-reseat")
            if wanted_reseat and not RESEAT_DONE["done"]:
                RESEAT_DONE["done"] = True
                info = reseat_once()
                log("索引复位：%s" % info)
                note("resume-e2e-reseated", {"reseat": info, "received": upload_entry().get("received_bytes")})
            entry = upload_entry() or entry
            if entry.get("verified") and entry.get("received_bytes") == entry.get("size"):
                break
            time.sleep(POLL_SECONDS)
        if not gate.get("size"):
            raise RuntimeError("Host 从未下发上传身份（seed 窗）")
        src = os.path.join(runtime_storage(), "transfers", UPLOAD_ID)
        h = hashlib.sha256()
        with open(src, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        if h.hexdigest() != entry.get("sha256"):
            raise RuntimeError("Runner 落盘摘要与上传声明不一致")
        log("上传已校验：%d B sha256=%s" % (os.path.getsize(src), h.hexdigest()))
        RESULT["upload"] = {"bytes": os.path.getsize(src), "sha256": h.hexdigest(),
                            "progress_samples": samples,
                            "first_positive_sample": next((s for s in samples if s["received"]), None)}
        UPLOAD_OK["done"] = True
        note("resume-e2e-uploaded", {"sha256": h.hexdigest(), "bytes": os.path.getsize(src),
                                     "reseat": RESEAT_DONE["done"]})

        mod = build_modified(src)
        log("Runner 修改完成：%d B" % mod["bytes"])
        rec = agent.post("/v1/state/checkpoint", {"type": "TASK", "checkpoint_id": CHECKPOINT_ID,
                                                  "task_state_path": "state/modified.bin"})
        record = rec.get("checkpoint", {}) or {}
        obj = (record.get("objects") or [{}])[0]
        if not obj.get("id") or obj.get("plaintext_sha256") != mod["sha256"]:
            raise RuntimeError("TASK checkpoint 对象摘要与本地修改内容不一致")
        RESULT.update({"completed": True, "modified": mod,
                       "checkpoint": {k: obj.get(k) for k in ("id", "size", "sha256", "plaintext_sha256",
                                                              "encrypted", "key_id")}})
        dump("phase.json", RESULT)
        log("TASK checkpoint 已生成：%s（密文 %s B）" % (obj.get("id"), obj.get("size")))
    except Exception as exc:
        import traceback
        RESULT["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:400])
        RESULT["traceback"] = traceback.format_exc()[-3000:]
        RESULT["channel_errors"] = LAST_NOTE_ERROR
        log("失败：%s\n%s" % (RESULT["error"], RESULT["traceback"]))
        dump("phase.json", RESULT)
        return 1

    try:
        deadline = time.time() + WAIT_SECONDS
        while time.time() < deadline and not stop_requested():
            reply = note("resume-e2e-poll", {"upload": UPLOAD_OK["done"], "t": int(time.time())})
            ack = NOTES.get("resume-e2e-ack")
            if isinstance(ack, dict) and ack.get("action") == "resume_ok":
                RESULT["host"] = ack
                dump("host.json", RESULT)
                log("收到 Host resume_ok")
                return 0
            time.sleep(POLL_SECONDS)
        if stop_requested():
            log("收到 Runner 退出请求（本 run 结束）")
            return 0
        raise RuntimeError("等待 Host resume_ok 超时")
    except Exception as exc:
        RESULT["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:400])
        log("失败：%s" % RESULT["error"])
        dump("phase.json", RESULT)
        return 1


if __name__ == "__main__":
    sys.exit(main())
