"""RFB 3.8 客户端（WebSocket 传输），供脚本化桌面接管验收使用。

Transport framing (WebSocket message boundaries) has no relation to RFB protocol
units: one WS frame can carry many RFB messages and one RFB message can span many
WS frames.  So the client keeps a single byte FIFO and every read is
"wait until the FIFO holds N bytes, consume exactly N, keep the rest".

只实现 None 安全类型 + Raw 编码 + DesktopSize，够用来真实发键鼠事件并截帧；
像素假设为 BGRX 32bpp（ClientInit 后主动 SetPixelFormat）。
"""
from __future__ import annotations

import hashlib
import base64
import os
import socket
import ssl
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


class RFBError(RuntimeError):
    pass


def _ws_header(payload_len: int, opcode: int, mask: bool = True) -> bytes:
    b0 = 0x80 | opcode
    out = bytearray([b0])
    flag = 0x80 if mask else 0
    if payload_len < 126:
        out.append(flag | payload_len)
    elif payload_len < 65536:
        out.append(flag | 126)
        out += struct.pack("!H", payload_len)
    else:
        out.append(flag | 127)
        out += struct.pack("!Q", payload_len)
    return bytes(out)


class WebSocket:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 30.0):
        u = urlparse(url)
        secure = u.scheme == "wss"
        host = u.hostname
        port = u.port or (443 if secure else 80)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        sock = socket.create_connection((host, port), timeout=timeout)
        if secure:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        host_header = host if port == (443 if secure else 80) else f"{host}:{port}"
        req = [f"GET {path} HTTP/1.1", f"Host: {host_header}", "Upgrade: websocket",
               "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
               "Sec-WebSocket-Version: 13"]
        for k, v in (headers or {}).items():
            req.append(f"{k}: {v}")
        sock.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise RFBError("ws handshake: closed")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode(errors="replace")
        if " 101 " not in status + " ":
            raise RFBError(f"ws handshake failed: {status}")
        meta = {}
        for line in head.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip().lower()] = v.strip()
        expect = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if meta.get("sec-websocket-accept") != expect:
            raise RFBError("ws handshake: bad accept")
        self.sock = sock
        self.fifo = bytearray(rest)
        self.payload = bytearray()
        self.closed = False
        self.frames_received = 0
        self.bytes_received = len(rest)
        # 收与发必须解耦：接管期间客户端会连续写几秒键鼠，若这期间不读，
        # 服务端（x11vnc/websockify）的发送窗口会填满并把连接写断。
        self._error: Optional[RFBError] = None
        self._cond = threading.Condition(threading.RLock())
        self._send_lock = threading.Lock()
        # 写入必须离开读取线程：后台读取线程若卡在 sendall（对端不读），接收也会一起停。
        # 收端写满（Windows 上对端只写不读时很常见）时丢 pong，优先级低于收帧。
        self._pong_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, name="rfb-ws-reader", daemon=True)
        self._reader.start()

    def _consume(self, chunk: Optional[bytes]) -> bool:
        """收一段字节并解帧；返回 False 表示读取应停止。"""
        pongs: List[bytes] = []
        with self._cond:
            if chunk:
                self.fifo += chunk
                self.bytes_received += len(chunk)
            try:
                pongs = self._decode_frames()
            except RFBError as exc:
                self._error = self._error or exc
                self.closed = True
                self._cond.notify_all()
                return False
            self._cond.notify_all()
        for payload in pongs:
            if not self._pong(payload):
                return False
        return True

    def _pong(self, payload: bytes) -> bool:
        """回写 pong；拿不到发送权时丢弃（收继续跑，不能为回写而停）。"""
        if not self._pong_lock.acquire(blocking=False):
            return True
        try:
            self._send_frame(payload, 0xA)
        except OSError:
            return False
        finally:
            self._pong_lock.release()
        return True

    def _read_loop(self) -> None:
        """后台持续读取：把字节收进 fifo，解出 WS 帧写入 payload，永不因写入而停。"""
        try:
            self.sock.settimeout(None)
        except OSError:
            pass
        # 握手响应可能和首批帧同包到达：rest 里已有的字节必须先解出来，
        # 否则要等下一次 recv 才会被处理（对端不发新数据时表现为假超时）。
        if not self._consume(None):
            return
        while True:
            try:
                chunk = self.sock.recv(65536)
            except (OSError, ValueError) as exc:
                # close() 同时惊动阻塞中的 recv（Windows 上只 close 不唤醒）；截断长度
                # 与并发 close 相遇时还会抛 ValueError。两者都按连接关闭收尾。
                self._fail(RFBError(f"websocket read failed: {type(exc).__name__}"))
                return
            if not chunk:
                self._fail(RFBError("websocket closed"))
                return
            if not self._consume(chunk):
                return

    def _fail(self, exc: RFBError) -> None:
        with self._cond:
            self.closed = True
            self._error = self._error or exc
            self._cond.notify_all()

    def _decode_frames(self) -> List[bytes]:
        """按 WS 帧边界解包，返回需要回写的 pong payload。

        调用方必须持有 ``self._cond``；RFB 字节流写进 ``payload``，
        与 WS 帧边界无关（一帧可含多条 RFB 消息，一条 RFB 消息也可跨帧）。"""
        pongs: List[bytes] = []
        while True:
            raw = self.fifo
            if len(raw) < 2:
                return pongs
            b0, b1 = raw[0], raw[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            pos = 2
            if ln == 126:
                if len(raw) < 4:
                    return pongs
                ln = struct.unpack("!H", raw[2:4])[0]
                pos = 4
            elif ln == 127:
                if len(raw) < 10:
                    return pongs
                ln = struct.unpack("!Q", raw[2:10])[0]
                pos = 10
            mask = b""
            if masked:
                if len(raw) < pos + 4:
                    return pongs
                mask = bytes(raw[pos:pos + 4])
                pos += 4
            if len(raw) < pos + ln:
                return pongs
            payload = bytes(raw[pos:pos + ln])
            if masked:
                payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
            del raw[:pos + ln]
            if opcode == 0x8:
                raise RFBError("websocket close frame")
            if opcode == 0x9:
                pongs.append(payload)
                continue
            if opcode in (0x0, 0x1, 0x2):
                self.frames_received += 1
                self.payload += payload
            # 0xA pong: ignore

    def _send_frame(self, payload: bytes, opcode: int = 0x2) -> None:
        mask = os.urandom(4)
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        with self._send_lock:
            self.sock.sendall(_ws_header(len(payload), opcode) + mask + masked)

    def send(self, payload: bytes) -> None:
        self._send_frame(payload, 0x2)

    def read_exact(self, n: int, timeout: float = 60.0) -> bytes:
        """等后台读取线程攒够 n 字节再取走；已缓冲的字节优先，不会因错误丢掉。"""
        deadline = time.time() + timeout
        with self._cond:
            while len(self.payload) < n:
                if self._error is not None:
                    raise self._error
                if self.closed:
                    raise RFBError("websocket closed while waiting for bytes")
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise RFBError("timeout waiting for stream bytes")
                self._cond.wait(remaining)
            out = bytes(self.payload[:n])
            del self.payload[:n]
            return out

    def close(self) -> None:
        with self._cond:
            self.closed = True
            self._cond.notify_all()
        try:
            # Windows 上 close 不会唤醒阻塞在 recv 里的后台线程，必须先 shutdown，
            # 否则读取线程会滞留到对端自行关闭为止。
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
        except OSError:
            pass
        # 读取线程是 daemon，关停时不必等它收尾（对端半开会让 join 白等）。


class RFB:
    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.width = 0
        self.height = 0
        self.name = ""
        self.rects: List[Tuple[int, int, int, int, bytes]] = []

    # --- protocol
    def handshake(self) -> None:
        ver = self.ws.read_exact(12)
        if not ver.startswith(b"RFB 003.00"):
            raise RFBError(f"unexpected version {ver!r}")
        self.ws.send(b"RFB 003.008\n")
        n = self.ws.read_exact(1)[0]
        if n == 0:
            ln = struct.unpack("!I", self.ws.read_exact(4))[0]
            raise RFBError(self.ws.read_exact(ln).decode(errors="replace"))
        types = self.ws.read_exact(n)
        if 1 not in types:
            raise RFBError(f"no None security among {list(types)}")
        self.ws.send(bytes([1]))
        res = struct.unpack("!I", self.ws.read_exact(4))[0]
        if res != 0:
            raise RFBError(f"security result {res}")
        self.ws.send(b"\x01")
        self.width, self.height = struct.unpack("!HH", self.ws.read_exact(4))
        self.ws.read_exact(16)
        ln = struct.unpack("!I", self.ws.read_exact(4))[0]
        self.name = self.ws.read_exact(ln).decode(errors="replace")
        # SetPixelFormat BGRX 32bpp
        pf = struct.pack("!BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        self.ws.send(b"\x00\x00\x00\x00" + pf)
        self.set_encodings([0, -223])

    def set_encodings(self, encs: List[int]) -> None:
        body = b"\x02\x00" + struct.pack("!H", len(encs)) + b"".join(struct.pack("!i", e) for e in encs)
        self.ws.send(body)

    def update_request(self, incremental: bool) -> None:
        self.ws.send(b"\x03" + bytes([1 if incremental else 0]) +
                     struct.pack("!HHHH", 0, 0, self.width, self.height))

    def pump(self, timeout: float = 20.0) -> bool:
        """Read server messages until one FBUR with rects; returns True when received."""
        deadline = time.time() + timeout
        got = False
        while time.time() < deadline:
            t = self.ws.read_exact(1, timeout=max(1.0, deadline - time.time()))[0]
            if t == 0:
                self.ws.read_exact(1)
                nr = struct.unpack("!H", self.ws.read_exact(2))[0]
                rects = []
                for _ in range(nr):
                    x, y, w, h, enc = struct.unpack("!HHHHi", self.ws.read_exact(12))
                    if enc == 0:
                        rects.append((x, y, w, h, self.ws.read_exact(w * h * 4)))
                    elif enc == -223:
                        self.width, self.height = w, h
                    elif enc == -239:
                        self.ws.read_exact(w * h * 4)
                    else:
                        raise RFBError(f"unexpected encoding {enc}")
                self.rects = rects
                got = got or bool(rects)
            elif t == 1:
                ns = struct.unpack("!H", self.ws.read_exact(2))[0]
                self.ws.read_exact(ns * 4)
                nd = struct.unpack("!H", self.ws.read_exact(2))[0]
                self.ws.read_exact(nd * 4)
            elif t == 2:
                pass
            elif t == 3:
                self.ws.read_exact(3)
                ln = struct.unpack("!I", self.ws.read_exact(4))[0]
                self.ws.read_exact(ln)
            else:
                raise RFBError(f"unexpected message type {t}")
            if got:
                return True
        return got

    # --- input
    def key(self, keysym: int, down: bool) -> None:
        self.ws.send(b"\x04" + bytes([1 if down else 0, 0, 0, 0]) + struct.pack("!I", keysym))

    def tap(self, keysym: int, delay: float = 0.05) -> None:
        self.key(keysym, True)
        time.sleep(0.02)
        self.key(keysym, False)
        time.sleep(delay)

    def pointer(self, mask: int, x: int, y: int) -> None:
        self.ws.send(b"\x05" + bytes([mask]) + struct.pack("!HH", x, y))

    def click(self, x: int, y: int, button: int = 1) -> None:
        self.pointer(0, x, y)
        time.sleep(0.05)
        self.pointer(1 << (button - 1), x, y)
        time.sleep(0.07)
        self.pointer(0, x, y)
        time.sleep(0.12)

    def type_text(self, text: str, delay: float = 0.05) -> None:
        for ch in text:
            ks = char_keysym(ch)
            if ks is None:
                continue
            self.tap(ks, delay)

    def chord(self, mod: int, keysym: int) -> None:
        self.key(mod, True)
        time.sleep(0.04)
        self.tap(keysym)
        self.key(mod, False)
        time.sleep(0.05)


SHIFT, CTRL, ALT = 0xFFE1, 0xFFE3, 0xFFE9


def char_keysym(ch: str) -> Optional[int]:
    table = {
        " ": 0x20, "\n": 0xFF0D, "\t": 0xFF09, "/": 0x2F, ":": 0x3A, ".": 0x2E,
        "-": 0x2D, "_": 0x5F, "?": 0x3F, "=": 0x3D, "&": 0x26, "#": 0x23,
        "@": 0x40, "~": 0x7E, "%": 0x25, "+": 0x2B, ",": 0x2C, ";": 0x3B,
        "!": 0x21, "*": 0x2A, "(": 0x28, ")": 0x29, "'": 0x27, '"': 0x22,
    }
    if ch in table:
        return table[ch]
    if 32 <= ord(ch) < 127:
        return ord(ch)
    return None
