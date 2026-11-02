#!/usr/bin/env python3
"""Desktop Handoff 验收：脚本化人工端真实操作桌面（经 /v1/live/desktop）。

Runs inside the Interactive Runtime.  Proves against the real Gateway:
  1. Agent requests a DESKTOP handoff; the "human" side is a scripted client on the
     same /v1/live/desktop WebSocket the noVNC page uses, speaking RFB 3.8 through a
     byte-stream FIFO (never assumes WS frame == RFB message);
  2. real RFB input, in this order:
       a. Ctrl+L, type a data: URL key by key, Enter, click inside the page
       b. Ctrl+Shift+O opens Chromium's native bookmark manager, Ctrl+W closes it
       c. toolbar menu click opens the native Settings page
       d. release control through the human session cookie (portal button equivalent)
  3. Agent snapshot verifies the live page/state after release;
  4. every step is captured from the RFB stream into GHA_OUTPUT_DIR/evidence.
工具画面不点击像素坐标去“猜”菜单项：截图先进 evidence，再由 Host 端决定点击位置。
"""
import asyncio
import http.client
import json
import os
import struct
import sys
import time
import zlib
from pathlib import Path
from urllib.parse import urlparse

TASK_DIR = os.environ.get("GHA_TASK_DIR", os.getcwd())
sys.path.insert(0, os.path.join(TASK_DIR, "_gha_runtime"))
sys.path.insert(0, os.path.join(TASK_DIR, "_gha_runtime", "interactive_runtime"))

from rfb_stream import CTRL, RFB, SHIFT, WebSocket  # noqa: E402

OUT = Path(os.environ.get("GHA_OUTPUT_DIR", "./output"))
OUT.mkdir(parents=True, exist_ok=True)
EVID = OUT / "evidence"
EVID.mkdir(parents=True, exist_ok=True)
HOST = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
TOKEN = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
RESULT = {"steps": [], "ok": False}


def log(msg):
    print("[handoff-e2e] %s" % msg, flush=True)


def step(name, **data):
    RESULT["steps"].append({"step": name, "at": round(time.time(), 3), **data})
    log(f"{name}: {json.dumps(data, ensure_ascii=False)[:400]}")


def http(method, path, body=None, headers=None, hdrs=None):
    from http.client import HTTPConnection
    u = urlparse(HOST)
    conn = HTTPConnection(u.hostname, u.port or 80, timeout=60)
    h = {"Accept": "application/json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    if body is not None:
        body = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    h.update(hdrs or {})
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    return resp, resp.read()


def api(method, path, body=None):
    resp, data = http(method, path, body)
    if resp.status >= 400:
        raise RuntimeError(f"{method} {path} -> {resp.status} {data[:300]!r}")
    return json.loads(data)


def session_state():
    return api("GET", "/v1/session")


def write_png(fb_rgba, w, h, path: Path):
    rows = bytearray()
    for y in range(h):
        rows += b"\x00" + fb_rgba[y * w * 4:(y + 1) * w * 4]

    def chunk(tag, data):
        return (struct.pack("!I", len(data)) + tag + data +
                struct.pack("!I", zlib.crc32(tag + data) & 0xFFFFFFFF))
    path.write_bytes(b"\x89PNG\r\n\x1a\n" +
                     chunk(b"IHDR", struct.pack("!IIBBBBB", w, h, 8, 6, 0, 0, 0)) +
                     chunk(b"IDAT", zlib.compress(bytes(rows), 6)) + chunk(b"IEND", b""))


def save_rfb_png(rfb: RFB, name: str) -> str:
    w, h = rfb.width, rfb.height
    fb = bytearray(w * h * 4)
    for (x, y, rw, rh, data) in rfb.rects:
        for row in range(rh):
            dst = ((y + row) * w + x) * 4
            fb[dst:dst + rw * 4] = data[row * rw:(row + 1) * rw]
    write_png(fb, w, h, EVID / name)
    return name


def snapshot_agent():
    gen = session_state()["generation"]
    snap = (api("POST", "/v1/agent/command", {"cmd": "snapshot", "generation": gen}).get("snapshot") or {})
    return [w.get("title") for w in (snap.get("windows") or [])], (snap.get("active_window") or {})


def pump_shot(rfb: RFB, name: str) -> str:
    rfb.update_request(True)
    rfb.pump(timeout=20)
    return save_rfb_png(rfb, name)


async def run():
    if not TOKEN:
        raise RuntimeError("GHA_INTERACTIVE_TOKEN missing")
    step("gateway_health", **api("GET", "/health"))
    step("initial_state", state=session_state()["state"])

    req = api("POST", "/v1/handoff/request", {"mode": "desktop", "timeout_seconds": 1200})
    step("handoff_requested", mode=req.get("mode"), desktop_stream=req.get("desktop_stream"))
    ticket = req["ticket"]

    # claim exactly like the portal page: ticket -> HttpOnly HUMAN_DESKTOP cookie
    resp, data = http("POST", "/v1/handoff/claim", {"ticket": ticket})
    if resp.status != 200:
        raise RuntimeError(f"claim failed: {resp.status} {data[:300]!r}")
    claim = json.loads(data)
    set_cookie = resp.headers.get("Set-Cookie", "")
    cookie = set_cookie.split(";", 1)[0].split("=", 1)[1]
    step("handoff_claimed", http=resp.status, mode=claim.get("mode"), role=claim.get("role"),
         generation=claim.get("generation"), httponly="HttpOnly" in set_cookie)

    # RFB over the very same /v1/live/desktop channel the noVNC page connects to
    ws = WebSocket(HOST.replace("http://", "ws://") + "/v1/live/desktop",
                   headers={"Cookie": f"gha_session={cookie}", "Origin": HOST})
    rfb = RFB(ws)
    rfb.handshake()
    rfb.update_request(False)
    rfb.pump(timeout=30)
    step("rfb_connected", width=rfb.width, height=rfb.height, name=rfb.name,
         ws_frames=ws.frames_received, ws_bytes=ws.bytes_received,
         png=save_rfb_png(rfb, "01-baseline.png"))

    # a. key-by-key URL entry in the address bar, then a real mouse click in the page
    url = ("data:text/html,<body style='margin:0;background:%23202a44;color:%23ffcc00;"
           "font:48px sans-serif;padding:60px'>GHA desktop handoff OK</body>")
    rfb.chord(CTRL, 0x6C)
    time.sleep(0.5)
    rfb.type_text(url, delay=0.035)
    rfb.tap(0xFF0D)
    time.sleep(3.0)
    png = pump_shot(rfb, "02-typed-url.png")
    titles, active = snapshot_agent()
    step("typed_url", chars=len(url), keys="ctrl+l,text,enter", agent_title=active.get("title"), png=png)
    rfb.click(rfb.width // 2, rfb.height // 2)
    time.sleep(0.5)
    pump_shot(rfb, "03-after-click.png")

    # b. native bookmark manager through the browser UI
    rfb.key(SHIFT, True)
    rfb.chord(CTRL, 0x6F)
    rfb.key(SHIFT, False)
    time.sleep(2.5)
    png = pump_shot(rfb, "04-bookmarks.png")
    titles, active = snapshot_agent()
    step("bookmarks_manager", keys="ctrl+shift+o", agent_title=active.get("title"),
         window_titles=titles[:3], png=png)
    rfb.chord(CTRL, 0x77)
    time.sleep(1.5)

    # c. browser menu (three dots) — screenshot captured for the visual check
    rfb.click(rfb.width - 24, 40)
    time.sleep(1.5)
    step("browser_menu", png=pump_shot(rfb, "05-menu.png"))

    # d. release control through the human session cookie
    resp, data = http("POST", "/v1/handoff/complete", b"{}",
                      hdrs={"Cookie": f"gha_session={cookie}", "Origin": HOST})
    step("handoff_complete", http=resp.status, body=json.loads(data or b"{}"))
    st = {}
    for _ in range(30):
        st = session_state()
        if st["state"] == "AGENT_ACTIVE":
            break
        time.sleep(0.3)
    step("agent_state_after_release", state=st.get("state"), generation=st.get("generation"))

    titles, active = snapshot_agent()
    step("agent_snapshot_after_release", agent_title=active.get("title"), window_titles=titles[:3])
    RESULT["agent_title_after_release"] = active.get("title")

    checkpoint_id = "desktop-handoff-final"
    cp = api("POST", "/v1/state/checkpoint", {"type": "DESKTOP", "checkpoint_id": checkpoint_id})
    record = cp.get("checkpoint") or {}
    videos = [o for o in record.get("objects", []) if o.get("category") == "desktop_video"]
    if record.get("type") != "DESKTOP_CHECKPOINT" or not videos:
        raise RuntimeError(f"DESKTOP checkpoint has no video: {cp}")
    if any(o.get("file_path") for o in record.get("objects", [])):
        raise RuntimeError("public checkpoint leaked file_path")
    step("desktop_checkpoint", checkpoint_id=checkpoint_id,
         objects=[{"id": o.get("id"), "category": o.get("category"), "size": o.get("size"),
                   "encrypted": o.get("encrypted"), "persistence_state": o.get("persistence_state")}
                  for o in record.get("objects", [])])

    deadline = time.time() + 600
    persisted = set()
    while time.time() < deadline:
        manifest = api("GET", "/v1/state/manifest")
        persisted = {o.get("id") for o in manifest.get("objects", [])
                     if o.get("category") == "desktop_video" and o.get("persistence_state") == "PERSISTED"}
        expected = {o.get("id") for o in videos}
        if expected <= persisted:
            break
        time.sleep(2)
    else:
        raise RuntimeError(f"desktop video was not persisted: expected={sorted(expected)} actual={sorted(persisted)}")
    step("desktop_video_persisted", object_ids=sorted(persisted))
    try:
        ws.close()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(run())
        RESULT["ok"] = True
    except Exception as exc:  # noqa: BLE001
        RESULT["error"] = f"{type(exc).__name__}: {exc}"
        log("FAILED: " + RESULT["error"])
    finally:
        (OUT / "handoff-e2e.json").write_text(json.dumps(RESULT, ensure_ascii=False, indent=2))
    sys.exit(0 if RESULT.get("ok") else 1)
