"""Interactive Runtime 真实链路自查：官方 noVNC 接管 + DESKTOP 录像加密回传。

在【已配置好并正在运行】的环境里跑（真实 GHA Runner，或本机 Linux/CI 自查）：
Xvfb / openbox / AT-SPI / x11vnc / websockify / 官方 noVNC 资源 / Playwright 全部由
产品自带的环境与组件提供，本脚本不绕开任何产品代码：

1. 同一 DISPLAY 上另起一个浏览器进程扮演「人工端」，打开真实 Ticket 的门户页面；
2. 官方 noVNC（容器自带的 @novnc/novnc）经 Gateway ``/v1/live/desktop`` 接管画面；
3. 真实鼠标点击 + 键盘键入 + 打开原生弹窗，Agent 侧读窗口并确认；
4. 页面点「交还控制权给 Agent」，Agent 用 xdotool 证明输入已回到自己手里；
5. DESKTOP 检查点：录像由 X25519+HKDF+AES-256-GCM 封套加密回传，Host 解封后核对
   SHA-256 / ffprobe / 全帧解码，并要求解密视频里出现第 4 步之后录到的已知内容。

这个浏览器进程只验证「真实 noVNC 交互与录像闭环」，不是 Host 侧外网通道。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.request
from typing import Any, Dict, List, Optional

import aiohttp
from playwright.async_api import async_playwright

from ..browser import BrowserManager
from ..desktop import DesktopManager
from ..desktop_stream import DesktopStreamManager
from ..recording import DesktopRecorder
from ..session import SessionContext
from ..state_export import StateExporter
from ..transfer import ChunkedTransferEngine
from . import marker

MANUAL_MARKER = "manual-handoff-ok"
AGENT_MARKER = "agent-resumed-ok"
DIALOG_TITLE = "gha-runner 接管自测"
# 弹窗里的输入框是只读的（xdialog 不支持可编辑输入）：对话框闭环 = 人工端真点到按钮 →
# 原生窗口在 Agent 桌面出现 → xdotool 在弹窗上按键 → 弹窗收到输入并自关 → 页面读回。
DIALOG_MARKER = "typed-by-x11"
# 终止用户页面输入框在 framebuffer 里的位置（1280x800 桌面、Chromium 窗口在左上）
DESKTOP_INPUT_XY = (320, 278)

# noVNC 1.7 不给容器加 class（老版的 noVNC_screen 已不存在）：结构是
# #viewport-container > 我们给的 host div > RFB 自建 screen div > canvas。
# 用"容器里任意 div 下的 canvas"定位，既避开直接子级的 #stream-canvas，也不依赖类名。
NOVNC_CANVAS = "#viewport-container div > canvas"

POLL_SECONDS = 3.0
HANDOFF_BUDGET = 70.0


class LoopFailed(Exception):
    """自查失败；调用方把已完成的步骤与原因写进 handoff-loop.json。"""


def _now() -> float:
    return round(time.time(), 3)


class _Steps:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(self, step: str, ok: bool = True, **fields: Any) -> None:
        item = {"step": step, "at": _now(), "ok": ok}
        item.update(fields)
        self.items.append(item)
        print(f"[handoff-loop] {step}: {json.dumps(item, ensure_ascii=False)}", flush=True)


class _SiteServer:
    """自查站（dialogue-host）：node + 官方 noVNC 的兄弟依赖 jsdom，或原生 X11 对话框。"""

    def __init__(self) -> None:
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}/"
        self.proc: Optional[subprocess.Popen] = None
        self.host = "node"
        self.dialog_host = os.environ.get("HANDOFF_SITE_HOST", "jsdom")
        self.last_output = ""

    def start(self) -> None:
        node = shutil.which("node")
        if not node:
            raise LoopFailed("缺少 node：自查站需要 Node 提供终端用户页面")
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site.js")
        self.proc = subprocess.Popen(
            [node, script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env=dict(os.environ, HANDOFF_SITE_PORT=str(self.port)),
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(self.url + "__status", timeout=2) as resp:
                    json.loads(resp.read().decode("utf-8"))
                    return
            except Exception:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.3)
        self.last_output = (self.proc.stdout.read() if self.proc.stdout else "")[-800:] if self.proc.poll() is not None else ""
        raise LoopFailed(f"自查站未能启动（{type(self.proc)} rc={self.proc.poll()}）：{self.last_output}")

    def status(self) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(self.url + "__status", timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            return {"error": f"{type(exc).__name__}"}

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class HandoffLoopTest:
    def __init__(self, config=None, run_id: str = "local-selftest") -> None:
        self.run_id = run_id
        self.ctx = SessionContext.create(run_id=run_id, config=config)
        self.display = self.ctx.config.graphical.display
        # 与 Runtime 的终止用户浏览器并存：同一个 chrome-profile 会被 ProcessSingleton
        # 占用，所以自查用独立 profile 目录，不碰 Supervisor 的浏览器。
        self.browser = BrowserManager(
            display=self.display, cdp_port=0,
            user_data_dir=os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"),
                                       "gha-handoff-loop", "chrome-profile"),
        )
        self.desktop = DesktopManager(display=self.display)
        # 接管运行中的 Gateway 时，桌面流由它自己管；另起一份只会握不上它那条 x11vnc。
        self.external_portal = bool(os.environ.get("GHA_SELFTEST_PORTAL_BASE"))
        self.desktop_stream = None if self.external_portal else DesktopStreamManager(display=self.display)
        self.steps = _Steps()
        self.port = 0
        self.base = ""
        self.exporter: Optional[StateExporter] = None
        self.site: Optional[_SiteServer] = None
        self.vault_root = ""
        self._data_dir = ""
        self._http: Optional[aiohttp.ClientSession] = None
        self._agent_headers: Dict[str, str] = {}

    # ------------------------------------------------------------------ 组件
    async def setup(self) -> None:
        """真实组件：终止用户的浏览器 + 桌面录像 + 隔离的加密结果目录。"""
        if not await self.browser.start():
            raise LoopFailed(f"终止用户浏览器启动失败：{self.browser.last_error}")
        # 终止用户页面由自查站提供（与开发网站时本机起服务同一条路径）：
        # 真人在 noVNC 里点的输入框就是 Runner 上 Chromium 渲染的这一页。
        self.site = _SiteServer()
        self.site.start()
        page = await self.browser.get_active_page()
        await page.goto(self.site.url, wait_until="load")
        self.steps.add("terminal_page_loaded",
                       host=self.site.host, dialog_host=self.site.dialog_host,
                       path=self.site.url)

        self._data_dir = os.environ.get("GHA_SELFTEST_DATA") or os.path.join(
            os.environ.get("RUNNER_TEMP", "/tmp"), "gha-handoff-loop")
        self.vault_root = os.environ.get("GHA_SELFTEST_VAULT") or os.path.join(
            os.environ.get("RUNNER_TEMP", "/tmp"), "gha-handoff-loop-vault")
        for path in (self._data_dir, self.vault_root):
            os.makedirs(path, mode=0o700, exist_ok=True)

        recordings = os.path.join(self._data_dir, "recordings")
        shutil.rmtree(recordings, ignore_errors=True)
        seat = StateExporter(
            transfer_engine=ChunkedTransferEngine(storage_dir=os.path.join(self._data_dir, "transfers")),
            browser_mgr=self.browser,
            desktop_mgr=self.desktop,
            storage_dir=os.path.join(self._data_dir, "exports"),
        )
        if seat.sealer is None:
            raise LoopFailed("未配置 Host 状态公钥（GHA_STATE_PUBLIC_KEY/GHA_STATE_KEY_ID），"
                             "DESKTOP 检查点会拒绝回传录像")
        # 接管运行中的 Gateway 时，录像与检查点由它自己的 recorder/exporter 负责；
        # 本进程只借它的 sealer 判「加密可用」，绝不覆盖运行中的那套（那会把录像目录换掉）。
        self.key_id = seat.sealer.key_id
        self.exporter = None if self.external_portal else seat
        if self.exporter is not None:
            recorder = DesktopRecorder(
                output_dir=recordings,
                display=self.display,
                segment_seconds=self.ctx.config.persistence.desktop_video.segment_seconds,
            )
            if not recorder.start():
                raise LoopFailed(f"桌面录像启动失败：{recorder.last_error or 'unknown'}")
            self.exporter.recorder = recorder
        # key_id 本身就是 GHA_STATE_KEY_ID 的值：写进步骤会被产物扫描按已注册凭证判泄露。
        self.steps.add("encryption_ready", key_id_configured=True,
                       algo="X25519+HKDF-SHA256+AES-256-GCM",
                       external_recorder=bool(self.external_portal))
        for key in ("GHA_STATE_KEY_ID", "GHA_STATE_PUBLIC_KEY",
                    "GHA_RENDEZVOUS_TOKEN", "GHA_TUNNEL_TOKEN"):
            # 步骤里 console 会打 JSON；值一旦出现就会被产物扫描判为泄露并拦下上传。
            value = os.environ.get(key) or ""
            if value:
                print("::add-mask::" + value, flush=True)

        self.port = _free_port()
        # 门户默认走本机回环；给 GHA_SELFTEST_PORTAL_BASE 时人工端改走公开入口，
        # 这样 Tunnel/Registry 路径也被真实门户页面覆盖（本机回环看不到这条路径）。
        self.base = (os.environ.get("GHA_SELFTEST_PORTAL_BASE") or "").rstrip("/") or (
            f"http://127.0.0.1:{self.port}")
        # 接管运行中的 Gateway 时，检查点导出走它自己的（同一录像目录、同一密钥）；
        # 只有自建门户才在本进程另起一份导出。
        self.external_portal = bool(os.environ.get("GHA_SELFTEST_PORTAL_BASE"))
        # 产品 Gateway 是 HTTP/1.1（Tunnel 负责 h2）；aiohttp 默认不向明文端口发 cookie，
        # 关闭 h2 升级与 TLS 内层要求在本地回环上等价于浏览器行为。
        # 运行中 Runtime 把 Agent Token 挂在自身进程环境里（它签出的凭证 Gateway 才认）；
        # 没有它就只能自签，而自签的凭证对运行中的 Gateway 一律 401。
        runtime_token = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
        if self.external_portal and runtime_token:
            self.use_agent_token(runtime_token)
        else:
            self._agent_headers = {"Authorization": f"Bearer {self.ctx.auth.create_agent_token()}"}
        self._http = self._new_http()

    def use_agent_token(self, token: str) -> None:
        """接管 Runtime 常驻进程的 Agent Token：Gateway 只认它签出的凭证。

        只记在 ``_agent_headers``；会话头交给 ``_new_http`` 统一设置，避免同一请求
        同时带会话级与请求级两个 Authorization。
        """
        if not token:
            raise LoopFailed("Runtime 没有给出自查用的 Agent Token")
        self._agent_headers = {"Authorization": f"Bearer {token}"}

    def _new_http(self) -> aiohttp.ClientSession:
        """新建会话并把已认下的 Agent 凭证作为会话头带上去（换连接必须带）。

        产品 Gateway 是 HTTP/1.1（Tunnel 负责 h2）；运行中的 Gateway 可能经公开入口
        访问，此时回环 127.0.0.1 的 Cookie 例外不适用，按地址决定 unsafe。
        """
        connector = aiohttp.TCPConnector(ssl=self.base.startswith("https://"))
        session = aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.CookieJar(unsafe=not self.base.startswith("http://127.0.0.1")),
            auto_decompress=True,
        )
        if self._agent_headers:
            session.headers["Authorization"] = self._agent_headers["Authorization"]
        return session

    async def run(self, portal: Optional[str] = None, auth=None) -> Dict[str, Any]:
        """portal/auth 给出运行中 Gateway 的地址与认证件时，人工端直接接上去。

        不重复建 Gateway，也不另签 Token：运行中 Gateway 只认它自己签出的凭证。
        """
        if auth is not None:
            self.ctx.auth = auth
        if self.external_portal:
            # 检查点导出由运行中 Gateway 自己的 exporter 负责（同一录像目录、同一密钥）；
            # 本进程这份与它不在同一个 Vault 口径下，故不参与检查点。
            self.exporter = None
            # 同一 Gateway 只接受 1 个桌面控制器；镜像的 display/标记像素与实际同一 X 一致。
            self.desktop = DesktopManager(display=self.display)
        if portal:
            self.base = portal.rstrip("/")
        if (self.external_portal or portal) and self._http is None:
            # 换连接必须带上 setup() 认下的凭证，否则新会话上没有 Authorization。
            self._http = self._new_http()
        result: Dict[str, Any] = {"ok": False, "steps": self.steps.items,
                                  "markers": {"manual": MANUAL_MARKER, "agent": AGENT_MARKER,
                                              "dialog": DIALOG_MARKER}}
        human: Optional[_HumanPage] = None
        try:
            agent = _AgentApi(self)
            human = _HumanPage(self)
            await agent.wait("AGENT_ACTIVE", HANDOFF_BUDGET)
            self.steps.add("agent_initial", state="AGENT_ACTIVE")

            # 真实产品顺序：先发起接管（Agent 拿票据）→ 门户在认领前无会话 → 认领 → 桌面流
            await human.launch()
            ticket = await human.request_handoff()
            await agent.wait("HANDOFF_REQUESTED")
            waiting = await human.waiting_before_claim()
            self.steps.add("handoff_requested", mode="desktop", preclaim=waiting)
            await human.open_ticket_page(ticket)
            await agent.wait("HUMAN_ACTIVE")
            desktop = await human.claim_desktop()
            self.steps.add("handoff_claimed", generation=agent.generation, **desktop)
            await agent.must_reject_input("接管期间 Agent 输入必须被状态机拒绝")
            self.steps.add("exclusive_control_verified")

            await human.interact()
            result["dialog"] = human.dialog

            await human.complete()
            state = await agent.wait("AGENT_ACTIVE")
            self.steps.add("handoff_completed", generation=state.get("generation"))
            closed = await human.stream_closed_after_complete()
            self.steps.add("novnc_disconnected_after_complete", ok=closed["canvases"] == 0, **closed)

            await agent.resume_probe(state.get("generation"))
            self.steps.add("agent_input_restored", marker=AGENT_MARKER)

            result["recording"] = await agent.checkpoint_and_verify("DESKTOP", "desktop_video")
            result["ok"] = True
        except LoopFailed as exc:
            result["error"] = str(exc)
        except Exception as exc:  # 证据优先：任何异常都要落进结果
            result["error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        finally:
            if human is not None:
                result["human_page"] = human.evidence
                await human.close()
            await self.teardown()
            result["steps"] = self.steps.items
        return result

    async def teardown(self) -> None:
        try:
            if self.desktop_stream is not None:  # 外部 Gateway 的桌面流由它自己收尾
                self.desktop_stream.stop_streaming()
        except Exception:
            pass
        if self.site is not None:
            self.site.stop()
        try:
            recorder = getattr(self.exporter, "recorder", None)
            if recorder is not None:
                recorder.stop()
        except Exception:
            pass
        await self.browser.close()
        if self._http is not None:
            await self._http.close()

def _os_release() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------- Agent 侧
class _AgentApi:
    """只用 Agent Token 调 Gateway，端点与语义与产品 CLI 相同。"""

    def __init__(self, test: HandoffLoopTest) -> None:
        self.t = test
        self.generation: Optional[int] = None

    async def get(self, path: str) -> Dict[str, Any]:
        async with self.t._http.get(self.t.base + path, headers=self.t._agent_headers) as resp:
            body = await resp.json()
            if resp.status != 200:
                raise LoopFailed(f"GET {path} 期望 200，实际 {resp.status}：{str(body)[:300]}")
            return body

    async def post(self, path: str, payload: Dict[str, Any]) -> aiohttp.ClientResponse:
        return await self.t._http.post(self.t.base + path, json=payload,
                                       headers=self.t._agent_headers)

    async def wait(self, state: str, budget: float = HANDOFF_BUDGET) -> Dict[str, Any]:
        deadline = time.monotonic() + budget
        last: Any = None
        while time.monotonic() < deadline:
            last = await self.get("/v1/session")
            if last.get("state") == state:
                if last.get("generation") is not None:
                    self.generation = last["generation"]
                return last
            await asyncio.sleep(POLL_SECONDS)
        raise LoopFailed(f"等待状态 {state} 超时（最后：{json.dumps(last, ensure_ascii=False)[:300]}）")

    async def command(self, payload: Dict[str, Any]) -> aiohttp.ClientResponse:
        return await self.post("/v1/agent/command", payload)

    async def must_reject_input(self, why: str) -> None:
        resp = await self.command({"cmd": "type", "text": "must-not-land",
                                   "generation": self.generation})
        async with resp:
            if resp.status != 403:
                raise LoopFailed(f"{why}：实际 HTTP {resp.status}（{(await resp.text())[:200]}）")

    async def resume_probe(self, generation: Optional[int]) -> None:
        """xdotool 在 Xvfb 里往终止用户页面的输入框键入，页面读回证明输入回到 Agent。"""
        page = await self.t.browser.get_active_page()
        await page.bring_to_front()
        await page.click("#loop-probe")
        if not self.t.desktop.click(320, 278):
            raise LoopFailed(f"Agent 点击失败：{json.dumps(self.t.desktop.last_error_dict())}")
        await asyncio.sleep(0.4)
        if not self.t.desktop.type_text(AGENT_MARKER):
            raise LoopFailed("Agent 键入失败")
        await asyncio.sleep(0.6)
        value = await page.input_value("#loop-probe")
        if value != AGENT_MARKER:
            raise LoopFailed(f"Agent 输入未落到页面输入框：期望 {AGENT_MARKER!r}，实际 {value!r}")
        self.t.desktop.key_press("ctrl+a")
        self.t.desktop.key_press("Delete")

    async def checkpoint_and_verify(self, kind: str, category: str) -> Dict[str, Any]:
        cp_id = f"selftest-{kind.lower()}-{int(time.time())}"
        resp = await self.post("/v1/state/checkpoint", {"type": kind, "checkpoint_id": cp_id})
        async with resp:
            body = await resp.json()
            if resp.status != 200:
                raise LoopFailed(f"{kind} 检查点失败：HTTP {resp.status} {str(body)[:400]}")
        record = body.get("checkpoint") or {}
        objects = record.get("objects") or []
        wanted = [o["id"] for o in objects if o.get("category") == category]
        # 公开报告只报对象 id 与类别：key_id 是已注册凭证值，file_path 是 Runner 本地路径
        self.t.steps.add("checkpoint_created", checkpoint_id=cp_id, type=kind,
                         objects=[{"id": o.get("id"), "category": o.get("category"),
                                   "encrypted": o.get("encrypted")} for o in objects],
                         errors=record.get("video_errors") or record.get("errors") or [])
        if not wanted:
            raise LoopFailed(f"{kind} 检查点没有 {category} 对象：{json.dumps(record, ensure_ascii=False)[:400]}")
        return await _pull_and_verify(self.t, cp_id, objects, wanted)


async def _pull_and_verify(test: HandoffLoopTest, cp_id: str, objects: List[Dict[str, Any]],
                           wanted: List[str]) -> Dict[str, Any]:
    """产品同一路径：清单 → 下载 → 解封时核对声明的 SHA-256/长度 → ffprobe/全帧解码。"""
    from gha_runner.interactive_client import InteractiveClient
    from gha_runner.state_client import StateClient
    from gha_runner.vault import Vault

    manifest = await _get_json(test, "/v1/state/manifest")
    by_id = {o.get("id"): o for o in manifest.get("objects") or []}
    missing = [vid for vid in wanted if vid not in by_id]
    if missing:
        raise LoopFailed(f"清单里缺少对象：{missing}")

    vault = Vault(root_dir=test.vault_root)
    state = StateClient(InteractiveClient(test.base, token=test._agent_headers["Authorization"][7:]),
                        vault=vault)
    project = "selftest"
    state.export_selected([by_id[vid] for vid in wanted], project=project)
    if state.plaintext_objects:
        raise LoopFailed(f"发现明文回传的敏感对象：{state.plaintext_objects}")

    out: Dict[str, Any] = {"checkpoint_id": cp_id, "videos": []}
    for vid in wanted:
        meta = by_id[vid]
        data, stored = vault.get_binary_object(project, vid)
        if data is None:
            raise LoopFailed(f"Vault 里找不到解密对象 {vid}")
        out["videos"].append(_verify_video(test, vid, meta, data, stored))
    # 已知内容逐帧识别只在显式给色时启用（实验室把这段录制区域换成纯色验证闭环）
    known = (os.environ.get("GHA_SELFTEST_MARKER_RGB") or "").strip()
    if known:
        rgb = marker.parse_rgb(known)
        first = next((v for v in out["videos"]
                      if marker.marker_frames(v["path"], rgb) is not None), None)
        if first is None:
            raise LoopFailed(f"解密后的录像里没有已知内容颜色 {rgb}（录像闭环未证明）")
        out["marker_seen"] = marker.marker_frames(first["path"], rgb)
    return out


def _verify_video(test: HandoffLoopTest, vid: str, meta: Dict[str, Any], data: bytes,
                  stored: Any) -> Dict[str, Any]:
    work = os.path.join(test.vault_root, "verify")
    os.makedirs(work, exist_ok=True)
    path = os.path.join(work, "decoded-" + re.sub(r"[^A-Za-z0-9._-]", "_", vid) + ".mp4")
    with open(path, "wb") as fh:
        fh.write(data)

    plain_sha = hashlib.sha256(data).hexdigest()
    if not meta.get("encrypted"):
        raise LoopFailed(f"{vid} 清单声明未加密（encrypted=False）")
    if meta.get("plaintext_sha256") and meta["plaintext_sha256"] != plain_sha:
        raise LoopFailed(f"{vid} 解密后 SHA-256 与清单声明不符")
    if isinstance(meta.get("plaintext_size"), int) and meta["plaintext_size"] != len(data):
        raise LoopFailed(f"{vid} 解密后长度与清单声明不符")
    sealed_size = meta.get("size")
    if not isinstance(sealed_size, int) or sealed_size <= len(data):
        # 封套含固定头部与 16 字节 tag：密文必然大于明文，否则落盘的就不是密文
        raise LoopFailed(f"{vid} 传输长度 {sealed_size} 未大于明文长度 {len(data)}，疑似明文回传")

    ffprobe, ffmpeg = shutil.which("ffprobe"), shutil.which("ffmpeg")
    if not ffprobe or not ffmpeg:
        raise LoopFailed("缺少 ffprobe/ffmpeg")
    probe = _run([ffprobe, "-v", "error", "-show_entries",
                  "stream=codec_name,width,height:format=duration", "-of", "json", path], 30)
    if probe.returncode != 0:
        raise LoopFailed(f"{vid} ffprobe 失败：{(probe.stderr or '')[:300]}")
    info = json.loads(probe.stdout or "{}")
    stream = (info.get("streams") or [{}])[0]
    duration = float((info.get("format") or {}).get("duration") or 0)

    decoded = _run([ffmpeg, "-v", "error", "-i", path, "-f", "framemd5", "-"], 180)
    if decoded.returncode != 0:
        raise LoopFailed(f"{vid} ffmpeg 解码失败：{(decoded.stderr or '')[:300]}")
    frames = len([ln for ln in decoded.stdout.splitlines() if ln and not ln.startswith("#")])

    item = {
        "id": vid,
        "encrypted": bool(meta.get("encrypted")),
        "envelope_version": meta.get("envelope_version"),
        "transfer_sha256": meta.get("sha256"),
        "transfer_size": sealed_size,
        "plaintext_sha256": plain_sha,
        "plaintext_size": len(data),
        "vault_sha256": getattr(stored, "sha256", None),
        "vault_algo": getattr(stored, "encryption_algo", None),
        "codec": stream.get("codec_name"),
        "resolution": [stream.get("width"), stream.get("height")],
        "duration_s": round(duration, 2),
        "decoded_frames": frames,
        "path": path,
    }
    if item["vault_sha256"] != plain_sha:
        raise LoopFailed(f"{vid} Vault 落盘摘要与解密内容不一致")
    test.steps.add("video_verified", **{k: item[k] for k in (
        "id", "transfer_size", "plaintext_size", "duration_s", "decoded_frames")})
    return item


def _run(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


async def _get_json(test: HandoffLoopTest, path: str) -> Dict[str, Any]:
    async with test._http.get(test.base + path, headers=test._agent_headers) as resp:
        if resp.status != 200:
            raise LoopFailed(f"GET {path} 失败：HTTP {resp.status}")
        return await resp.json()


# ---------------------------------------------------------------------- 人工端
class _HumanPage:
    """人工端：第二个浏览器进程 + 官方 noVNC。所有输入都以坐标/键盘事件发生，
    与真人操作同一条链路（noVNC → Gateway → websockify → x11vnc → X）。"""

    def __init__(self, test: HandoffLoopTest) -> None:
        self.t = test
        self.pw = None
        self.browser = None
        self.context = None
        self.page = None
        self.dialog: Optional[Dict[str, Any]] = None
        self.evidence: Dict[str, Any] = {"console": [], "requests": []}

    async def launch(self) -> None:
        """起人工端浏览器（headless，同一 DISPLAY 之外只做门户页面）。"""
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage",
                  "--use-gl=swiftshader", "--enable-unsafe-swiftshader"],
        )
        self.context = await self.browser.new_context(viewport={"width": 1280, "height": 800})
        self.page = await self.context.new_page()
        self.page.on("console", lambda m: self.evidence["console"].append(
            {"type": m.type, "text": m.text[:300]}))
        self.page.on("pageerror", lambda e: self.evidence["console"].append(
            {"type": "pageerror", "text": str(e)[:300]}))
        self.page.on("request", lambda r: self.evidence["requests"].append(
            {"method": r.method, "path": _path_of(r.url)}) if _watch(r.url) else None)

    async def request_handoff(self) -> Dict[str, Any]:
        """Agent 侧发起桌面接管：拿一次性票据，并要求 x11vnc/websockify 已就绪。"""
        async with await _AgentApi(self.t).post(
                "/v1/handoff/request", {"mode": "desktop", "timeout_seconds": 600}) as resp:
            body = await resp.json()
            if resp.status != 200:
                raise LoopFailed(f"请求桌面接管失败：HTTP {resp.status} {str(body)[:300]}")
        if not body.get("desktop_stream"):
            raise LoopFailed(f"x11vnc/websockify 未就绪：{body.get('detail') or body}")
        if not body.get("handoff_url"):
            raise LoopFailed(f"接管响应里没有门户地址：{str(body)[:300]}")
        self.evidence["ticket_delivered"] = True
        self.page_url_masked = _path_of(self.t.base + body["handoff_url"])
        return body

    async def waiting_before_claim(self) -> Dict[str, Any]:
        """认领前：不带票据打开门户 → 没有会话 Cookie，桌面流被 401，界面必须显示未连接。

        这一页与真人在拿到链接前的观感一致：能看见门户，但还没有任何控制权。
        """
        page = await self.context.new_page()
        await page.goto(self.t.base + "/?mode=desktop", wait_until="load", timeout=30000)
        await page.wait_for_selector("#conn-status", timeout=20000)
        await page.wait_for_timeout(2500)
        cookies = await self.context.cookies(self.t.base)
        info = {
            "conn": (await page.inner_text("#conn-status")).strip(),
            "complete_disabled": await page.is_disabled("#btn-complete"),
            "session_cookie": any(c.get("name") == "gha_session" for c in cookies),
            "canvases": await page.evaluate(
                "() => document.querySelectorAll('#viewport-container div > canvas').length"),
        }
        await page.close()
        return info

    async def open_ticket_page(self, body: Dict[str, Any]) -> None:
        """带票据打开门户：页面自己认领（POST /v1/handoff/claim）并切到桌面流。"""
        await self.page.goto(self.t.base + body["handoff_url"], wait_until="load", timeout=30000)

    async def claim_desktop(self) -> Dict[str, Any]:
        # 认领是页面自己的产品逻辑：hashchange → POST /v1/handoff/claim（HttpOnly Cookie）
        # → 就地切到 desktop → 官方 noVNC → WebSocket /v1/live/desktop。
        await self.page.wait_for_function(
            "() => document.getElementById('conn-status').textContent.includes('已连接（同一桌面）')",
            timeout=45000)
        await self.page.wait_for_selector(NOVNC_CANVAS, timeout=45000)
        await self.page.wait_for_timeout(2500)
        info = await self.page.evaluate("""() => {
            const c = document.querySelector('#viewport-container div > canvas');
            const r = c.getBoundingClientRect();
            const s = c.parentElement;
            return {
              title: document.title,
              badge: document.getElementById('mode-badge').textContent,
              gen: document.getElementById('gen-tag').textContent,
              canvas: {width: c.width, height: c.height,
                       css: [Math.round(r.left), Math.round(r.top), Math.round(r.width), Math.round(r.height)]},
              screen: s ? {scroll: [s.scrollLeft, s.scrollTop], size: [s.scrollWidth, s.scrollHeight]} : null,
              session_width: c.parentElement ? c.parentElement.style.width : null,
            };
        }""")
        if info.get("canvas", {}).get("width", 0) < 100:
            raise LoopFailed(f"noVNC 画布尺寸异常：{info}")
        cookies = await self.context.cookies(self.t.base)
        credential = {
            "session_cookie_httponly": any(
                c.get("name") == "gha_session" and c.get("httpOnly") for c in cookies),
            "url": self.page_url_masked,
        }
        if not credential["session_cookie_httponly"]:
            raise LoopFailed(f"认领后没有拿到 HttpOnly 会话 Cookie：{credential}")
        if "ticket=" in credential["url"] or "token=" in credential["url"]:
            raise LoopFailed(f"认领后地址栏仍带票据：{credential['url']}")
        await self._capture("01-novnc-connected")
        return {"credential": credential, "novnc": info}

    async def interact(self) -> None:
        """人工端在 noVNC 画面上做真实操作：坐标点击 → 键入 → 切到按钮 → 回车开弹窗。

        注意：输入框在**远端桌面**的终止用户页面里，不在门户 DOM 里。所以点的是
        noVNC 画布上的 framebuffer 坐标（按画布缩放换算），键入走 noVNC 的键盘通道，
        读回则在 Agent 侧那个真实浏览器页面上做 —— 只有两侧对上才算数。
        """
        canvas = await self.page.locator(NOVNC_CANVAS).bounding_box()
        if not canvas:
            raise LoopFailed("找不到 noVNC 画布")
        remote = await self.page.evaluate(
            """() => { const c = document.querySelector('#viewport-container div > canvas');
                        return [c.width, c.height]; }""")
        rw, rh = int(remote[0]), int(remote[1])
        if rw < 100 or rh < 100:
            raise LoopFailed(f"noVNC framebuffer 尺寸异常：{remote}")

        # 1) 真实点击：按 framebuffer 坐标换算到画布像素，事件经 noVNC → x11vnc 注入 X
        fx, fy = DESKTOP_INPUT_XY[0] / rw, DESKTOP_INPUT_XY[1] / rh
        x = canvas["x"] + fx * canvas["width"]
        y = canvas["y"] + fy * canvas["height"]
        await self.page.mouse.click(x, y)
        await asyncio.sleep(0.6)
        agent_page = await self.t.browser.get_active_page()
        focused = await agent_page.evaluate(
            "() => document.activeElement && document.activeElement.id")
        self.t.steps.add("novnc_click_landed", fraction=[round(fx, 4), round(fy, 4)],
                               framebuffer=[rw, rh], focused_element=focused)
        if focused != "loop-probe":
            raise LoopFailed(f"noVNC 点击没有落到终止用户页面的输入框：activeElement={focused!r}")

        # 2) 真实键入：每个字符单独 keydown/keyup，读回的是 Agent 侧真实页面
        await self.page.keyboard.type(MANUAL_MARKER, delay=60)
        await asyncio.sleep(0.6)
        value = await agent_page.input_value("#loop-probe")
        if value != MANUAL_MARKER:
            raise LoopFailed(f"noVNC 键入未生效：期望 {MANUAL_MARKER!r}，实际 {value!r}")
        self.t.steps.add("novnc_typed", value=value)
        await self._capture("02-novnc-typed")

        # Tab 把焦点移到按钮，回车触发按钮点击（都经 noVNC 键盘通道）
        await self.page.keyboard.press("Tab")
        await asyncio.sleep(0.4)
        await agent_page.wait_for_function(
            "() => document.activeElement && document.activeElement.id === 'loop-open'", timeout=15000)
        # 3) 回车打开原生弹窗（页面在真实浏览器里的按钮点击）
        before = {(w.get("id"), w.get("title")) for w in self.t.desktop.x11_windows()}
        await self.page.keyboard.press("Enter")
        site_state: Dict[str, Any] = {}
        expect_pid = ""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            site_state = self.t.site.status()
            if site_state.get("dialog_pid"):
                expect_pid = str(site_state["dialog_pid"])
                break
            if str(site_state.get("dialog", "")).startswith("error"):
                break
            await asyncio.sleep(0.3)
        self.evidence["dialog_site_state"] = site_state
        if str(site_state.get("dialog", "")).startswith("error"):
            raise LoopFailed(f"自查站启动原生弹窗失败：{site_state}")
        found = _wait_dialog(self.t, before, expect_pid=expect_pid)
        # 弹窗是页面按钮 → 自查站（node）→ 原生程序 这条链上真实生成的：
        # 祖先里必须有自查站进程，否则就是我们不认识的东西弹了个同名窗口。
        # wmctrl 拿不到 pid 时（少数 WM）无法核对，如实标注而不是假装通过。
        ancestor_ok = None
        # wmctrl 对 xmessage 这类程序常把 pid 报成 0：这不是真进程，跳过祖先核对，
        # 改用"自查站状态里确实有 dialog_pid"作为归属证据（下面一并记录）。
        if str(found.get("pid") or "").isdigit() and int(found["pid"]) > 1:
            host_pid = self.t.site.proc.pid if self.t.site and self.t.site.proc else None
            ancestor_ok = _has_ancestor(int(found["pid"]), [host_pid])
            if not ancestor_ok:
                raise LoopFailed(f"原生弹窗不是自查站发起的：pid={found['pid']}")
        self.t.steps.add("native_dialog_opened", pid=found["pid"],
                         parent_pid=found["parent_pid"], title=found["title"],
                         dialog_class=_dialog_class(), source=found.get("source"),
                         site_dialog_pid=str((site_state or {}).get("dialog_pid") or ""),
                         ancestor_verified=ancestor_ok)
        await self._capture("03-native-dialog")

        # 4) xdotool 在弹窗上按键：弹窗收到输入并自己关闭（Agent 用的同一条 X 通路）
        # 原生对话框（xmessage/zenity）不一定会拿到焦点，先用窗口管理器激活它。
        focused, backend = self.t.desktop.focus_window_detailed(
            found.get("window_id") or DIALOG_TITLE)
        if not focused and found.get("window_id"):
            # wmctrl -a 对 xmessage 这类无标题窗口常失败：用窗口 id 直接激活
            focused = self.t.desktop.activate_window(str(found["window_id"]))
            backend = "xdotool-windowactivate" if focused else backend
        self.t.steps.add("native_dialog_focused", ok=focused, backend=backend)
        self.t.desktop.key_press("Return")
        if self.t.site.dialog_host == "x11":
            closed = self._wait_window_gone(found.get("window_id"), 20.0)
            if not closed:
                raise LoopFailed("原生弹窗按 Enter 后没有关闭")
        else:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and self.t.site.status().get("dialog") != "confirmed":
                time.sleep(0.3)
            if self.t.site.status().get("dialog") != "confirmed":
                raise LoopFailed(f"弹窗宿主没有收到回车：{self.t.site.status()}")
        self.t.steps.add("native_dialog_closed")
        self.dialog = found
        out_dir = os.environ.get("GHA_OUTPUT_DIR", "")
        shot = self.t.desktop.screenshot()
        if out_dir and shot:
            with open(os.path.join(out_dir, "desktop-native-dialog.png"), "wb") as fh:
                fh.write(shot)
        await self._capture("03-native-dialog-confirmed")

        # 5) xdotool 把人工标记输入到终止用户自己的页面；截图进 output 作证据
        # 先清空：#loop-probe 里已经有 noVNC 键入的人工标记，再键入一次会变成两段拼接。
        page = await self.t.browser.get_active_page()
        await page.bring_to_front()
        await page.fill("#loop-probe", "")
        await page.click("#loop-probe")
        if not self.t.desktop.click(320, 278):
            raise LoopFailed("xdotool 点击终止用户页面失败")
        await asyncio.sleep(0.4)
        if not self.t.desktop.type_text(MANUAL_MARKER):
            raise LoopFailed("xdotool 键入终止用户页面失败")
        await asyncio.sleep(0.6)
        typed = await page.input_value("#loop-probe")
        if typed != MANUAL_MARKER:
            raise LoopFailed(f"人工标记未落到终止用户页面：{typed!r}")
        out_dir = os.environ.get("GHA_OUTPUT_DIR", "")
        shot = self.t.desktop.screenshot()
        if out_dir and shot:
            with open(os.path.join(out_dir, "desktop-agent-view.png"), "wb") as fh:
                fh.write(shot)
        self.evidence["site"] = self.t.site.status()
        self.t.steps.add("manual_input_reached_agent_page", value=typed, shot_bytes=len(shot),
                               dialog_host=self.t.site.dialog_host,
                               dialog_state=self.evidence["site"].get("dialog"))

        # 6) 交还前按住录制区一片已知内容，两侧（人/Agent）都能在录像里对上
        await asyncio.sleep(2.0)
        await self._capture("04-manual-input")

    def _wait_window_gone(self, window_id: Optional[str], timeout: float) -> bool:
        """按窗口 id 判断弹窗是否已关闭（wmctrl 的 pid 常为 0，id 才是稳定的）。"""
        if not window_id:
            return False
        deadline = time.monotonic() + timeout
        klass = _dialog_class()
        while time.monotonic() < deadline:
            rows = self.t.desktop.x11_windows()
            if not any(str(r.get("id")) == str(window_id) for r in rows) and not any(
                    str(r.get("class") or "").lower().split(".")[0] == klass for r in rows):
                return True
            time.sleep(0.3)
        return False

    async def complete(self) -> None:
        # 7) 门户自己的「交还控制权给 Agent」：POST /v1/handoff/complete → 停流
        await self.page.click("#btn-complete")
        await self.page.wait_for_function(
            "() => document.getElementById('conn-status').textContent.includes('已交还 Agent')",
            timeout=30000)
        self.t.steps.add("portal_completed",
                               conn=(await self.page.inner_text("#conn-status")).strip())
        await self._capture("05-portal-completed")

    async def stream_closed_after_complete(self) -> Dict[str, Any]:
        # 交还后 teardownStream() 移除 noVNC 画面容器：以后输入没有可转发的连接。
        await self.page.mouse.click(640, 400)
        await self.page.keyboard.press("a")
        await self.page.wait_for_timeout(1500)
        info = await self.page.evaluate("""() => ({
            canvases: document.querySelectorAll('#viewport-container div > canvas').length,
            conn: document.getElementById('conn-status').textContent.trim(),
        })""")
        self.evidence["after_complete"] = info
        return info

    async def _capture(self, name: str) -> None:
        out_dir = os.environ.get("GHA_OUTPUT_DIR", "")
        if out_dir:
            try:
                await self.page.screenshot(path=os.path.join(out_dir, f"human-{name}.png"))
            except Exception:
                pass

    async def close(self) -> None:
        for closer in (self.context, self.browser):
            try:
                if closer:
                    await closer.close()
            except Exception:
                pass
        if self.pw:
            try:
                await self.pw.stop()
            except Exception:
                pass


def _path_of(url: str) -> str:
    rest = url.split("://", 1)[-1]
    path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return path.split("#", 1)[0].split("?", 1)[0]


def _watch(url: str) -> bool:
    return any(k in url for k in ("/v1/handoff/", "/v1/live/", "/web/"))


def _has_ancestor(pid: int, ancestors: List[Optional[int]]) -> bool:
    wanted = {a for a in ancestors if a}
    if not os.path.isdir("/proc"):
        return True
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        if pid in wanted:
            return True
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                pid = int(fh.read().rsplit(")", 1)[-1].split()[1])
        except (OSError, ValueError, IndexError):
            return False
    return False


def _pid_alive(pid: Any) -> bool:
    try:
        target = int(pid)
    except (TypeError, ValueError):
        return False
    if os.path.isdir("/proc"):
        # Runner 上 /proc 是权威：僵尸进程（已退出未回收）不算活着
        stat = f"/proc/{target}/stat"
        try:
            with open(stat, encoding="utf-8") as fh:
                return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
        except OSError:
            return False
    try:
        os.kill(target, 0)
        return True
    except OSError:
        return False


def _dialog_class() -> str:
    """原生对话框程序的 WM_CLASS 前缀（xmessage → xmessage，zenity → zenity）。"""
    name = os.path.basename(os.environ.get("HANDOFF_DIALOG_BIN", "") or "")
    return name.split("-")[0].lower()


def _wait_dialog(test: HandoffLoopTest, before: Optional[set] = None,
                 expect_pid: str = "", timeout: float = 25.0) -> Dict[str, Any]:
    """等原生对话框出现，只读 wmctrl 的窗口表（不经过状态机）。

    判据按可靠性排序：WM_CLASS 命中（xmessage 这类程序不设标题、wmctrl 还常把 pid 报成
    0，只有 class 稳定）→ 标题命中 → 触发后新出现且进程祖先里有自查站的窗口。
    """
    baseline = set(before or ())
    host_pid = test.site.proc.pid if test.site and test.site.proc else None
    klass = _dialog_class()
    deadline = time.monotonic() + timeout
    seen: List[str] = []
    while time.monotonic() < deadline:
        for row in test.desktop.x11_windows():
            title = str(row.get("title") or "")
            row_class = str(row.get("class") or "").lower()
            pid = str(row.get("pid") or "")
            if title and title not in seen:
                seen.append(title)
            item = {"pid": pid, "parent_pid": None, "title": title,
                    "window_id": row.get("id"), "bounds": None}
            if klass and row_class.split(".")[0] == klass:
                return dict(item, source="wmctrl-class")
            if expect_pid and pid == expect_pid and pid != "0":
                return dict(item, source="wmctrl-pid")
            if DIALOG_TITLE in title:
                return dict(item, source="wmctrl-title")
        time.sleep(0.5)
    state = test.site.status() if test.site else {}
    raise LoopFailed(f"原生弹窗未出现（class={klass or '-'} pid={expect_pid or '-'}；"
                     f"窗口：{seen[:8]}；自查站状态：{state}）")


# ---------------------------------------------------------------------- 输出
def _public_video(item: Dict[str, Any]) -> Dict[str, Any]:
    # path 指向 Runner 本地临时文件：公开报告里不留，证据由 Reporter 侧单独登记
    return {k: v for k, v in item.items() if k != "path"}


def write_report(result: Dict[str, Any], reporter=None) -> str:
    """把指纹级证据写进 output：无 key_id、无 file_path、无本地路径。"""
    out_dir = os.environ.get("GHA_OUTPUT_DIR", "")
    recording = (result or {}).get("recording") or {}
    videos = [_public_video(v) for v in recording.get("videos") or []]
    report: Dict[str, Any] = {
        "schema": "gha-selftest-handoff/v1",
        "ok": bool(result.get("ok")),
        "error": result.get("error") or "",
        "steps": [s.get("step") for s in result.get("steps") or []],
        "markers": result.get("markers") or {},
        "dialog": {k: v for k, v in (result.get("dialog") or {}).items() if k != "bounds"},
        "encryption": {k: v for k, v in recording.items()
                       if k in ("checkpoint_id", "marker_seen")},
        "videos": videos,
        "recording_checks": {
            "all_encrypted": bool(videos) and all(v.get("encrypted") for v in videos),
            "all_non_empty": bool(videos) and all((v.get("plaintext_size") or 0) > 0
                                                  and (v.get("transfer_size") or 0) > 0 for v in videos),
            "sha_matches": bool(videos) and all(
                v.get("plaintext_sha256") and v.get("plaintext_sha256") == v.get("vault_sha256")
                for v in videos),
            "duration_positive": bool(videos) and all((v.get("duration_s") or 0) > 0 for v in videos),
            "frames_decoded": bool(videos) and all((v.get("decoded_frames") or 0) > 0 for v in videos),
        },
        "human_page": result.get("human_page") or {},
    }
    if reporter is not None:
        report["ffprobe"] = reporter.ffprobe
        report["durations_consistent"] = reporter.durations_consistent
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "handoff-report.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    return json.dumps({"ok": report["ok"], "error": report["error"], "steps": report["steps"],
                       "checks": report["recording_checks"],
                       "ffprobe": report.get("ffprobe"),
                       "durations_consistent": report.get("durations_consistent")},
                      ensure_ascii=False)


def write_result(result: Dict[str, Any]) -> int:
    out_dir = os.environ.get("GHA_OUTPUT_DIR", "")
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        write_report(result)
        with open(os.path.join(out_dir, "_outputs.env"), "w", encoding="utf-8") as fh:
            fh.write(f"handoff_loop={'ok' if result.get('ok') else 'failed'}\n")
            if result.get("error"):
                fh.write(f"handoff_loop_error={' '.join(str(result['error']).split())[:200]}\n")
    print(json.dumps({"ok": result.get("ok"), "error": result.get("error"),
                      "steps": [s.get("step") for s in result.get("steps") or []],
                      "recording": {k: v for k, v in (result.get("recording") or {}).items()
                                    if k not in ("videos",)}},
                     ensure_ascii=False), flush=True)
    return 0 if result.get("ok") else 1
