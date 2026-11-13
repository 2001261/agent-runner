"""Chromium 单实例管理与 Playwright / CDP 集成。

遵循《2.0 迭代.md》第四章 4.3、4.4 与第七章。
核心原则：
1. 单一 Chromium 实例，Playwright、agent-browser 与 Handoff 共享同一实例；
2. 启动时开启 CDP 与 Accessibility；
3. 人工接管与自动化前后保持同一个 BrowserContext；
4. 退出前优雅关闭浏览器并确保落盘，以便完整 Profile 归档；
5. 按配置采集浏览器录像与 Playwright Trace，产物只写入 Runner 私有目录。
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class BrowserRestartExhausted(RuntimeError):
    """Chromium 有界重启次数已用尽：调用方必须如实上报失败，不得当作健康。"""


def read_chromium_version(profile_dir: str) -> str:
    """读取 Profile 目录下 Chromium 写入的版本号（`Last Version`），无则返回空串。

    归档侧用同一个文件生成 compatibility_meta，恢复侧据此比较大版本。
    """
    try:
        with open(os.path.join(profile_dir, "Last Version"), encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


class BrowserManager:
    """单一 Chromium 实例生命周期与 Playwright 控制器"""

    def __init__(
        self,
        cdp_port: int = 9222,
        user_data_dir: Optional[str] = None,
        display: str = ":99",
        force_mock: bool = False,
        video_enabled: bool = False,
        video_dir: Optional[str] = None,
        video_size: Optional[Tuple[int, int]] = None,
        video_fps: int = 25,
        trace_enabled: bool = False,
        trace_dir: Optional[str] = None,
        restart_max_attempts: int = 3,
        restart_window_seconds: float = 600.0,
        restart_backoff_seconds: float = 1.0,
    ):
        self.cdp_port = cdp_port
        self.display = display
        self.runner_temp = os.environ.get("RUNNER_TEMP", "/tmp")
        self.private_root = os.path.join(self.runner_temp, "gha-interactive-private")
        self.user_data_dir = user_data_dir or os.path.join(self.private_root, "chrome-profile")
        self.force_mock = force_mock
        self.last_error = ""

        # 录像与 Trace 均落在私有目录下的独立子目录，绝不进入 output/ 或公开日志
        self.video_enabled = video_enabled
        self.video_dir = video_dir or os.path.join(self.private_root, "browser-video")
        self.video_size = video_size
        # Playwright 录像接口不暴露帧率；保留该字段以便将来复用时透传
        self.video_fps = video_fps
        self.trace_enabled = trace_enabled
        self.trace_dir = trace_dir or os.path.join(self.private_root, "browser-trace")

        self._process: Optional[subprocess.Popen] = None
        self._playwright = None
        self._browser: Optional[Any] = None
        self._context: Optional[Any] = None
        self._active_page: Optional[Any] = None

        self._video_started = False
        self._trace_started = False
        # 每次 start() 生成一个批次 ID，避免多次启动的录像/Trace 文件互相混淆
        self._run_id = ""
        self._run_seq = 0
        self._video_out: List[str] = []
        self._video_handles: List[Any] = []
        self._trace_out: List[str] = []
        self._capture_errors: List[str] = []

        # 运行期崩溃检测与有界重启：窗口内的重启次数超限后只如实上报，不再尝试。
        self.restart_max_attempts = max(0, int(restart_max_attempts))
        self.restart_window_seconds = max(0.0, float(restart_window_seconds))
        self.restart_backoff_seconds = max(0.0, float(restart_backoff_seconds))
        self._restart_times: List[float] = []
        self._restart_count = 0
        self.crashes = 0
        self.reconnected = 0
        self._health = "stopped"
        self._last_healthy_url = ""
        self._outage: Optional[Dict[str, Any]] = None

        # 模拟状态（无图形或无浏览器依赖环境使用）
        self._mock_url = "about:blank"
        self._mock_title = "Mock Browser Page"
        self._mock_dom = "<html><body><h1>gha-runner Interactive</h1></body></html>"

    @property
    def is_running(self) -> bool:
        if self.force_mock:
            return True
        if self._process is not None and self._process.poll() is None:
            return True
        return self._context is not None

    @property
    def capture_enabled(self) -> bool:
        return self.video_enabled or self.trace_enabled

    # ------------------------------------------------------------------
    # 运行期健康检测与有界重启
    # ------------------------------------------------------------------

    @property
    def restarts_exhausted(self) -> bool:
        return self._restart_count >= self.restart_max_attempts

    def _probe_errors(self) -> List[str]:
        """同步探测浏览器是否仍然可用（不经网络，可在事件循环里直接调用）。"""
        errors: List[str] = []
        proc = self._process
        if proc is not None and proc.poll() is not None:
            # 外部 Chromium 已退出：回收句柄，下次启动会重新拉起进程
            self._process = None
            errors.append("Chromium 进程已退出（退出码 %s）" % proc.returncode)
            proc = None
        if proc is None and self._context is not None:
            browser = self._browser
            connected = getattr(browser, "is_connected", None)
            if callable(connected):
                try:
                    if not connected():
                        errors.append("CDP 连接已断开")
                except Exception:  # noqa: BLE001 - 探测自身异常同样视为断开
                    errors.append("CDP 连接探测失败")
        return errors

    def check_health(self) -> Optional[str]:
        """返回故障描述；``None`` 表示仍在使用。调用方据此如实标记，不做假成功。"""
        if self.force_mock:
            return None
        errors = self._probe_errors()
        if errors:
            self._mark_crashed(errors[0])
            return self.last_error
        if self._context is None:
            if not self.last_error:
                self.last_error = "浏览器不可用（没有活动的 BrowserContext）"
            self._health = "down"
            return self.last_error
        self._health = "running"
        self._remember_url()
        return None

    def _mark_crashed(self, reason: str) -> None:
        self.crashes += 1
        self._health = "crashed"
        self.last_error = reason
        if self._outage is None:
            self._outage = {"at": time.time(), "reason": reason}

    @staticmethod
    def _close_quietly(handle: Any) -> None:
        try:
            handle.close()
        except Exception:  # noqa: BLE001 - 资源可能已随进程消失
            pass

    async def restart(self) -> bool:
        """有界重启：回收旧句柄后用同一 user_data_dir 重新拉起。

        Profile 目录原样复用，不做移动/清理/迁移；重启失败时记录脱敏原因并返回 False，
        由调用方决定是否继续（``supervisor`` 在次数用尽时如实失败）。
        """
        if self.force_mock:
            return True
        try:
            if self._context is not None:
                self._close_quietly(self._context)
            if self._browser is not None:
                self._close_quietly(self._browser)
            if self._playwright is not None:
                stop = getattr(self._playwright, "stop", None)
                if stop is not None:
                    result = stop()
                    if asyncio.iscoroutine(result):
                        await result
        except Exception as exc:  # noqa: BLE001 - 回收失败不阻止重新拉起
            self.last_error = f"回收旧浏览器句柄失败: {type(exc).__name__}"
        finally:
            self._context = None
            self._browser = None
            self._active_page = None
            self._playwright = None
            self._process = None
            self._video_started = False
            self._trace_started = False

        now = time.monotonic()
        self._restart_times = [t for t in self._restart_times
                               if now - t < self.restart_window_seconds]
        if len(self._restart_times) >= self.restart_max_attempts:
            self._health = "restart_exhausted"
            self.last_error = ("Chromium 在 %.0f 秒内已重启 %d 次，达到上限；不再自动重启"
                                % (self.restart_window_seconds, len(self._restart_times)))
            raise BrowserRestartExhausted(self.last_error)
        self._restart_times.append(now)
        self._restart_count += 1

        if self.restart_backoff_seconds:
            await asyncio.sleep(self.restart_backoff_seconds)
        ok = await self.start()
        if not ok:
            self._health = "restart_failed"
            if not self.last_error:
                self.last_error = "Chromium 重启失败（原因未知）"
            return False
        self.reconnected += 1
        self._health = "running"
        if self._outage is not None:
            self._outage["recovered_at"] = time.time()
            self._outage["restarts"] = self._restart_count
            self._outage = None
        await self._restore_last_url()
        return True

    async def _restore_last_url(self) -> None:
        """把崩溃前的页面地址带回来；失败不影响“已恢复”结论，只记入错误列表。"""
        url = self._last_healthy_url
        if not url or url in ("about:blank", "chrome://newtab/") or not self._active_page:
            return
        try:
            await self._active_page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as exc:  # noqa: BLE001
            self._capture_errors.append(
                "恢复崩溃前页面失败: %s" % type(exc).__name__)

    def health(self) -> Dict[str, Any]:
        """运行期健康摘要：只含状态与脱敏原因，可安全写入日志/状态接口。"""
        return {
            "status": self._health,
            "crashes": self.crashes,
            "restarts": self._restart_count,
            "reconnected": self.reconnected,
            "running": self.is_running,
            "last_error": self.last_error,
        }

    async def start(self) -> bool:
        """启动 Chromium 进程并初始化 Playwright CDP 连接"""
        ok = await self._launch()
        if not ok:
            self._health = "failed"
        elif not self.force_mock:
            self._health = "running"
            self._outage = None
            self._remember_url()
        return ok

    def _remember_url(self) -> None:
        """记录最近一次确认可用的页面地址，崩溃重启后据此把页面带回来。"""
        page = self._active_page
        if page is None:
            return
        try:
            if not page.is_closed():
                self._last_healthy_url = page.url
        except Exception:  # noqa: BLE001 - 页面已随崩溃失效，不影响“进程存活”结论
            pass

    async def _launch(self) -> bool:
        os.makedirs(self.user_data_dir, exist_ok=True)
        # 持久化 Context 被关闭后整个 Browser 随之失效；重启动时必须先清掉旧句柄，
        # 否则 get_active_page / restore_storage_state 会继续用已关闭的 Context。
        self._browser = None
        self._context = None
        self._active_page = None
        self._capture_errors = []
        self._video_out = []
        self._video_handles = []
        self._trace_out = []
        self._video_started = False
        self._trace_started = False
        self._start_capture_run()

        if self.force_mock:
            self._mock_url = "about:blank"
            return True
        if not HAS_PLAYWRIGHT:
            if self.capture_enabled:
                self.last_error = "录像/Trace 已启用，但 Playwright 不可用"
                return False
            if os.environ.get("GITHUB_ACTIONS") == "true":
                return False
            self.force_mock = True
            self._mock_url = "about:blank"
            return True

        # 默认使用 Playwright 自带 Chromium + 持久化用户目录：避免系统 Chrome
        # CDP 启动差异，同时保证 Profile 可真实归档。可用 GHA_CHROME_BIN 显式覆盖。
        if not os.environ.get("GHA_CHROME_BIN"):
            try:
                self._playwright = await async_playwright().start()
                browser_env = os.environ.copy()
                browser_env["DISPLAY"] = self.display
                browser_env["ACCESSIBILITY_ENABLED"] = "1"
                self._context = await self._playwright.chromium.launch_persistent_context(
                    self.user_data_dir,
                    headless=False,
                    env=browser_env,
                    record_video_dir=self.video_dir if self.video_enabled else None,
                    record_video_size={"width": self.video_size[0], "height": self.video_size[1]} if self.video_size else None,
                    args=[
                        f"--remote-debugging-port={self.cdp_port}",
                        "--force-renderer-accessibility",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ],
                )
                self._browser = self._context.browser
                pages = self._context.pages
                self._active_page = pages[0] if pages else await self._context.new_page()
                # 录制开启时不允许静默落到 mock，否则录像永远不会产生
                if not await self._begin_capture():
                    return False
                return True
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
                if os.environ.get("GITHUB_ACTIONS") == "true" or self.capture_enabled:
                    return False
                self.force_mock = True
                return True

        # 查找 chromium 或 google-chrome 可执行路径
        chrome_bin = os.environ.get("GHA_CHROME_BIN")
        if not chrome_bin:
            for cand in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]:
                p = shutil.which(cand)
                if p:
                    chrome_bin = p
                    break

        if not chrome_bin:
            # 尝试通过 playwright 内部驱动启动或降级为 mock 模式
            try:
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=False,
                    args=[
                        f"--remote-debugging-port={self.cdp_port}",
                        "--force-renderer-accessibility",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                    ],
                )
                self._context = await self._browser.new_context()
                self._active_page = await self._context.new_page()
                if not await self._begin_capture():
                    return False
                return True
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                if os.environ.get("GITHUB_ACTIONS") == "true" or self.capture_enabled:
                    return False
                self.force_mock = True
                return True

        # 使用外部进程启动独立 Chromium（以可见窗口运行在虚拟 DISPLAY 上）
        env = os.environ.copy()
        env["DISPLAY"] = self.display
        env["ACCESSIBILITY_ENABLED"] = "1"

        args = [
            chrome_bin,
            f"--remote-debugging-port={self.cdp_port}",
            f"--user-data-dir={self.user_data_dir}",
            "--force-renderer-accessibility",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--window-size=1280,800",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ]

        launch_log = os.path.join(os.path.dirname(self.user_data_dir), "chrome-launch.log")
        try:
            with open(launch_log, "wb") as log_file:
                self._process = subprocess.Popen(
                    args,
                    env=env,
                    stdout=log_file,
                    stderr=log_file,
                )
            self._playwright = await async_playwright().start()
            last_cdp_error = None
            for _ in range(30):
                try:
                    self._browser = await self._playwright.chromium.connect_over_cdp(
                        f"http://127.0.0.1:{self.cdp_port}", timeout=1000)
                    break
                except Exception as exc:
                    last_cdp_error = exc
                    await asyncio.sleep(0.5)
            if self._browser is None:
                raise RuntimeError(f"CDP 连接失败: {last_cdp_error}")
            contexts = self._browser.contexts
            self._context = contexts[0] if contexts else await self._browser.new_context()
            pages = self._context.pages
            self._active_page = pages[0] if pages else await self._context.new_page()
            if not await self._begin_capture():
                return False
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            if os.path.isfile(launch_log):
                with open(launch_log, encoding="utf-8", errors="replace") as f:
                    self.last_error += " | " + f.read()[-1000:]
            if os.environ.get("GITHUB_ACTIONS") == "true" or self.capture_enabled:
                return False
            self.force_mock = True
            return True

    async def get_active_page(self) -> Any:
        if self.force_mock:
            return None
        if not self._active_page and self._context:
            pages = self._context.pages
            self._active_page = pages[0] if pages else await self._context.new_page()
        return self._active_page

    async def navigate(self, url: str) -> Dict[str, Any]:
        """导航至指定 URL"""
        if self.force_mock:
            self._mock_url = url
            self._mock_title = f"Page: {url}"
            self._mock_dom = f"<html><body><h1>Loaded {url}</h1></body></html>"
            return {"url": url, "status": 200, "title": self._mock_title}

        page = await self.get_active_page()
        if not page:
            return {"error": "No active page"}

        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        status = resp.status if resp else 200
        title = await page.title()
        return {"url": page.url, "status": status, "title": title}

    async def snapshot(self) -> Dict[str, Any]:
        """获取当前页面 DOM 与无障碍树快照"""
        if self.force_mock:
            return {
                "url": self._mock_url,
                "title": self._mock_title,
                "accessibility": {"role": "document", "name": self._mock_title},
                "dom_sample": self._mock_dom,
            }

        page = await self.get_active_page()
        if not page:
            return {"error": "No active page"}

        url = page.url
        title = await page.title()
        try:
            ax = await page.accessibility.snapshot()
        except Exception:
            ax = {}

        try:
            content = await page.content()
            dom_sample = content[:4000]
        except Exception:
            dom_sample = ""

        return {
            "url": url,
            "title": title,
            "accessibility": ax or {},
            "dom_sample": dom_sample,
        }

    async def screenshot(self) -> bytes:
        """捕获当前页面截图"""
        if self.force_mock:
            # 构造最小 1x1 PNG
            return (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff"
                b"?\x00\x05\xfe\x02\xfe\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82"
            )

        page = await self.get_active_page()
        if not page:
            return b""
        return await page.screenshot(type="png")

    async def dispatch_mouse(self, event_type: str, x: int, y: int, button: str = "left", click_count: int = 1) -> bool:
        """注入鼠标事件"""
        if self.force_mock:
            return True
        page = await self.get_active_page()
        if not page:
            return False
        try:
            if event_type == "click":
                await page.mouse.click(x, y, button=button, click_count=click_count)
            elif event_type == "move":
                await page.mouse.move(x, y)
            elif event_type == "down":
                await page.mouse.down(button=button)
            elif event_type == "up":
                await page.mouse.up(button=button)
            return True
        except Exception:
            return False

    async def dispatch_key(self, event_type: str, key: str, text: Optional[str] = None) -> bool:
        """注入键盘按键与文字"""
        if self.force_mock:
            return True
        page = await self.get_active_page()
        if not page:
            return False
        try:
            if event_type == "press":
                await page.keyboard.press(key)
            elif event_type == "type" and text:
                await page.keyboard.type(text)
            elif event_type == "down":
                await page.keyboard.down(key)
            elif event_type == "up":
                await page.keyboard.up(key)
            return True
        except Exception:
            return False

    async def export_storage_state(self) -> Dict[str, Any]:
        """导出当前认证状态（Cookie 与 Storage）"""
        if self.force_mock:
            return {
                "cookies": [{"name": "mock_session", "value": "12345", "domain": "example.com", "path": "/"}],
                "origins": [{"origin": "https://example.com", "localStorage": [{"name": "token", "value": "xyz"}]}],
            }
        if not self._context:
            return {"cookies": [], "origins": []}
        try:
            return await self._context.storage_state(indexed_db=True)
        except Exception:
            return await self._context.storage_state()

    async def cdp_command(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """对活跃页面所在 Context 发一条 CDP 命令（非 mock 模式）。"""
        if self.force_mock:
            return {"mock": True}
        page = await self.get_active_page()
        if not page:
            raise RuntimeError("No active page")
        session = await page.context.new_cdp_session(page)
        return await session.send(method, params or {})

    async def set_download_behavior(self, directory: str, behavior: str = "allow") -> Dict[str, Any]:
        """让 Chromium 自己设置下载目录（写入内存偏好，关闭时落盘到 Profile 的 Preferences）。"""
        return await self.cdp_command("Browser.setDownloadBehavior",
                                      {"behavior": behavior, "downloadPath": directory,
                                       "eventsEnabled": False})

    async def restore_storage_state(self, state: Dict[str, Any]) -> bool:
        """恢复认证状态到当前 BrowserContext"""
        if self.force_mock:
            return True
        if not self._browser:
            return False
        try:
            previous = self._context
            # 先建立新 Context：持久化 Context 一旦关闭，整个 Browser 也会随之关闭，
            # 旧的实现顺序因此必然触发 TargetClosedError。
            new_context = self._browser.new_context
            if self.video_enabled:
                kwargs: Dict[str, Any] = {"record_video_dir": self.video_dir}
                if self.video_size:
                    kwargs["record_video_size"] = {"width": self.video_size[0], "height": self.video_size[1]}
                self._context = await new_context(storage_state=state, **kwargs)
            else:
                self._context = await new_context(storage_state=state)
            self._active_page = await self._context.new_page()
            if not await self._begin_capture():
                return False
            # 不能在这里关闭 previous：持久化 Context 的关闭会连带整个 Browser，
            # 新 Context 也随之失效。旧 Context 统一由 close() 在任务结束时回收。
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            return False

    async def close(self) -> None:
        """优雅关闭浏览器进程并确保 Profile、录像与 Trace 落盘"""
        if self._context:
            # Trace 必须在 Context 关闭前停止，否则来不及写入文件
            await self._stop_trace()
            # 录像确认补丁必须紧跟 Context 关闭执行，否则可能读取到已释放的页面
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None

        # Context 关闭后 Playwright 才把录像写盘，需等待文件名出现
        await self._settle_video()

        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        self._health = "stopped"
        self._outage = None

    # ------------------------------------------------------------------
    # 浏览器录像与 Playwright Trace 生命周期
    # ------------------------------------------------------------------

    def _start_capture_run(self) -> None:
        """为本次启动分配独立的采集批次 ID"""
        self._run_seq += 1
        self._run_id = f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{os.getpid()}-{self._run_seq}"

    def _capture_path(self, base_dir: str, stem: str, ext: str) -> str:
        return os.path.join(base_dir, stem, f"{stem}-{self._run_id}{ext}")

    def _prepare_capture_dir(self, path: str) -> bool:
        parent = os.path.dirname(os.path.abspath(path))
        try:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            return True
        except Exception as exc:
            self._capture_errors.append(f"创建录制目录失败: {type(exc).__name__}")
            return False

    async def _begin_capture(self) -> bool:
        """在当前 Context 上开启 Trace；录像由 Context 参数负责。

        返回 False 表示录制已配置但启动失败，调用方不得伪装成功。
        """
        if not self._context:
            if self.capture_enabled:
                self._capture_errors.append("浏览器未启动，无法开始录像/Trace")
                return False
            return True

        if self.video_enabled:
            if os.environ.get("GHA_CHROME_BIN"):
                # 外部 Chrome 经 CDP 接入时无法由 Playwright 录制视频
                self._capture_errors.append("GHA_CHROME_BIN 外部浏览器模式不支持录像")
                return False
            self._video_started = True

        if self.trace_enabled:
            trace_path = self._capture_path(self.trace_dir, "trace", ".zip")
            if not self._prepare_capture_dir(trace_path):
                return False
            self._trace_out.append(trace_path)
            try:
                await self._context.tracing.start(screenshots=True, snapshots=True, sources=False)
                self._trace_started = True
            except Exception as exc:
                self._capture_errors.append(f"Trace 启动失败: {type(exc).__name__}: {str(exc)[:200]}")
                return False
        self._note_video_handles()
        return True

    async def _stop_trace(self) -> None:
        if not self._trace_started or not self._context:
            self._trace_started = False
            return
        self._trace_started = False
        trace_path = self._trace_out[-1] if self._trace_out else None
        try:
            await self._context.tracing.stop(path=trace_path)
        except Exception as exc:
            # 未配对停止或导出失败时 trace 文件不会存在，capture_artifacts 不会登记它
            self._capture_errors.append(f"Trace 停止/导出失败: {type(exc).__name__}: {str(exc)[:200]}")

    def _note_video_handles(self) -> None:
        """记录当前页面的 video 句柄：Context 关闭后 pages 为空，必须提前持有"""
        try:
            pages = list(self._context.pages) if self._context is not None else []
        except Exception:
            return
        for page in pages:
            try:
                video = page.video
            except Exception:
                continue
            if video is not None and all(v is not video for v in self._video_handles):
                self._video_handles.append(video)

    async def _settle_video(self, timeout: float = 15.0) -> None:
        """等待 Context 关闭后 Playwright 写出录像文件"""
        if not self._video_started:
            return
        self._note_video_handles()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if await self._collect_video_files():
                return
            await asyncio.sleep(0.2)
        self._capture_errors.append("等待浏览器录像落盘超时")

    async def _collect_video_files(self) -> List[str]:
        """从预先持有的 video 句柄收集已落盘的录像文件路径"""
        found: List[str] = []
        for video in self._video_handles:
            try:
                found.append(str(await video.path()))
            except Exception:
                continue
        if found:
            self._video_out = sorted(set(self._video_out) | set(found))
        return self._video_out

    async def capture_artifacts(self) -> List[Dict[str, str]]:
        """返回本次运行已落盘的录像与 Trace 文件（仅路径，文件不存在则不返回）"""
        artifacts: List[Dict[str, str]] = []
        if self.video_enabled:
            if self._video_started and not self._video_out:
                await self._collect_video_files()
            for path in self._video_out:
                if path and os.path.isfile(path):
                    artifacts.append({"kind": "browser_video", "path": path})
        if self.trace_enabled:
            for path in self._trace_out:
                if path and os.path.isfile(path):
                    artifacts.append({"kind": "playwright_trace", "path": path})
        return artifacts

    @property
    def capture_errors(self) -> List[str]:
        return list(self._capture_errors)
