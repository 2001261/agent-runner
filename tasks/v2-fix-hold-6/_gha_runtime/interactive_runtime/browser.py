"""Chromium 单实例管理与 Playwright / CDP 集成。

遵循《2.0 迭代.md》第四章 4.3、4.4 与第七章。
核心原则：
1. 单一 Chromium 实例，Playwright、agent-browser 与 Handoff 共享同一实例；
2. 启动时开启 CDP 与 Accessibility；
3. 人工接管与自动化前后保持同一个 BrowserContext；
4. 退出前优雅关闭浏览器并确保落盘，以便完整 Profile 归档。
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


class BrowserManager:
    """单一 Chromium 实例生命周期与 Playwright 控制器"""

    def __init__(
        self,
        cdp_port: int = 9222,
        user_data_dir: Optional[str] = None,
        display: str = ":99",
        force_mock: bool = False,
    ):
        self.cdp_port = cdp_port
        self.display = display
        runner_temp = os.environ.get("RUNNER_TEMP", "/tmp")
        self.user_data_dir = user_data_dir or os.path.join(runner_temp, "gha-interactive-private", "chrome-profile")
        self.force_mock = force_mock
        self.last_error = ""

        self._process: Optional[subprocess.Popen] = None
        self._playwright = None
        self._browser: Optional[Any] = None
        self._context: Optional[Any] = None
        self._active_page: Optional[Any] = None

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

    async def start(self) -> bool:
        """启动 Chromium 进程并初始化 Playwright CDP 连接"""
        os.makedirs(self.user_data_dir, exist_ok=True)

        if self.force_mock:
            self._mock_url = "about:blank"
            return True
        if not HAS_PLAYWRIGHT:
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
                self._context = await self._playwright.chromium.launch_persistent_context(
                    self.user_data_dir,
                    headless=False,
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
                return True
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
                if os.environ.get("GITHUB_ACTIONS") == "true":
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
                return True
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
                if os.environ.get("GITHUB_ACTIONS") == "true":
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
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            if os.path.isfile(launch_log):
                with open(launch_log, encoding="utf-8", errors="replace") as f:
                    self.last_error += " | " + f.read()[-1000:]
            if os.environ.get("GITHUB_ACTIONS") == "true":
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
            self._context = await self._browser.new_context(storage_state=state)
            self._active_page = await self._context.new_page()
            # 不能在这里关闭 previous：持久化 Context 的关闭会连带整个 Browser，
            # 新 Context 也随之失效。旧 Context 统一由 close() 在任务结束时回收。
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            return False

    async def close(self) -> None:
        """优雅关闭浏览器进程并确保 Profile 落盘"""
        if self._context:
            try:
                await self._context.close()
            except Exception:
                pass
            self._context = None

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
