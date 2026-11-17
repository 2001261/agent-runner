"""Runner 临时执行环境资源清理与会话撤销。

遵循《2.0 迭代.md》第十九章 19.3 与第二十章清理规范。
任务结束或异常退出时：
1. 撤销全部授权 Token；
2. 停止 Cloudflare Tunnel；
3. 关闭录像与音频采集；
4. 关闭 Chromium 进程；
5. 关闭 VNC 与桌面窗口；
6. 清理 Runner 私有敏感目录。
"""

from __future__ import annotations

import os
import shutil
from typing import Optional

from .auth import AuthManager
from .browser import BrowserManager
from .desktop_stream import DesktopStreamManager
from .recording import DesktopRecorder
from .tunnel import TunnelProvider


class RuntimeCleaner:
    """环境资源彻底回收清理器"""

    def __init__(
        self,
        auth_mgr: AuthManager,
        tunnel: Optional[TunnelProvider] = None,
        browser: Optional[BrowserManager] = None,
        desktop_stream: Optional[DesktopStreamManager] = None,
        recorder: Optional[DesktopRecorder] = None,
        private_dirs: Optional[list[str]] = None,
    ):
        self.auth = auth_mgr
        self.tunnel = tunnel
        self.browser = browser
        self.desktop_stream = desktop_stream
        self.recorder = recorder
        self.private_dirs = private_dirs or []

    async def cleanup_all(self) -> None:
        """执行全套资源回收"""
        # 1. 撤销授权凭证
        self.auth.revoke_all()

        # 2. 停止录像
        if self.recorder:
            try:
                self.recorder.stop()
            except Exception:
                pass

        # 3. 关闭浏览器
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass

        # 4. 停止 VNC 流
        if self.desktop_stream:
            try:
                self.desktop_stream.stop_streaming()
            except Exception:
                pass

        # 5. 停止 Tunnel
        if self.tunnel:
            try:
                await self.tunnel.stop()
            except Exception:
                pass

        # 6. 删除本地敏感私有文件
        for p in self.private_dirs:
            if os.path.exists(p):
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                except Exception:
                    pass
