"""原生 Linux 桌面控制与 agent-desktop 集成。

遵循《2.0 迭代.md》第四章 4.5 与第八章。
支持：
- 窗口枚举与焦点切换；
- AT-SPI 无障碍快照；
- 键鼠物理输入与文本输入；
- 桌面截屏。
当缺少 X11 环境时提供优雅的测试模拟模式。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


class DesktopManager:
    """桌面窗口与 GUI 自动化管理器"""

    def __init__(self, display: str = ":99", force_mock: bool = False):
        self.display = display
        self.force_mock = force_mock

        # 检测可用系统工具
        self.has_agent_desktop = bool(shutil.which("agent-desktop"))
        self.has_xdotool = bool(shutil.which("xdotool"))
        self.has_wmctrl = bool(shutil.which("wmctrl"))
        self.has_import = bool(shutil.which("import")) or bool(shutil.which("scrot"))

    def list_windows(self) -> List[Dict[str, Any]]:
        """列出当前桌面所有窗口"""
        if self.force_mock or not self.has_wmctrl:
            return [
                {"id": "0x01", "title": "Chromium", "class": "chromium.Chromium", "geometry": "0,0,1280,800"},
                {"id": "0x02", "title": "Openbox", "class": "openbox.Openbox", "geometry": "0,0,1280,800"},
            ]

        env = os.environ.copy()
        env["DISPLAY"] = self.display
        try:
            res = subprocess.run(
                ["wmctrl", "-l", "-G", "-x"],
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
            )
            windows = []
            for line in res.stdout.splitlines():
                parts = line.split(None, 8)
                if len(parts) >= 8:
                    windows.append({
                        "id": parts[0],
                        "desktop": parts[1],
                        "geometry": f"{parts[2]},{parts[3]},{parts[4]},{parts[5]}",
                        "class": parts[6],
                        "title": parts[8] if len(parts) > 8 else "",
                    })
            return windows
        except Exception:
            return []

    def focus_window(self, window_title_or_id: str) -> bool:
        """激活并聚焦指定窗口"""
        if self.force_mock or not self.has_wmctrl:
            return True

        env = os.environ.copy()
        env["DISPLAY"] = self.display
        try:
            subprocess.run(
                ["wmctrl", "-a", window_title_or_id],
                env=env,
                check=True,
                timeout=5,
            )
            return True
        except Exception:
            return False

    def snapshot(self) -> Dict[str, Any]:
        """获取桌面无障碍与窗口结构快照"""
        windows = self.list_windows()
        result = {
            "display": self.display,
            "windows": windows,
            "active_window": windows[0] if windows else None,
            "accessibility_supported": self.has_agent_desktop,
        }
        if self.has_agent_desktop and not self.force_mock:
            if windows:
                target = windows[0].get("title") or windows[0].get("id", "")
                if target:
                    self.focus_window(target)
            env = os.environ.copy()
            env["DISPLAY"] = self.display
            try:
                command = ["agent-desktop", "snapshot", "-i"]
                # 优先使用 agent-desktop 自己的 window id，而不是 X11 焦点或 wmctrl id。
                listing = subprocess.run(
                    ["agent-desktop", "list-windows"],
                    env=env, capture_output=True, text=True, timeout=15,
                )
                if listing.returncode == 0 and listing.stdout.strip():
                    payload = json.loads(listing.stdout)
                    data = payload.get("data", {})
                    candidates = data.get("windows", data) if isinstance(data, dict) else data
                    if isinstance(candidates, list) and candidates:
                        first = candidates[0]
                        window_id = first.get("id") or first.get("window_id")
                        if window_id:
                            command.extend(["--window-id", str(window_id)])
                res = subprocess.run(
                    command,
                    env=env, capture_output=True, text=True, timeout=20,
                )
                if res.returncode == 0 and res.stdout.strip():
                    result["agent_desktop"] = json.loads(res.stdout)
                else:
                    result["agent_desktop_error"] = (res.stderr or res.stdout)[:200]
                    result["accessibility_supported"] = False
            except Exception as exc:
                result["agent_desktop_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
                result["accessibility_supported"] = False
        return result

    def click(self, x: int, y: int, button: int = 1) -> bool:
        """在屏幕物理坐标执行点击"""
        if self.force_mock or not self.has_xdotool:
            return True

        env = os.environ.copy()
        env["DISPLAY"] = self.display
        try:
            subprocess.run(
                ["xdotool", "mousemove", str(x), str(y), "click", str(button)],
                env=env,
                check=True,
                timeout=5,
            )
            return True
        except Exception:
            return False

    def type_text(self, text: str) -> bool:
        """键入文本字符串"""
        if self.force_mock or not self.has_xdotool:
            return True

        env = os.environ.copy()
        env["DISPLAY"] = self.display
        try:
            subprocess.run(
                ["xdotool", "type", "--delay", "12", text],
                env=env,
                check=True,
                timeout=10,
            )
            return True
        except Exception:
            return False

    def key_press(self, key_combination: str) -> bool:
        """触发快捷键 (例如: 'ctrl+c', 'Return', 'alt+F4')"""
        if self.force_mock or not self.has_xdotool:
            return True

        env = os.environ.copy()
        env["DISPLAY"] = self.display
        try:
            subprocess.run(
                ["xdotool", "key", key_combination],
                env=env,
                check=True,
                timeout=5,
            )
            return True
        except Exception:
            return False

    def screenshot(self) -> bytes:
        """捕获完整虚拟桌面截图"""
        if self.force_mock:
            # 最小 1x1 PNG
            return (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff"
                b"?\x00\x05\xfe\x02\xfe\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82"
            )

        env = os.environ.copy()
        env["DISPLAY"] = self.display

        # 尝试 import (ImageMagick) 或 scrot
        if shutil.which("import"):
            try:
                res = subprocess.run(
                    ["import", "-window", "root", "png:-"],
                    env=env,
                    capture_output=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout:
                    return res.stdout
            except Exception:
                pass

        return b""
