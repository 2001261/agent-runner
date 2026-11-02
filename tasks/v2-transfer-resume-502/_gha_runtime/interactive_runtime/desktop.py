"""原生 Linux 桌面控制与 agent-desktop 集成。

遵循《2.0 迭代.md》第四章 4.5 与第八章。
支持：
- 窗口枚举与焦点切换；
- AT-SPI 无障碍快照；
- 键鼠物理输入与文本输入；
- 桌面截屏。
当缺少 X11 环境时提供优雅的测试模拟模式。

agent-desktop 的约定（依据 1.0.2 包内 Linux skill 与 docs/json-output.md）：
- 每条命令在 stdout 打印且只打印一个 JSON envelope：成功为
  ``{"version", "ok": true, "command", "data"}``，失败为
  ``{"ok": false, "command", "error": {"code", "message", ...}}``；
- ``list-windows`` 的 ``data`` 本身就是窗口对象数组，每行含 ``id``、``title``、
  ``app_name``、``pid``、``is_focused``，窗口 id 是 34~70 个字符的不透明句柄；
- ``snapshot --window-id <id>`` 以该窗口为根，同时打开的对话框必须按 id 指定；
  2.2+ 会用 ``ok: true`` + ``complete: false`` 表示预算耗尽的部分树；
- 退出码：0 成功、1 结构化错误、2 参数错误，都需读取 envelope 的 ``error.code``。

输入类命令（取自 docs/commands/mouse.mdx、keyboard.mdx、observation.mdx）：
- ``--headed mouse-click --xy X,Y [--button left|right|middle] [--count N]``：坐标点击，
  不带 ``--headed`` 会被 ``POLICY_DENIED`` 拒绝；
- ``press COMBO [--window-id ID]``：组合键就是 ``ctrl+c`` 这种写法，直接兼容；
- ``screenshot`` 不传 PATH 时把 PNG 以 base64 放在 ``data.data``，传 PATH 则写文件；
- agent-desktop 没有“裸键盘文本”命令（``type`` 需要快照 ref，得先 snapshot 定位控件），
  因此 type_text 直接使用 xdotool ``type``，缺少 xdotool 就报 XDOTOOL_MISSING。

所有输入方法：force_mock 时跳过；否则真实投递成功返回 True，全部后端失败返回
False，并把最后一个结构化错误留在 ``last_error`` 里，绝不把“没投递”当成功。
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

AGENT_DESKTOP = "agent-desktop"

_LIST_WINDOWS_TIMEOUT = 20
_SNAPSHOT_TIMEOUT = 30
_INPUT_TIMEOUT = 15
_SCREENSHOT_TIMEOUT = 20

_BUTTON_NAMES = {1: "left", 2: "middle", 3: "right"}


class AgentDesktopError(RuntimeError):
    """agent-desktop 调用失败，保留结构化错误码供上层区分与上报。"""

    def __init__(self, code: str, message: str, suggestion: str = "", details: Any = None):
        super().__init__(f"{code}: {message}" + (f"（{suggestion}）" if suggestion else ""))
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.suggestion:
            out["suggestion"] = self.suggestion
        if self.details is not None:
            out["details"] = self.details
        return out


def _short(value: Any, limit: int = 200) -> str:
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _load_envelope(stdout: str) -> Dict[str, Any]:
    """提取 agent-desktop 输出中的 JSON envelope。

    正常返回单行 JSON；日志（如 launcher 提示）若混入 stdout，则退回到
    最后一个能解析且带 ``ok`` 字段的对象。
    """
    text = (stdout or "").strip()
    if not text:
        raise ValueError("stdout 为空")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
        for line in reversed(text.splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                candidate = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and "ok" in candidate:
                payload = candidate
                break
        if payload is None:
            raise ValueError("未找到 JSON envelope")
    if not isinstance(payload, dict) or "ok" not in payload:
        raise ValueError("JSON 中没有 ok 字段")
    return payload


def parse_window_rows(data: Any) -> List[Dict[str, Any]]:
    """把 ``list-windows`` 的 ``data`` 归一化为窗口行列表。

    兼容 ``data`` 为数组（官方形态）、``{"windows": [...]}`` 以及带一层包装的
    ``{"result": ...}``；无法识别的结构返回空列表，由调用方按“无窗口”处理。
    """
    for _ in range(3):
        if isinstance(data, list):
            rows = []
            for item in data:
                if isinstance(item, dict) and item.get("id"):
                    rows.append(item)
            return rows
        if isinstance(data, dict):
            for key in ("windows", "items", "result", "data"):
                if key in data:
                    data = data[key]
                    break
            else:
                return []
            continue
        return []
    return []


def _format_bounds(bounds: Any) -> str:
    """agent-desktop 的 ``bounds``（x/y/width/height）转 wmctrl 风格的几何串。"""
    if not isinstance(bounds, dict):
        return ""
    try:
        return "{x},{y},{width},{height}".format(
            x=int(bounds.get("x", 0)),
            y=int(bounds.get("y", 0)),
            width=int(bounds.get("width", 0)),
            height=int(bounds.get("height", 0)),
        )
    except (TypeError, ValueError):
        return ""


def select_window(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """优先选择浏览器窗口，否则取 ``list-windows`` 的第一行（它总是聚焦窗口）。"""
    for row in rows:
        app = str(row.get("app_name") or "").lower()
        title = str(row.get("title") or "").lower()
        if "chrom" in app or "chrom" in title:
            return row
    return rows[0] if rows else None


def _merge_tool_error(primary: Optional[AgentDesktopError], fallback: Optional[AgentDesktopError]) -> Optional[AgentDesktopError]:
    """agent-desktop 优先：保留它的错误码，把 xdotool 兜底的错误放进 details。"""
    if primary is None:
        return fallback
    if fallback is not None:
        merged = dict(primary.details) if isinstance(primary.details, dict) else {"details": primary.details}
        merged["fallback"] = fallback.to_dict()
        return AgentDesktopError(primary.code, primary.message, primary.suggestion, merged)
    return primary


def _tool_missing(name: str) -> AgentDesktopError:
    return AgentDesktopError(f"{name.upper().replace('-', '_')}_MISSING", f"未找到 {name} 可执行文件")


class DesktopManager:
    """桌面窗口与 GUI 自动化管理器"""

    def __init__(self, display: str = ":99", force_mock: bool = False):
        self.display = display
        self.force_mock = force_mock

        # 检测可用系统工具
        self.has_agent_desktop = bool(shutil.which(AGENT_DESKTOP))
        self.has_xdotool = bool(shutil.which("xdotool"))
        self.has_wmctrl = bool(shutil.which("wmctrl"))
        self.has_import = bool(shutil.which("import")) or bool(shutil.which("scrot"))
        self._last_agent_desktop_error: Optional[AgentDesktopError] = None
        self.last_error: Optional[AgentDesktopError] = None
        self._agent_rows: List[Dict[str, Any]] = []

    def _record_error(self, err: Optional[AgentDesktopError]) -> None:
        """记住最近一次输入/截图失败；成功时清空。``last_error`` 供网关回传给 Agent。"""
        self.last_error = err

    def last_error_dict(self) -> Optional[Dict[str, Any]]:
        return self.last_error.to_dict() if self.last_error is not None else None

    def refresh_tools(self) -> str:
        """重新探测外部命令（安装脚本之后调用的场景），返回 agent-desktop 路径或空串。"""
        path = shutil.which(AGENT_DESKTOP) or ""
        self.has_agent_desktop = bool(path)
        self.has_xdotool = bool(shutil.which("xdotool"))
        self.has_wmctrl = bool(shutil.which("wmctrl"))
        return path

    def _env(self) -> Dict[str, str]:
        env = os.environ.copy()
        env["DISPLAY"] = self.display
        return env

    def _agent_desktop(self, args: List[str], timeout: int) -> Any:
        """执行一条 agent-desktop 命令并返回 envelope 的 ``data``。

        任何失败（缺二进制、超时、非零退出、``ok`` 为假、输出不可解析）都抛出
        ``AgentDesktopError``，绝不降级成“空桌面”之类的伪成功。
        """
        self._last_agent_desktop_error = None
        binary = shutil.which(AGENT_DESKTOP)
        if not binary:
            self.has_agent_desktop = False
            err = AgentDesktopError("AGENT_DESKTOP_MISSING", "未找到 agent-desktop 可执行文件")
            self._last_agent_desktop_error = err
            raise err
        cmd = [binary] + args
        try:
            res = subprocess.run(
                cmd, env=self._env(), capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            err = AgentDesktopError(
                "TIMEOUT", f"{' '.join(args)} 超过 {timeout}s 未返回", "提高超时或检查 AT-SPI 总线是否卡住"
            )
            self._last_agent_desktop_error = err
            raise err from exc
        except OSError as exc:
            err = AgentDesktopError("AGENT_DESKTOP_EXEC", f"{type(exc).__name__}: {exc}")
            self._last_agent_desktop_error = err
            raise err

        try:
            envelope = _load_envelope(res.stdout)
        except ValueError as exc:
            err = AgentDesktopError(
                "INVALID_OUTPUT",
                f"{' '.join(args)} 输出不是 JSON envelope：{_short(exc)}",
                details={"exit_code": res.returncode, "stderr": _short(res.stderr)},
            )
            self._last_agent_desktop_error = err
            raise err

        if not envelope.get("ok"):
            error = envelope.get("error") if isinstance(envelope.get("error"), dict) else {}
            code = str(error.get("code") or f"EXIT_{res.returncode}")
            details = error.get("details")
            if error.get("recovery") is not None:
                details = dict(details) if isinstance(details, dict) else {"details": details}
                details["recovery"] = error["recovery"]
            err = AgentDesktopError(
                code,
                str(error.get("message") or _short(res.stderr) or "agent-desktop 返回失败"),
                str(error.get("suggestion") or ""),
                details,
            )
            self._last_agent_desktop_error = err
            raise err
        if res.returncode != 0:
            err = AgentDesktopError(
                f"EXIT_{res.returncode}",
                f"envelope 声称成功但退出码为 {res.returncode}",
                details={"stderr": _short(res.stderr)},
            )
            self._last_agent_desktop_error = err
            raise err
        return envelope.get("data")

    def _agent_desktop_raw(self, args: List[str], timeout: int) -> subprocess.CompletedProcess:
        """与 ``_agent_desktop`` 同样判定失败，但 stdout 不作纯 JSON 解析。

        screenshot 的输出可以带二进制尾巴，交给 ``_extract_png`` 处理。
        """
        self._last_agent_desktop_error = None
        binary = shutil.which(AGENT_DESKTOP)
        if not binary:
            self.has_agent_desktop = False
            err = AgentDesktopError("AGENT_DESKTOP_MISSING", "未找到 agent-desktop 可执行文件")
            self._last_agent_desktop_error = err
            raise err
        try:
            res = subprocess.run(
                [binary] + args, env=self._env(), capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            err = AgentDesktopError("TIMEOUT", f"{' '.join(args)} 超过 {timeout}s 未返回")
            self._last_agent_desktop_error = err
            raise err from exc
        except OSError as exc:
            err = AgentDesktopError("AGENT_DESKTOP_EXEC", f"{type(exc).__name__}: {exc}")
            self._last_agent_desktop_error = err
            raise err
        if res.returncode != 0:
            # 先看 envelope：结构化错误码（POLICY_DENIED/WINDOW_NOT_FOUND…）比 EXIT_n 有用得多。
            try:
                envelope = _load_envelope(res.stdout)
                error = envelope.get("error") if isinstance(envelope.get("error"), dict) else {}
                code = str(error.get("code") or f"EXIT_{res.returncode}")
                message = str(error.get("message") or "")
                suggestion = str(error.get("suggestion") or "")
            except ValueError:
                code, message, suggestion = f"EXIT_{res.returncode}", "", ""
            stderr = res.stderr.decode("utf-8", "replace") if isinstance(res.stderr, bytes) else res.stderr
            err = AgentDesktopError(
                code,
                message or _short(stderr) or f"agent-desktop {' '.join(args)} 退出码 {res.returncode}",
                suggestion,
            )
            self._last_agent_desktop_error = err
            raise err
        return res

    @staticmethod
    def _extract_png(stdout: Any) -> bytes:
        """从 screenshot 的 stdout 取 PNG 字节；不是 PNG 时返回 ``b""``。

        优先解析 envelope 的 ``data.data``（base64）；若 stdout 里直接含 PNG 签名，就从签名处切片。
        """
        if isinstance(stdout, bytes):
            marker = b"\x89PNG\r\n\x1a\n"
            pos = stdout.find(marker)
            if pos >= 0:
                return stdout[pos:]
            text = stdout.decode("utf-8", "replace")
        else:
            text = stdout or ""
        try:
            envelope = _load_envelope(text)
        except ValueError:
            return b""
        if not envelope.get("ok"):
            error = envelope.get("error") if isinstance(envelope.get("error"), dict) else {}
            raise AgentDesktopError(
                str(error.get("code") or "SCREENSHOT_FAILED"),
                str(error.get("message") or "agent-desktop screenshot 失败"),
                str(error.get("suggestion") or ""),
            )
        return DesktopManager._decode_screenshot(envelope.get("data"))

    def agent_desktop_call(self, args: List[str], timeout: int = 20) -> Dict[str, Any]:
        """供其他组件复用的 agent-desktop 调用入口。"""
        return self._agent_desktop(list(args), timeout)

    def list_agent_windows(self) -> List[Dict[str, Any]]:
        """通过 agent-desktop 列出可快照的窗口（AT-SPI 视角）。失败即抛错。"""
        return parse_window_rows(self._agent_desktop(["list-windows"], _LIST_WINDOWS_TIMEOUT))

    def _wmctrl_windows(self) -> List[Dict[str, Any]]:
        res = subprocess.run(
            ["wmctrl", "-l", "-G", "-x"],
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0:
            return []
        windows = []
        for line in res.stdout.splitlines():
            parts = line.split(None, 7)
            if len(parts) >= 7:
                windows.append({
                    "id": parts[0],
                    "desktop": parts[1],
                    "geometry": f"{parts[2]},{parts[3]},{parts[4]},{parts[5]}",
                    "class": parts[6],
                    "title": parts[7] if len(parts) > 7 else "",
                })
        return windows

    def list_windows(self) -> List[Dict[str, Any]]:
        """列出当前桌面所有窗口。

        X11 层用 wmctrl 给出几何与标题；agent-desktop 可用时再补上 AT-SPI 窗口
        句柄（``agent_window_id``），供快照按 id 定位。
        """
        if self.force_mock:
            return [
                {"id": "0x01", "title": "Chromium", "class": "chromium.Chromium", "geometry": "0,0,1280,800"},
                {"id": "0x02", "title": "Openbox", "class": "openbox.Openbox", "geometry": "0,0,1280,800"},
            ]

        windows: List[Dict[str, Any]] = []
        self._agent_rows = []
        if self.has_wmctrl:
            try:
                windows = self._wmctrl_windows()
            except (OSError, subprocess.SubprocessError):
                windows = []

        if not self.has_agent_desktop:
            return windows
        try:
            agent_rows = self.list_agent_windows()
        except AgentDesktopError:
            agent_rows = []
        for row in agent_rows:
            title = str(row.get("title") or "")
            match = self._match_agent_row(windows, title)
            if match is not None:
                match["agent_window_id"] = row.get("id")
                match.setdefault("app_name", row.get("app_name"))
                match.setdefault("focused", row.get("is_focused"))
                continue
            windows.append({
                "id": str(row.get("id")),
                "title": title,
                "class": str(row.get("app_name") or ""),
                "app_name": row.get("app_name"),
                "geometry": _format_bounds(row.get("bounds")),
                "agent_window_id": row.get("id"),
                "focused": row.get("is_focused"),
            })
        return windows

    @staticmethod
    def _match_agent_row(windows: List[Dict[str, Any]], title: str) -> Optional[Dict[str, Any]]:
        if not title:
            return None
        for window in windows:
            if "agent_window_id" in window:
                continue
            if str(window.get("title") or "") == title:
                return window
        return None

    def focus_window(self, window_title_or_id: str) -> bool:
        """激活并聚焦指定窗口（X11 十六进制 id、agent-desktop 窗口 id 或标题）。

        标题/id 同时交给 wmctrl 与 agent-desktop 的 ``focus-window``；两者都失败才返回
        False，并把 agent-desktop 的结构化错误（含 wmctrl 兜底错误）留在 ``last_error``。
        """
        if self.force_mock:
            return True
        ok, _backend = self.focus_window_detailed(window_title_or_id)
        return ok

    def focus_window_detailed(self, target: str):
        """返回 ``(ok, backend)``；backend 是实际生效的 ``wmctrl``/``agent-desktop``，便于诊断。"""
        target = target.strip() if isinstance(target, str) else ""
        if not target:
            err = AgentDesktopError("INVALID_ARGS", "focus 需要窗口标题或窗口 id")
            self._record_error(err)
            return False, None
        if self.force_mock:
            self._record_error(None)
            return True, "mock"

        wmctrl_err: Optional[AgentDesktopError] = None
        if self.has_wmctrl:
            try:
                res = subprocess.run(
                    ["wmctrl", "-a", target],
                    env=self._env(),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0:
                    self._record_error(None)
                    return True, "wmctrl"
                wmctrl_err = AgentDesktopError(
                    "WMCTRL_FAILED",
                    _short(res.stderr) or f"wmctrl 退出码 {res.returncode}",
                )
            except (OSError, subprocess.SubprocessError) as exc:
                wmctrl_err = AgentDesktopError("WMCTRL_FAILED", f"{type(exc).__name__}: {exc}")

        agent_err: Optional[AgentDesktopError] = None
        # 0x 开头是 X11 窗口 id、w- 开头是 agent-desktop 的不透明句柄，其余按标题匹配。
        if target.startswith(("0x", "w-")):
            selectors = [["--window-id", target]]
        else:
            selectors = [["--title", target]]
        for selector in selectors:
            try:
                self._agent_desktop(["focus-window"] + selector, timeout=10)
                self._record_error(None)
                return True, "agent-desktop"
            except AgentDesktopError as exc:
                agent_err = exc

        self._record_error(_merge_tool_error(agent_err, wmctrl_err))
        if self.last_error is None:
            self.last_error = AgentDesktopError(
                "FOCUS_UNAVAILABLE", "wmctrl 与 agent-desktop 均不可用，无法聚焦窗口")
        return False, None

    def _focus_agent_window(self, window_id: str, title: str) -> bool:
        """用 AT-SPI 窗口 id 或标题聚焦；agent-desktop 的 focus-window 走 EWMH。

        wmctrl 能用标题直接激活（快，且不依赖 AT-SPI 状态）；失败再退回 agent-desktop。
        """
        if self.has_wmctrl and title and self.focus_window(title):
            return True
        for selector in (["--window-id", window_id] if window_id else [], ["--title", title] if title else []):
            if not selector:
                continue
            try:
                self._agent_desktop(["focus-window"] + selector, timeout=10)
                return True
            except AgentDesktopError:
                continue
        return False

    def snapshot(self, window_id: Optional[str] = None) -> Dict[str, Any]:
        """获取桌面无障碍与窗口结构快照。

        ``window_id`` 未给出时自动选择（优先浏览器窗口）。返回值的
        ``ok``/``active_window``/``window_id``/``agent_desktop`` 如实反映 AT-SPI
        结果；失败时附带 ``agent_desktop_error`` 结构化错误，而不是假装成功。
        """
        windows = self.list_windows()
        selected: Optional[Dict[str, Any]] = None
        if window_id:
            for window in windows:
                if window_id in (window.get("agent_window_id"), window.get("id")):
                    selected = window
                    break
            if selected is None:
                selected = {"id": window_id, "agent_window_id": window_id, "title": ""}
        elif not self.force_mock:
            chosen = select_window([
                row for row in (self._agent_rows or []) if isinstance(row, dict) and row.get("id")
            ])
            if chosen:
                for window in windows:
                    if window.get("agent_window_id") == chosen.get("id"):
                        selected = window
                        break
                if selected is None:
                    selected = {
                        "id": str(chosen.get("id")),
                        "agent_window_id": chosen.get("id"),
                        "title": chosen.get("title"),
                    }
        if selected is None and windows:
            selected = windows[0]

        window_id = (selected or {}).get("agent_window_id") or window_id
        title = str((selected or {}).get("title") or "")
        result: Dict[str, Any] = {
            "display": self.display,
            "windows": windows,
            "active_window": selected,
            "window_id": window_id,
            "accessibility_supported": bool(self.has_agent_desktop and windows),
            "ok": False,
        }
        if self.force_mock:
            result["ok"] = True
            result["mock"] = True
            return result
        if not self.has_agent_desktop:
            result["agent_desktop_error"] = AgentDesktopError(
                "AGENT_DESKTOP_MISSING", "未安装 agent-desktop，无法读取 AT-SPI 无障碍树"
            ).to_dict()
            return result
        if selected is None:
            # 没有窗口（应用未注册到 AT-SPI 总线，或尚未启动）时不要盲调 snapshot。
            # 如果 list-windows 本身报错（例如没有会话总线），保留它的原始错误码。
            if self._last_agent_desktop_error is not None:
                result["agent_desktop_error"] = self._last_agent_desktop_error.to_dict()
            elif windows:
                result["agent_desktop_error"] = AgentDesktopError(
                    "NO_WINDOW",
                    "X11 上有窗口，但 agent-desktop 没有列出任何窗口；应用未在 AT-SPI 总线上注册",
                    "确认 DISPLAY/DBUS_SESSION_BUS_ADDRESS 一致，并重启在总线出现前启动的应用",
                ).to_dict()
            else:
                result["agent_desktop_error"] = AgentDesktopError(
                    "NO_WINDOW",
                    "agent-desktop 没有列出任何窗口，桌面上也没有可识别的应用",
                    "先用浏览器或 launch 打开一个应用，再重新快照",
                ).to_dict()
            return result

        # 先把焦点落到目标窗口：Chromium 在后台时 AT-SPI 树可能一直处于未构建状态。
        self._focus_agent_window(str(window_id or ""), title)

        args = ["snapshot", "-i"]
        if window_id:
            args.extend(["--window-id", str(window_id)])
        try:
            data = self._agent_desktop(args, _SNAPSHOT_TIMEOUT)
            result["ok"] = True
            result["agent_desktop"] = data
            if isinstance(data, dict):
                # 2.2+ 的 snapshot 会用 complete=false 明确表示“预算耗尽但有部分树”，
                # 这与旧版 TIMEOUT 语义不同，必须原样透传给上层。
                if "complete" in data:
                    result["complete"] = bool(data.get("complete"))
                if isinstance(data.get("window"), dict):
                    result["window_id"] = data["window"].get("id") or window_id
        except AgentDesktopError as exc:
            result["agent_desktop_error"] = exc.to_dict()
            result["accessibility_supported"] = False
        return result

    # ---- GUI 输入：agent-desktop 优先，xdotool 兜底

    def _xdotool(self, args: List[str], timeout: int) -> Optional[AgentDesktopError]:
        """执行一条 xdotool 命令；成功返回 None，失败返回结构化错误（不抛异常）。"""
        if not shutil.which("xdotool"):
            self.has_xdotool = False
            return _tool_missing("xdotool")
        try:
            res = subprocess.run(
                ["xdotool"] + args,
                env=self._env(),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return AgentDesktopError("XDOTOOL_TIMEOUT", f"xdotool {' '.join(args)} 超过 {timeout}s 未返回")
        except OSError as exc:
            return AgentDesktopError("XDOTOOL_EXEC", f"{type(exc).__name__}: {exc}")
        if res.returncode != 0:
            return AgentDesktopError(
                "XDOTOOL_FAILED",
                _short(res.stderr) or f"xdotool 退出码 {res.returncode}",
                details={"exit_code": res.returncode},
            )
        return None

    def click(self, x: int, y: int, button: int = 1) -> bool:
        """在屏幕物理坐标点击。agent-desktop ``--headed mouse-click`` 优先，xdotool 兜底。

        agent-desktop 的坐标点击需要 ``--headed``（允许物理输入与光标移动）；不带会被
        ``POLICY_DENIED`` 拒绝，这里直接带上。它不可用时改用 xdotool mousemove+click。
        """
        if self.force_mock:
            return True
        try:
            x, y = int(x), int(y)
        except (TypeError, ValueError):
            self._record_error(AgentDesktopError("INVALID_ARGS", f"坐标必须是整数：{x!r},{y!r}"))
            return False
        if x < 0 or y < 0:
            self._record_error(AgentDesktopError("INVALID_ARGS", f"屏幕坐标不能为负：{x},{y}"))
            return False
        name = _BUTTON_NAMES.get(button)
        if name is None:
            self._record_error(AgentDesktopError("INVALID_ARGS", f"不支持的鼠标按键：{button}（1 左 / 2 中 / 3 右）"))
            return False

        agent_err: Optional[AgentDesktopError] = None
        if self.has_agent_desktop:
            try:
                self._agent_desktop(
                    ["--headed", "mouse-click", "--xy", f"{x},{y}", "--button", name],
                    _INPUT_TIMEOUT,
                )
                self._record_error(None)
                return True
            except AgentDesktopError as exc:
                agent_err = exc
        else:
            agent_err = _tool_missing(AGENT_DESKTOP)

        fallback_err = self._xdotool(["mousemove", str(x), str(y), "click", str(button)], 5)
        if fallback_err is None:
            self._record_error(None)
            return True
        self._record_error(_merge_tool_error(agent_err, fallback_err))
        return False

    def type_text(self, text: str) -> bool:
        """向当前焦点键入文本。

        agent-desktop 的 ``type`` 只能作用于快照 ref（要先 snapshot 才能定位文本控件），
        没有“裸键盘文本”命令；因此文本输入直接走 xdotool ``type``，xdotool 缺失时
        明确报 XDOTOOL_MISSING，而不是返回成功。
        """
        if self.force_mock:
            return True
        if not isinstance(text, str) or text == "":
            self._record_error(AgentDesktopError("INVALID_ARGS", "type 需要非空文本"))
            return False
        err = self._xdotool(["type", "--delay", "12", text], 10)
        self._record_error(err)
        return err is None

    def key_press(self, key_combination: str) -> bool:
        """触发快捷键（例如 'ctrl+c'、'Return'、'alt+F4'）。

        agent-desktop ``press COMBO`` 的写法与 xdotool 一致（最后一段是键，前面是修饰键），
        直接透传；它失败（如 ``POLICY_DENIED`` 的危险组合）后再试 xdotool。
        """
        if self.force_mock:
            return True
        combo = (key_combination or "").strip()
        if not combo:
            self._record_error(AgentDesktopError("INVALID_ARGS", "key 需要组合键，例如 ctrl+c"))
            return False

        agent_err: Optional[AgentDesktopError] = None
        if self.has_agent_desktop:
            try:
                self._agent_desktop(["press", combo], _INPUT_TIMEOUT)
                self._record_error(None)
                return True
            except AgentDesktopError as exc:
                agent_err = exc
        else:
            agent_err = _tool_missing(AGENT_DESKTOP)

        fallback_err = self._xdotool(["key", combo], 5)
        if fallback_err is None:
            self._record_error(None)
            return True
        self._record_error(_merge_tool_error(agent_err, fallback_err))
        return False

    @staticmethod
    def _decode_screenshot(data: Any) -> bytes:
        """解析 agent-desktop screenshot 的 ``data.data``（base64 PNG 或 data URI）。"""
        if not isinstance(data, dict):
            return b""
        raw = data.get("data")
        if not isinstance(raw, str) or not raw:
            return b""
        if raw.startswith("data:"):
            _, _, raw = raw.partition(",")
        try:
            return base64.b64decode(raw, validate=False)
        except (ValueError, TypeError):
            return b""

    def screenshot(self) -> bytes:
        """捕获完整虚拟桌面截图（PNG 字节）；截不到返回 ``b""`` 并记录 ``last_error``。

        agent-desktop ``screenshot``（不带 PATH 时返回 base64）优先；不可用时依次尝试
        ImageMagick ``import`` 与 ``scrot``。
        """
        if self.force_mock:
            # 最小 1x1 PNG
            return (
                b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff"
                b"?\x00\x05\xfe\x02\xfe\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82"
            )

        errors: List[AgentDesktopError] = []
        if self.has_agent_desktop:
            try:
                # 每个进程最多输出一个 envelope，design 上 base64 放在 data.data；
                # 万一启动器直接写 PNG 字节，_extract_png 也能从 stdout 里切出来。
                res = self._agent_desktop_raw(["screenshot"], _SCREENSHOT_TIMEOUT)
                png = self._extract_png(res.stdout)
                if png.startswith(b"\x89PNG"):
                    self._record_error(None)
                    return png
                errors.append(AgentDesktopError(
                    "INVALID_OUTPUT", "agent-desktop screenshot 未返回 PNG"))
            except AgentDesktopError as exc:
                errors.append(exc)
        else:
            errors.append(_tool_missing(AGENT_DESKTOP))

        env = self._env()
        if shutil.which("import"):
            try:
                res = subprocess.run(
                    ["import", "-window", "root", "png:-"],
                    env=env,
                    capture_output=True,
                    timeout=5,
                )
                if res.returncode == 0 and res.stdout.startswith(b"\x89PNG"):
                    self._record_error(None)
                    return res.stdout
                errors.append(AgentDesktopError("IMPORT_FAILED", "ImageMagick import 未返回 PNG"))
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(AgentDesktopError("IMPORT_FAILED", f"{type(exc).__name__}: {exc}"))

        if shutil.which("scrot"):
            fd, path = tempfile.mkstemp(suffix=".png", prefix="gha-scrot-")
            os.close(fd)
            try:
                res = subprocess.run(
                    ["scrot", "--overwrite", "-o", path],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                with open(path, "rb") as fp:
                    png = fp.read()
                if res.returncode == 0 and png.startswith(b"\x89PNG"):
                    self._record_error(None)
                    return png
                errors.append(AgentDesktopError(
                    "SCROT_FAILED",
                    _short(res.stderr) or f"scrot 退出码 {res.returncode}",
                ))
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append(AgentDesktopError("SCROT_FAILED", f"{type(exc).__name__}: {exc}"))
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass

        merged: Optional[AgentDesktopError] = None
        for err in errors:
            merged = _merge_tool_error(merged, err) if merged is not None else err
        self._record_error(merged or AgentDesktopError(
            "SCREENSHOT_UNAVAILABLE", "没有可用的截图后端（agent-desktop / import / scrot 均不可用）"))
        return b""
