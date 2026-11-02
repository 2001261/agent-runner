"""状态恢复与 Profile 兼容性验证器。

遵循《2.0 迭代.md》第十一章 11.4 与第十二章 12.4、12.5 规范。
恢复优先级策略：
1. 校验环境与元数据：OS、架构与 Chromium 大版本都匹配时，才解包恢复完整 Profile；
2. 若环境不兼容，不触碰现有浏览器，由 Host 回退为创建全新 BrowserContext 并应用
   storage_state；
3. 如果认证均失效，返回明确状态以触发人工重新登录。

失败语义（任何一条都不允许回报 verified=true）：
- 归档在解包前被拒绝（不兼容、路径穿越、链接逃逸……）：浏览器保持原状；
- 解包失败：临时目录清理，浏览器未关闭；
- 关闭浏览器后替换失败：把旧 Profile 原子换回并重新启动浏览器；
- 浏览器重启失败：明确返回失败，由 Host 降级到 storage_state 恢复。
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any, Dict, Optional, Tuple

from .browser import BrowserManager, read_chromium_version
from .transfer import ChunkedTransferEngine


class StateImporter:
    """状态恢复导入器"""

    def __init__(self, transfer_engine: ChunkedTransferEngine, browser_mgr: BrowserManager):
        self.transfer = transfer_engine
        self.browser = browser_mgr

    def check_profile_compatibility(self, compat_meta: Dict[str, Any]) -> Tuple[bool, str]:
        """核验 Profile 平台兼容性：OS、架构、Chromium 大版本（按规范 12.4 / 12.5）。"""
        host_os = compat_meta.get("os", "")
        host_arch = compat_meta.get("architecture", "")

        curr_os = platform.system()
        curr_arch = platform.machine()

        if host_os and host_os != curr_os:
            return False, f"操作系统不匹配: 归档为 {host_os}, 当前 Runner 为 {curr_os}"

        if host_arch and host_arch != curr_arch:
            return False, f"架构不匹配: 归档为 {host_arch}, 当前 Runner 为 {curr_arch}"

        archived_major = _chromium_major(compat_meta.get("chromium_version"))
        current_major = _chromium_major(read_chromium_version(self.browser.user_data_dir))
        if not current_major:
            current_major = _chromium_major(_configured_chromium_version())
        # 只有双方都拿得到大版本时才比较；缺失元数据时保持旧行为，避免误判为不兼容
        if archived_major and current_major and archived_major != current_major:
            return False, (
                f"Chromium 大版本不匹配: 归档为 {archived_major}.x, "
                f"当前 Runner 为 {current_major}.x"
            )

        return True, "兼容"

    @staticmethod
    def _validated_members(tar: tarfile.TarFile, staging_root: str) -> None:
        """逐个成员做严格校验：拒绝绝对路径、路径穿越、链接、设备文件与越界条目。"""
        for member in tar.getmembers():
            name = member.name.replace("\\", "/")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise ValueError("归档含绝对路径")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts):
                raise ValueError("归档含路径穿越")
            if member.issym() or member.islnk():
                raise ValueError("归档含符号链接或硬链接")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"归档含非常规条目: {member.name}")
            resolved = os.path.realpath(os.path.join(staging_root, *parts))
            if os.path.commonpath([staging_root, resolved]) != staging_root:
                raise ValueError("归档条目越界")

    async def restore_profile_archive(self, archive_file_path: str, compat_meta: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """全量校验后解包到临时目录，关闭浏览器并原子替换 Profile。

        返回 (True, 消息) 仅表示新 Profile 已落位且浏览器重新拉起成功；
        任何失败都返回 (False, 原因)，Host 据此不得认为恢复已完成。
        """
        if compat_meta:
            ok, reason = self.check_profile_compatibility(compat_meta)
            if not ok:
                # 不兼容时保持现有浏览器不动，由 Host 回退 storage_state 恢复
                return False, f"Profile 恢复跳过（环境不兼容，请回退 storage_state）: {reason}"
        if not os.path.isfile(archive_file_path):
            return False, "归档文件不存在"

        target_dir = os.path.abspath(self.browser.user_data_dir)
        parent = os.path.dirname(target_dir)
        os.makedirs(parent, exist_ok=True)
        staging = tempfile.mkdtemp(prefix=".profile-restore-", dir=parent)
        backup: Optional[str] = None
        browser_closed = False
        try:
            staging_root = os.path.realpath(staging)
            with tarfile.open(archive_file_path, "r:*") as tar:
                self._validated_members(tar, staging_root)
                # 3.12+ 默认过滤器会拒绝链接；这里已自行完成严格校验
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=staging, filter="fully_trusted")
                else:
                    tar.extractall(path=staging)

            await self.browser.close()
            browser_closed = True

            if os.path.exists(target_dir):
                backup = tempfile.mkdtemp(prefix=".profile-old-", dir=parent)
                os.rmdir(backup)
                os.replace(target_dir, backup)
            os.replace(staging, target_dir)

            # 新 Profile 已落位：浏览器必须能重新拉起，否则不能声称恢复成功
            if not await self.browser.start():
                raise RuntimeError(
                    f"Profile 已替换，但浏览器重启失败: {self.browser.last_error or 'unknown'}"
                )

            if backup is not None:
                shutil.rmtree(backup, ignore_errors=True)
                backup = None
            return True, "Profile 恢复成功"
        except Exception as e:
            if os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)

            parts = [f"恢复失败: {e}"]
            if backup is not None:
                # 替换中途失败：把旧 Profile 换回原位；回滚失败时保留备份，不能删
                if os.path.exists(target_dir):
                    shutil.rmtree(target_dir, ignore_errors=True)
                try:
                    os.replace(backup, target_dir)
                    backup = None
                except OSError as rollback_exc:
                    parts.append(f"旧 Profile 回滚失败: {rollback_exc}（备份保留于 {backup}）")

            if browser_closed:
                # 浏览器已关闭：无论替换是否成功，都要重新拉起持久化 Context
                try:
                    if not await self.browser.start():
                        parts.append(
                            f"浏览器重启失败: {self.browser.last_error or 'unknown'}"
                        )
                except Exception as restart_exc:
                    parts.append(f"浏览器重启失败: {restart_exc}")
            return False, "；".join(parts)
        finally:
            if os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)

    async def restore_auth_state(self, auth_json_path: str) -> Tuple[bool, str]:
        """恢复 Playwright storage_state 认证数据"""
        if not os.path.isfile(auth_json_path):
            return False, "认证状态文件不存在"

        try:
            with open(auth_json_path, "r", encoding="utf-8") as f:
                state_dict = json.load(f)
        except Exception as e:
            return False, f"解析恢复认证状态异常: {e}"
        if not isinstance(state_dict, dict):
            return False, "认证状态文件顶层不是对象"

        try:
            ok = await self.browser.restore_storage_state(state_dict)
        except Exception as e:
            return False, f"恢复认证状态异常: {e}"
        if ok:
            return True, "Auth state 恢复成功"
        return False, f"BrowserContext 恢复状态失败: {self.browser.last_error}"


def _chromium_major(version: Any) -> str:
    """从 "131.0.6778.85" / "Chrome/131.0.6778.85" 中提取大版本号。"""
    if not isinstance(version, str):
        return ""
    match = re.search(r"(\d+)\.", version.strip())
    return match.group(1) if match else ""


def _configured_chromium_version() -> str:
    """读取 GHA_CHROME_BIN 指向的 Chromium/Chrome 版本（无外部浏览器时为空）。"""
    chrome_bin = os.environ.get("GHA_CHROME_BIN")
    if not chrome_bin:
        return ""
    try:
        res = subprocess.run([chrome_bin, "--version"], capture_output=True, text=True, timeout=10)
    except Exception:
        return ""
    return (res.stdout or res.stderr or "").strip()
