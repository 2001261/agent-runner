"""状态恢复与 Profile 兼容性验证器。

遵循《2.0 迭代.md》第十一章 11.4 与第十二章 12.4、12.5 规范。
恢复优先级策略：
1. 校验环境与元数据：如果 OS 与平台架构完全匹配，优先解包恢复完整 Profile；
2. 若环境不兼容，回退为创建全新 BrowserContext 并应用 storage_state；
3. 如果认证均失效，返回明确状态以触发人工重新登录。
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import tarfile
import tempfile
from typing import Any, Dict, Optional, Tuple

from .browser import BrowserManager
from .transfer import ChunkedTransferEngine


class StateImporter:
    """状态恢复导入器"""

    def __init__(self, transfer_engine: ChunkedTransferEngine, browser_mgr: BrowserManager):
        self.transfer = transfer_engine
        self.browser = browser_mgr

    def check_profile_compatibility(self, compat_meta: Dict[str, Any]) -> Tuple[bool, str]:
        """核验 Profile 平台兼容性"""
        host_os = compat_meta.get("os", "")
        host_arch = compat_meta.get("architecture", "")

        curr_os = platform.system()
        curr_arch = platform.machine()

        if host_os and host_os != curr_os:
            return False, f"操作系统不匹配: 归档为 {host_os}, 当前 Runner 为 {curr_os}"

        if host_arch and host_arch != curr_arch:
            return False, f"架构不匹配: 归档为 {host_arch}, 当前 Runner 为 {curr_arch}"

        return True, "兼容"

    async def restore_profile_archive(self, archive_file_path: str, compat_meta: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """全量校验后解包到临时目录，关闭浏览器并原子替换 Profile。"""
        if compat_meta:
            ok, reason = self.check_profile_compatibility(compat_meta)
            if not ok:
                return False, f"Profile 恢复跳过: {reason}"
        if not os.path.isfile(archive_file_path):
            return False, "归档文件不存在"

        target_dir = os.path.abspath(self.browser.user_data_dir)
        parent = os.path.dirname(target_dir)
        os.makedirs(parent, exist_ok=True)
        staging = tempfile.mkdtemp(prefix=".profile-restore-", dir=parent)
        browser_closed = False
        try:
            staging_root = os.path.realpath(staging)
            with tarfile.open(archive_file_path, "r:*") as tar:
                members = tar.getmembers()
                for member in members:
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
                    resolved = os.path.realpath(os.path.join(staging, *parts))
                    if os.path.commonpath([staging_root, resolved]) != staging_root:
                        raise ValueError("归档条目越界")
                # 3.12+ 默认过滤器会拒绝链接；这里已自行完成严格校验
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=staging, filter="fully_trusted")
                else:
                    tar.extractall(path=staging)
            await self.browser.close()
            browser_closed = True
            backup = None
            if os.path.exists(target_dir):
                backup = tempfile.mkdtemp(prefix=".profile-old-", dir=parent)
                os.rmdir(backup)
                os.replace(target_dir, backup)
            try:
                os.replace(staging, target_dir)
            except OSError:
                if backup is not None:
                    os.replace(backup, target_dir)
                raise
            if backup is not None:
                shutil.rmtree(backup, ignore_errors=True)
            return True, "Profile 恢复成功"
        except Exception as e:
            if os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)
            if browser_closed:
                # Profile 已被关闭但未能落位：重新拉起持久化 Context，避免会话失去浏览器
                try:
                    await self.browser.start()
                except Exception as restart_exc:
                    return False, f"解压失败: {e}；浏览器重启失败: {restart_exc}"
            return False, f"解压失败: {e}"

    async def restore_auth_state(self, auth_json_path: str) -> Tuple[bool, str]:
        """恢复 Playwright storage_state 认证数据"""
        if not os.path.isfile(auth_json_path):
            return False, "认证状态文件不存在"

        try:
            with open(auth_json_path, "r", encoding="utf-8") as f:
                state_dict = json.load(f)
            ok = await self.browser.restore_storage_state(state_dict)
            if ok:
                return True, "Auth state 恢复成功"
            return False, f"BrowserContext 恢复状态失败: {self.browser.last_error}"
        except Exception as e:
            return False, f"解析恢复认证状态异常: {e}"
