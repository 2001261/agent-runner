"""运行时状态导出与 Checkpoint 制造器。

遵循《2.0 迭代.md》第十章、第十一章、第十二章与第十六章。
支持生成五种 Checkpoint：
- AUTH_CHECKPOINT：浏览器认证状态（Cookie/LocalStorage/IndexedDB）；
- BROWSER_CHECKPOINT：当前打开标签页、URL及DOM；
- DESKTOP_CHECKPOINT：桌面窗口与截屏；
- TASK_CHECKPOINT：业务中间产物；
- FINAL_CHECKPOINT：优雅关闭浏览器后完整 Profile 归档。
"""

from __future__ import annotations

import json
import os
import platform
import tarfile
import time
from typing import Any, Dict, List, Optional

from .browser import BrowserManager
from .desktop import DesktopManager
from .transfer import ChunkedTransferEngine


class StateExporter:
    """状态导出管理器"""

    def __init__(
        self,
        transfer_engine: ChunkedTransferEngine,
        browser_mgr: BrowserManager,
        desktop_mgr: DesktopManager,
        storage_dir: str,
    ):
        self.transfer = transfer_engine
        self.browser = browser_mgr
        self.desktop = desktop_mgr
        self.storage_dir = storage_dir
        self._checkpoints: List[Dict[str, Any]] = []
        os.makedirs(self.storage_dir, exist_ok=True)

    async def create_auth_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成认证状态检查点"""
        state_data = await self.browser.export_storage_state()
        fn = f"auth-{checkpoint_id}.json"
        fp = os.path.join(self.storage_dir, fn)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(state_data, f, ensure_ascii=False, indent=2)

        obj_id = f"obj-auth-{checkpoint_id}"
        meta = self.transfer.register_outgoing_object(obj_id, fp, category="auth_state")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "AUTH_CHECKPOINT",
            "created_at": time.time(),
            "objects": [meta],
        }
        self._checkpoints.append(record)
        return record

    async def create_browser_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成浏览器当前运行视图检查点"""
        snap = await self.browser.snapshot()
        fn = f"browser-{checkpoint_id}.json"
        fp = os.path.join(self.storage_dir, fn)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)

        obj_id = f"obj-browser-{checkpoint_id}"
        meta = self.transfer.register_outgoing_object(obj_id, fp, category="browser_state")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "BROWSER_CHECKPOINT",
            "created_at": time.time(),
            "objects": [meta],
        }
        self._checkpoints.append(record)
        return record

    async def create_desktop_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成桌面状态检查点（含截图与窗口表）"""
        snap = self.desktop.snapshot()
        ss = self.desktop.screenshot()

        fn_snap = f"desktop-snap-{checkpoint_id}.json"
        fp_snap = os.path.join(self.storage_dir, fn_snap)
        with open(fp_snap, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)

        fn_ss = f"desktop-screen-{checkpoint_id}.png"
        fp_ss = os.path.join(self.storage_dir, fn_ss)
        with open(fp_ss, "wb") as f:
            f.write(ss)

        obj_snap = self.transfer.register_outgoing_object(f"obj-desk-snap-{checkpoint_id}", fp_snap, category="desktop_state")
        obj_ss = self.transfer.register_outgoing_object(f"obj-desk-screen-{checkpoint_id}", fp_ss, category="desktop_screenshot")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "DESKTOP_CHECKPOINT",
            "created_at": time.time(),
            "objects": [obj_snap, obj_ss],
        }
        self._checkpoints.append(record)
        return record

    async def create_final_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """
        生成最终归档检查点：
        1. 导出最新 auth_state；
        2. 优雅退出 Chromium 进程确保 sqlite 数据落盘；
        3. 打包完整 user-data-dir Profile 目录；
        4. 记录平台与环境兼容性元数据。
        """
        # 1. 认证状态
        auth_rec = await self.create_auth_checkpoint(checkpoint_id + "-final")

        # 2. 优雅退出浏览器
        await self.browser.close()

        # 3. 打包 Profile
        profile_dir = self.browser.user_data_dir
        archive_name = f"profile-{checkpoint_id}.tar.gz"
        archive_path = os.path.join(self.storage_dir, archive_name)

        if os.path.isdir(profile_dir):
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(profile_dir, arcname="chrome-profile")
        else:
            # 兼容空目录
            with tarfile.open(archive_path, "w:gz") as tar:
                pass

        obj_profile = self.transfer.register_outgoing_object(
            f"obj-profile-{checkpoint_id}",
            archive_path,
            category="browser_profile",
        )

        # 4. 环境元数据（恢复时用于兼容性判断；不包含任何秘密）
        chromium_version = ""
        last_version = os.path.join(profile_dir, "Last Version")
        if os.path.isfile(last_version):
            with open(last_version, encoding="utf-8", errors="replace") as f:
                chromium_version = f.read().strip()
        try:
            from importlib.metadata import version as package_version
            playwright_version = package_version("playwright")
        except Exception:
            playwright_version = ""
        compat_info = {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "chromium_version": chromium_version,
            "playwright_version": playwright_version,
            "locale": os.environ.get("LANG", ""),
            "browser_flags": ["--force-renderer-accessibility", "--disable-dev-shm-usage"],
            "encryption_backend": "host-vault-AES-256-GCM",
            "schema_version": "2.0",
        }
        compat_fn = f"compat-{checkpoint_id}.json"
        compat_fp = os.path.join(self.storage_dir, compat_fn)
        with open(compat_fp, "w", encoding="utf-8") as f:
            json.dump(compat_info, f, ensure_ascii=False, indent=2)
        obj_compat = self.transfer.register_outgoing_object(
            f"obj-compat-{checkpoint_id}",
            compat_fp,
            category="compatibility_meta",
        )

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "FINAL_CHECKPOINT",
            "created_at": time.time(),
            "objects": auth_rec["objects"] + [obj_profile, obj_compat],
        }
        self._checkpoints.append(record)
        return record

    def get_manifest(self) -> Dict[str, Any]:
        """汇总当前所有可回传对象清单"""
        all_objects = []
        for cp in self._checkpoints:
            for obj in cp.get("objects", []):
                all_objects.append({
                    "id": obj["id"],
                    "category": obj["category"],
                    "size": obj["size"],
                    "sha256": obj["sha256"],
                    "encrypted": obj.get("encrypted", False),
                    "persistence_state": obj.get("persistence_state", "PENDING"),
                })
        return {
            "schema": "gha-state/v2",
            "total_checkpoints": len(self._checkpoints),
            "checkpoints": self._checkpoints,
            "objects": all_objects,
        }
