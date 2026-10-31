"""State 状态持久化与双向文件同步客户端。

遵循《2.0 迭代.md》第十章、第十五章与第二十一章 21.2。
支持：
- gha state list <task-id>
- gha state checkpoint <task-id>
- gha state export <task-id>
- gha state import <task-id>
- gha state restore <task-id>
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .interactive_client import InteractiveClient
from .vault import Vault


class StateClient:
    """状态回传与恢复客户端"""

    def __init__(self, client: InteractiveClient, vault: Optional[Vault] = None):
        self.client = client
        self.vault = vault or Vault()

    def list_manifest(self) -> Dict[str, Any]:
        """获取 Runner 当前所有可回传对象清单"""
        return self.client.get("/v1/state/manifest")

    def create_checkpoint(self, checkpoint_type: str = "AUTH", checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        """触发生成指定类型的检查点"""
        body = {"type": checkpoint_type}
        if checkpoint_id:
            body["checkpoint_id"] = checkpoint_id
        return self.client.post("/v1/state/checkpoint", body)

    def _download_object(self, obj: Dict[str, Any]) -> bytes:
        """按 Range 分块下载；中断后从 .part 偏移继续，完整校验前不算成功。"""
        obj_id = obj["id"]
        total = int(obj.get("size", 0))
        safe = self.vault._path_component(obj_id)
        part = self.vault.transfers_dir / "partial" / f"{safe}.part"
        offset = part.stat().st_size if part.exists() else 0
        if offset > total:
            part.unlink()
            offset = 0
        while offset < total:
            end = min(offset + 4 * 1024 * 1024 - 1, total - 1)
            last_error = None
            for attempt in range(3):
                try:
                    data, headers = self.client.get_raw(
                        f"/v1/state/objects/{obj_id}",
                        range_header=f"bytes={offset}-{end}",
                    )
                    if not data:
                        raise ValueError("空分块")
                    if offset > 0 and "Content-Range" not in headers and "content-range" not in headers:
                        raise ValueError("服务端未按 Range 返回分块")
                    break
                except Exception as exc:
                    last_error = exc
                    data = None
            if data is None:
                raise ValueError(f"对象 {obj_id} 在偏移 {offset} 下载失败，已保留断点：{last_error}")
            with open(part, "ab") as f:
                f.write(data)
                f.flush()
            offset += len(data)
        raw = part.read_bytes() if part.exists() else b""
        expected = obj.get("sha256", "")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError(f"对象 {obj_id} SHA-256 校验失败：期望 {expected}，实际 {actual}")
        return raw

    def _store_downloaded_object(self, project: str, obj: Dict[str, Any], data: bytes,
                                 compatibility: Optional[Dict[str, Any]] = None) -> None:
        obj_id = obj["id"]
        category = obj["category"]
        if category == "auth_state":
            state_dict = json.loads(data.decode("utf-8"))
            self.vault.store_auth_state(project=project, name=obj_id, state_dict=state_dict)
        elif category == "browser_profile":
            tmp_archive = self.vault.transfers_dir / "incoming" / f"{self.vault._path_component(obj_id)}.tar.gz"
            with open(tmp_archive, "wb") as f:
                f.write(data)
            self.vault.store_profile_archive(
                project=project, name=obj_id, archive_path=str(tmp_archive),
                compatibility=compatibility,
            )
            if tmp_archive.exists():
                tmp_archive.unlink()
        else:
            self.vault.store_binary_object(project=project, name=obj_id, data=data, category=category)

    def export_state_to_vault(self, project: str = "default") -> Dict[str, Any]:
        """分块下载、SHA-256 校验、加密原子落盘，最后才向 Runner 回复 PERSISTED ACK。"""
        manifest = self.list_manifest()
        objects = manifest.get("objects", [])
        compatibility = None
        for obj in objects:
            if obj.get("category") == "compatibility_meta":
                compatibility = json.loads(self._download_object(obj).decode("utf-8"))
        synced = []
        for obj in objects:
            data = self._download_object(obj)
            self._store_downloaded_object(project, obj, data, compatibility=compatibility)
            self.client.post("/v1/state/ack", {"object_id": obj["id"], "status": "PERSISTED"})
            part = self.vault.transfers_dir / "partial" / f"{self.vault._path_component(obj['id'])}.part"
            if part.exists():
                part.unlink()
            synced.append(obj["id"])
        return {"status": "completed", "total_objects": len(objects), "synced_objects": synced}

    def import_state_from_vault(self, project: str, object_name: str, category: str = "auth_state") -> Dict[str, Any]:
        """从本地 Vault 读取状态并推送至 Runner"""
        if category == "auth_state":
            state_dict, meta = self.vault.get_auth_state(project, object_name)
            if not state_dict or not meta:
                raise ValueError(f"Vault 中不存在认证状态: {project}/{object_name}")
            data = json.dumps(state_dict).encode("utf-8")
            obj_id = f"import-auth-{object_name}"
        elif category == "browser_profile":
            archive = self.vault.transfers_dir / "outgoing" / f"{self.vault._path_component(object_name)}.tar.gz"
            meta = self.vault.extract_profile_archive(project, object_name, str(archive))
            if not meta:
                raise ValueError(f"Vault 中不存在 Profile: {project}/{object_name}")
            data = archive.read_bytes()
            obj_id = f"import-profile-{object_name}"
        else:
            raise NotImplementedError(f"暂不支持直接推送分类: {category}")

        sha256 = hashlib.sha256(data).hexdigest()
        headers = {
            "X-Object-ID": obj_id,
            "X-Total-Size": str(len(data)),
            "X-SHA256": sha256,
            "X-Category": category,
            "X-Offset": "0",
            "Content-Type": "application/octet-stream",
        }
        if category == "browser_profile" and meta and meta.compatibility:
            headers["X-Compatibility"] = json.dumps(meta.compatibility, ensure_ascii=False)

        return self.client.post_raw("/v1/state/import", data, headers)
