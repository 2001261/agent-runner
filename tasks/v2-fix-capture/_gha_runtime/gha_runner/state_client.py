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
import tempfile
from typing import Any, Dict, List, Optional

from .interactive_client import InteractiveClient
from .vault import HAS_CRYPTOGRAPHY, Vault, VaultError

CHUNK_SIZE = 4 * 1024 * 1024


class StateClient:
    """状态回传与恢复客户端"""

    # 大对象上传/持久化校验远超普通 API 超时
    UPLOAD_TIMEOUT = 300.0
    DOWNLOAD_ATTEMPTS = 3

    def __init__(self, client: InteractiveClient, vault: Optional[Vault] = None,
                 chunk_size: int = CHUNK_SIZE):
        self.client = client
        self.vault = vault or Vault()
        self.chunk_size = chunk_size

    def list_manifest(self) -> Dict[str, Any]:
        """获取 Runner 当前所有可回传对象清单"""
        return self.client.get("/v1/state/manifest")

    def create_checkpoint(self, checkpoint_type: str = "AUTH", checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        """触发生成指定类型的检查点"""
        body = {"type": checkpoint_type}
        if checkpoint_id:
            body["checkpoint_id"] = checkpoint_id
        return self.client.post("/v1/state/checkpoint", body)

    def _require_crypto(self) -> None:
        """缺 cryptography 时 encrypt_data 必然失败；在下载/覆盖任何状态前就拒绝。"""
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法使用 AES-256-GCM 加密落盘；请安装后重试")

    def _part_path(self, obj_id: str) -> Any:
        return self.vault.transfers_dir / "partial" / f"{self.vault._path_component(obj_id)}.part"

    @staticmethod
    def _content_range(headers: Dict[str, str]) -> Optional[Any]:
        """解析 Content-Range: bytes start-end/total；通配符或不可解析返回 None。"""
        for key, value in headers.items():
            if key.lower() == "content-range":
                try:
                    unit, _, span = value.strip().partition(" ")
                    if unit.lower() != "bytes":
                        return None
                    s, e = span.split("/")[0].split("-", 1)
                    return int(s), int(e)
                except ValueError:
                    return None
        return None

    def _download_object(self, obj: Dict[str, Any]) -> bytes:
        """按 Range 分块下载；中断后从 .part 偏移继续，完整校验前不算成功。"""
        if obj.get("encrypted"):
            obj_id = obj["id"]
            raise ValueError(f"对象 {obj_id} 为 Runner 侧明文，本地无法用 Runner 派生密钥解密；拒绝落盘")
        obj_id = obj["id"]
        total = int(obj.get("size", 0))
        if total == 0:
            raise ValueError(f"对象 {obj_id} 大小未声明，拒绝下载")
        part = self._part_path(obj_id)
        offset = part.stat().st_size if part.exists() else 0
        if offset > total:
            part.unlink()
            offset = 0
        while offset < total:
            end = min(offset + self.chunk_size - 1, total - 1)
            last_error = None
            data = None
            for _ in range(self.DOWNLOAD_ATTEMPTS):
                try:
                    chunk, headers = self.client.get_raw(
                        f"/v1/state/objects/{obj_id}",
                        range_header=f"bytes={offset}-{end}",
                    )
                    if not chunk:
                        raise ValueError("空分块")
                    if offset > 0:
                        span = self._content_range(headers)
                        if span is None:
                            raise ValueError("服务端未按 Range 返回分块")
                        if span[0] != offset:
                            raise ValueError(f"Content-Range 起点 {span[0]} 与请求偏移 {offset} 不一致")
                    expect = end - offset + 1
                    if len(chunk) != expect:
                        # 截断/越界都以服务端声明的范围为准，绝不写入多余字节
                        raise ValueError(f"分块长度 {len(chunk)} 与请求范围 {expect} 不一致")
                    data = chunk
                    break
                except Exception as exc:
                    last_error = exc
            if data is None:
                raise ValueError(f"对象 {obj_id} 在偏移 {offset} 下载失败，已保留断点：{last_error}")
            # 断点文件可能已被外部损坏；最终 SHA-256 校验兜底
            with open(part, "ab") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            offset += len(data)
        raw = part.read_bytes() if part.exists() else b""
        expected = obj.get("sha256", "")
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            part.unlink()
            raise ValueError(f"对象 {obj_id} SHA-256 校验失败：期望 {expected}，实际 {actual}（已丢弃断点）")
        return raw

    def _store_downloaded_object(self, project: str, obj: Dict[str, Any], data: bytes,
                                 compatibility: Optional[Dict[str, Any]] = None) -> None:
        obj_id = obj["id"]
        category = obj["category"]
        if category == "auth_state":
            state_dict = json.loads(data.decode("utf-8"))
            self.vault.store_auth_state(project=project, name=obj_id, state_dict=state_dict,
                                        compatibility=compatibility)
        elif category == "browser_profile":
            incoming = self.vault.transfers_dir / "incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f"{self.vault._path_component(obj_id)}-", suffix=".tar.gz", dir=str(incoming))
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                self.vault.store_profile_archive(
                    project=project, name=obj_id, archive_path=tmp_name,
                    compatibility=compatibility,
                )
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        elif category == "compatibility_meta":
            # 仅用于 X-Compatibility，不单独落盘
            return
        else:
            self.vault.store_binary_object(project=project, name=obj_id, data=data,
                                           category=category, compatibility=compatibility)

    def _ack(self, obj_id: str, status: str) -> None:
        """ACK 是断点文件清理的唯一依据：服务端明确接收才删除。"""
        res = self.client.post("/v1/state/ack", {"object_id": obj_id, "status": status})
        if not isinstance(res, dict) or res.get("status") != "acknowledged":
            raise ValueError(f"Runner 未确认对象 {obj_id} 的 ACK：{res}")

    def export_state_to_vault(self, project: str = "default") -> Dict[str, Any]:
        """分块下载、SHA-256 校验、加密原子落盘，最后才向 Runner 回复 PERSISTED ACK。"""
        self._require_crypto()
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
            self._ack(obj["id"], "PERSISTED")
            part = self._part_path(obj["id"])
            if part.exists():
                part.unlink()
            synced.append(obj["id"])
        return {"status": "completed", "total_objects": len(objects), "synced_objects": synced}

    def _push_object(self, obj_id: str, category: str, data: bytes,
                     compatibility: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """按 X-Offset 分块上传；仅返回 verified=True 才算恢复成功。"""
        total = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        base = {
            "X-Object-ID": obj_id,
            "X-Total-Size": str(total),
            "X-SHA256": sha256,
            "X-Category": category,
            "Content-Type": "application/octet-stream",
        }
        if compatibility:
            base["X-Compatibility"] = json.dumps(compatibility, ensure_ascii=False)
        res: Dict[str, Any] = {}
        offset = 0
        while True:
            chunk = data[offset:offset + self.chunk_size]
            headers = dict(base, **{"X-Offset": str(offset)})
            res = self.client.post_raw("/v1/state/import", chunk, headers, timeout=self.UPLOAD_TIMEOUT)
            res = res if isinstance(res, dict) else {"status": "invalid_response", "raw": str(res)}
            next_offset = offset + len(chunk)
            if next_offset >= total:
                break
            if res.get("status") != "chunk_received":
                raise ValueError(f"对象 {obj_id} 在偏移 {offset} 上传中断：{res}")
            if int(res.get("received", next_offset)) != next_offset:
                raise ValueError(f"对象 {obj_id} 在偏移 {offset} 的服务端进度 {res.get('received')} 不一致")
            offset = next_offset
        if not res.get("verified"):
            raise ValueError(f"对象 {obj_id} 导入失败：Runner 未确认恢复：{res}")
        return res

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

        try:
            return self._push_object(obj_id, category, data,
                                     compatibility=meta.compatibility if meta else None)
        finally:
            if category == "browser_profile":
                try:
                    archive.unlink()
                except OSError:
                    pass
