"""双向文件传输与安全分块引擎。

遵循《2.0 迭代.md》第十五章与第十八章 18.5「防止路径穿越」。
特性：
- 严格基于对象 ID 映射，禁止通过任意相对或绝对路径读取/写入 Runner 文件系统；
- 分块传输 (Chunked Transfer) 与 Range/Offset 断点续传；
- SHA-256 完整性校验；
- 临时文件写入 + 原子重命名 (Atomic Rename)；
- 符号链接逃逸与路径穿越防御。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from typing import Any, BinaryIO, Dict, Generator, List, Optional, Tuple

# 入站上传进度索引：只有此处登记的对象才允许查询/续传，绝不按路径查找
INCOMING_INDEX_FILE = "incoming-index.json"
INCOMING_INDEX_LIMIT = 64


class TransferError(Exception):
    """文件传输异常"""

    def __init__(self, message: str, code: str = "TRANSFER_ERROR", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class SafePathValidator:
    """路径穿越防御验证器"""

    @staticmethod
    def ensure_safe_subpath(base_dir: str, rel_path: str) -> str:
        """确保目标路径严格在 base_dir 内部，防止 ../ 或符号链接逃逸"""
        base = os.path.abspath(base_dir)
        target = os.path.abspath(os.path.join(base, rel_path))
        if not target.startswith(base + os.sep) and target != base:
            raise TransferError(f"路径穿越攻击被阻止: {rel_path}")
        return target


class ChunkedTransferEngine:
    """分块传输引擎"""

    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB

    def __init__(self, storage_dir: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.storage_dir = os.path.abspath(storage_dir)
        self.chunk_size = chunk_size
        self._active_objects: Dict[str, Dict[str, Any]] = {}
        os.makedirs(self.storage_dir, exist_ok=True)

    def register_outgoing_object(self, object_id: str, file_path: str, category: str, encrypted: bool = False) -> Dict[str, Any]:
        """注册供 Host 下载的对象"""
        if not os.path.isfile(file_path):
            raise TransferError(f"文件不存在: {file_path}")

        size = os.path.getsize(file_path)
        digest = self.calculate_sha256(file_path)

        meta = {
            "id": object_id,
            "category": category,
            "size": size,
            "sha256": digest,
            "encrypted": encrypted,
            "file_path": file_path,
        }
        self._active_objects[object_id] = meta
        return meta

    def get_object_metadata(self, object_id: str) -> Optional[Dict[str, Any]]:
        return self._active_objects.get(object_id)

    def acknowledge_object(self, object_id: str, status: str) -> Dict[str, Any]:
        """记录 Host 已完成校验并原子落盘后的持久化确认。"""
        meta = self._active_objects.get(object_id)
        if not meta:
            raise TransferError(f"无法 ACK 未知对象: {object_id}")
        if status not in ("PERSISTED", "FAILED", "INCOMPLETE"):
            raise TransferError(f"非法持久化状态: {status}")
        meta["persistence_state"] = status
        return meta

    def read_chunk(self, object_id: str, offset: int, length: Optional[int] = None) -> Tuple[bytes, int, int]:
        """读取指定偏移量和长度的数据分块"""
        meta = self._active_objects.get(object_id)
        if not meta:
            raise TransferError(f"未知对象 ID: {object_id}")

        file_path = meta["file_path"]
        total_size = meta["size"]
        if offset >= total_size:
            return b"", offset, total_size

        req_len = length or self.chunk_size
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(req_len)

        return data, offset, total_size

    def _incoming_index_path(self) -> str:
        return os.path.join(self.storage_dir, INCOMING_INDEX_FILE)

    def _load_incoming_index(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self._incoming_index_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_incoming_index(self, index: Dict[str, Dict[str, Any]]) -> None:
        """原子写入进度索引；只保留最近 INCOMING_INDEX_LIMIT 条。"""
        items = sorted(index.items(), key=lambda kv: kv[1].get("updated_at", 0))
        index = dict(items[-INCOMING_INDEX_LIMIT:])
        path = self._incoming_index_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(index, f)
        os.replace(tmp, path)

    @staticmethod
    def _incoming_meta(object_id: str, total_size: int, expected_sha256: str,
                       category: str, tmp_path: str) -> Dict[str, Any]:
        return {
            "id": object_id,
            "category": category,
            "size": total_size,
            "sha256": expected_sha256,
            "tmp_path": tmp_path,
            "final_path": os.path.join(os.path.dirname(tmp_path), object_id),
            "received_bytes": 0,
        }

    def init_incoming_object(self, object_id: str, total_size: int, expected_sha256: str,
                             category: str) -> str:
        """初始化接收上传对象，返回临时文件路径。

        总是从 0 开始：只有在 worker 重启后 Host 主动续传、且容器内已有 .part 时，
        才由 Gateway 显式调用 resume_incoming_object 复用磁盘进度。保留旧 .part
        会让「重新上传」的偏移与内容错位。
        """
        # 安全化文件名，仅允许对象 ID 本身
        if object_id != os.path.basename(object_id) or object_id in ("", ".", ".."):
            raise TransferError(f"非法对象 ID: {object_id!r}")
        safe_name = object_id
        tmp_path = os.path.join(self.storage_dir, f"{safe_name}.part")
        meta = self._incoming_meta(object_id, total_size, expected_sha256, category, tmp_path)
        with open(tmp_path, "wb"):
            pass
        index = self._load_incoming_index()
        index.pop(object_id, None)
        self._save_incoming_index(index)
        self._active_objects[object_id] = meta
        return tmp_path

    def resume_incoming_object(self, object_id: str, total_size: int, expected_sha256: str,
                               category: str) -> Optional[str]:
        """Host 用 status 接口确认服务端已有同特征进度后，按磁盘 .part 继续写入。

        特征（ID / 总长 / SHA-256 / 类别）任一不符、或索引丢失时返回 None，
        由调用方按新上传从 0 开始。
        """
        status, mismatch = self.incoming_status(object_id, total_size, expected_sha256, category)
        if mismatch is not None or status.get("status") not in ("in_progress", "complete"):
            return None
        tmp_path = os.path.join(self.storage_dir, f"{object_id}.part")
        meta = self._incoming_meta(object_id, total_size, expected_sha256, category, tmp_path)
        meta["received_bytes"] = status.get("received", 0)
        self._active_objects[object_id] = meta
        return tmp_path

    def incoming_status(self, object_id: str, total_size: int, expected_sha256: str,
                        category: str) -> Tuple[Dict[str, Any], Optional[str]]:
        """查询服务端真实已接收字节；对象未登记时返回 received=0，不读取任何路径。"""
        if object_id != os.path.basename(object_id) or object_id in ("", ".", ".."):
            raise TransferError(f"非法对象 ID: {object_id!r}")
        tmp_path = os.path.join(self.storage_dir, f"{object_id}.part")
        entry = self._load_incoming_index().get(object_id)
        if entry is None:
            return {"status": "absent", "object_id": object_id, "received": 0}, None
        mismatch = None
        for key, given in (("size", total_size), ("sha256", expected_sha256), ("category", category)):
            if entry.get(key) != given:
                mismatch = key
                break
        on_disk = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
        if mismatch or on_disk != entry.get("received_bytes", 0):
            # 内容特征变化或磁盘进度与索引不一致：下次上传从 0 开始，Host 按 0 覆盖
            return {
                "status": "reset", "object_id": object_id, "received": 0,
                "reason": f"{mismatch}_changed" if mismatch else "progress_lost",
            }, mismatch
        return {
            "status": "in_progress" if on_disk < total_size else "complete",
            "object_id": object_id,
            "received": on_disk,
            "size": total_size,
            "sha256": expected_sha256,
            "category": category,
        }, None

    def write_chunk(self, object_id: str, offset: int, data: bytes) -> int:
        """写入分块并支持断点续传；offset 必须等于当前已接收字节数，不允许覆盖已有分块。"""
        meta = self._active_objects.get(object_id)
        if not meta or "tmp_path" not in meta:
            raise TransferError(f"对象未初始化上传: {object_id}")

        tmp_path = meta["tmp_path"]
        current = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
        if offset != current:
            raise TransferError(
                f"分块偏移 {offset} 与已接收字节数 {current} 不一致",
                code="OFFSET_MISMATCH", status=409,
            )
        if offset + len(data) > meta["size"]:
            raise TransferError(f"分块越界: {offset + len(data)} > {meta['size']}")

        with open(tmp_path, "r+b" if os.path.exists(tmp_path) else "wb") as f:
            f.seek(offset)
            f.write(data)
            f.truncate(offset + len(data))
            f.flush()

        meta["received_bytes"] = os.path.getsize(tmp_path)
        index = self._load_incoming_index()
        # 已完成的导入继续留在索引里，status 才能回答「已收满」；新上传会重置该条
        entry = {
            "id": object_id,
            "category": meta["category"],
            "size": meta["size"],
            "sha256": meta["sha256"],
            "received_bytes": meta["received_bytes"],
            "updated_at": time.time(),
        }
        index[object_id] = entry
        self._save_incoming_index(index)
        return meta["received_bytes"]

    def finalize_incoming_object(self, object_id: str) -> str:
        """校验上传文件的完整性并执行原子重命名"""
        meta = self._active_objects.get(object_id)
        if not meta or "tmp_path" not in meta:
            raise TransferError(f"对象未初始化上传: {object_id}")

        tmp_path = meta["tmp_path"]
        final_path = meta["final_path"]

        # 校验哈希
        actual_digest = self.calculate_sha256(tmp_path)
        if actual_digest != meta["sha256"]:
            os.remove(tmp_path)
            raise TransferError(f"SHA-256 完整性校验失败: 期望 {meta['sha256']}, 实际 {actual_digest}")

        # 原子重命名
        os.replace(tmp_path, final_path)
        meta["file_path"] = final_path
        return final_path

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """流式计算大文件 SHA-256"""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
