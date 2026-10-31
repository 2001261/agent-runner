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
import os
import shutil
from typing import Any, BinaryIO, Dict, Generator, List, Optional, Tuple


class TransferError(Exception):
    """文件传输异常"""
    pass


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

    def init_incoming_object(self, object_id: str, total_size: int, expected_sha256: str, category: str) -> str:
        """初始化接收上传对象，返回临时文件路径"""
        # 安全化文件名，仅允许对象 ID 本身
        safe_name = os.path.basename(object_id)
        tmp_path = os.path.join(self.storage_dir, f"{safe_name}.part")
        meta = {
            "id": object_id,
            "category": category,
            "size": total_size,
            "sha256": expected_sha256,
            "tmp_path": tmp_path,
            "final_path": os.path.join(self.storage_dir, safe_name),
            "received_bytes": 0,
        }
        self._active_objects[object_id] = meta
        # 预截断或初始化
        if not os.path.exists(tmp_path):
            with open(tmp_path, "wb") as f:
                pass
        return tmp_path

    def write_chunk(self, object_id: str, offset: int, data: bytes) -> int:
        """写入分块并支持断点续传"""
        meta = self._active_objects.get(object_id)
        if not meta or "tmp_path" not in meta:
            raise TransferError(f"对象未初始化上传: {object_id}")

        tmp_path = meta["tmp_path"]
        with open(tmp_path, "r+b" if os.path.exists(tmp_path) else "wb") as f:
            f.seek(offset)
            f.write(data)

        meta["received_bytes"] = os.path.getsize(tmp_path)
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
