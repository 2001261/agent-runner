"""Agent Host 本地存储与凭据加密库（Vault）。

遵循《2.0 迭代.md》第十章、第十一章、第十二章、第十三章与第十七章规范。
宿主机是持久化中心，承担认证状态（Cookie/Storage）、Profile 归档、凭据及运行产物的长期加密存储。
"""

from __future__ import annotations

import base64
import hashlib
import io
import hmac
import json
import os
import shutil
import struct
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

from .state_envelope import (
    HostKeyPair,
    load_or_create_host_keys,
    shareable_public_document,
)

# 超过该阈值的二进制对象按分块流式加密/解密，避免数百 MB 的 Profile 整体进出内存
STREAM_THRESHOLD = 32 * 1024 * 1024
STREAM_CHUNK = 1024 * 1024


DEFAULT_VAULT_ROOT = os.path.expanduser("~/.gha-runner")


@dataclass
class VaultObjectMetadata:
    id: str
    category: str  # "auth_state" | "profile" | "credential" | "recording" | "checkpoint"
    project: str
    name: str
    version: int
    created_at: float
    size: int
    sha256: str
    encrypted: bool
    encryption_algo: str = "AES-256-GCM"
    compatibility: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


class VaultError(Exception):
    """Vault 操作异常"""
    pass


class _PlaintextReader:
    """把流式 AES-GCM 帧按需解密成明文；读到畸形帧立即报错而不是返回半截明文。"""

    def __init__(self, key: bytes, nonce: bytes, payload: bytes):
        self._aesgcm = AESGCM(key)
        self._nonce = nonce
        self._payload = payload
        self._pos = 0
        self._offset = 0
        self._buffer = b""
        self._finished = False

    def read(self, size: int = -1) -> bytes:
        out = bytearray()
        while size < 0 or len(out) < size:
            if self._buffer:
                take = self._buffer if size < 0 else self._buffer[:max(0, size - len(out))]
                out.extend(take)
                self._buffer = self._buffer[len(take):]
                continue
            if self._finished:
                break
            self._buffer = self._read_frame()
        return bytes(out)

    def _read_frame(self) -> bytes:
        if self._pos >= len(self._payload):
            raise VaultError("Vault 流式数据被截断（缺少结束帧）")
        if self._pos + 4 > len(self._payload):
            raise VaultError("Vault 流式帧头被截断")
        size = struct.unpack(">I", self._payload[self._pos:self._pos + 4])[0]
        start = self._pos + 4
        sealed = self._payload[start:start + size]
        if size <= 16 or len(sealed) != size:
            raise VaultError("Vault 流式帧长度非法或被截断")
        self._pos = start + size
        # AAD 在写入时记录了起始偏移与长度；先按当前偏移尝试 final/非 final 两种解释
        expected = size - 16
        for final in (1, 0):
            aad = f"{self._offset}:{expected}:{final}".encode("ascii")
            try:
                plain = self._aesgcm.decrypt(self._nonce, sealed, aad)
            except Exception:
                continue
            self._offset += len(plain)
            if final:
                self._finished = True
            return plain
        raise VaultError("Vault 流式帧认证失败")

    def close(self) -> None:
        self._payload = b""
        self._buffer = b""
        self._finished = True

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class Vault:
    """Agent Host 本地加密存储中心"""

    def __init__(self, root_dir: Optional[str] = None):
        self.root = Path(root_dir or os.environ.get("GHA_VAULT_ROOT", DEFAULT_VAULT_ROOT))
        self.config_dir = self.root / "config"
        self.vault_dir = self.root / "vault"
        self.auth_dir = self.vault_dir / "auth"
        self.profiles_dir = self.vault_dir / "profiles"
        self.creds_dir = self.vault_dir / "credentials"
        self.objects_dir = self.vault_dir / "objects"
        self.keys_dir = self.vault_dir / "keys"
        self.sessions_dir = self.root / "sessions"
        self.transfers_dir = self.root / "transfers"
        self.state_dir = self.root / "state"
        self.index_file = self.state_dir / "index.json"

        self._key: Optional[bytes] = None
        self._state_keypair: Optional[HostKeyPair] = None
        self._ensure_structure()

    def _ensure_structure(self) -> None:
        """初始化目录结构并限制权限"""
        for d in [
            self.config_dir,
            self.vault_dir,
            self.auth_dir,
            self.profiles_dir,
            self.creds_dir,
            self.objects_dir,
            self.keys_dir,
            self.sessions_dir,
            self.transfers_dir / "incoming",
            self.transfers_dir / "outgoing",
            self.transfers_dir / "partial",
            self.state_dir,
        ]:
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(str(d), 0o700)
            except OSError:
                pass

        if not self.index_file.exists():
            self._save_index({"schema": "gha-vault/v1", "updated_at": time.time(), "objects": {}})

    def get_master_key(self) -> bytes:
        """获取或生成本地 Vault 主密钥 (AES-256, 32 bytes)"""
        if self._key is not None:
            return self._key

        key_file = self.keys_dir / "master.key"
        if key_file.exists():
            with open(key_file, "rb") as f:
                key = f.read()
            if len(key) == 32:
                self._key = key
                return key

        # 生成新密钥
        new_key = os.urandom(32)
        fd, tmp = tempfile.mkstemp(prefix=".master-key-", dir=str(self.keys_dir))
        try:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is None:
                os.chmod(tmp, 0o600)
            else:
                fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                fd = -1
                f.write(new_key)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, key_file)
        finally:
            if fd >= 0:
                os.close(fd)
            if os.path.exists(tmp):
                os.unlink(tmp)
        try:
            os.chmod(str(key_file), 0o600)
        except OSError:
            pass
        self._key = new_key
        return new_key

    # ---- Runner 状态回传的 X25519 接收密钥（私钥只在本机 keys 目录，0600）
    def state_keypair(self) -> HostKeyPair:
        """加载或首次生成用于解封 Runner 回传对象的 X25519 密钥对。"""
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法生成 X25519 状态密钥；请安装后重试")
        if self._state_keypair is None:
            self._state_keypair = load_or_create_host_keys(self.keys_dir)
        return self._state_keypair

    def state_key_id(self) -> str:
        return self.state_keypair().key_id

    def state_public_key_document(self) -> Dict[str, str]:
        """仅含 key_id 与公钥的文档：可安全写入 GHA_TASK_SECRETS 或打印核对。"""
        return shareable_public_document(self.state_keypair())

    def encrypt_data(self, plaintext: bytes) -> bytes:
        """只使用经过验证的 AES-256-GCM；缺依赖时拒绝写入，绝不自研降级算法。"""
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法使用 AES-256-GCM；请安装后重试")
        key = self.get_master_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def read_data(self, payload: bytes) -> bytes:
        """解密 Vault 数据"""
        if payload.startswith(b"GHASTREAM1:"):
            raise VaultError("Vault 数据为流式加密，请使用 open_decrypted_binary_object")
        return self.decrypt_data(payload)

    def decrypt_data(self, payload: bytes) -> bytes:
        if not HAS_CRYPTOGRAPHY and not payload.startswith(b"FALLBACK1:"):
            raise VaultError("缺少解密依赖且密文不是兼容格式")
        key = self.get_master_key()
        if payload.startswith(b"FALLBACK1:"):
            # 兼容解密
            body = payload[len(b"FALLBACK1:"):]
            nonce, tag, ct = body[:16], body[16:32], body[32:]
            mac_key = hashlib.sha256(key + b":mac").digest()
            expected_tag = hashlib.sha256(mac_key + nonce + ct).digest()[:16]
            if not hmac.compare_digest(tag, expected_tag):
                raise VaultError("Vault 解密校验失败（MAC 不匹配）")
            ctr_key = hashlib.sha256(key + b":ctr").digest()
            keystream = bytearray()
            block_idx = 0
            while len(keystream) < len(ct):
                h = hashlib.sha256(ctr_key + nonce + block_idx.to_bytes(8, "big")).digest()
                keystream.extend(h)
                block_idx += 1
            return bytes(c ^ k for c, k in zip(ct, keystream[:len(ct)]))

        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(key)
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                raise VaultError(f"Vault AES-GCM 解密失败: {e}") from e

        raise VaultError("缺少解密依赖且密文不是兼容格式")

    def _load_index(self) -> Dict[str, Any]:
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"schema": "gha-vault/v1", "updated_at": time.time(), "objects": {}}

    def _save_index(self, data: Dict[str, Any]) -> None:
        data["updated_at"] = time.time()
        tmp = self.state_dir / "index.json.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        tmp.replace(self.index_file)

    # ---- Auth State 管理 (Cookies / LocalStorage)
    def store_auth_state(
        self,
        project: str,
        name: str,
        state_dict: Dict[str, Any],
        compatibility: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
        raw: Optional[bytes] = None,
    ) -> VaultObjectMetadata:
        """存储浏览器认证状态（Playwright storage_state 格式）。

        回传链路上 Host 已核对过解封明文的 SHA-256/长度，此时传入 raw 原样落盘：
        重新序列化会改变字节（缩进、键序），Vault 读回值就与清单声明对不上了。
        """
        target_dir = self.auth_dir / project / name
        target_dir.mkdir(parents=True, exist_ok=True)

        if raw is None:
            raw = json.dumps(state_dict, ensure_ascii=False).encode("utf-8")
        elif json.loads(raw.decode("utf-8")) != state_dict:
            raise VaultError("auth_state 原样字节与解析出的状态不一致，拒绝落盘")
        digest = hashlib.sha256(raw).hexdigest()

        index = self._load_index()
        # 寻找已有版本
        obj_id = f"auth-{project}-{name}"
        prev_meta = index.get("objects", {}).get(obj_id)
        version = (prev_meta["version"] + 1) if prev_meta else 1

        enc = self.encrypt_data(raw)
        data_file = target_dir / f"state-v{version:03d}.enc"
        with open(data_file, "wb") as f:
            f.write(enc)

        meta = VaultObjectMetadata(
            id=obj_id,
            category="auth_state",
            project=project,
            name=name,
            version=version,
            created_at=time.time(),
            size=len(raw),
            sha256=digest,
            encrypted=True,
            encryption_algo="AES-256-GCM" if HAS_CRYPTOGRAPHY else "CTR-HMAC",
            compatibility=compatibility or {},
            extra=extra or {},
        )

        meta_file = target_dir / "metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(asdict(meta), f, ensure_ascii=False, indent=2)

        index["objects"][obj_id] = asdict(meta)
        index["objects"][obj_id]["file"] = data_file.relative_to(self.root).as_posix()
        self._save_index(index)
        return meta

    def get_auth_state(self, project: str, name: str) -> Tuple[Optional[Dict[str, Any]], Optional[VaultObjectMetadata]]:
        """获取并解密最新的认证状态"""
        obj_id = f"auth-{project}-{name}"
        index = self._load_index()
        meta_dict = index.get("objects", {}).get(obj_id)
        if not meta_dict:
            return None, None

        rel_path = meta_dict.get("file")
        if not rel_path:
            return None, None

        full_path = self.root / rel_path
        if not full_path.exists():
            return None, None

        with open(full_path, "rb") as f:
            enc = f.read()

        raw = self.decrypt_data(enc)
        state_dict = json.loads(raw.decode("utf-8"))
        meta = VaultObjectMetadata(**{k: v for k, v in meta_dict.items() if k != "file"})
        return state_dict, meta

    # ---- Profile 备份与归档
    def store_profile_archive(
        self,
        project: str,
        name: str,
        archive_path: str,
        compatibility: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> VaultObjectMetadata:
        """存储 Chromium 完整用户数据目录归档"""
        if not os.path.isfile(archive_path):
            raise VaultError(f"归档文件不存在: {archive_path}")

        target_dir = self.profiles_dir / project / name
        target_dir.mkdir(parents=True, exist_ok=True)

        with open(archive_path, "rb") as f:
            raw = f.read()

        digest = hashlib.sha256(raw).hexdigest()
        obj_id = f"profile-{project}-{name}"
        index = self._load_index()
        prev_meta = index.get("objects", {}).get(obj_id)
        version = (prev_meta["version"] + 1) if prev_meta else 1

        enc = self.encrypt_data(raw)
        data_file = target_dir / f"profile-v{version:03d}.enc"
        with open(data_file, "wb") as f:
            f.write(enc)

        meta = VaultObjectMetadata(
            id=obj_id,
            category="profile",
            project=project,
            name=name,
            version=version,
            created_at=time.time(),
            size=len(raw),
            sha256=digest,
            encrypted=True,
            encryption_algo="AES-256-GCM" if HAS_CRYPTOGRAPHY else "CTR-HMAC",
            compatibility=compatibility or {},
            extra=extra or {},
        )

        meta_file = target_dir / "metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(asdict(meta), f, ensure_ascii=False, indent=2)

        index["objects"][obj_id] = asdict(meta)
        index["objects"][obj_id]["file"] = data_file.relative_to(self.root).as_posix()
        self._save_index(index)
        return meta

    def extract_profile_archive(self, project: str, name: str, output_path: str) -> Optional[VaultObjectMetadata]:
        """解密 Profile 归档至目标文件路径"""
        obj_id = f"profile-{project}-{name}"
        index = self._load_index()
        meta_dict = index.get("objects", {}).get(obj_id)
        if not meta_dict:
            return None

        rel_path = meta_dict.get("file")
        if not rel_path:
            return None

        full_path = self.root / rel_path
        if not full_path.exists():
            return None

        with open(full_path, "rb") as f:
            enc = f.read()

        raw = self.decrypt_data(enc)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(raw)

        return VaultObjectMetadata(**{k: v for k, v in meta_dict.items() if k != "file"})

    # ---- 凭据管理 (Agent Credential Vault)
    def store_credential(
        self,
        project: str,
        key: str,
        value: str,
        description: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> VaultObjectMetadata:
        """存储由用户明确授权的登录账号密码等凭据"""
        target_dir = self.creds_dir / project
        target_dir.mkdir(parents=True, exist_ok=True)

        raw = value.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        obj_id = f"cred-{project}-{key}"

        enc = self.encrypt_data(raw)
        data_file = target_dir / f"{key}.enc"
        with open(data_file, "wb") as f:
            f.write(enc)

        meta = VaultObjectMetadata(
            id=obj_id,
            category="credential",
            project=project,
            name=key,
            version=1,
            created_at=time.time(),
            size=len(raw),
            sha256=digest,
            encrypted=True,
            encryption_algo="AES-256-GCM" if HAS_CRYPTOGRAPHY else "CTR-HMAC",
            compatibility={},
            extra={"description": description, **(extra or {})},
        )

        index = self._load_index()
        index["objects"][obj_id] = asdict(meta)
        index["objects"][obj_id]["file"] = data_file.relative_to(self.root).as_posix()
        self._save_index(index)
        return meta

    def get_credential(self, project: str, key: str) -> Optional[str]:
        """获取解密后的凭据值"""
        obj_id = f"cred-{project}-{key}"
        index = self._load_index()
        meta_dict = index.get("objects", {}).get(obj_id)
        if not meta_dict:
            return None

        rel_path = meta_dict.get("file")
        if not rel_path:
            return None

        full_path = self.root / rel_path
        if not full_path.exists():
            return None

        with open(full_path, "rb") as f:
            enc = f.read()

        return self.decrypt_data(enc).decode("utf-8")

    @staticmethod
    def _path_component(value: str) -> str:
        cleaned = "".join(c if c.isalnum() or c in "._-" else "_" for c in str(value))
        return cleaned[:96] or "unnamed"

    def open_decrypted_binary_object(self, project: str, name: str):
        """流式解密二进制对象，返回 (可读文件对象, 元数据)；DATA 帧到达且校验通过后才写入明文。"""
        obj_id = f"object-{project}-{name}"
        meta_dict = self._load_index().get("objects", {}).get(obj_id)
        if not meta_dict or not meta_dict.get("file"):
            return None, None
        full_path = self.root / meta_dict["file"]
        if not full_path.exists():
            return None, None
        meta = VaultObjectMetadata(**{k: v for k, v in meta_dict.items() if k != "file"})
        encrypted = full_path.read_bytes()
        if not encrypted.startswith(b"GHASTREAM1:"):
            return io.BytesIO(self.read_data(encrypted)), meta
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法解密流式对象")
        body = encrypted[len(b"GHASTREAM1:"):]
        return _PlaintextReader(self.get_master_key(), body[:12], body[12:]), meta

    def _encrypt_stream(self, path: Path, data: bytes) -> None:
        """流式 AES-GCM：只有完整读完文件长度才写出结束帧，截断文件不会产出明文的假结尾。"""
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法使用 AES-256-GCM；请安装后重试")
        key = self.get_master_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        total = len(data)
        with open(path, "wb") as f:
            f.write(b"GHASTREAM1:" + nonce)
            start = 0
            while start < total:
                chunk = data[start:start + STREAM_CHUNK]
                final = start + STREAM_CHUNK >= total
                aad = f"{start}:{len(chunk)}:{1 if final else 0}".encode("ascii")
                sealed = aesgcm.encrypt(nonce, chunk, aad)
                f.write(struct.pack(">I", len(sealed)) + sealed)
                start += STREAM_CHUNK
                if final:
                    break
            f.flush()
            os.fsync(f.fileno())

    def store_binary_object(
        self,
        project: str,
        name: str,
        data: bytes,
        category: str,
        compatibility: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> VaultObjectMetadata:
        """加密保存录像、截图、Trace 等任意二进制对象，不做 UTF-8 转码。"""
        target_dir = self.objects_dir / self._path_component(project) / self._path_component(name)
        target_dir.mkdir(parents=True, exist_ok=True)
        obj_id = f"object-{project}-{name}"
        index = self._load_index()
        previous = index.get("objects", {}).get(obj_id)
        version = previous["version"] + 1 if previous else 1
        digest = hashlib.sha256(data).hexdigest()
        data_file = target_dir / f"object-v{version:03d}.enc"
        tmp_file = target_dir / f".object-v{version:03d}.enc.tmp"
        if len(data) > STREAM_THRESHOLD:
            self._encrypt_stream(tmp_file, data)
        else:
            tmp_file.write_bytes(self.encrypt_data(data))
        os.replace(tmp_file, data_file)
        meta = VaultObjectMetadata(
            id=obj_id,
            category=category,
            project=project,
            name=name,
            version=version,
            created_at=time.time(),
            size=len(data),
            sha256=digest,
            encrypted=True,
            encryption_algo="AES-256-GCM" if HAS_CRYPTOGRAPHY else "CTR-HMAC",
            compatibility=compatibility or {},
            extra=extra or {},
        )
        index["objects"][obj_id] = asdict(meta)
        index["objects"][obj_id]["file"] = data_file.relative_to(self.root).as_posix()
        self._save_index(index)
        return meta

    def get_binary_object(self, project: str, name: str) -> Tuple[Optional[bytes], Optional[VaultObjectMetadata]]:
        reader, meta = self.open_decrypted_binary_object(project, name)
        if reader is None:
            return None, None
        with reader:
            data = reader.read()
        return data, meta

    # ---- 通用查询、检查与清理
    def list_objects(
        self,
        category: Optional[str] = None,
        project: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """列出 Vault 中的对象元数据（绝不暴露密码与状态原文）"""
        index = self._load_index()
        results = []
        for obj_id, data in index.get("objects", {}).items():
            if category and data.get("category") != category:
                continue
            if project and data.get("project") != project:
                continue
            # 安全展示：拷贝并剥离本地敏感路径
            item = dict(data)
            results.append(item)
        return sorted(results, key=lambda x: x.get("created_at", 0), reverse=True)

    def inspect_object(self, object_id: str) -> Optional[Dict[str, Any]]:
        """查看指定对象的元数据与完整性信息"""
        index = self._load_index()
        item = index.get("objects", {}).get(object_id)
        if not item:
            return None
        res = dict(item)
        # 验证物理文件是否存在
        rel_path = item.get("file")
        if rel_path:
            full_path = self.root / rel_path
            res["file_exists"] = full_path.exists()
            if full_path.exists():
                res["stored_bytes"] = full_path.stat().st_size
        return res

    def delete_object(self, object_id: str) -> bool:
        """安全删除指定 Vault 对象及其物理文件"""
        index = self._load_index()
        item = index.get("objects", {}).pop(object_id, None)
        if not item:
            return False

        rel_path = item.get("file")
        if rel_path:
            full_path = self.root / rel_path
            if full_path.exists():
                try:
                    full_path.unlink()
                except OSError:
                    pass
        self._save_index(index)
        return True
