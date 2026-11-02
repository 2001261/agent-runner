"""Runner → Host 敏感状态对象的端到端封套（X25519 + HKDF-SHA256 + AES-256-GCM）。

方向：Host 生成并保管密钥对 → Runner 只拿公钥加密 → 密文随普通对象传输 →
Host 用私钥解封后再按类别存 Vault。Runner 上没有任何可解密数据的密钥。

封套格式（v1，小端无符号整数，全部为固定布局，便于先读头再流式解密）：

    offset  size  field
    0       4     magic  b"GHSE"
    4       1     version = 1
    5       1     suite   = 1  (X25519-HKDF-SHA256-AES-256-GCM)
    6       2     key_id 长度 L (1..64)
    8       L     key_id  (UTF-8)
    8+L     32    ephemeral X25519 public key
    40+L    12    AES-GCM nonce
    52+L    ..    ciphertext || 16 字节 GCM tag

密钥派生：

    shared = X25519(ephemeral_secret, recipient_public)
    ikm    = shared || ephemeral_public || recipient_public
    key    = HKDF-SHA256(ikm, salt=nonce, info=b"gha-state-envelope/v1|" + key_id)

AAD 绑定格式头（magic..nonce）与明文格式版本，任何篡改、错 key、错绑定的 key_id 或
跨对象重放都会导致解封失败，而不是返回损坏的明文。

超过 1 MiB 的明文按顺序切成多个独立封套帧（每帧各自生成临时密钥与 nonce），
Host 逐帧解密并拼接，内存占用与单个对象大小无关。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - 环境缺少 cryptography 时 fail-closed
    HAS_CRYPTOGRAPHY = False
    X25519PrivateKey = X25519PublicKey = AESGCM = HKDF = serialization = hashes = None  # type: ignore

MAGIC = b"GHSE"
VERSION = 1
SUITE_X25519_AESGCM = 1

KEY_ID_MAX = 64
NONCE_SIZE = 12
PUBLIC_KEY_SIZE = 32
TAG_SIZE = 16

# 单帧明文上限；超出时按此大小切片，每片一个独立封套帧
FRAME_PLAINTEXT = 1024 * 1024

# Host 配置里允许携带的明文类别（其余一切类别一律视为敏感）
NON_SENSITIVE_CATEGORIES = frozenset({"compatibility_meta"})

# X25519 私钥原始字节（本库导出的 raw 格式）长度
_PRIVATE_RAW_SIZE = 32
_PRIVATE_RAW_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b656e04220420")

_FIXED_HEADER = 4 + 1 + 1 + 2


class EnvelopeError(Exception):
    """封套加解密失败（格式错误、篡改、密钥不匹配等）"""


def is_sensitive_category(category: str) -> bool:
    """除明确列入非敏感清单的类别外，所有回传类别都按敏感处理。"""
    return category not in NON_SENSITIVE_CATEGORIES


def _require_crypto() -> None:
    if not HAS_CRYPTOGRAPHY:
        raise EnvelopeError("缺少 cryptography，无法使用 X25519/AES-256-GCM 封套；请安装后重试")


def _validate_key_id(key_id: str) -> bytes:
    if not isinstance(key_id, str) or not key_id:
        raise EnvelopeError("key_id 必须是非空字符串")
    raw = key_id.encode("utf-8")
    if len(raw) > KEY_ID_MAX:
        raise EnvelopeError(f"key_id 过长（最多 {KEY_ID_MAX} 字节）")
    return raw


def _derive_key(shared: bytes, ephemeral_public: bytes, recipient_public: bytes,
                nonce: bytes, key_id: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=b"gha-state-envelope/v1|" + key_id,
    )
    return hkdf.derive(shared + ephemeral_public + recipient_public)


def _header_aad(key_id: bytes, ephemeral_public: bytes, nonce: bytes, plaintext_schema: str) -> bytes:
    header = MAGIC + struct.pack("<BBH", VERSION, SUITE_X25519_AESGCM, len(key_id)) + key_id + ephemeral_public + nonce
    return header + b"|" + plaintext_schema.encode("utf-8")


# ---------------------------------------------------------------------------
# Host 侧：密钥对生成、加载与解封
# ---------------------------------------------------------------------------

@dataclass
class HostKeyPair:
    key_id: str
    private_key: Any
    public_key: Any

    def public_b64(self) -> str:
        return base64.b64encode(self.public_key.public_bytes_raw()).decode("ascii")

    def private_secret(self) -> str:
        """私钥的 secret 字符串；调用方负责注入 GHA_TASK_SECRETS，绝不打印或写日志。"""
        return base64.b64encode(self.private_key.private_bytes_raw()).decode("ascii")

    def public_document(self) -> Dict[str, str]:
        return {"key_id": self.key_id, "public_key": self.public_b64()}


def generate_host_key_pair(key_id: Optional[str] = None) -> HostKeyPair:
    """生成 X25519 密钥对；key_id 缺省用公钥前 8 字节十六进制，便于对账。"""
    _require_crypto()
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    kid = key_id or "x25519-" + public_key.public_bytes_raw()[:8].hex()
    _validate_key_id(kid)
    return HostKeyPair(key_id=kid, private_key=private_key, public_key=public_key)


def load_host_key_pair(key_id: str, private_secret: str) -> HostKeyPair:
    """从 base64(raw 32 字节) 私钥恢复密钥对；也接受 PEM PKCS8，便于外部工具生成。"""
    _require_crypto()
    _validate_key_id(key_id)
    if not private_secret:
        raise EnvelopeError("私钥为空")
    secret = private_secret.strip()
    if secret.startswith("-----BEGIN"):
        try:
            private_key = serialization.load_pem_private_key(secret.encode("ascii"), password=None)
        except Exception as exc:
            raise EnvelopeError(f"私钥 PEM 解析失败: {type(exc).__name__}") from exc
    else:
        try:
            raw = base64.b64decode(secret, validate=True)
        except Exception as exc:
            raise EnvelopeError("私钥不是合法 base64") from exc
        if len(raw) == _PRIVATE_RAW_SIZE:
            der = _PRIVATE_RAW_PKCS8_PREFIX + raw
        elif len(raw) == len(_PRIVATE_RAW_PKCS8_PREFIX) + _PRIVATE_RAW_SIZE:
            der = raw
        else:
            raise EnvelopeError(f"私钥长度非法: {len(raw)}")
        try:
            private_key = serialization.load_der_private_key(der, password=None)
        except Exception as exc:
            raise EnvelopeError(f"私钥解析失败: {type(exc).__name__}") from exc
    if not isinstance(private_key, X25519PrivateKey):
        raise EnvelopeError("私钥类型不是 X25519")
    return HostKeyPair(key_id=key_id, private_key=private_key, public_key=private_key.public_key())


def load_public_key(public_key_b64: str) -> Any:
    _require_crypto()
    try:
        raw = base64.b64decode(public_key_b64 or "", validate=True)
    except Exception as exc:
        raise EnvelopeError("公钥不是合法 base64") from exc
    if len(raw) != PUBLIC_KEY_SIZE:
        raise EnvelopeError(f"公钥长度非法: {len(raw)}")
    try:
        return X25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise EnvelopeError("公钥解析失败") from exc


def _read_header(payload: bytes, key_id: str) -> Dict[str, Any]:
    if len(payload) < _FIXED_HEADER:
        raise EnvelopeError("封套头被截断")
    if payload[:4] != MAGIC:
        raise EnvelopeError("封套魔数不匹配")
    version, suite, kid_len = struct.unpack("<BBH", payload[4:8])
    if version != VERSION:
        raise EnvelopeError(f"不支持的封套版本: {version}")
    if suite != SUITE_X25519_AESGCM:
        raise EnvelopeError(f"不支持的封套算法套件: {suite}")
    if kid_len == 0 or kid_len > KEY_ID_MAX:
        raise EnvelopeError("封套 key_id 长度非法")
    pos = _FIXED_HEADER
    need = kid_len + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE
    if len(payload) < pos + need:
        raise EnvelopeError("封套被截断")
    kid_raw = payload[pos:pos + kid_len]
    try:
        kid = kid_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("封套 key_id 编码非法") from exc
    if kid != key_id:
        raise EnvelopeError(f"封套 key_id 不匹配: 期望 {key_id}，实际 {kid}")
    pos += kid_len
    ephemeral_public = payload[pos:pos + PUBLIC_KEY_SIZE]
    pos += PUBLIC_KEY_SIZE
    nonce = payload[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE
    return {"kid_raw": kid_raw, "ephemeral_public": ephemeral_public,
            "nonce": nonce, "offset": pos, "header_len": pos}


def _open_frame(pair: HostKeyPair, payload: bytes, plaintext_schema: str, key_id: str) -> bytes:
    hdr = _read_header(payload, key_id)
    try:
        peer = X25519PublicKey.from_public_bytes(hdr["ephemeral_public"])
        shared = pair.private_key.exchange(peer)
    except Exception as exc:
        raise EnvelopeError(f"X25519 密钥协商失败: {type(exc).__name__}") from exc
    recipient_public = pair.public_key.public_bytes_raw()
    key = _derive_key(shared, hdr["ephemeral_public"], recipient_public, hdr["nonce"], hdr["kid_raw"])
    aad = _header_aad(hdr["kid_raw"], hdr["ephemeral_public"], hdr["nonce"], plaintext_schema)
    try:
        return AESGCM(key).decrypt(hdr["nonce"], payload[hdr["offset"]:], aad)
    except Exception as exc:
        raise EnvelopeError("封套认证失败：密文被篡改、key_id 不匹配或不是发给本宿主的对象") from exc


def _frame_ct_len(plain_len: int, key_id_len: int) -> int:
    """封套帧总长度 = 明文 + 头 + GCM tag；多帧按固定长度切分。"""
    return plain_len + _FIXED_HEADER + key_id_len + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE


def decrypt_envelope(pair: HostKeyPair, payload: bytes, key_id: Optional[str] = None,
                     plaintext_schema: str = "gha-plain/v1") -> bytes:
    """解开 Runner 回传的封套（单帧或多帧），返回原始明文。任何异常都抛 EnvelopeError。"""
    _require_crypto()
    kid = key_id or pair.key_id
    _validate_key_id(kid)
    if not payload:
        raise EnvelopeError("封套为空")
    key_id_len = len(kid.encode("utf-8"))
    single_min = _frame_ct_len(1, key_id_len)
    single_max = _frame_ct_len(FRAME_PLAINTEXT, key_id_len)
    if len(payload) <= single_max:
        # 单帧：整包解密，一次校验 tag
        return _open_frame(pair, payload, plaintext_schema, kid)

    # 多帧：每帧密文长度固定，按长度直接切分，不用扫描内容
    out = bytearray()
    pos = 0
    while pos < len(payload):
        remaining = len(payload) - pos
        if remaining >= single_max:
            take = single_max
        elif remaining >= single_min:
            take = remaining
        else:
            raise EnvelopeError("封套多帧数据被截断")
        out.extend(_open_frame(pair, payload[pos:pos + take], plaintext_schema, kid))
        pos += take
    return bytes(out)


# ---------------------------------------------------------------------------
# Runner 侧：只用公钥加密
# ---------------------------------------------------------------------------

class EnvelopeSealer:
    """Runner 侧封套加密器：只持有 Host 公钥。"""

    def __init__(self, key_id: str, public_key_b64: str, plaintext_schema: str = "gha-plain/v1"):
        _require_crypto()
        self.key_id = key_id
        self._kid_raw = _validate_key_id(key_id)
        self._recipient_public = load_public_key(public_key_b64).public_bytes_raw()
        self.plaintext_schema = plaintext_schema

    def _seal_frame(self, plaintext: bytes) -> bytes:
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(self._recipient_public))
        nonce = os.urandom(NONCE_SIZE)
        key = _derive_key(shared, ephemeral_public, self._recipient_public, nonce, self._kid_raw)
        aad = _header_aad(self._kid_raw, ephemeral_public, nonce, self.plaintext_schema)
        header = (MAGIC + struct.pack("<BBH", VERSION, SUITE_X25519_AESGCM, len(self._kid_raw))
                  + self._kid_raw + ephemeral_public + nonce)
        return header + AESGCM(key).encrypt(nonce, plaintext, aad)

    def seal(self, plaintext: bytes) -> bytes:
        if len(plaintext) <= FRAME_PLAINTEXT:
            return self._seal_frame(plaintext)
        frames = []
        for start in range(0, len(plaintext), FRAME_PLAINTEXT):
            frames.append(self._seal_frame(plaintext[start:start + FRAME_PLAINTEXT]))
        return b"".join(frames)

    def seal_file(self, plaintext_path: str) -> bytes:
        """读入明文并返回完整封套密文；明文文件本身不在此处删除。"""
        with open(plaintext_path, "rb") as f:
            return self.seal(f.read())

    def seal_stream(self, plaintext_path: str, output_path: str) -> Tuple[str, int]:
        """逐帧封装到目标文件，同时返回 (明文 SHA-256, 明文字节数)。

        内存占用恒定为单帧大小，适合数百 MB 的 Profile / 录像。
        """
        digest = hashlib.sha256()
        total = 0
        with open(plaintext_path, "rb") as src, open(output_path, "wb") as dst:
            while True:
                chunk = src.read(FRAME_PLAINTEXT)
                if not chunk:
                    break
                dst.write(self._seal_frame(chunk))
                digest.update(chunk)
                total += len(chunk)
            if total == 0:
                dst.write(self._seal_frame(b""))
            dst.flush()
            os.fsync(dst.fileno())
        return digest.hexdigest(), total

    def metadata(self) -> Dict[str, str]:
        return {
            "envelope": "gha-state-envelope",
            "envelope_version": str(VERSION),
            "envelope_algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
            "key_id": self.key_id,
            "key_fingerprint": fingerprint_public_key(self._recipient_public),
        }


def fingerprint_public_key(public_key_raw: bytes) -> str:
    return hashlib.sha256(public_key_raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Runner 侧密钥配置：从配置文件 / 环境注入读取，只拿公钥
# ---------------------------------------------------------------------------

PUBLIC_KEY_ENV = "GHA_STATE_PUBLIC_KEY"
KEY_ID_ENV = "GHA_STATE_KEY_ID"


@dataclass
class RecipientConfig:
    key_id: Optional[str] = None
    public_key: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.key_id and self.public_key)

    def sealer(self) -> EnvelopeSealer:
        if not self.configured:
            raise EnvelopeError("未配置 Host 公钥")
        return EnvelopeSealer(self.key_id or "", self.public_key or "")


def _load_config_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml
        data = yaml.safe_load(text) or {}
    except ImportError:  # 极简解析：只认 key_id / public_key 两行
        data = {}
        for line in text.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() in ("key_id", "public_key"):
                data[key.strip()] = value.strip().strip("'\"")
    return data


def _from_blob(raw: Optional[str]) -> Dict[str, Any]:
    """GHA_STATE_SECRETS 三种合法形态：JSON 对象、JSON 字符串、base64(JSON)。

    也接受被 `state_keys` 包一层的写法，与配置文件保持一致。
    """
    if not raw:
        return {}
    text = raw.strip()
    for _ in range(3):
        try:
            data = json.loads(text)
        except ValueError:
            try:
                data = json.loads(base64.b64decode(text, validate=True).decode("utf-8"))
            except Exception as exc:
                raise EnvelopeError(f"状态密钥 blob 无法解析: {type(exc).__name__}") from exc
        if isinstance(data, dict):
            nested = data.get("state_keys")
            return nested if isinstance(nested, dict) else data
        if isinstance(data, str):
            text = data.strip()
            continue
        raise EnvelopeError("状态密钥 blob 必须是 JSON 对象")
    raise EnvelopeError("状态密钥 blob 嵌套层数过多")


def load_recipient_config(env: Optional[Dict[str, str]] = None,
                          config_path: Optional[str] = None) -> RecipientConfig:
    """优先级：显式 env > GHA_STATE_SECRETS blob > 配置文件。

    只读取公钥与 key_id；任何私钥字段都不会被读取，更不会被打印。
    """
    env = os.environ if env is None else env
    key_id = env.get(KEY_ID_ENV) or None
    public_key = env.get(PUBLIC_KEY_ENV) or None
    blob = env.get("GHA_STATE_SECRETS") or None
    path = config_path or env.get("GHA_STATE_KEYS_FILE") or None

    if blob:
        try:
            data = _from_blob(blob)
        except EnvelopeError:
            raise
        except Exception as exc:
            raise EnvelopeError(f"状态密钥 blob 无法解析: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise EnvelopeError("状态密钥 blob 必须是 JSON 对象")
        if data.get("private_key") or data.get("private_secret"):
            # 私钥出现在 Runner 上说明配置放错了地方；直接拒绝，绝不读入
            raise EnvelopeError("Runner 侧密钥配置包含私钥字段；Runner 只能拿公钥")
        key_id = key_id or data.get("key_id")
        public_key = public_key or data.get("public_key")
    elif path:
        if not os.path.isfile(path):
            raise EnvelopeError(f"状态密钥文件不存在: {path}")
        try:
            data = _load_config_file(path)
        except Exception as exc:
            raise EnvelopeError(f"状态密钥文件无法解析: {type(exc).__name__}") from exc
        if isinstance(data.get("state_keys"), dict):
            data = data["state_keys"]
        if data.get("private_key") or data.get("private_secret"):
            raise EnvelopeError("Runner 侧密钥配置包含私钥字段；Runner 只能拿公钥")
        key_id = key_id or data.get("key_id")
        public_key = public_key or data.get("public_key")

    cfg = RecipientConfig(key_id=key_id, public_key=public_key)
    if cfg.configured:
        # 早失败：公钥不合法就在启动期报错，而不是等到首个 checkpoint
        EnvelopeSealer(cfg.key_id, cfg.public_key)  # type: ignore[arg-type]
    return cfg


# ---------------------------------------------------------------------------
# Host 侧密钥存储：私钥与 Vault 同级目录、0600 权限
# ---------------------------------------------------------------------------

DEFAULT_KEY_FILE_NAME = "state-recipient.json"


def _chmod(path: Any, mode: int) -> None:
    try:
        os.chmod(str(path), mode)
    except OSError:
        pass


def load_or_create_host_keys(keys_dir: Any, key_id: Optional[str] = None) -> HostKeyPair:
    """在 keys_dir 下保存 Host 私钥（0600）；已存在则加载。"""
    _require_crypto()
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    _chmod(keys_dir, 0o700)
    path = keys_dir / DEFAULT_KEY_FILE_NAME
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        pair = load_host_key_pair(doc["key_id"], doc["private_key"])
        _chmod(path, 0o600)
        return pair
    pair = generate_host_key_pair(key_id)
    doc = {
        "schema": "gha-host-key/v1",
        "algorithm": "X25519",
        "key_id": pair.key_id,
        "private_key": pair.private_secret(),
        "public_key": pair.public_b64(),
        "created_at": time.time(),
    }
    fd, tmp = tempfile.mkstemp(prefix=".state-recipient-", dir=str(keys_dir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    _chmod(path, 0o600)
    return pair


def shareable_public_document(pair: HostKeyPair) -> Dict[str, str]:
    """可安全打印/写入 GHA_TASK_SECRETS 的公钥文档（不含私钥）。"""
    return pair.public_document()
