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
# v1：AAD 只绑定格式头与 schema；v2：格式头内再绑定明文声明（摘要/长度/总帧数）
LEGACY_VERSION = 1
VERSION = 2
SUITE_X25519_AESGCM = 1

# v2 明文声明段：2 字节标记 + 32 字节明文 SHA-256 + 4 字节明文长度 + 4 字节总帧数
DECL_MAGIC = 0x0044
DECL_NONE = 0xFFFF
DECL_SHA_SIZE = 32
DECL_BLOCK_SIZE = 2 + DECL_SHA_SIZE + 8

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


def _header_aad(key_id: bytes, ephemeral_public: bytes, nonce: bytes, plaintext_schema: str,
                declaration: bytes = b"", version: int = LEGACY_VERSION) -> bytes:
    header = MAGIC + struct.pack("<BBH", version, SUITE_X25519_AESGCM, len(key_id)) + key_id
    # 声明段夹在 key_id 与临时公钥之间：只进 AAD，v1 不写（保持既有封套格式不变）
    header += declaration + ephemeral_public + nonce
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


def envelope_key_id(payload: bytes) -> Optional[str]:
    """从封套固定头里读出 key_id（长度上限 KEY_ID_MAX）；格式不对返回 None。

    公开 manifest 不带 key_id，Host 解封时从这里取，再和本地私钥的 key_id 比对。
    """
    if len(payload) < 8 or payload[:4] != MAGIC:
        return None
    kid_len = struct.unpack("<H", payload[6:8])[0]
    if kid_len < 1 or kid_len > KEY_ID_MAX or len(payload) < 8 + kid_len:
        return None
    try:
        return payload[8:8 + kid_len].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_header(payload: bytes, key_id: str) -> Dict[str, Any]:
    if len(payload) < _FIXED_HEADER:
        raise EnvelopeError("封套头被截断")
    if payload[:4] != MAGIC:
        raise EnvelopeError("封套魔数不匹配")
    version, suite, kid_len = struct.unpack("<BBH", payload[4:8])
    if version not in (LEGACY_VERSION, VERSION):
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
    declarations: Dict[str, Any] = {}
    declaration = b""
    if version == VERSION:
        # 2 字节标记 + 32 字节明文摘要 + 4 字节明文长度 + 4 字节总帧数，全部绑定在 AAD 里。
        # _FIXED_HEADER 只有 8 字节，key_id 较长时声明段可能跨过它，必须按 pos 再判长度。
        if len(payload) < pos + DECL_BLOCK_SIZE:
            raise EnvelopeError("封套明文声明段被截断")
        declaration = payload[pos:pos + DECL_BLOCK_SIZE]
        marker = struct.unpack("<H", declaration[:2])[0]
        if marker == DECL_MAGIC:
            sha_raw = declaration[2:2 + DECL_SHA_SIZE]
            size, frames = struct.unpack("<II", declaration[2 + DECL_SHA_SIZE:])
            if frames == 0:
                raise EnvelopeError("封套明文声明段非法")
            declarations = {"plaintext_sha256": sha_raw.hex(), "plaintext_size": size,
                            "plaintext_frames": frames}
        elif marker != DECL_NONE:
            raise EnvelopeError("封套明文声明段非法")
        pos += DECL_BLOCK_SIZE
    ephemeral_public = payload[pos:pos + PUBLIC_KEY_SIZE]
    pos += PUBLIC_KEY_SIZE
    nonce = payload[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE
    return {"kid_raw": kid_raw, "ephemeral_public": ephemeral_public,
            "nonce": nonce, "offset": pos, "header_len": pos, "version": version,
            "declaration": declaration, **declarations}


# 解封时对“封套头声明的明文摘要/长度”的对账结果（同进程内最近一次，不含明文）
_LAST_VERIFIED: Dict[str, Any] = {}


def last_verified_envelope() -> Dict[str, Any]:
    """最近一次成功解封时与封套声明对上的明文摘要与长度；未声明时为 None。"""
    return dict(_LAST_VERIFIED)


def _open_frame(pair: HostKeyPair, payload: bytes, plaintext_schema: str, key_id: str,
                frame_index: int = 0, expected_sha256: Optional[str] = None,
                expected_size: Optional[int] = None, expected_total_frames: Optional[int] = None,
                record_verification: bool = True) -> bytes:
    hdr = _read_header(payload, key_id)
    try:
        peer = X25519PublicKey.from_public_bytes(hdr["ephemeral_public"])
        shared = pair.private_key.exchange(peer)
    except Exception as exc:
        raise EnvelopeError(f"X25519 密钥协商失败: {type(exc).__name__}") from exc
    recipient_public = pair.public_key.public_bytes_raw()
    key = _derive_key(shared, hdr["ephemeral_public"], recipient_public, hdr["nonce"], hdr["kid_raw"])
    aad = _header_aad(hdr["kid_raw"], hdr["ephemeral_public"], hdr["nonce"], plaintext_schema,
                      hdr["declaration"], hdr["version"])
    try:
        plaintext = AESGCM(key).decrypt(hdr["nonce"], payload[hdr["offset"]:], aad)
    except Exception as exc:
        raise EnvelopeError("封套认证失败：密文被篡改、key_id 不匹配或不是发给本宿主的对象") from exc
    # 封套 AAD 绑定过的明文声明：篡改或与清单错配在这里拒绝，而不是解出内容再比对
    declared_sha = hdr.get("plaintext_sha256")
    declared_size = hdr.get("plaintext_size")
    declared_frames = hdr.get("plaintext_frames")
    if declared_sha is not None:
        if expected_sha256 is not None and declared_sha != expected_sha256:
            raise EnvelopeError("封套声明的明文摘要与清单 plaintext_sha256 不一致")
        # 多帧时声明段描述整段明文，单帧比对放到拼完后；帧内只认 AAD
        if declared_frames == 1 and hashlib.sha256(plaintext).hexdigest() != declared_sha:
            raise EnvelopeError("封套声明的明文摘要与实际解出的明文不一致")
    # 多帧时声明段描述整段明文，帧内长度另行按帧累计核对
    if declared_size is not None and declared_frames == 1 and len(plaintext) != declared_size:
        raise EnvelopeError("封套声明的明文长度与实际解出的明文不一致")
    if declared_frames is not None:
        if expected_total_frames is not None and declared_frames != expected_total_frames:
            raise EnvelopeError("封套声明的帧数与实际不符")
        if frame_index >= declared_frames:
            raise EnvelopeError("封套帧序号超出声明帧数")
    if not record_verification:
        return plaintext
    _LAST_VERIFIED.clear()
    _LAST_VERIFIED.update({
        "plaintext_sha256": declared_sha,
        "plaintext_size": declared_size,
        "plaintext_frames": declared_frames,
        "frame_index": frame_index,
    })
    return plaintext


def _frame_ct_len(plain_len: int, key_id_len: int, digest_bound: bool = False) -> int:
    """封套帧总长度 = 明文 + 头（+ v2 声明段） + GCM tag；多帧按固定长度切分。"""
    decl = DECL_BLOCK_SIZE if digest_bound else 0
    return plain_len + _FIXED_HEADER + key_id_len + decl + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE


def decrypt_envelope(pair: HostKeyPair, payload: bytes, key_id: Optional[str] = None,
                     plaintext_schema: str = "gha-plain/v1",
                     expected_sha256: Optional[str] = None,
                     expected_size: Optional[int] = None) -> bytes:
    """解开 Runner 回传的封套（单帧或多帧），返回原始明文。任何异常都抛 EnvelopeError。

    expected_* 来自清单：v2 封套头内的声明必须与之相符，解出的明文也必须相符。
    """
    _require_crypto()
    kid = key_id or pair.key_id
    _validate_key_id(kid)
    if not payload:
        raise EnvelopeError("封套为空")
    key_id_len = len(kid.encode("utf-8"))
    single = _checked_frame_len(payload[:8], key_id_len)
    single_min = _frame_ct_len(1, key_id_len, single)
    single_max = _frame_ct_len(FRAME_PLAINTEXT, key_id_len, single)
    if len(payload) <= single_max:
        # 单帧：整包解密，一次校验 tag
        return _open_frame(pair, payload, plaintext_schema, kid,
                           expected_sha256=expected_sha256,
                           expected_size=expected_size, expected_total_frames=1 if single else None)

    # 多帧：每帧密文长度固定，按长度直接切分，不用扫描内容
    out = bytearray()
    pos = 0
    index = 0
    declared_frames = None
    declared_sha = None
    declared_size = None
    while pos < len(payload):
        remaining = len(payload) - pos
        if remaining >= single_max:
            take = single_max
        elif remaining >= single_min:
            take = remaining
        else:
            raise EnvelopeError("封套多帧数据被截断")
        frame = _open_frame(pair, payload[pos:pos + take], plaintext_schema, kid,
                            frame_index=index, expected_sha256=expected_sha256,
                            expected_total_frames=declared_frames,
                            record_verification=index == 0)
        if declared_frames is None:
            declared_frames = _LAST_VERIFIED.get("plaintext_frames")
            declared_sha = _LAST_VERIFIED.get("plaintext_sha256")
            declared_size = _LAST_VERIFIED.get("plaintext_size")
        out.extend(frame)
        pos += take
        index += 1
    if declared_frames is not None and declared_frames != index:
        raise EnvelopeError(f"封套声明 {declared_frames} 帧，实际解出 {index} 帧")
    plaintext = bytes(out)
    if declared_size is not None and len(plaintext) != declared_size:
        raise EnvelopeError("封套声明的明文长度与实际解出的明文不一致")
    if declared_sha is not None and hashlib.sha256(plaintext).hexdigest() != declared_sha:
        raise EnvelopeError("封套声明的明文摘要与实际解出的明文不一致")
    if expected_size is not None and expected_size != len(plaintext):
        raise EnvelopeError(f"解封后明文 {len(plaintext)} 字节与清单声明 {expected_size} 不一致")
    return plaintext


def _checked_frame_len(fixed: bytes, key_id_len: int) -> bool:
    """根据固定头判断是否 v2（带明文声明段）。"""
    if len(fixed) < _FIXED_HEADER or fixed[:4] != MAGIC:
        return False
    return fixed[4] == VERSION


def _read_exact(f: Any, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise EnvelopeError("封套被截断")
    return data


def _open_frame_from_file(pair: HostKeyPair, f: Any, plaintext_schema: str, key_id: str,
                          frame_index: int = 0, record_verification: bool = True,
                          declarations: Optional[Dict[str, Any]] = None,
                          expected_sha256: Optional[str] = None) -> bytes:
    """按文件游标读取一个完整封套帧并解密；帧长由帧头版本与 key_id 长度决定。"""
    fixed = _read_exact(f, _FIXED_HEADER)
    if fixed[:4] != MAGIC:
        raise EnvelopeError("封套魔数不匹配")
    version = fixed[4]
    if version not in (LEGACY_VERSION, VERSION):
        raise EnvelopeError(f"不支持的封套版本: {version}")
    kid_len = struct.unpack("<H", fixed[6:8])[0]
    if kid_len == 0 or kid_len > KEY_ID_MAX:
        raise EnvelopeError("封套 key_id 长度非法")
    decl_len = DECL_BLOCK_SIZE if version == VERSION else 0
    rest_len = kid_len + decl_len + PUBLIC_KEY_SIZE + NONCE_SIZE + FRAME_PLAINTEXT + TAG_SIZE
    rest = f.read(rest_len)
    # 帧头 + 至少 1 字节明文 + tag；少了说明文件被截断
    if len(rest) < kid_len + decl_len + PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE + 1:
        raise EnvelopeError("封套被截断")
    frame = fixed + rest
    if declarations is not None:
        # 多帧文件要先知道总帧数才能核对每帧声明：先只解析头
        hdr = _read_header(frame, key_id)
        if hdr.get("plaintext_frames") is not None:
            declarations.setdefault("frames", hdr["plaintext_frames"])
    return _open_frame(pair, frame, plaintext_schema, key_id,
                       frame_index=frame_index, expected_sha256=expected_sha256,
                       expected_total_frames=(declarations or {}).get("frames"),
                       record_verification=record_verification)


def decrypt_envelope_to_file(pair: HostKeyPair, sealed_path: str, output_path: str,
                             key_id: Optional[str] = None,
                             plaintext_schema: str = "gha-plain/v1",
                             expected_sha256: Optional[str] = None,
                             expected_size: Optional[int] = None) -> int:
    """逐帧解密到输出文件，内存占用恒定为单帧；返回明文字节数。任何异常抛 EnvelopeError。

    expected_* 是清单声明：v2 封套头里的声明必须在解出任何明文前就与之一致，
    且总帧数必须与第 0 帧声明相同，避免跨对象拼接帧绕过校验。
    """
    _require_crypto()
    kid = key_id or pair.key_id
    _validate_key_id(kid)
    written = 0
    declarations: Dict[str, Any] = {}
    with open(sealed_path, "rb") as src, open(output_path, "wb") as dst:
        if not src.read(1):
            raise EnvelopeError("封套为空")
        src.seek(0)
        index = 0
        while True:
            mark = src.tell()
            if not src.read(1):
                break
            src.seek(mark)
            frame = _open_frame_from_file(pair, src, plaintext_schema, kid, frame_index=index,
                                          declarations=declarations,
                                          expected_sha256=expected_sha256)
            dst.write(frame)
            written += len(frame)
            index += 1
        dst.flush()
        os.fsync(dst.fileno())
    if declarations.get("frames") is not None and declarations["frames"] != index:
        raise EnvelopeError(f"封套声明 {declarations['frames']} 帧，实际解出 {index} 帧")
    if expected_size is not None and expected_size != written:
        raise EnvelopeError(f"解封后明文 {written} 字节与清单声明 {expected_size} 不一致")
    return written


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

    @staticmethod
    def declarations(plaintext: bytes, total_frames: int) -> bytes:
        """v2 声明段：整段明文的 SHA-256、长度与总帧数；随每个帧的 AAD 认证。"""
        return (struct.pack("<H", DECL_MAGIC) + hashlib.sha256(plaintext).digest()
                + struct.pack("<II", len(plaintext), total_frames))

    def _seal_frame(self, plaintext: bytes, declaration: Optional[bytes] = None) -> bytes:
        """封一帧明文；declaration 非空时产出 v2 封套（声明段进 AAD，篡改即认证失败）。"""
        declaration = declaration or b""
        version = VERSION if declaration else LEGACY_VERSION
        if declaration and len(declaration) != DECL_BLOCK_SIZE:
            raise EnvelopeError("封套声明段长度非法")
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(self._recipient_public))
        nonce = os.urandom(NONCE_SIZE)
        key = _derive_key(shared, ephemeral_public, self._recipient_public, nonce, self._kid_raw)
        aad = _header_aad(self._kid_raw, ephemeral_public, nonce, self.plaintext_schema,
                          declaration, version)
        header = (MAGIC + struct.pack("<BBH", version, SUITE_X25519_AESGCM, len(self._kid_raw))
                  + self._kid_raw + declaration + ephemeral_public + nonce)
        return header + AESGCM(key).encrypt(nonce, plaintext, aad)

    def seal(self, plaintext: bytes) -> bytes:
        frames = max(1, -(-len(plaintext) // FRAME_PLAINTEXT))
        declaration = self.declarations(plaintext, frames)
        return b"".join(
            self._seal_frame(plaintext[start:start + FRAME_PLAINTEXT], declaration)
            for start in range(0, max(len(plaintext), 1), FRAME_PLAINTEXT)
        )

    def seal_file(self, plaintext_path: str) -> bytes:
        """读入明文并返回完整封套密文；明文文件本身不在此处删除。"""
        with open(plaintext_path, "rb") as f:
            return self.seal(f.read())

    def seal_stream(self, plaintext_path: str, output_path: str) -> Tuple[str, int]:
        """逐帧封装到目标文件，同时返回 (明文 SHA-256, 明文字节数)。

        内存占用恒定为单帧大小，适合数百 MB 的 Profile / 录像。
        返回值只描述**明文**；密文摘要由写的字节另行计算，两者绝不能混用。
        """
        plaintext_sha, total, _ = self.seal_stream_verified(plaintext_path, output_path)
        return plaintext_sha, total

    def seal_stream_verified(self, plaintext_path: str, output_path: str) -> Tuple[str, int, str]:
        """封装并返回 (明文 SHA-256, 明文字节数, 密文文件 SHA-256)。

        明文摘要是**实际读入**的明文字节摘要，密文摘要按实际写入的封套字节累计；
        调用方据此分别声明传输摘要与明文摘要，而不是拿明文的摘要充当密文摘要
        （那样密文的传输校验形同虚设）。两遍读明文：先算出整段明文摘要与帧数，
        声明段随后随每帧 AAD 认证，Host 在解出任何明文前就能核对。
        """
        digest = hashlib.sha256()
        total = 0
        with open(plaintext_path, "rb") as src:
            while True:
                chunk = src.read(FRAME_PLAINTEXT)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
        frames = max(1, -(-total // FRAME_PLAINTEXT))
        declaration = self.declarations_sha(digest.hexdigest(), total, frames)
        sealed_digest = hashlib.sha256()
        with open(plaintext_path, "rb") as src, open(output_path, "wb") as dst:
            for _ in range(frames):
                chunk = src.read(FRAME_PLAINTEXT)
                frame = self._seal_frame(chunk, declaration)
                dst.write(frame)
                sealed_digest.update(frame)
            dst.flush()
            os.fsync(dst.fileno())
        return digest.hexdigest(), total, sealed_digest.hexdigest()

    @staticmethod
    def declarations_sha(plaintext_sha256: str, size: int, total_frames: int) -> bytes:
        return struct.pack("<H", DECL_MAGIC) + bytes.fromhex(plaintext_sha256) + struct.pack(
            "<II", size, total_frames)

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
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            os.chmod(tmp, 0o600)
        else:
            fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(doc, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
    _chmod(path, 0o600)
    return pair


def shareable_public_document(pair: HostKeyPair) -> Dict[str, str]:
    """可安全打印/写入 GHA_TASK_SECRETS 的公钥文档（不含私钥）。"""
    return pair.public_document()
