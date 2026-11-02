"""私有会话发现（Rendezvous Provider）与最小生产 Registry。

遵循《2.0 迭代.md》第五章 5.4 与 5.5「随机地址私有发现与 Registry 规范」。
职责：
- Runner 侧将生成的随机 trycloudflare URL 安全提交至私有 Registry 或 HTTPS 回调；
- Agent 侧从 Registry 安全查询当前 session_id / run_id 对应的公网网关入口；
- 绝不在 GitHub Actions Log, Job Summary 或 Artifact 中暴露随机地址。

Registry 协议（客户端与服务端共用）：

- 认证：``Authorization: Bearer <kid>``。``kid`` 是 Registry 凭证的摘要，同时出现在
  ``/v1/sessions/<kid>`` 路径段；Header 与路径段不一致直接拒绝。
- 签名：``X-GHA-Signature: v1=<hex>``，``v1 = HMAC-SHA256(HKDF(token), t + "\\n" + nonce
  + "\\n" + method + "\\n" + canonical_path + "\\n" + raw_body)``。查询参数不参与签名，
  因此规范路径里只保留 Registry 认识的安全参数（见 ``_SIGNED_QUERY_KEYS``）。
- 重放：``X-GHA-Timestamp``（±300s）+ 一次性 ``X-GHA-Nonce``。
- 租约：``run_id`` 原子占用；同一用户换新 session 续租时旧会话被原子撤销（防止同一 run
  两个 Runner 错路由），其他用户抢占返回 409；``hostname`` 同时只能属于一个用户，
  刚被释放的 hostname 有短暂冷却，防止 Named 固定域名在交接窗口内被错误路由。
- 隔离：解析时提供的 ``user`` 必须与登记一致；不提供 user 的 GET 一律拒绝。
- 响应：每个成功响应附带 ``response_signature``，客户端必须校验。
- 内容加密：登记正文用凭证派生的 AES-256-GCM 加密，磁盘上看不到 origin / Agent Token。

服务端依赖 AES-GCM（``cryptography``，Runtime 已依赖）。缺少该包时
``create_registry_server`` 返回 ``None``（fail-closed）；只有凭证单独保存在
``private_dirs``（RUNNER_TEMP 等任务包之外的位置）时才允许降级为内存明文存储，
避免把密文/明文写进任务包或制品。
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

SIGNATURE_VERSION = "v1"
CLOCK_SKEW_SECONDS = 300
NONCE_RETENTION_SECONDS = 600
GC_INTERVAL_SECONDS = 5.0
DEFAULT_FORGET_GUARD_SECONDS = 300
MAX_BODY_BYTES = 64 * 1024
MAX_TTL_SECONDS = 24 * 3600
MAX_USER_LENGTH = 256
DEFAULT_LEASE_TTL_SECONDS = 7200

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
KID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

_KDF_INFO = b"gha-rendezvous/v1"
_AAD = b"gha-rendezvous/v1"
_SIGNED_QUERY_KEYS = ("run_id", "user")
_LEASE_PREFIX = "lease/"
_NONCE_PREFIX = "nonce/"


class RegistryError(Exception):
    """Registry 错误（客户端与存储层共用）"""

    def __init__(self, status: Optional[int], message: str):
        super().__init__(message)
        self.status = status


class SignatureError(Exception):
    """请求或响应签名不匹配"""


# ---------------------------------------------------------------------------
# 元数据清洗 / 确定性 JSON
# ---------------------------------------------------------------------------


def sanitize_metadata(raw: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """只保留短的标量元数据，丢弃 URL/Token/口令样式的值，避免敏感信息进入公开状态。"""
    secret_words = ("token", "secret", "password", "cookie", "authorization")
    clean: Dict[str, str] = {}
    for key, value in (raw or {}).items():
        if not isinstance(key, str) or not isinstance(value, (str, int, float, bool)):
            continue
        lowered = (key + " " + str(value)).lower()
        if "://" in str(value) or any(word in lowered for word in secret_words):
            continue
        clean[key[:64]] = str(value)[:256]
    return clean


def canonical_json(payload: Any) -> bytes:
    """键排序、无空白的 UTF-8 JSON，用于签名与加密前的序列化。"""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# 签名
# ---------------------------------------------------------------------------


def signing_key(auth_token: str) -> bytes:
    return hmac.new(auth_token.encode("utf-8"), _KDF_INFO, hashlib.sha256).digest()


def signature_string(auth_token: str, method: str, canonical_path: str, body: bytes,
                     timestamp: int = 0, nonce: str = "-") -> str:
    canonical = "%d\n%s\n%s\n%s\n" % (int(timestamp), nonce, method.upper(), canonical_path)
    digest = hmac.new(signing_key(auth_token), canonical.encode("utf-8") + body, hashlib.sha256)
    return SIGNATURE_VERSION + "=" + digest.hexdigest()


def signing_headers(
    auth_token: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
    kid: Optional[str] = None,
) -> Dict[str, str]:
    """构造带签名的认证 Header。

    ``auth_token`` 是签名密钥（Registry 凭证）；``kid`` 是路径段中的租约凭证，
    默认与 ``auth_token`` 相同。时间戳与 nonce 可显式指定（测试时钟/重放用例）。
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    n = nonce or secrets.token_hex(16)
    return {
        "Authorization": f"Bearer {kid or auth_token}",
        "X-GHA-Timestamp": str(ts),
        "X-GHA-Nonce": n,
        "X-GHA-Signature": signature_string(auth_token, method, path, body, ts, n),
    }


def _signed_path(raw_path: str) -> str:
    """签名覆盖的规范路径：去掉非白名单查询参数，参数按键排序。"""
    parts = urllib.parse.urlsplit(raw_path)
    query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    kept = []
    for key in _SIGNED_QUERY_KEYS:
        for value in query.get(key, []):
            kept.append((key, value))
    kept.sort()
    return parts.path + (("?" + urllib.parse.urlencode(kept)) if kept else "")


# ---------------------------------------------------------------------------
# 登记内容加密
# ---------------------------------------------------------------------------


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        return None


def _seal_key(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8") + _KDF_INFO + b"/seal").digest()


class _Sealed:
    """凭证派生的 AES-256-GCM 密文容器（内存中也不保留明文）。"""

    __slots__ = ("_nonce", "_ciphertext")

    def __init__(self, secret: str, payload: Mapping[str, Any]):
        aesgcm = _aesgcm()
        if aesgcm is None:
            raise RegistryError(None, "缺少 cryptography，无法加密 Registry 登记内容")
        self._nonce = secrets.token_bytes(12)
        self._ciphertext = aesgcm(_seal_key(secret)).encrypt(
            self._nonce, canonical_json(dict(payload)), _AAD
        )

    def open(self, secret: str) -> Dict[str, Any]:
        aesgcm = _aesgcm()
        if aesgcm is None:
            raise RegistryError(None, "缺少 cryptography，无法解密 Registry 登记内容")
        plain = aesgcm(_seal_key(secret)).decrypt(self._nonce, self._ciphertext, _AAD)
        return json.loads(plain.decode("utf-8"))


class _Plain:
    """缺少 cryptography 时的内存明文容器：只在凭证位于任务包外时使用，绝不落盘。"""

    __slots__ = ("_payload",)

    def __init__(self, payload: Mapping[str, Any]):
        self._payload = dict(payload)

    def open(self, _secret: str) -> Dict[str, Any]:
        return dict(self._payload)


# ---------------------------------------------------------------------------
# 租约表
# ---------------------------------------------------------------------------


class _Ttl:
    """KV 中带过期时间的值（nonce 等一次性记录），由 ``_gc`` 回收。"""

    __slots__ = ("value", "release_at")

    def __init__(self, value: Any, release_at: float):
        self.value = value
        self.release_at = release_at


class _Entry:
    __slots__ = (
        "session_id", "run_id", "user", "hostname", "content",
        "expires_at", "kid", "secret",
    )

    def __init__(self, session_id: str, run_id: str, user: str, hostname: str,
                 content: Any, expires_at: float, kid: str, secret: str):
        self.session_id = session_id
        self.run_id = run_id
        self.user = user
        self.hostname = hostname
        self.content = content
        self.expires_at = expires_at
        self.kid = kid
        self.secret = secret

    def open(self) -> Dict[str, Any]:
        return self.content.open(self.secret)


class RendezvousRegistry:
    """最小生产 Registry 存储（只读内部状态，没有公开列举接口）。

    ``kv`` 可用 Cloudflare KV 等具备 get/put/delete/scan 能力的存储替换（最终一致性
    场景需自行保证原子性，见《2.0 迭代.md》5.5）；``lock`` 保证进程内操作原子。
    """

    def __init__(
        self,
        kv: Optional[Mapping[str, Any]] = None,
        lock: Optional[threading.RLock] = None,
        credentials: Optional[Iterable[str]] = None,
        private_dirs: Optional[Iterable[str]] = None,
        clock=None,
        max_ttl: int = MAX_TTL_SECONDS,
        forget_guard_seconds: int = DEFAULT_FORGET_GUARD_SECONDS,
        nonce_retention: int = NONCE_RETENTION_SECONDS,
    ):
        self.kv: Any = kv if kv is not None else {}
        self.lock = lock or threading.RLock()
        self._clock = clock or time.time
        self._max_ttl = int(max_ttl)
        self._forget_guard = float(forget_guard_seconds)
        self._nonce_retention = float(nonce_retention)
        self._credentials: Dict[str, str] = {}
        self._last_gc = -GC_INTERVAL_SECONDS
        # 凭证只能从私有目录读取；任何其他来源（任务包、制品）一律不信任明文存储。
        self._plaintext_dir = next(
            (d for d in (private_dirs or ()) if d and os.path.isdir(d)), None
        )
        for token in credentials or ():
            if token:
                self._credentials.setdefault(self._kid_for(token), token)

    # -- 基础 --------------------------------------------------------------

    @staticmethod
    def _kid_for(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:32]

    def _now(self) -> float:
        return float(self._clock())

    def _can_seal(self) -> bool:
        return _aesgcm() is not None

    def _seal(self, secret: str, payload: Mapping[str, Any]) -> Any:
        if _aesgcm() is not None:
            return _Sealed(secret, payload)
        if self._plaintext_dir is None:
            raise RegistryError(
                503, "缺少 cryptography：Registry 无法加密登记内容，拒绝明文存储"
            )
        return _Plain(payload)

    def _get(self, key: str, now: float) -> Any:
        with self.lock:
            holder = self.kv.get(key)
        if type(holder) is not _Ttl:
            return holder
        return None if holder.release_at <= now else holder.value

    def _put(self, key: str, value: Any, release_at: Optional[float] = None) -> None:
        """KV 写入；带 ``release_at``（绝对时刻）的值包成 ``_Ttl`` 由 reaper 回收。"""
        stored = value if release_at is None else _Ttl(value, release_at)
        with self.lock:
            if hasattr(self.kv, "put"):
                self.kv.put(key, stored)
            else:
                self.kv[key] = stored
        if release_at is not None:
            self._cache_mirror(key, release_at)

    def _delete(self, key: str) -> None:
        with self.lock:
            if hasattr(self.kv, "delete"):
                self.kv.delete(key)
            else:
                self.kv.pop(key, None)

    def _credential(self, kid: str) -> Optional[str]:
        return self._credentials.get(kid)

    # -- 请求认证 ----------------------------------------------------------

    def authenticate(
        self,
        method: str,
        raw_path: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> Optional[str]:
        """校验 Bearer + 签名 + 时间戳 + 一次性 nonce；成功返回凭证 kid，否则 None。"""
        now = self._now()
        lower = {str(k).lower(): v for k, v in headers.items()}
        auth = str(lower.get("authorization", ""))
        bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        parts = urllib.parse.urlsplit(raw_path).path.split("/")
        kid = parts[-1] if len(parts) > 1 and KID_RE.match(parts[-1]) else ""
        # Header 必须与路径段一致；kid 只是租约标识，签名密钥仍由 Registry 侧保管。
        if not bearer or not kid or not hmac.compare_digest(bearer, kid):
            return None
        token = self._credential(kid)
        if token is None:
            return None
        try:
            ts = int(lower.get("x-gha-timestamp", ""))
        except (TypeError, ValueError):
            return None
        if abs(now - ts) > CLOCK_SKEW_SECONDS:
            return None
        nonce = str(lower.get("x-gha-nonce", ""))
        signature = str(lower.get("x-gha-signature", ""))
        if not nonce or len(nonce) > 128:
            return None
        expected = signature_string(token, method, _signed_path(raw_path), body, ts, nonce)
        if not hmac.compare_digest(expected, signature):
            return None
        nonce_key = _NONCE_PREFIX + "%s/%s" % (kid, nonce)
        with self.lock:
            if self.kv.get(nonce_key) is not None or self._seen_on_disk(nonce_key):
                return None
            self._put(nonce_key, now, now + self._nonce_retention)
        return kid

    # -- 租约 --------------------------------------------------------------

    def register(
        self,
        kid: str,
        payload: Mapping[str, Any],
        user: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """登记或续租；返回 ``(响应, 被撤销的旧 session_id)``，冲突抛 ``RegistryError(409)``。"""
        with self.lock:
            return self._register_locked(kid, payload, user)

    def _register_locked(self, kid: str, payload: Mapping[str, Any], user: Optional[str]):
        now = self._now()
        secret = self._credential(kid)
        if secret is None:
            raise RegistryError(401, "unknown credential")
        self._gc(now)
        data = dict(payload)
        session_id = str(data.get("session_id") or "")
        if not SESSION_ID_RE.match(session_id):
            raise RegistryError(400, "invalid session_id")
        if not data.get("run_id") and not data.get("origin"):
            # 仅续租：不动入口内容，只延长 TTL（Runner 长任务心跳走这条）。
            existing = self._lease(session_id, now)
            if existing is None or existing.kid != kid:
                raise RegistryError(404, "session not found")
            try:
                renew_to = float(data.get("expires_at") or 0)
            except (TypeError, ValueError):
                raise RegistryError(400, "invalid expires_at")
            if renew_to <= now:
                raise RegistryError(400, "expires_at is in the past")
            existing.expires_at = min(renew_to, now + self._max_ttl)
            return self._ack(existing), None
        run_id = str(data.get("run_id") or "")
        origin = str(data.get("origin") or "")
        if not SESSION_ID_RE.match(session_id) or not RUN_ID_RE.match(run_id):
            raise RegistryError(400, "invalid session_id or run_id")
        origin_parts = urllib.parse.urlsplit(origin)
        hostname = str(data.get("hostname") or origin_parts.hostname or "").lower()
        user = str(data.get("user") or user or "")
        if not user or len(user) > MAX_USER_LENGTH:
            raise RegistryError(400, "user required")
        try:
            expires_at = float(data.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            raise RegistryError(400, "expires_at is in the past")
        if expires_at - now > self._max_ttl:
            expires_at = now + self._max_ttl
        if origin_parts.scheme != "https":
            # Quick / Named 都只经 HTTPS 暴露；拒绝明文入口避免凭证走 http。
            raise RegistryError(400, "origin must be https")
        content = {
            "origin": origin,
            "token": data.get("agent_token"),
            "hostname": hostname,
            "metadata": sanitize_metadata(data.get("metadata")),
        }

        existing = self._lease(session_id, now)
        if existing is not None:
            if existing.run_id != run_id or existing.kid != kid:
                raise RegistryError(409, "session_id 已绑定其他 run")
            if existing.open().get("origin") != origin:
                raise RegistryError(409, "session_id 已登记其他 origin")
            if self._run_lease(run_id, now) is not existing:
                raise RegistryError(409, "run 租约已被收回")
            existing.expires_at = expires_at
            existing.content = self._seal(secret, content)
            return self._ack(existing), None

        superseded: Optional[str] = None
        previous = self._run_lease(run_id, now)
        if previous is not None:
            if previous.user != user:
                raise RegistryError(409, "run_id 已被其他用户占用")
            self._forget(previous, now)
            superseded = previous.session_id

        # 固定域名不得同时服务多个用户；过期条目已在本函数开头的 _gc 中被回收。
        # 同一用户换 run（重跑/重启）允许原子接管：旧 session 立即变成不可解析，
        # 而 run_id→origin 的唯一映射保证宿主不会拿到别人的入口。真正的防错路由
        # 仍由 Gateway 逐次核验 session_id / Agent Token 兜底（固定域名不等于身份）。
        host_owner = self._host_owner(hostname, now)
        if host_owner is None and self._host_guard_active(hostname, user, now):
            # 上一个 Runner 刚释放固定域名：cloudflared 连接可能仍在拆除，
            # 此时换用户接同一域名会把请求路由到错误的 Runner。
            raise RegistryError(409, "hostname 刚被其他用户释放，仍在防错误路由冷却期")
        if host_owner is not None and host_owner.user != user:
            raise RegistryError(409, "hostname 已被其他用户占用：固定域名不可跨用户共用")

        entry = _Entry(session_id, run_id, user, hostname, self._seal(secret, content),
                       expires_at, kid, secret)
        self._put("session:" + session_id, entry)
        self._put(_LEASE_PREFIX + run_id, entry)
        self._put(self._host_key(hostname), entry)
        return self._ack(entry), superseded

    @staticmethod
    def _ack(entry: _Entry) -> Dict[str, Any]:
        return {
            "status": "ok",
            "kind": "lease",
            "session_id": entry.session_id,
            "run_id": entry.run_id,
            "expires_at": int(entry.expires_at),
        }

    def _lease(self, session_id: str, now: float) -> Optional[_Entry]:
        return self._alive(self._get("session:" + session_id, now), now)

    def _run_lease(self, run_id: str, now: float) -> Optional[_Entry]:
        return self._alive(self._get(_LEASE_PREFIX + run_id, now), now)

    @staticmethod
    def _host_key(hostname: str) -> str:
        """hostname 索引只存摘要：Quick Tunnel 的随机域名本身就不该出现在存储键里。"""
        return "host/" + hashlib.sha256(hostname.encode("utf-8")).hexdigest()

    def _host_owner(self, hostname: str, now: float) -> Optional[_Entry]:
        return self._alive(self._get(self._host_key(hostname), now), now)

    @staticmethod
    def _alive(holder: Any, now: float) -> Optional[_Entry]:
        """租约到期即视为不存在：TTL 是唯一真相，不依赖后台 reaper 时效。"""
        if type(holder) is not _Entry or holder.expires_at <= now:
            return None
        return holder

    def _forget(self, entry: _Entry, now: float) -> None:
        if self._get("session:" + entry.session_id, now) is entry:
            self._delete("session:" + entry.session_id)
        if self._get(_LEASE_PREFIX + entry.run_id, now) is entry:
            self._delete(_LEASE_PREFIX + entry.run_id)
        if self._get(self._host_key(entry.hostname), now) is entry:
            self._delete(self._host_key(entry.hostname))
            # 冷却期从"该租约实际失效的时刻"起算：自然到期用 expires_at，显式撤销用现在。
            released = min(entry.expires_at, now) + self._forget_guard
            self._put("forget/" + self._host_key(entry.hostname)[5:], entry.user, released)

    def _host_guard_active(self, hostname: str, user: str, now: float) -> bool:
        """冷却期内只允许同一用户重新占用刚释放的 hostname。"""
        previous_user = self._get("forget/" + self._host_key(hostname)[5:], now)
        return previous_user is not None and previous_user != user

    # -- 解析 --------------------------------------------------------------

    def resolve(
        self,
        kind: str,
        identifier: str,
        user: Optional[str],
        run_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not user:
            return None
        now = self._now()
        with self.lock:
            if kind == "session":
                entry = self._lease(identifier, now)
                if entry is None or (run_id is not None and entry.run_id != run_id):
                    return None
            elif kind == "run":
                entry = self._run_lease(identifier, now)
                if entry is None:
                    return None
            else:
                return None
            if entry.user != user:
                return None
            content = entry.open()
        return {
            "session_id": entry.session_id,
            "run_id": entry.run_id,
            "origin": content.get("origin"),
            "agent_token": content.get("token"),
            "hostname": content.get("hostname"),
            "expires_at": int(entry.expires_at),
            "metadata": content.get("metadata") or {},
        }

    # -- 撤销 / 清理 -------------------------------------------------------

    def revoke(self, kid: str, session_id: str) -> bool:
        with self.lock:
            now = self._now()
            entry = self._lease(session_id, now)
            if entry is None or entry.kid != kid:
                return False
            self._forget(entry, now)
            return True

    def prune_expired(self) -> int:
        with self.lock:
            return self._gc(self._now())

    def _gc(self, now: float) -> int:
        if not hasattr(self.kv, "items"):
            return 0
        items = list(self.kv.items())
        # 用 type() 身份比较：kv 里混存 _Entry / _Ttl，不希望对子类或同名对象做 isinstance 放宽。
        removed = sum(1 for _, v in items if type(v) is _Ttl and v.release_at <= now)
        for entry in [v for _, v in items if type(v) is _Entry and v.expires_at <= now]:
            self._forget(entry, now)
            removed += 1
        if now - self._last_gc >= GC_INTERVAL_SECONDS:
            self._last_gc = now
            for key, value in items:
                if (isinstance(key, str) and key.startswith(_NONCE_PREFIX)
                        and type(value) is _Ttl and value.release_at <= now):
                    self._delete(key)
            self._remove_stale_nonces(now - self._nonce_retention)
        return removed

    def _remove_stale_nonces(self, limit: float) -> None:
        if not self._plaintext_dir:
            return
        for path in self._nonce_files():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    value = float(json.load(f).get("value", 0))
                if value < limit:
                    os.remove(path)
            except (OSError, ValueError, TypeError):
                continue

    def _nonce_dir(self) -> Optional[str]:
        return os.path.join(self._plaintext_dir, "registry-kv", "nonce") if self._plaintext_dir else None

    # -- 镜像到私有目录（KV 不具备扫描能力时用于 reaper） -------------------

    def _nonce_files(self) -> List[str]:
        directory = self._nonce_dir()
        if not directory:
            return []
        try:
            return [os.path.join(directory, n) for n in os.listdir(directory) if n.endswith(".json")]
        except OSError:
            return []

    def _cache_mirror(self, key: str, release_at: float) -> None:
        """把 nonce 的过期时间镜像到私有目录，并检查持久化记录中的重放。"""
        directory = self._nonce_dir()
        if not directory or not key.startswith(_NONCE_PREFIX):
            return
        name = hashlib.sha256(key[len(_NONCE_PREFIX):].encode("utf-8")).hexdigest() + ".json"
        try:
            os.makedirs(directory, exist_ok=True)
            fd = os.open(os.path.join(directory, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"key": key, "value": release_at}, f)
        except OSError:
            pass

    def _seen_on_disk(self, key: str) -> bool:
        directory = self._nonce_dir()
        if not directory:
            return False
        name = hashlib.sha256(key[len(_NONCE_PREFIX):].encode("utf-8")).hexdigest() + ".json"
        try:
            with open(os.path.join(directory, name), "r", encoding="utf-8") as f:
                return json.load(f).get("key") == key
        except (OSError, ValueError, AttributeError):
            return False

    def close(self) -> None:
        self.prune_expired()


# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------


class _Transport:
    def __init__(self, client: "RendezvousClient"):
        self.client = client

    async def run(self, method: str, path: str, body: Optional[bytes] = None,
                  cache_path: Optional[str] = None) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync, method, path, body, cache_path)

    def _sync(self, method, path, body, cache_path):
        client = self.client
        url = (client.endpoint or "").rstrip("/") + path
        data = body if body is not None else b""
        headers = {"User-Agent": "gha-runner/2.0", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        token = client.auth_token or ""
        if token:
            headers.update(signing_headers(token, method, _signed_path(path), data,
                                           kid=client.kid))
        req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=client.timeout) as resp:
                raw = resp.read(MAX_BODY_BYTES)
                payload = json.loads(raw.decode("utf-8")) if raw else {}
                if not isinstance(payload, dict):
                    raise SignatureError("Registry 响应格式错误")
                if resp.status == 200 and token:
                    _verify_response(token, _signed_path(path), payload)
            return 200, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except Exception:
                payload = {}
            return exc.code, payload if isinstance(payload, dict) else {}
        except (urllib.error.URLError, OSError) as exc:
            if method.upper() == "GET" and cache_path:
                cached = _read_cache(cache_path)
                if cached is not None:
                    return 200, cached
            raise RegistryError(None, "Registry 不可达") from exc


def _verify_response(token: str, signed_path: str, payload: Dict[str, Any]) -> None:
    provided = payload.pop("response_signature", None)
    if not provided:
        raise SignatureError("Registry 响应缺少签名")
    expected = signature_string(token, "RESPONSE", signed_path, canonical_json(payload))
    if not hmac.compare_digest(str(provided), expected):
        raise SignatureError("Registry 响应签名不匹配")


def _read_cache(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and time.time() < float(data.get("expires_at", 0)):
            return data
    except (OSError, ValueError, TypeError):
        return None
    return None


def _write_cache(path: str, body: Mapping[str, Any]) -> None:
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dict(body), f, ensure_ascii=False)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass


class RendezvousClient:
    """私有注册中心通信客户端。

    ``auth_token`` 为 Registry 认证凭证（经 GHA Secret 注入）；``user`` 为租户 ID
    （默认 GITHUB_REPOSITORY），用于用户隔离。登记成功后响应写入 ``cache_path``
    （0600），Registry 不可达时用于 TTL 内离线解析。
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        auth_token: Optional[str] = None,
        user: Optional[str] = None,
        cache_path: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.endpoint = endpoint
        self.auth_token = auth_token
        # Runner 与宿主必须解析出同一个租户：GHA 下默认仓库名，本地退回 "default"。
        self.user = user or os.environ.get("GITHUB_REPOSITORY") or "default"
        self.cache_path = cache_path
        self.timeout = timeout
        self.last_error: Optional[str] = None

    @property
    def enrolled(self) -> bool:
        return bool(self.endpoint and self.auth_token)

    @property
    def kid(self) -> str:
        """本实例的租约凭证 ID（由 Token 派生，可公开出现在路径段）。"""
        return RendezvousRegistry._kid_for(self.auth_token or "")

    async def register_session(
        self,
        session_id: str,
        run_id: str,
        origin: str,
        ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        agent_token: Optional[str] = None,
        hostname: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """登记会话入口；失败时 ``last_error`` 只含错误码/简短原因，绝不含正文。"""
        self.last_error = None
        if not self.endpoint:
            # 本地开发或 Named Tunnel 可不使用 Registry；GHA Quick 由 Supervisor 强制要求。
            return True
        if not self.auth_token:
            # 配了 endpoint 却没配 Token：必须 fail-closed，不能静默跳过发布。
            self.last_error = "missing registry token"
            return False
        if not SESSION_ID_RE.match(session_id or "") or not RUN_ID_RE.match(run_id or ""):
            self.last_error = "invalid identifiers"
            return False
        payload: Dict[str, Any] = {
            "session_id": session_id,
            "run_id": run_id,
            "origin": origin,
            "expires_at": int(time.time() + ttl_seconds),
            "metadata": sanitize_metadata(metadata),
        }
        if agent_token:
            payload["agent_token"] = agent_token
        if hostname:
            payload["hostname"] = hostname.lower()
        payload["user"] = self.user
        try:
            status, body = await _Transport(self).run(
                "POST", "/v1/sessions/" + self.kid, canonical_json(payload)
            )
        except (RegistryError, SignatureError) as exc:
            self.last_error = str(exc)
            return False
        body = body or {}
        if status != 200:
            self.last_error = str(body.get("error") or f"HTTP {status}")
            return False
        if self.cache_path:
            _write_cache(self.cache_path, body)
        return True

    async def resolve_session(self, session_id: str, run_id: Optional[str] = None) -> Optional[str]:
        """按 session_id 获取当前 Session 的网关 URL（租约校验 run_id/user）。"""
        record = await self._resolve("/v1/sessions/" + session_id, {"run_id": run_id,
                                                                    "user": self.user})
        return record.get("origin") if record else None

    async def resolve_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """按 GitHub run_id 获取当前会话的私有连接信息（origin + 受限 Agent Token）。"""
        record = await self._resolve("/v1/runs/" + run_id, {"user": self.user})
        if not record or not record.get("agent_token"):
            return None
        return record

    async def renew(self, session_id: str, ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS) -> bool:
        if not self.enrolled:
            return False
        body = canonical_json({
            "session_id": session_id,
            "expires_at": int(time.time() + ttl_seconds),
            "user": self.user or "",
        })
        try:
            status, _ = await _Transport(self).run("POST", "/v1/sessions/" + self.kid, body)
        except (RegistryError, SignatureError):
            return False
        return status == 200

    async def revoke_session(self, session_id: str) -> bool:
        if not self.enrolled:
            return False
        body = canonical_json({"session_id": session_id})
        try:
            status, _ = await _Transport(self).run("DELETE", "/v1/sessions/" + self.kid, body)
        except (RegistryError, SignatureError):
            return False
        return status in (200, 204)

    async def _resolve(self, path: str, params: Mapping[str, Optional[str]]) -> Optional[Dict[str, Any]]:
        if not self.enrolled:
            return None
        query = {k: v for k, v in params.items() if v}
        if query:
            path = path + "?" + urllib.parse.urlencode(query)
        try:
            status, body = await _Transport(self).run("GET", path, cache_path=self.cache_path)
        except (RegistryError, SignatureError):
            return None
        if status != 200 or not body or not body.get("origin"):
            return None
        return body


# ---------------------------------------------------------------------------
# 最小 Registry HTTP 服务（aiohttp 可选；不可用时返回 None，由 Supervisor fail-closed）
# ---------------------------------------------------------------------------


class RegistryService:
    """Registry HTTP 处理：所有响应（含错误）都不回显请求正文与 origin。"""

    ROUTE_RE = re.compile(r"^/v1/(sessions|runs)/([A-Za-z0-9_.:-]{1,128})/?$")

    def __init__(self, registry: RendezvousRegistry, max_body: int = MAX_BODY_BYTES):
        self.registry = registry
        self.max_body = max_body

    def handle(self, method: str, raw_path: str, headers: Mapping[str, str],
               body: bytes) -> Tuple[int, Dict[str, Any]]:
        status, payload, token = self._dispatch(method.upper(), raw_path, headers, body)
        if status == 200 and token:
            payload["response_signature"] = signature_string(
                token, "RESPONSE", _signed_path(raw_path), canonical_json(dict(payload))
            )
        return status, payload

    def _dispatch(self, method: str, raw_path: str, headers: Mapping[str, str],
                  body: bytes) -> Tuple[int, Dict[str, Any], Optional[str]]:
        if method == "GET" and urllib.parse.urlsplit(raw_path).path == "/health":
            return 200, {"status": "ok"}, None
        if len(body) > self.max_body:
            return 413, {"error": "payload too large"}, None
        match = self.ROUTE_RE.match(urllib.parse.urlsplit(raw_path).path)
        if not match:
            return 404, {"error": "not found"}, None
        kind, identifier = match.groups()
        if kind == "sessions" and method in ("POST", "DELETE"):
            # 路径段是租约凭证 kid；session_id 只来自请求体（DELETE 可省略）。
            kid = self.registry.authenticate(method, raw_path, headers, body)
            if kid is None or kid != identifier:
                return 401, {"error": "unauthorized"}, None
            token = self.registry._credential(kid)
            try:
                payload = _loads(body)
                if method == "DELETE":
                    target = str(payload.get("session_id") or "")
                    if not SESSION_ID_RE.match(target) or not self.registry.revoke(kid, target):
                        return 404, {"error": "not found"}, token
                    return 204, {}, token
                response, superseded = self.registry.register(kid, payload, self._user(headers))
                if superseded:
                    response["superseded"] = superseded
                return 200, response, token
            except RegistryError as exc:
                return exc.status or 400, {"error": str(exc)}, token
            except (ValueError, UnicodeDecodeError):
                return 400, {"error": "invalid json"}, token
        # 解析接口同样要求 Bearer 凭证：没有凭证就不能探测任何 run/session 是否存在。
        kid = self._bearer(headers)
        token = self.registry._credential(kid) if kid else None
        if token is None:
            return 401, {"error": "unauthorized"}, None
        if kind == "runs":
            if method != "GET":
                return 405, {"error": "method not allowed"}, token
            return self._resolve("run", identifier, raw_path, token)
        if method == "GET":
            return self._resolve("session", identifier, raw_path, token)
        return 405, {"error": "method not allowed"}, token

    @staticmethod
    def _bearer(headers: Mapping[str, str]) -> str:
        auth = str({k.lower(): v for k, v in headers.items()}.get("authorization", ""))
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def _resolve(self, kind: str, identifier: str, raw_path: str,
                 token: Optional[str]) -> Tuple[int, Dict[str, Any], Optional[str]]:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(raw_path).query)
        user = (query.get("user") or [""])[0]
        run_id = (query.get("run_id") or [None])[0]
        record = self.registry.resolve(kind, identifier, user, run_id)
        if record is None or not record.get("origin"):
            return 404, {"error": "not found"}, token
        response = {
            "session_id": record["session_id"],
            "run_id": record["run_id"],
            "origin": record["origin"],
            "expires_at": record["expires_at"],
            "metadata": record.get("metadata") or {},
        }
        if kind == "run" and record.get("agent_token"):
            response["agent_token"] = record["agent_token"]
        return 200, response, token

    def _user(self, headers: Mapping[str, str]) -> Optional[str]:
        """租户号：Agent 侧统一配置的 ``X-GHA-User``，缺省为 ``default``。"""
        value = {k.lower(): v for k, v in headers.items()}.get("x-gha-user")
        return str(value or "default")


def _loads(body: bytes) -> Dict[str, Any]:
    payload = json.loads(body.decode("utf-8") or "{}") if body else {}
    if not isinstance(payload, dict):
        raise ValueError("payload must be object")
    return payload


def create_registry_server(
    auth_tokens: Iterable[str],
    host: str = "127.0.0.1",
    port: int = 8787,
    private_dirs: Optional[Iterable[str]] = None,
    registry: Optional[RendezvousRegistry] = None,
) -> Optional[Tuple[RendezvousRegistry, Any]]:
    """构建可启动的 Registry；缺凭证 / 缺 aiohttp / 缺加密能力时返回 ``None``。"""
    tokens = [t for t in auth_tokens if t]
    if registry is None:
        if not tokens:
            return None
        registry = RendezvousRegistry(credentials=tokens, private_dirs=private_dirs)
    if not tokens and not registry._credentials:
        return None
    if not registry._can_seal() and registry._plaintext_dir is None:
        return None
    try:
        from aiohttp import web
    except ImportError:
        return None
    service = RegistryService(registry)

    async def handler(req: web.Request) -> web.Response:
        body = await req.read() if req.method in ("POST", "DELETE") else b""
        status, payload = service.handle(req.method, req.path_qs, req.headers, body)
        if status == 204:
            return web.Response(status=204)
        return web.json_response(payload, status=status)

    app = web.Application(client_max_size=MAX_BODY_BYTES)
    app.router.add_route("*", "/{tail:.*}", handler)
    return registry, web.AppRunner(app)


class RegistryStdlibServer:
    """只用标准库的 Registry HTTP 服务：``python3 -m interactive_runtime.rendezvous serve``。

    生产可放在 HTTPS 反向代理之后（Registry 要求 HTTPS）；本类只负责应用层协议，
    这样即使目标环境没有 aiohttp 也能跑起最小 Registry。
    """

    def __init__(self, registry: RendezvousRegistry, host: str = "127.0.0.1", port: int = 8787):
        self.registry = registry
        self.host = host
        self.port = port
        self.httpd = None
        self._thread = None

    def start(self) -> "RegistryStdlibServer":
        import http.server
        import socketserver
        import threading

        service = RegistryService(self.registry)

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "gha-rendezvous"
            sys_version = ""

            def _respond(self, method: str, send_body: bool) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY_BYTES:
                    # 先看长度再读，避免被超大请求体拖进内存。
                    self.send_response(413)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                body = self.rfile.read(length) if send_body and length > 0 else b""
                status, payload = service.handle(method, self.path, self.headers, body)
                data = b"" if status == 204 else canonical_json(payload)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def do_GET(self):
                self._respond("GET", False)

            def do_POST(self):
                self._respond("POST", True)

            def do_DELETE(self):
                self._respond("DELETE", True)

            def log_message(self, fmt, *args):
                # 不记录请求行/正文：Registry 日志一旦落盘就可能泄露入口 URL。
                pass

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = Server((self.host, self.port), Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, name="gha-registry", daemon=True)
        self._thread.start()
        return self

    @property
    def endpoint(self) -> str:
        return "http://%s:%d" % (self.host, self.port)

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


def run_registry_server(
    auth_tokens: Iterable[str],
    host: str = "127.0.0.1",
    port: int = 8787,
    private_dirs: Optional[Iterable[str]] = None,
) -> RegistryStdlibServer:
    """启动最小 Registry（标准库实现），返回可 ``stop()`` 的句柄。"""
    tokens = [t for t in auth_tokens if t]
    if not tokens:
        raise RegistryError(None, "缺少 Registry 凭证")
    registry = RendezvousRegistry(credentials=tokens, private_dirs=private_dirs)
    if not registry._can_seal() and registry._plaintext_dir is None:
        raise RegistryError(503, "缺少 cryptography：拒绝明文保存登记内容")
    return RegistryStdlibServer(registry, host, port).start()


def _main(argv: Optional[list] = None) -> int:
    """``python3 -m interactive_runtime.rendezvous serve`` 的入口（凭证只从 env 读）。"""
    import argparse

    parser = argparse.ArgumentParser(description="gha-runner 最小私有 Registry")
    parser.add_argument("command", choices=["serve"], nargs="?", default="serve")
    parser.add_argument("--host", default=os.environ.get("GHA_REGISTRY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("GHA_REGISTRY_PORT", "8787")))
    parser.add_argument("--token-env", default="GHA_RENDEZVOUS_TOKEN",
                        help="保存 Registry 凭证的环境变量名（推荐经 GHA Secret 注入）")
    parser.add_argument("--private-dir",
                        help="凭证文件的私有目录；提供后允许在缺 cryptography 时降级为内存明文")
    args = parser.parse_args(argv)

    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print("缺少 Registry 凭证：请设置 %s" % args.token_env)
        return 2
    try:
        server = run_registry_server([token], args.host, args.port,
                                     private_dirs=[args.private_dir] if args.private_dir else None)
    except RegistryError as exc:
        print(str(exc))
        return 2
    print("gha-rendezvous listening on %s (token/env: %s)" % (server.endpoint, args.token_env))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover - 进程入口
    raise SystemExit(_main())


# ---------------------------------------------------------------------------
# 本地测试路径（保持原有接口）
# ---------------------------------------------------------------------------


class InMemoryRegistry:
    """供本地测试与回环演示的模拟 Registry 服务（无鉴权，仅限进程内）。"""

    def __init__(self):
        self._entries: Dict[str, Dict[str, Any]] = {}

    def register(self, session_id: str, run_id: str, origin: str, ttl: int = 3600) -> None:
        self._entries[session_id] = {
            "session_id": session_id,
            "run_id": run_id,
            "origin": origin,
            "expires_at": time.time() + ttl,
        }

    def resolve(self, session_id: str) -> Optional[str]:
        entry = self._entries.get(session_id)
        if entry and time.time() < entry["expires_at"]:
            return entry["origin"]
        return None
