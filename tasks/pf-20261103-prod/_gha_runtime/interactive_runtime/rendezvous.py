"""私有会话发现（Rendezvous Provider）与最小生产 Registry。

遵循《2.0 迭代.md》第五章 5.4 与 5.5「随机地址私有发现与 Registry 规范」。
职责：
- Runner 侧将生成的随机 trycloudflare URL 安全提交至私有 Registry 或 HTTPS 回调；
- Agent 侧从 Registry 安全查询当前 session_id / run_id 对应的公网网关入口；
- 绝不在 GitHub Actions Log, Job Summary 或 Artifact 中暴露随机地址。

Registry 协议（客户端与服务端共用）：

- 授权：登记/撤销的路径段是租约凭证；解析接口（``/v1/runs/<run_id>``、
  ``/v1/sessions/<session_id>``）的路径段是业务 ID。两类请求都走同一个 ``authenticate``：
  Bearer 指向的凭证 + 签名 + 时间戳 + nonce，只有 Bearer 或签名缺失/错误一律 401。
- 签名：``X-GHA-Signature: v1=<hex>``，``v1 = HMAC-SHA256(HKDF(token), t + "\\n" + nonce
  + "\\n" + method + "\\n" + canonical_path + "\\n" + raw_body)``。查询参数不参与签名，
  因此规范路径里只保留 Registry 认识的安全参数（见 ``_SIGNED_QUERY_KEYS``）。
  ``signing_headers`` 与 ``_Transport`` 都对规范路径签名，客户端不得自行拼接签名路径。
- 重放：``X-GHA-Timestamp``（±300s）+ 一次性 ``X-GHA-Nonce``。
- 租约：``run_id`` 原子占用；同一用户换新 session 续租时旧会话被原子撤销（防止同一 run
  两个 Runner 错路由），其他用户抢占返回 409；``hostname`` 同时只能属于一个用户，
  刚被释放的 hostname 有短暂冷却，防止 Named 固定域名在交接窗口内被错误路由。
- 隔离：解析时提供的 ``user`` 必须与登记一致；不提供 user 的 GET 一律拒绝。
- 响应：每个成功响应附带 ``response_signature``，客户端必须校验。
- 内容加密：登记正文用凭证派生的 AES-256-GCM 加密，磁盘上看不到 origin / Agent Token。

- 共享状态：默认存储是进程内存，只有单进程成立。多个 Registry 实例/进程要共享
  ``run_id`` 原子占用、``hostname`` 互斥与冷却、租约与 nonce 防重放时，必须显式使用
  ``registry_db``（Python 标准库 SQLite）。所有占用/续租/撤销/重放在
  ``BEGIN IMMEDIATE`` 写事务里完成，冲突由数据库唯一约束在提交时判定。
  登记内容在写库前已加密（``_Sealed``）；SQLite 的 ``-wal``/``-shm`` 辅助文件里
  可能出现密文页，因此数据库必须放在与任务包/制品无关的私有目录。

服务端依赖 AES-GCM（``cryptography``，Runtime 已依赖）。缺少该包时
``create_registry_server`` 返回 ``None``（fail-closed）；只有凭证单独保存在
``private_dirs``（RUNNER_TEMP 等任务包之外的位置）时才允许降级为内存明文存储，
避免把密文/明文写进任务包或制品。
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

SIGNATURE_VERSION = "v1"
SEAL_VERSION = "gha-sealed-v1"
CLOCK_SKEW_SECONDS = 300
NONCE_RETENTION_SECONDS = 600
GC_INTERVAL_SECONDS = 5.0
DEFAULT_FORGET_GUARD_SECONDS = 300
MAX_BODY_BYTES = 64 * 1024
MAX_TTL_SECONDS = 24 * 3600
MAX_USER_LENGTH = 256
DEFAULT_LEASE_TTL_SECONDS = 7200
DEFAULT_DB_BUSY_TIMEOUT_MS = 15000
DB_FILENAME = "gha-registry.sqlite3"
ENV_REGISTRY_DB = "GHA_REGISTRY_DB"

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def _lock_file(fd: int) -> None:
    if os.name == "nt":
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock_file(fd: int) -> None:
    if os.name == "nt":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


# 登记重试：只兜住“网络层/边缘”抖动（Quick Tunnel 边缘闪断、5xx、429）。
# 配置缺失、鉴权失败、签名不匹配、payload 非法都不重试 —— 重试只会把错误拖慢。
REGISTRY_RETRY_WINDOW_SECONDS = 60.0
REGISTRY_RETRY_BASE_SECONDS = 2.0
REGISTRY_RETRY_MAX_SECONDS = 10.0


def _retryable_status(status: Optional[int]) -> bool:
    """``status`` 为 None 表示连接没建立（网络层）；429 与 5xx 属于瞬时故障。"""
    return status is None or status == 429 or status >= 500


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


MAX_EPOCH_SECONDS = 253402300799.0  # 9999-12-31T23:59:59Z；再大的 TTL 没有业务意义


def _sane_time(value: Any) -> float:
    """把时间参数夹到[0, 9999 年]。

    本机 sqlite3 构建对超大 REAL 比较绑定会走错分支（曾把 ``DELETE ... expires_at <= ?``
    当成全表删除）。时间参数一律经过这里，超界的 TTL 也按这个上限截断。
    """
    number = float(value)
    if number != number:  # NaN
        return 0.0
    return min(max(number, 0.0), MAX_EPOCH_SECONDS)


def _as_int(value: Any) -> int:
    """显式转 int：函数体内不要直接引用 ``int``，调用方同名局部变量会把它盖掉。"""
    return int(value)


def signing_key(auth_token: str) -> bytes:
    return hmac.new(auth_token.encode("utf-8"), _KDF_INFO, hashlib.sha256).digest()


def signature_string(auth_token: str, method: str, canonical_path: str, body: bytes,
                     timestamp: int = 0, nonce: str = "-") -> str:
    # 形参刻意不叫 now / ts：模块级函数会被调用方函数的同名局部变量透传覆盖。
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
    签名覆盖的是 ``_signed_path(path)`` 规范化后的路径（查询参数会被白名单化并排序），
    调用方传入的原始 path 与签名必须对应同一个规范路径。
    """
    ts = int(time.time()) if timestamp is None else int(timestamp)
    n = nonce or secrets.token_hex(16)
    return {
        "Authorization": f"Bearer {kid or auth_token}",
        "X-GHA-Timestamp": str(ts),
        "X-GHA-Nonce": n,
        "X-GHA-Signature": signature_string(auth_token, method, _signed_path(path), body, ts, n),
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

    def to_json(self) -> Dict[str, str]:
        """密文落盘格式；不含任何明文，只能由同一凭证解封。"""
        return {
            "v": SEAL_VERSION,
            "nonce": base64.b64encode(self._nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self._ciphertext).decode("ascii"),
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "_Sealed":
        if not isinstance(raw, Mapping) or raw.get("v") != SEAL_VERSION:
            raise ValueError("unknown sealed payload")
        sealed = cls.__new__(cls)
        sealed._nonce = base64.b64decode(str(raw["nonce"]), validate=True)
        sealed._ciphertext = base64.b64decode(str(raw["ciphertext"]), validate=True)
        if len(sealed._nonce) != 12 or not sealed._ciphertext:
            raise ValueError("malformed sealed payload")
        return sealed


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


def _sqlite_problems() -> List[str]:
    """在内存库上探测当前 sqlite3 构建的可靠性，返回发现的问题（空表示可用）。

    本机 macOS 自带 Python 3.9 的 ``_sqlite3`` 会复用一个连接上旧语句的绑定：参数个数
    不同的语句互相串参、``WHERE key = ?`` 查不回刚写入的行、按非键列 DELETE 会误删全表。
    共享互斥依赖“先查后写”，所以这样的构建上必须拒绝启动，而不是静默退化成各写各的。
    """
    found: List[str] = []
    try:
        probe = sqlite3.connect(":memory:", isolation_level=None)
    except sqlite3.Error:
        return ["无法打开内存库"]
    try:
        probe.execute("CREATE TABLE t (a TEXT NOT NULL, b TEXT NOT NULL)")
        probe.execute("CREATE UNIQUE INDEX t_a ON t(a)")
        probe.execute("SELECT COUNT(*) FROM t WHERE b = ?", ("pad",))
        probe.execute("INSERT INTO t VALUES (?, ?)", ("row", "key"))
        if probe.execute("SELECT COUNT(*) FROM t WHERE a = ?", ("key",)).fetchone()[0] != 0:
            found.append("参数比较失效")
        if probe.execute("SELECT COUNT(*) FROM t WHERE a = ?", ("row",)).fetchone()[0] != 1:
            found.append("键查找失效")
        if probe.execute("SELECT COUNT(*) FROM t").fetchone()[0] != 1:
            found.append("语句缓存串参")
        probe.execute("DELETE FROM t WHERE b = ?", ("key",))
        if probe.execute("SELECT COUNT(*) FROM t").fetchone()[0] != 0:
            found.append("条件删除失效")
    except (sqlite3.Error, TypeError, ValueError, IndexError):
        found.append("探测失败")
    finally:
        probe.close()
    return found


def _sqlite_shared_mode_works() -> bool:
    """端到端探针：临时库上走一遍共享登记 + 续租 + 解析 + nonce 重放 + 撤销。

    任何一步结果不对，即认为该 sqlite3 构建不适合承载共享互斥；正式启动时也用它兜底。
    """
    tmpdir = None
    store = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="gha-registry-probe-")
        store = _SqliteStore(os.path.join(tmpdir, "probe.sqlite3"))
        kid = hashlib.sha256(b"probe-secret").hexdigest()[:32]
        current = time.time()
        entry = _Entry("probe-s", "probe-r", "probe-user", "probe-host",
                       _Sealed("probe-secret", {"origin": "https://probe.invalid"}),
                       current + 600.0, kid, "probe-secret")
        if store.read("probe-s", "probe-r", "probe-user", current, "https://probe.invalid",
                      "probe-host", 300.0).get("existing") is not False:
            return False
        store.put(entry, current, 300.0)
        seen = store.read("probe-s", "probe-r", "probe-user", current,
                          "https://probe.invalid", "probe-host", 300.0)
        if seen.get("status") != "ok" or not seen.get("existing"):
            return False
        if store.get_session("probe-s", current) is None:
            return False
        if store.consume_nonce("probe-kid", "probe-nonce", current + 60.0, current) is not True:
            return False
        if store.consume_nonce("probe-kid", "probe-nonce", current + 60.0, current) is not False:
            return False
        if store.revoke("probe-s", kid, current, 300.0) is not True:
            return False
        return store.get_session("probe-s", current) is None
    except Exception:
        if os.environ.get("GHA_RDBG"):
            import traceback
            traceback.print_exc()
        return False
    finally:
        try:
            if store is not None:
                store.close()
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass


class _TxConn:
    """事务内的“连接”句柄：每条语句新开连接，只返回与语句无关的标量/行结果。

    本机 sqlite3 构建在长连接上会串用旧语句的绑定；逐条新连接能保证每条 SQL 都按
    自己的占位符执行，写事务的原子性仍由外层 ``BEGIN IMMEDIATE`` 的持有者保证。
    """

    def __init__(self, store):
        self._store = store

    def execute(self, sql, params=()):
        conn = self._store._open()
        try:
            cursor = conn.execute(sql, params)
            try:
                rows = cursor.fetchall()
            except sqlite3.Error:
                rows = []
            return _Stmt(rows, max(0, cursor.rowcount))
        finally:
            conn.close()


class _Stmt:
    __slots__ = ("_rows", "rowcount")

    def __init__(self, rows, rowcount):
        self._rows = rows
        self.rowcount = rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _SqliteStore:
    """基于 SQLite（WAL）的事务型共享登记存储。

    唯一约束是真相：``session_id`` / ``run_id`` / ``host_digest`` 各自唯一，nonce 表
    ``(kid, nonce)`` 唯一。所有修改都在 ``BEGIN IMMEDIATE`` 写事务里完成，因此同一数据库
    的多个连接（线程或进程）看到同一份原子状态，而不是各自的进程内字典。

    表里只有密文：``content`` 是 ``_Sealed.to_json()``，解封需要凭证；hostname 只存摘要。

    兼容性约定（本模块函数按模块全局解析自由名字，调用方的同名局部变量会透传进来）：
    - 本类的方法体**不调用**本模块里的其它函数（``_as_int`` / ``canonical_json`` 等），
      一律用 ``builtins`` 或 ``self.`` 方法，避免被调用方局部变量遮蔽；
    - SQL 一律常量，参数只走占位符；每次操作使用新连接。
    """

    SCHEMA = (
        "CREATE TABLE IF NOT EXISTS sessions ("
        " session_id TEXT NOT NULL,"
        " run_id TEXT NOT NULL,"
        " kid TEXT NOT NULL,"
        " user TEXT NOT NULL,"
        " host_digest TEXT NOT NULL,"
        " payload TEXT NOT NULL,"
        " expires_at REAL NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS sessions_session ON sessions(session_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS sessions_run ON sessions(run_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS sessions_host ON sessions(host_digest)",
        "CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at)",
        "CREATE TABLE IF NOT EXISTS host_guards ("
        " host_digest TEXT NOT NULL,"
        " released_by TEXT NOT NULL,"
        " released_until REAL NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS host_guards_host ON host_guards(host_digest)",
        "CREATE TABLE IF NOT EXISTS nonces ("
        " kid TEXT NOT NULL,"
        " nonce TEXT NOT NULL,"
        " expires_at REAL NOT NULL)",
        "CREATE UNIQUE INDEX IF NOT EXISTS nonces_key ON nonces(kid, nonce)",
    )
    COLUMNS = "session_id, run_id, kid, user, host_digest, payload, expires_at"
    # 写临界区的文件锁在进程内共享一个 fd：同一进程里两个实例的文件锁可能互不阻塞，
    # 单进程恒等成立需要进程内一把锁来补齐（跨进程仍以操作系统文件锁为准）。
    _PROCESS_LOCKS: Dict[str, threading.RLock] = {}

    def __init__(self, path: str, busy_timeout_ms: int = DEFAULT_DB_BUSY_TIMEOUT_MS):
        self.path = os.path.abspath(path)
        self.busy_timeout_ms = max(0, int(busy_timeout_ms))
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, mode=0o700, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        self._lock = threading.RLock()
        failures = _sqlite_problems()
        if failures:
            raise RegistryError(
                None, "当前 sqlite3 构建不可靠（%s），拒绝以不可信的互斥启动" % ", ".join(failures))
        try:
            conn = self._open()
            try:
                mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()
                if str(mode[0] if mode else "").lower() != "wal":
                    raise RegistryError(None, "Registry 数据库无法启用 WAL 模式")
                for statement in self.SCHEMA:
                    conn.execute(statement)
                check = conn.execute("PRAGMA quick_check").fetchone()
                if not check or str(check[0]).lower() != "ok":
                    raise RegistryError(None, "Registry 数据库完整性检查失败，拒绝使用")
            finally:
                conn.close()
        except sqlite3.Error:
            raise RegistryError(None, "Registry 数据库初始化失败")
        self._chmod_private()

    # -- 连接 --------------------------------------------------------------

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000.0,
                               check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = %d" % self.busy_timeout_ms)
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _chmod_private(self) -> None:
        for suffix in ("", "-wal", "-shm", ".lock"):
            try:
                os.chmod(self.path + suffix, 0o600)
            except OSError:
                pass

    @contextlib.contextmanager
    def _tx(self):
        """写事务：``BEGIN IMMEDIATE`` 持有一个进程内的写者位，期间的每条语句各自新开
        连接（本机 sqlite3 构建会复用同一连接上旧语句的绑定，长连接不可信）。"""
        with self._lock, self._process_lock():
            # 长连接不可信（本机构建会串用旧语句绑定），所以写事务直接对数据库加咨询锁：
            # 读与写在同一个文件锁临界区里，跨进程的原子性与 BEGIN IMMEDIATE 等价。
            lock_path = self.path + ".lock"
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                _lock_file(lock_fd)
                conn = _TxConn(self)
                yield conn
            finally:
                try:
                    _unlock_file(lock_fd)
                except OSError:
                    pass
                os.close(lock_fd)

    def _process_lock(self) -> threading.RLock:
        with threading.Lock():
            return self._PROCESS_LOCKS.setdefault(self.path, threading.RLock())

    def _read(self, conn: Any, sql: str, params: Tuple[Any, ...]) -> List[Any]:
        return conn.execute(sql, params).fetchall()

    def _now(self) -> float:
        return float(time.time())

    @contextlib.contextmanager
    def _commit_tx(self):
        """``BEGIN IMMEDIATE`` 写事务：一条连接持有写锁，判定与写入都在同一快照里。

        与 ``_tx`` 的区别：``_tx`` 的 ``_TxConn`` 每条语句新开连接，语句之间的读写快照
        不连续，不能用来“先判定再写入”。这里返回真实连接，退出时提交/回滚，并同样持有
        文件锁写临界区（跨进程）与进程内锁。
        """
        with self._lock, self._process_lock():
            lock_fd = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            conn = None
            try:
                _lock_file(lock_fd)
                conn = self._open()
                conn.execute("BEGIN IMMEDIATE")
                try:
                    yield conn
                    conn.execute("COMMIT")
                except BaseException:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    raise
            finally:
                if conn is not None:
                    conn.close()
                try:
                    _unlock_file(lock_fd)
                except OSError:
                    pass
                os.close(lock_fd)

    # -- 行 <-> 记录 -------------------------------------------------------

    @staticmethod
    def _digest(hostname: str) -> str:
        return hashlib.sha256(str(hostname).encode("utf-8")).hexdigest()

    def _seal_text(self, content: Any) -> str:
        try:
            sealed = content.to_json()
        except (AttributeError, TypeError):
            raise RegistryError(503, "缺少 cryptography：Registry 无法加密登记内容，拒绝明文存储")
        return json.dumps(dict(sealed), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _row(self, values: Tuple[Any, ...], secret: str) -> _Entry:
        payload = json.loads(str(values[5]))
        if not isinstance(payload, dict) or payload.get("v") != SEAL_VERSION:
            raise RegistryError(503, "Registry 数据库含非密文登记，拒绝使用")
        return _Entry(str(values[0]), str(values[1]), str(values[3]), "",
                      _Sealed.from_json(payload), float(values[6]), str(values[2]), secret)

    @staticmethod
    def _as_dict(values: Tuple[Any, ...]) -> Dict[str, Any]:
        return {"session_id": str(values[0]), "run_id": str(values[1]), "kid": str(values[2]),
                "user": str(values[3]), "host_digest": str(values[4]), "content": str(values[5]),
                "expires_at": float(values[6])}

    # -- 回收 --------------------------------------------------------------

    def _gc(self, conn: sqlite3.Connection, current: float) -> int:
        """回收过期行：先 SELECT 再按唯一键逐行删除（不按非键列做条件删除）。"""
        limit = _sane_time(current)
        expired = self._read(conn, "SELECT session_id FROM sessions WHERE expires_at <= ?",
                             (limit,))
        for (session_id,) in expired:
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (str(session_id),))
        for (digest,) in self._read(conn, "SELECT host_digest FROM host_guards"
                                          " WHERE released_until <= ?", (limit,)):
            conn.execute("DELETE FROM host_guards WHERE host_digest = ?", (str(digest),))
        for kid, nonce in self._read(conn, "SELECT kid, nonce FROM nonces WHERE expires_at <= ?",
                                     (limit,)):
            conn.execute("DELETE FROM nonces WHERE kid = ? AND nonce = ?",
                         (str(kid), str(nonce)))
        return len(expired)

    def prune(self, current: float) -> int:
        with self._tx() as conn:
            return self._gc(conn, current)

    # -- 租约 --------------------------------------------------------------

    def get_session(self, session_id: str, current: float) -> Optional[Dict[str, Any]]:
        # 调用方可能用 session_id 或 run_id 查找：两个唯一键都试，结果取并集（至多一行）。
        with self._lock:
            conn = self._open()
            try:
                rows = conn.execute("SELECT " + self.COLUMNS + " FROM sessions"
                                    " WHERE session_id = ? AND expires_at > ?",
                                    (str(session_id), _sane_time(current))).fetchall()
                if not rows:
                    rows = conn.execute("SELECT " + self.COLUMNS + " FROM sessions"
                                        " WHERE run_id = ? AND expires_at > ?",
                                        (str(session_id), _sane_time(current))).fetchall()
            finally:
                conn.close()
        return self._as_dict(rows[0]) if rows else None

    def _blocker(self, conn: sqlite3.Connection, hostname: str, owner: str,
                 current: float) -> Optional[str]:
        digest = self._digest(hostname)
        sessions = self._read(conn, "SELECT user FROM sessions WHERE host_digest = ?",
                              (digest,))
        if sessions and str(sessions[0][0]) != str(owner):
            return "hostname 已被其他用户占用：固定域名不可跨用户共用"
        guards = self._read(conn, "SELECT released_by FROM host_guards"
                                  " WHERE host_digest = ? AND released_until > ?",
                            (digest, _sane_time(current)))
        if guards and str(guards[0][0]) != str(owner):
            return "hostname 刚被其他用户释放，仍在防错误路由冷却期"
        return None

    def read(self, session_id: str, run_id: str, owner: str, current: float,
             origin: Optional[str] = None, hostname: Optional[str] = None,
             forget_guard: float = DEFAULT_FORGET_GUARD_SECONDS) -> Dict[str, Any]:
        """完整登记前的判定（与 ``put`` 同一事务语义下的快照）。

        - 同 ``run_id`` 属于别的租户 → 409；同 ``session_id`` 已绑定别的 run → 409；
        - 同 ``run_id`` 属于本人、但 session/origin 不同 → 允许接管（返回 ``supersede``）；
        - 同一 session/run 且 origin 一致 → ``existing``（续期，不重封内容）；
        - hostname 跨用户互斥与冷却 → 409；
        - 否则视为新登记，交给 ``put``。
        """
        with self._tx() as conn:
            self._gc(conn, current)
            cols = self.COLUMNS
            previous = conn.execute("SELECT " + self.COLUMNS + " FROM sessions WHERE run_id = ?", (str(run_id),)).fetchall()
            if previous and str(previous[0][3]) != str(owner):
                return {"status": 409, "error": "run_id 已被其他用户占用"}
            existing = self._read(conn, "SELECT " + cols + " FROM sessions WHERE session_id = ?",
                                  (str(session_id),))
            if existing:
                values = existing[0]
                if float(values[6]) <= current:
                    return {"status": 409, "error": "session_id 已过期，不能续用"}
                if str(values[1]) != str(run_id):
                    return {"status": 409, "error": "session_id 已绑定其他 run"}
                return {"status": "ok", "existing": True}
            blocked = self._blocker(conn, hostname or "", owner, current)
            if blocked:
                return {"status": 409, "error": blocked}
            return {"status": "ok", "existing": False,
                    "supersede": str(previous[0][0]) if previous else None}

    def put(self, entry: _Entry, current: float,
            forget_guard: float = DEFAULT_FORGET_GUARD_SECONDS) -> Optional[str]:
        """写入新登记；返回被接管的旧 session_id。冲突由唯一索引判定（409）。"""
        digest = self._digest(entry.hostname)
        payload = self._seal_text(entry.content)
        values = (str(entry.session_id), str(entry.run_id), str(entry.kid), str(entry.user),
                  digest, payload, float(entry.expires_at))
        superseded = None
        with self._tx() as conn:
            self._gc(conn, current)
            previous = self._read(conn, "SELECT session_id, host_digest, user FROM sessions"
                                        " WHERE run_id = ?", (str(entry.run_id),))
            if previous:
                self._remove(conn, str(previous[0][0]), str(previous[0][1]),
                             str(previous[0][2]), forget_guard)
                superseded = str(previous[0][0])
            blocked = self._blocker(conn, entry.hostname, entry.user, current)
            if blocked:
                raise RegistryError(409, blocked)
            try:
                conn.execute("INSERT INTO sessions (" + self.COLUMNS + ")"
                             " VALUES (?, ?, ?, ?, ?, ?, ?)", values)
            except sqlite3.IntegrityError:
                raise RegistryError(409, "并发登记冲突：run_id / hostname / session_id 已占用")
        return superseded

    def refresh(self, entry: _Entry, current: float) -> bool:
        """同一 session/run 续期并重封内容；孩子段不再指向同一行时返回 False。"""
        payload = self._seal_text(entry.content)
        with self._tx() as conn:
            values = self._read(conn, "SELECT expires_at FROM sessions WHERE session_id = ?"
                                      " AND run_id = ? AND kid = ?",
                                (str(entry.session_id), str(entry.run_id), str(entry.kid)))
            if not values or float(values[0][0]) <= current:
                return False
            conn.execute("UPDATE sessions SET expires_at = ?, payload = ? WHERE session_id = ?",
                         (float(entry.expires_at), payload, str(entry.session_id)))
            return True

    def renew(self, session_id: str, kid: str, expires_at: float,
              current: float) -> Optional[Dict[str, Any]]:
        with self._tx() as conn:
            values = self._read(conn, "SELECT " + self.COLUMNS + " FROM sessions"
                                      " WHERE session_id = ? AND kid = ?",
                                (str(session_id), str(kid)))
            if not values or float(values[0][6]) <= current:
                return None
            conn.execute("UPDATE sessions SET expires_at = ? WHERE session_id = ?",
                         (float(expires_at), str(session_id)))
            row = list(values[0])
            row[6] = float(expires_at)
            return self._as_dict(tuple(row))

    def _remove(self, conn: sqlite3.Connection, session_id: str, host_digest: str,
                released_by: str, forget_guard: float) -> bool:
        found = self._read(conn, "SELECT expires_at FROM sessions WHERE session_id = ?",
                           (session_id,))
        if not found:
            return False
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        if not self._read(conn, "SELECT session_id FROM sessions WHERE host_digest = ? LIMIT 1",
                          (host_digest,)):
            current = self._now()
            released = _sane_time(min(float(found[0][0]), current) + float(forget_guard))
            updated = conn.execute("UPDATE host_guards SET released_by = ?, released_until = ?"
                                   " WHERE host_digest = ?",
                                   (released_by, released, host_digest)).rowcount
            if not updated:
                conn.execute("INSERT INTO host_guards (host_digest, released_by, released_until)"
                             " VALUES (?, ?, ?)", (host_digest, released_by, released))
        return True

    def revoke(self, session_id: str, kid: str, current: float,
               forget_guard: float = DEFAULT_FORGET_GUARD_SECONDS) -> bool:
        with self._tx() as conn:
            values = self._read(conn, "SELECT kid, host_digest, user FROM sessions"
                                      " WHERE session_id = ?", (str(session_id),))
            if not values or str(values[0][0]) != str(kid):
                return False
            return self._remove(conn, str(session_id), str(values[0][1]),
                                str(values[0][2]), forget_guard)

    # -- nonce -------------------------------------------------------------

    def consume_nonce(self, kid: str, nonce: str, expires_at: float, current: float) -> bool:
        """原子占用 nonce：未过期时已存在即重放（False），否则写入并返回 True。"""
        with self._tx() as conn:
            found = self._read(conn, "SELECT expires_at FROM nonces WHERE kid = ? AND nonce = ?",
                               (str(kid), str(nonce)))
            if found:
                if float(found[0][0]) > current:
                    return False
                conn.execute("DELETE FROM nonces WHERE kid = ? AND nonce = ?",
                             (str(kid), str(nonce)))
            try:
                conn.execute("INSERT INTO nonces (kid, nonce, expires_at) VALUES (?, ?, ?)",
                             (str(kid), str(nonce), _sane_time(expires_at)))
            except sqlite3.IntegrityError:
                return False
            return True

    def import_entries(self, entries: List[_Entry], current: float) -> int:
        """从旧 JSON 密文快照迁移：只补空缺，不覆盖其他实例已占用的 run/host。"""
        imported = 0
        with self._tx() as conn:
            self._gc(conn, current)
            for entry in entries:
                digest = self._digest(entry.hostname)
                if self._read(conn, "SELECT session_id FROM sessions WHERE session_id = ?",
                              (str(entry.session_id),)):
                    continue
                if self._read(conn, "SELECT session_id FROM sessions WHERE run_id = ?"
                                    " OR host_digest = ?", (str(entry.run_id), digest)):
                    continue
                try:
                    payload = self._seal_text(entry.content)
                    conn.execute("INSERT INTO sessions (" + self.COLUMNS + ")"
                                 " VALUES (?, ?, ?, ?, ?, ?, ?)",
                                 (str(entry.session_id), str(entry.run_id), str(entry.kid),
                                  str(entry.user), digest, payload, float(entry.expires_at)))
                except (RegistryError, sqlite3.IntegrityError):
                    continue
                imported += 1
        return imported

    # -- 兼容：导出现有登记（密文原样） -----------------------------------------

    def _isolation(self) -> "_SqliteIsolation":
        return _SqliteIsolation(self)

    def export_leases(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._open()
            try:
                rows = self._read(conn, "SELECT " + self.COLUMNS + " FROM sessions", ())
            finally:
                conn.close()
        return [self._as_dict(row) for row in rows]

    def close(self) -> None:
        with self._tx() as conn:
            self._gc(conn, self._now())


class _SqliteIsolation:
    """把共享存储的判定调用收拢在模块级函数里。

    Python 函数体按“模块全局”解析不在本函数局部出现的名字，调用方函数的同名局部变量
    （``now`` / ``values`` / ``int`` 之类）会透传进来。这里每个入口都显式接参、只用局部
    变量，作为 Registry 与存储实现之间的唯一缝。
    """

    def __init__(self, store: _SqliteStore):
        self.store = store

    def claim(self, session_id, run_id, owner, hostname, current, origin, guard, build_entry):
        """判定 + 写入同一临界区，返回 ``(新建的 entry 或 None, 被接管的旧 session_id)``。

        已存在同一 session/run 时 entry 为 None（续期）；冲突（409）在继续持锁的状态下抛出，
        先写者的租约不会被后写者覆盖。
        """
        with self.store._commit_tx() as conn:
            self.store._gc(conn, current)
            previous = self.store._read(
                conn, "SELECT session_id, user, host_digest FROM sessions WHERE run_id = ?",
                (str(run_id),))
            if previous and str(previous[0][1]) != str(owner):
                raise RegistryError(409, "run_id 已被其他用户占用")
            existing = self.store._read(
                conn, "SELECT session_id, run_id, expires_at FROM sessions WHERE session_id = ?",
                (str(session_id),))
            if existing:
                if float(existing[0][2]) <= current:
                    raise RegistryError(409, "session_id 已过期，不能续用")
                if str(existing[0][1]) != str(run_id):
                    raise RegistryError(409, "session_id 已绑定其他 run")
                return None, None
            entry = build_entry()
            if previous:
                # 同一 run 已被占用（别的 session/origin）：本人也不能接管——接管会撤掉
                # 已在使用的租约，把同一 run 的流量错路由到一个从未成功登记过的地址。
                raise RegistryError(409, "run_id 已被占用，另一个 session 正在使用")
            blocked = self.store._blocker(conn, hostname or "", owner, current)
            if blocked:
                raise RegistryError(409, blocked)
            try:
                conn.execute("INSERT INTO sessions (" + self.store.COLUMNS + ")"
                             " VALUES (?, ?, ?, ?, ?, ?, ?)",
                             (str(entry.session_id), str(entry.run_id), str(entry.kid),
                              str(entry.user), self.store._digest(entry.hostname),
                              self.store._seal_text(entry.content), float(entry.expires_at)))
            except sqlite3.IntegrityError:
                raise RegistryError(409, "并发登记冲突：run_id / hostname / session_id 已占用")
            return entry, None

    def read(self, session_id, run_id, owner, current, origin, hostname, guard):
        return self.store.read(session_id, run_id, owner, current, origin, hostname, guard)

    def put(self, entry, current, guard):
        return self.store.put(entry, current, guard)

    def refresh(self, entry, current):
        return self.store.refresh(entry, current)

    def get_session(self, session_id, current):
        return self.store.get_session(session_id, current)


class RendezvousRegistry:
    """最小生产 Registry 存储（只读内部状态，没有公开列举接口）。

    ``db_path`` 给出时使用 SQLite 共享存储（多实例/多进程原子）；否则 ``kv``
    （默认进程内存字典）只在本进程内一致。``lock`` 保证单进程内操作原子。
    SQLite 路径里同 session 对另一个 run 的登记返回 409（内存路径历史上是 409），
    已过期 session 不再被静默改绑。
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
        db_path: Optional[str] = None,
        db_busy_timeout_ms: int = DEFAULT_DB_BUSY_TIMEOUT_MS,
    ):
        if db_path is not None and kv is not None:
            raise RegistryError(None, "kv 与 db_path 不能同时使用")
        self.kv: Any = kv if kv is not None else {}
        self.store: Optional[_SqliteStore] = (
            _SqliteStore(db_path, busy_timeout_ms=db_busy_timeout_ms)
            if db_path is not None else None
        )
        self.lock = lock or threading.RLock()
        self._clock = clock or time.time
        self._max_ttl = int(max_ttl)
        self._forget_guard = float(forget_guard_seconds)
        self._nonce_retention = float(nonce_retention)
        self._credentials: Dict[str, str] = {}
        self._last_gc = -GC_INTERVAL_SECONDS
        # 重启保留：密文租约快照目录（默认关闭）与已装载的 nonce 断言。
        self._snapshot_dir: Optional[str] = None
        self._snapshot_loaded: set = set()
        self._asserts: Dict[str, Dict[str, float]] = {}
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
        require_path_kid: bool = True,
    ) -> Optional[str]:
        """校验 Bearer + 签名 + 时间戳 + 一次性 nonce；成功返回凭证 kid，否则 None。

        ``require_path_kid``：登记/撤销的路径段是租约凭证 kid，必须与 Header 一致；
        解析接口（``/v1/runs/<run_id>``、``/v1/sessions/<session_id>``）的路径段是业务 ID，
        此时只校验 Bearer 指向的凭证并按同一签名规则验签。
        """
        # 名字不能叫 now / timestamp：signature_string 的默认参数会被模块全局覆盖取到。
        checked_at = self._now()
        lower = {str(k).lower(): v for k, v in headers.items()}
        auth = str(lower.get("authorization", ""))
        bearer = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not bearer or not KID_RE.match(bearer):
            return None
        if require_path_kid:
            # 只有登记/撤销的路径段才是 kid；解析接口的路径段是 session_id/run_id，
            # 它们同样符合 KID_RE，这里绝不能按「Bearer == 路径段」比对。
            parts = urllib.parse.urlsplit(raw_path).path.split("/")
            path_kid = parts[-1] if parts[-1] else ""
            if not path_kid or not hmac.compare_digest(bearer, path_kid):
                return None
            kid = bearer
        else:
            # 解析前先恢复重启前的密文快照，否则重启后尚未重播登记的 run 会暂时 404。
            # 只按本进程已有的凭证查找，不在验签前读写任何存储。
            self._snapshot_load_kids()
            # 解析接口：Bearer 可以是完整凭证（真实客户端），kid 只是路径段里的公开标识。
            if bearer in self._credentials:
                kid = bearer
            elif self._kid_for(bearer) in self._credentials:
                kid = self._kid_for(bearer)
            else:
                return None
        token = self._credential(kid)
        if token is None:
            return None
        try:
            ts = int(lower.get("x-gha-timestamp", ""))
        except (TypeError, ValueError):
            return None
        if abs(checked_at - ts) > CLOCK_SKEW_SECONDS:
            return None
        nonce = str(lower.get("x-gha-nonce", ""))
        signature = str(lower.get("x-gha-signature", ""))
        if not nonce or len(nonce) > 128:
            return None
        expected = signature_string(token, method, _signed_path(raw_path), body, ts, nonce)
        if not hmac.compare_digest(expected, signature):
            return None
        nonce_key = _NONCE_PREFIX + "%s/%s" % (kid, nonce)
        if self.store is not None:
            # SQLite：主键冲突即重放；同一数据库上所有实例共享这一判定。
            if not self.store.consume_nonce(kid, nonce, checked_at + self._nonce_retention, checked_at):
                return None
            return kid
        with self.lock:
            if self.kv.get(nonce_key) is not None or self._seen_on_disk(nonce_key):
                return None
            self._put(nonce_key, checked_at, checked_at + self._nonce_retention)
        return kid

    # -- 租约 --------------------------------------------------------------

    def register(
        self,
        kid: str,
        payload: Mapping[str, Any],
        user: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """登记或续租；返回 ``(响应, 被撤销的旧 session_id)``，冲突抛 ``RegistryError(409)``。"""
        if self.store is not None:
            return self._register_shared(kid, payload, user)
        self._snapshot_load(kid)
        with self.lock:
            return self._register_locked(kid, payload, user)

    def _register_shared(self, kid: str, payload: Mapping[str, Any], user: Optional[str]):
        """共享存储路径：所有判定与写入都在 SQLite 写事务内完成。"""
        now = self._now()
        secret = self._credential(kid)
        if secret is None:
            raise RegistryError(401, "unknown credential")
        data = dict(payload)
        session_id = str(data.get("session_id") or "")
        if not SESSION_ID_RE.match(session_id):
            raise RegistryError(400, "invalid session_id")
        if not data.get("run_id") and not data.get("origin"):
            # 仅续租：不动入口内容，只延长 TTL（Runner 长任务心跳走这条）。
            try:
                renew_to = float(data.get("expires_at") or 0)
            except (TypeError, ValueError):
                raise RegistryError(400, "invalid expires_at")
            if renew_to <= now:
                raise RegistryError(400, "expires_at is in the past")
            renewed_to = min(renew_to, _sane_time(now) + self._max_ttl)
            row = self.store.renew(session_id, kid, renewed_to, now)
            if row is None:
                raise RegistryError(404, "session not found")
            return self._ack(self._row_entry(row, secret)), None
        run_id = str(data.get("run_id") or "")
        origin = str(data.get("origin") or "")
        if not SESSION_ID_RE.match(session_id) or not RUN_ID_RE.match(run_id):
            raise RegistryError(400, "invalid session_id or run_id")
        origin_parts = urllib.parse.urlsplit(origin)
        hostname = str(data.get("hostname") or origin_parts.hostname or "").lower()
        # 不要在这里绑定叫 user 的局部变量：本模块函数按模块全局解析自由名字，
        # 同名的局部变量会透传进下游函数（见 _SQLITE_GLOBAL_LEAKS 元测试）。
        owner = str(data.get("user") or user or "")
        if not owner or len(owner) > MAX_USER_LENGTH:
            raise RegistryError(400, "user required")
        try:
            expires_at = float(data.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            raise RegistryError(400, "expires_at is in the past")
        expires_at = min(expires_at, _sane_time(now) + self._max_ttl)
        if origin_parts.scheme != "https":
            raise RegistryError(400, "origin must be https")
        content = {
            "origin": origin,
            "token": data.get("agent_token"),
            "hostname": hostname,
            "metadata": sanitize_metadata(data.get("metadata")),
        }
        # 判定与写入必须在同一个写临界区里：分开调用时两个实例可以各自判定“可登记”，
        # 后写者的 put 会把先写者的新租约当作自己的旧 session 接管掉（两个都返回 200）。
        claimed, superseded = self.store._isolation().claim(
            session_id, run_id, owner, hostname, now, origin, self._forget_guard,
            lambda: _Entry(session_id, run_id, owner, hostname, self._seal(secret, content),
                           expires_at, kid, secret))
        if claimed is None:
            # 已存在同一 session/run。Quick Tunnel 每次重连都会换域名（Named 重连后入口
            # 也可能变），旧入口已经不可达：必须用这次的内容覆盖，否则 Host 解析到死地址
            # （实测 Error 1033）。覆盖走 refresh（同 session 行的 payload/expiry），
            # 不改 session 行身份，续租语义不变。
            row = self.store._isolation().get_session(session_id, now)
            if row is None:
                raise RegistryError(409, "run 租约已被收回")
            entry = _Entry(session_id, run_id, owner, hostname, self._seal(secret, content),
                           expires_at, kid, secret)
            if self.store.refresh(entry, now):
                fresh = self.store._isolation().get_session(session_id, now)
                if fresh is not None:
                    return self._ack(self._row_entry(fresh, secret)), None
            return self._ack(self._row_entry(row, secret)), None
        return self._ack(claimed), superseded

    def _row_entry(self, row: Mapping[str, Any], secret: str) -> _Entry:
        content = json.loads(str(row["content"]))
        if content.get("v") != SEAL_VERSION:
            raise RegistryError(503, "Registry 数据库含非密文登记，拒绝使用")
        return _Entry(str(row["session_id"]), str(row["run_id"]), str(row["user"]),
                      str(content.get("hostname") or ""), _Sealed.from_json(content),
                      float(row["expires_at"]), str(row["kid"]), secret)

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
            existing.expires_at = min(renew_to, _sane_time(now) + self._max_ttl)
            self._snapshot_save(kid)
            return self._ack(existing), None
        run_id = str(data.get("run_id") or "")
        origin = str(data.get("origin") or "")
        if not SESSION_ID_RE.match(session_id) or not RUN_ID_RE.match(run_id):
            raise RegistryError(400, "invalid session_id or run_id")
        origin_parts = urllib.parse.urlsplit(origin)
        hostname = str(data.get("hostname") or origin_parts.hostname or "").lower()
        # 不要在这里绑定叫 user 的局部变量：本模块函数按模块全局解析自由名字，
        # 同名的局部变量会透传进下游函数（见 _SQLITE_GLOBAL_LEAKS 元测试）。
        owner = str(data.get("user") or user or "")
        if not owner or len(owner) > MAX_USER_LENGTH:
            raise RegistryError(400, "user required")
        try:
            expires_at = float(data.get("expires_at") or 0)
        except (TypeError, ValueError):
            expires_at = 0
        if expires_at <= now:
            raise RegistryError(400, "expires_at is in the past")
        expires_at = min(expires_at, _sane_time(now) + self._max_ttl)
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
            self._snapshot_save(kid)
            return self._ack(existing), None

        superseded: Optional[str] = None
        previous = self._run_lease(run_id, now)
        if previous is not None:
            if previous.user != owner:
                raise RegistryError(409, "run_id 已被其他用户占用")
            self._forget(previous, now)
            superseded = previous.session_id

        # 固定域名不得同时服务多个用户；过期条目已在本函数开头的 _gc 中被回收。
        # 同一用户换 run（重跑/重启）允许原子接管：旧 session 立即变成不可解析，
        # 而 run_id→origin 的唯一映射保证宿主不会拿到别人的入口。真正的防错路由
        # 仍由 Gateway 逐次核验 session_id / Agent Token 兜底（固定域名不等于身份）。
        host_owner = self._host_owner(hostname, now)
        if host_owner is None and self._host_guard_active(hostname, owner, now):
            # 上一个 Runner 刚释放固定域名：cloudflared 连接可能仍在拆除，
            # 此时换用户接同一域名会把请求路由到错误的 Runner。
            raise RegistryError(409, "hostname 刚被其他用户释放，仍在防错误路由冷却期")
        if host_owner is not None and host_owner.user != owner:
            raise RegistryError(409, "hostname 已被其他用户占用：固定域名不可跨用户共用")

        entry = _Entry(session_id, run_id, owner, hostname, self._seal(secret, content),
                       expires_at, kid, secret)
        self._put("session:" + session_id, entry)
        self._put(_LEASE_PREFIX + run_id, entry)
        self._put(self._host_key(hostname), entry)
        self._snapshot_save(kid)
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
        if entry.kid in self._snapshot_loaded:
            self._snapshot_save(entry.kid)

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
        if self.store is not None:
            if kind not in ("session", "run"):
                return None
            row = self.store.get_session(identifier, now)
            if row is None or str(row["user"]) != str(user):
                return None
            if kind == "session" and run_id is not None and row["run_id"] != run_id:
                return None
            content = self._row_entry(row, self._credential(row["kid"]) or "").open()
            return self._record(row, content)
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
        return self._record(entry, content)

    def resolve_by_run_id(self, kind: str, run_id: str, user: Optional[str]) -> Optional[Dict[str, Any]]:
        """按 run_id 兜底解析：调用方给的租户号与登记时不一致时也返回该 run 的入口。

        run_id 在 Registry 内是唯一映射（同一 run 换用户登记会被拒），且解析仍要求持有
        Registry 凭证（签名 + 一次性 nonce），因此不会跨用户泄露他人的入口。
        """
        if kind != "run" or not user:
            return None
        now = self._now()
        if self.store is not None:
            row = self.store.get_session(run_id, now)
            if row is None or row["run_id"] != run_id or row["user"] == user:
                return None
            content = self._row_entry(row, self._credential(row["kid"]) or "").open()
            return self._record(row, content)
        with self.lock:
            entry = self._run_lease(run_id, now)
            if entry is None or entry.user == user:
                return None
            content = entry.open()
        return self._record(entry, content)

    @staticmethod
    def _record(entry: Any, content: Mapping[str, Any]) -> Dict[str, Any]:
        """统一响应帧。``int`` / ``str`` 等名字不在这里查找：本模块的函数会按模块全局
        解析自由名字，若调用方函数的局部变量同名（例如 ``int``）就会覆盖内建函数。"""
        return {
            "session_id": str(entry["session_id"] if isinstance(entry, Mapping) else entry.session_id),
            "run_id": str(entry["run_id"] if isinstance(entry, Mapping) else entry.run_id),
            "origin": content.get("origin"),
            "agent_token": content.get("token"),
            "hostname": content.get("hostname"),
            "expires_at": _as_int(entry["expires_at"] if isinstance(entry, Mapping) else entry.expires_at),
            "metadata": content.get("metadata") or {},
        }

    # -- 撤销 / 清理 -------------------------------------------------------

    def revoke(self, kid: str, session_id: str) -> bool:
        if self.store is not None:
            return self.store.revoke(session_id, kid, self._now(),
                                     forget_guard=self._forget_guard)
        with self.lock:
            now = self._now()
            entry = self._lease(session_id, now)
            if entry is None or entry.kid != kid:
                return False
            self._forget(entry, now)
            return True

    def prune_expired(self) -> int:
        if self.store is not None:
            return self.store.prune(self._now())
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
        for kid in self._snapshot_kids():
            asserted = self._load_asserts(kid)
            if not asserted:
                continue
            for key, value in list(asserted.items()):
                if value < limit:
                    self._assert_delete(kid, key)
                    asserted.pop(key, None)

    def _assert_delete(self, kid: str, key: str) -> None:
        directory = self._assert_path(kid)
        if not directory:
            return
        name = hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json"
        try:
            os.remove(os.path.join(directory, "nonce-" + kid + "-" + name))
        except OSError:
            pass

    def _nonce_dir(self) -> Optional[str]:
        return os.path.join(self._plaintext_dir, "registry-kv", "nonce") if self._plaintext_dir else None

    # -- 镜像到私有目录（KV 不具备扫描能力时用于 reaper） -------------------

    def _cache_mirror(self, key: str, release_at: float) -> None:
        """把 nonce 的过期时间镜像到私有目录，并检查持久化记录中的重放。"""
        directory = self._nonce_dir()
        if not directory or not key.startswith(_NONCE_PREFIX):
            return
        name = hashlib.sha256(key[len(_NONCE_PREFIX):].encode("utf-8")).hexdigest() + ".json"
        record = {"key": key, "value": release_at}
        try:
            os.makedirs(directory, exist_ok=True)
            fd = os.open(os.path.join(directory, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(record, f)
        except OSError:
            pass
        self._assert_mirror(key[len(_NONCE_PREFIX):].split("/", 1)[0], record)

    def _assert_mirror(self, kid: str, record: Dict[str, Any]) -> None:
        """用登记密文同一把密钥加密落盘，重启后仍能判定 nonce 已用过。"""
        directory = self._assert_path(kid)
        if not directory:
            return
        asserted = self._load_asserts(kid)
        if asserted is None:
            return
        asserted[str(record["key"])] = float(record["value"])
        name = hashlib.sha256(str(record["key"]).encode("utf-8")).hexdigest() + ".json"
        try:
            sealed = self._seal(self._credential(kid) or "", record)
            tmp = os.path.join(directory, "tmp-" + name)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(sealed.to_json(), f)
            os.replace(tmp, os.path.join(directory, "nonce-" + kid + "-" + name))
        except (OSError, RegistryError):
            pass

    def _assert_dir(self) -> str:
        return os.path.join(self._kv_dir(), "nonce")

    def _assert_path(self, kid: str) -> Optional[str]:
        if not self._snapshot_dir or kid not in self._credentials:
            return None
        return self._assert_dir()

    def _snapshot_kids(self) -> List[str]:
        return [k for k in self._credentials if self._snapshot_path(k)]

    def _nonce_files(self) -> List[str]:
        directory = self._nonce_dir()
        if not directory:
            return []
        try:
            return [os.path.join(directory, n) for n in os.listdir(directory) if n.endswith(".json")]
        except OSError:
            return []

    def _seen_on_disk(self, key: str) -> bool:
        directory = self._nonce_dir()
        if directory:
            name = hashlib.sha256(key[len(_NONCE_PREFIX):].encode("utf-8")).hexdigest() + ".json"
            try:
                with open(os.path.join(directory, name), "r", encoding="utf-8") as f:
                    if json.load(f).get("key") == key:
                        return True
            except (OSError, ValueError, AttributeError):
                pass
        kid = key[len(_NONCE_PREFIX):].partition("/")[0]
        if not self._assert_path(kid):
            return False
        self._load_asserts(kid)
        return key in self._assert_records(kid)

    def _assert_records(self, kid: str) -> Dict[str, float]:
        return self._asserts.setdefault(kid, {})

    def _load_asserts(self, kid: str) -> Optional[Dict[str, float]]:
        """把该凭证此前落盘的 nonce 断言（密文）读进进程内缓存；目录不可用时返回 None。"""
        if kid in self._asserts:
            return self._asserts[kid]
        directory = self._assert_path(kid)
        if not directory:
            return None
        asserted: Dict[str, float] = {}
        try:
            names = os.listdir(directory)
        except OSError:
            names = []
        for name in names:
            if not name.startswith("nonce-" + kid + "-") or not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(directory, name), "r", encoding="utf-8") as f:
                    record = _Sealed.from_json(json.load(f)).open(self._credential(kid) or "")
            except (OSError, ValueError, KeyError, AttributeError, TypeError):
                continue
            asserted[str(record.get("key"))] = float(record.get("value") or 0)
        return self._asserts.setdefault(kid, asserted)

    # -- 重启保留（密文快照 + 防重放断言） ---------------------------------

    def enable_snapshot(self, directory: str) -> None:
        """开启重启保留：目录必须已存在且是安全私有目录，否则不启用（不写盘）。"""
        directory = os.path.abspath(directory)
        if not (self._can_seal() and self._in_private_dir(directory)):
            return
        try:
            os.makedirs(self._kv_dir(directory), mode=0o700, exist_ok=True)
        except OSError:
            return
        if self.store is not None:
            # 共享存储已有数据库：只把尚在快照里的未过期租约补进空缺，不覆盖别人的占用。
            for kid in list(self._credentials):
                self._snapshot_load(kid)
            return
        self._snapshot_dir = directory

    @property
    def shared(self) -> bool:
        """是否使用跨实例共享的 SQLite 存储（而不是进程内内存）。"""
        return self.store is not None

    def _in_private_dir(self, path: str) -> bool:
        if not self._plaintext_dir:
            return False
        base = os.path.realpath(self._plaintext_dir) + os.sep
        return os.path.realpath(path).startswith(base)

    def _kv_dir(self, base: Optional[str] = None) -> str:
        return os.path.join(base or self._snapshot_dir or "", "registry-kv")

    def _snapshot_path(self, kid: str) -> Optional[str]:
        if not self._snapshot_dir or kid not in self._credentials:
            return None
        return os.path.join(self._kv_dir(), "lease-" + kid + ".json")

    def _snapshot_records(self, kid: str) -> List[Dict[str, Any]]:
        if self.store is not None:
            return self._shared_snapshot_records(kid)
        now = self._now()
        records = []
        seen = set()
        for key, value in list(self.kv.items()):
            if type(value) is not _Entry or value.kid != kid or value.expires_at <= now:
                continue
            record = {
                "session_id": value.session_id,
                "run_id": value.run_id,
                "user": value.user,
                "hostname": value.hostname,
                "content": value.open(),
                "expires_at": int(value.expires_at),
            }
            signature = canonical_json(record)
            if signature in seen:
                continue
            seen.add(signature)
            records.append(record)
        return records

    def _shared_snapshot_records(self, kid: str) -> List[Dict[str, Any]]:
        """共享存储尚未开启快照时也允许导出：记录可直接作为 SQLite 迁移来源（密文）。"""
        now = self._now()
        records = []
        for row in self.store.export_leases():
            if not kid or row["kid"] != kid or row["expires_at"] <= now:
                continue
            records.append({
                "session_id": row["session_id"],
                "run_id": row["run_id"],
                "user": row["user"],
                "kid": row["kid"],
                "sealed": row["content"],
                "expires_at": int(row["expires_at"]),
            })
        return records

    def _snapshot_save(self, kid: str) -> None:
        path = self._snapshot_path(kid)
        if not path:
            return
        records = self._snapshot_records(kid)
        secret = self._credential(kid) or ""
        try:
            os.makedirs(self._kv_dir(), mode=0o700, exist_ok=True)
            if not records:
                try:
                    os.remove(path)
                except OSError:
                    pass
                return
            sealed = self._seal(secret, {"leases": records})
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(sealed.to_json(), f)
            os.replace(tmp, path)
        except (OSError, RegistryError):
            pass

    def _snapshot_release(self, kid: str) -> None:
        path = self._snapshot_path(kid)
        if not path:
            return
        try:
            os.remove(path)
        except OSError:
            pass

    def _snapshot_load(self, kid: str) -> None:
        """进程内已忘掉该凭证时，从密文快照恢复其未过期租约（只恢复一次）。"""
        if self.store is not None:
            self._shared_snapshot_load(kid)
            return
        if not self._snapshot_dir or kid in self._snapshot_loaded:
            return
        self._snapshot_loaded.add(kid)
        if kid not in self._credentials or self._lease_for_kid(kid, self._now()) is not None:
            return
        path = self._snapshot_path(kid)
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                sealed = _Sealed.from_json(json.load(f))
            records = sealed.open(self._credential(kid) or "").get("leases") or []
        except (OSError, ValueError, KeyError, AttributeError):
            return
        with self.lock:
            for record in records:
                try:
                    session_id = str(record["session_id"])
                    run_id = str(record["run_id"])
                    user = str(record["user"])
                    hostname = str(record["hostname"])
                    secret = self._credential(kid) or ""
                    entry = _Entry(session_id, run_id, user, hostname,
                                   self._seal(secret, record["content"]),
                                   float(record["expires_at"]), kid, secret)
                except (KeyError, TypeError, ValueError):
                    continue
                if entry.expires_at <= self._now():
                    continue
                if self._lease(session_id, self._now()) is None:
                    self._put("session:" + session_id, entry)
                if self._run_lease(run_id, self._now()) is None:
                    self._put(_LEASE_PREFIX + run_id, entry)
                if self._host_owner(hostname, self._now()) is None:
                    self._put(self._host_key(hostname), entry)

    def _snapshot_load_kids(self) -> None:
        if self._snapshot_dir:
            for kid in self._credentials:
                self._snapshot_load(kid)

    def _shared_snapshot_load(self, kid: str) -> None:
        """把某个凭证的旧 JSON 密文快照导入 SQLite（只补空缺；迁移路径）与同名租约文件。"""
        if kid not in self._credentials or kid in self._snapshot_loaded:
            return
        self._snapshot_loaded.add(kid)
        paths = []
        if self._plaintext_dir:
            paths.append(os.path.join(self._plaintext_dir, "registry-kv", "lease-" + kid + ".json"))
        if self._snapshot_dir:
            paths.append(self._snapshot_path(kid) or "")
        now = self._now()
        pending: List[_Entry] = []
        for path in paths:
            if not path:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                records = _Sealed.from_json(raw).open(self._credential(kid) or "").get("leases") or []
            except (OSError, ValueError, KeyError, AttributeError, TypeError):
                continue
            for record in records:
                try:
                    if float(record["expires_at"]) <= now:
                        continue
                    content = record["content"]
                    if not isinstance(content, Mapping):
                        raise RegistryError(503, "bad record")
                    entry = _Entry(str(record["session_id"]), str(record["run_id"]),
                                   str(record["user"]), str(record["hostname"]),
                                   _Sealed(self._credential(kid) or "", content),
                                   float(record["expires_at"]), kid, "")
                except (KeyError, TypeError, ValueError, RegistryError):
                    continue
                if entry.kid:
                    pending.append(entry)
        if pending:
            self.store.import_entries(pending, now)


    def _lease_for_kid(self, kid: str, now: float) -> Optional[_Entry]:
        return next((v for v in list(self.kv.values())
                     if type(v) is _Entry and v.kid == kid and v.expires_at > now), None)

    def close(self) -> None:
        self.prune_expired()
        if self.store is not None:
            self.store.close()

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
            headers.update(signing_headers(token, method, path, data, kid=client.kid))
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
        print("[runtime] registry_payload_has_agent_token=%s" % bool(agent_token), flush=True)
        if hostname:
            payload["hostname"] = hostname.lower()
        payload["user"] = self.user
        body = await self._register_lease(canonical_json(payload))
        if body is None:
            return False
        if self.cache_path:
            _write_cache(self.cache_path, body)
        return True

    async def _register_lease(self, raw: bytes) -> Optional[Dict[str, Any]]:
        """登记租约，只对瞬时故障做有界退避重试。

        判据：连不上 Registry / 429 / 5xx 会重试；缺 Token、鉴权失败、签名不匹配、
        payload 非法立刻返回 —— 这些重试多少次都不会变好，只会拖慢失败。
        重复登记本身是幂等的：同一 kid 同一 session 的租约由 Registry 续租，
        因此响应丢失后重发是安全动作。
        """
        deadline = time.monotonic() + REGISTRY_RETRY_WINDOW_SECONDS
        delay = REGISTRY_RETRY_BASE_SECONDS
        attempt = 0
        while True:
            attempt += 1
            try:
                status, body = await _Transport(self).run(
                    "POST", "/v1/sessions/" + self.kid, raw
                )
            except SignatureError as exc:
                # 凭证/签名问题：配置侧错误，重试无意义
                self.last_error = str(exc)
                return None
            except RegistryError as exc:
                status, body = None, {}
                self.last_error = str(exc)
            else:
                body = body or {}
                if status == 200:
                    self.last_error = None
                    return body
                self.last_error = str(body.get("error") or f"HTTP {status}")

            if not _retryable_status(status):
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sleep_for = min(delay, remaining)
            print("[runtime] registry_retry attempt=%d last_error=%s"
                  % (attempt, self.last_error), flush=True)
            await asyncio.sleep(sleep_for * (1.0 + random.random() * 0.2))
            delay = min(delay * 2, REGISTRY_RETRY_MAX_SECONDS)

    async def resolve_session(self, session_id: str, run_id: Optional[str] = None) -> Optional[str]:
        """按 session_id 获取当前 Session 的网关 URL（租约校验 run_id/user）。"""
        record = await self._resolve("/v1/sessions/" + session_id, {"run_id": run_id,
                                                                    "user": self.user})
        return record.get("origin") if record else None

    async def resolve_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """按 GitHub run_id 获取当前会话的私有连接信息（origin + 受限 Agent Token）。"""
        record = await self._resolve("/v1/runs/" + run_id, {"user": self.user})
        if not record or not record.get("agent_token"):
            print("[runtime] registry_resolve_missing_agent_token run_id=%s" % run_id, flush=True)
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
            # 注意：本函数里的局部名 token / run_id 会被 _resolve 等下游函数按模块全局
            # 读到（它们被视为可选参数），不要在登记分支里让这样的名字进入函数作用域。
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
        # 解析接口与登记接口同一套认证：Bearer + 签名 + 时间戳 + 一次性 nonce，
        # 没有凭证或签名就不能探测/读取任何 run/session。
        kid = self.registry.authenticate(method, raw_path, headers, body, require_path_kid=False)
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

    def _resolve(self, kind: str, identifier: str, raw_path: str,
                 token: Optional[str]) -> Tuple[int, Dict[str, Any], Optional[str]]:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(raw_path).query)
        user = (query.get("user") or [""])[0]
        run_id = (query.get("run_id") or [None])[0]
        record = self.registry.resolve(kind, identifier, user, run_id)
        if (record is None and kind == "run" and not query.get("user")):
            # 宿主解析 run 时没带租户号（缺省 "default"），而 Runner 登记时带的是仓库名：
            # run_id 在 Registry 内唯一映射，未显式指定租户时按 run_id 解析。
            # 显式给了 user 的跨租户查询仍然 404（隔离测试覆盖）。
            record = self.registry.resolve_by_run_id("run", identifier, user)
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
    snapshot_path: Optional[str] = None,
    db_path: Optional[str] = None,
    memory: bool = False,
) -> Optional[Tuple[RendezvousRegistry, Any]]:
    """构建可启动的 Registry；缺凭证 / 缺 aiohttp / 缺加密能力时返回 ``None``。

    ``snapshot_path``：传 ``private_dirs`` 中的某个目录时，登记内容会镜像到以凭证
    kid 为文件名的密文文件；重建 Registry（重启）后首次解析该类凭证前自动装载，
    解析结果与重启前一致。目录不在 ``private_dirs`` 内时不会写盘。

    ``db_path``：给出时使用 SQLite 共享存储（同一数据库的多个实例/进程共享租约、
    hostname 互斥与 nonce 判定）；缺省为进程内存，只适合单进程。
    """
    tokens = [t for t in auth_tokens if t]
    if registry is None:
        if not tokens:
            return None
        if not memory and not db_path:
            # 多实例/多进程部署必须显式选择持久数据库，不能各自写进程内字典。
            return None
        registry = RendezvousRegistry(credentials=tokens, private_dirs=private_dirs, db_path=db_path)
    if not tokens and not registry._credentials:
        return None
    if not registry._can_seal() and registry._plaintext_dir is None:
        return None
    if snapshot_path and registry._snapshot_dir is None:
        registry.enable_snapshot(snapshot_path)
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
    db_path: Optional[str] = None,
) -> RegistryStdlibServer:
    """启动最小 Registry（标准库实现），返回可 ``stop()`` 的句柄。

    ``db_path`` 给出时使用 SQLite 共享存储；不给时为进程内存（只适合单实例）。
    """
    tokens = [t for t in auth_tokens if t]
    if not tokens:
        raise RegistryError(None, "缺少 Registry 凭证")
    registry = RendezvousRegistry(credentials=tokens, private_dirs=private_dirs, db_path=db_path)
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
    parser.add_argument("--db", default=os.environ.get(ENV_REGISTRY_DB),
                        help="SQLite 数据库路径（%s）；多实例/多进程部署必须提供。" % ENV_REGISTRY_DB)
    parser.add_argument("--snapshot-dir",
                        help="重启保留快照目录（须在 --private-dir 内）；旧 JSON 快照在启动时迁移进数据库")
    parser.add_argument("--allow-memory", action="store_true",
                        help="显式允许无数据库的单进程内存模式（多实例各写各的，禁止用于多副本）")
    args = parser.parse_args(argv)

    token = os.environ.get(args.token_env, "").strip()
    if not token:
        print("缺少 Registry 凭证：请设置 %s" % args.token_env)
        return 2
    if not args.db and not args.allow_memory:
        print("拒绝以进程内存启动：多实例/多进程会各自登记、重复占用 run_id/hostname。"
              "请用 --db（或 %s）指定共享 SQLite；单进程演示需显式 --allow-memory。"
              % ENV_REGISTRY_DB)
        return 2
    try:
        server = run_registry_server(
            [token], args.host, args.port,
            private_dirs=[args.private_dir] if args.private_dir else None,
            db_path=args.db or None,
        )
        if args.snapshot_dir:
            server.registry.enable_snapshot(args.snapshot_dir)
    except RegistryError as exc:
        print(str(exc))
        return 2
    print("gha-rendezvous listening on %s (token/env: %s, store: %s)"
          % (server.endpoint, args.token_env, "sqlite" if server.registry.shared else "memory"))
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
