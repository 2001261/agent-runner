"""GitHub Check Run 通道的临时入口移交（Runner → Host）。

背景：Cloudflare Quick Tunnel 的 origin 每次启动都换，且短命；把它写进仓库 Secret
会把一个“端点”变成需要运维维护的长期凭据，隧道一断 Secret 就作废。B 方案规定：
**任何公网端点都不进仓库 Secret**，origin 的发现改走 GitHub 原生通道。

链路：

    Runner（workflow 内进程，只持有 Host 公钥 GHA_STATE_PUBLIC_KEY）
        └─ 密封 {origin, agent_token, ...}（GHSE v2 封套）
           → base64 → Check Run 的 output.summary（Check Run 名 gha-rndz-<run_id>）
    Host（持有 Vault 中 X25519 私钥，GITHUB_TOKEN 只需读该 run/commit 的 check-run）
        └─ 轮询该 run 的 check-run → 取 summary → base64 解码 → 解封 → 校验 → 连 Gateway

安全边界：

- 通道上（公开仓库亦然）只有公钥加密后的密文；解密私钥只在 Host Vault
  （``Vault.state_keypair()``），Runner 上没有任何可解密数据的密钥。
- 明文封套的 AAD 绑定 schema ``gha-plane/v1``，与 Runner 状态封套的 ``gha-plain/v1``
  不同：同一条通道上把别的对象密文挪过来只会解封失败。
- 解封后必须全部字段校验通过才返回；任何缺失、类型错误、篡改、过期都抛
  ``RendezvousError``，绝不返回部分数据。
- 传输只依赖 GitHub REST v3 + workflow 自带 ``GITHUB_TOKEN``；不引入第三方依赖。
- 错误信息只含状态码/错误类型，绝不含 token、origin 或 payload 内容（它们会进日志）。

check-run 可见性：``POST /repos/{owner}/{repo}/check-runs`` 需要 Actions 令牌
（workflow 的 ``GITHUB_TOKEN`` 满足）；Host 读 check-run 只需该提交的读权限。
token 经 ``Authorization`` 头传递，不拼进 URL；本模块任何返回值/异常都不回显 URL 查询串。

“未发布”语义（Host 轮询依赖）：``GitHubRendezvousFetcher.fetch`` 在该 run / 该提交下
尚不存在 ``gha-rndz-<run_id>`` 的 check-run 时，**返回 None**；只有通道正常但密文不可用
（篡改、过期、字段不符）才抛 ``RendezvousError``。
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Union

from .state_envelope import (
    EnvelopeError,
    EnvelopeSealer,
    HostKeyPair,
    RecipientConfig,
    decrypt_envelope,
    envelope_key_id,
    load_host_key_pair,
    load_recipient_config,
)

DEFAULT_API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
# 封套 AAD 绑定的明文 schema；与 Runner 状态回传的 gha-plain/v1 区分，防止跨对象挪用
PLAINTEXT_SCHEMA = "gha-plane/v1"
CHECK_NAME_PREFIX = "gha-rndz-"
PAYLOAD_VERSION = 1
# 允许的时钟偏差：过期判断放宽这些秒，避免 Host 与 Runner 机器时钟差一点就误拒
CLOCK_SKEW_SECONDS = 120
ORIGIN_PREFIX = "https://"
# 私钥输入本身不带 key_id 时的占位值；封套头的 key_id 会覆盖它
_PLACEHOLDER_KEY_ID = "host-key"

# request_fn(method, url, token, body=None) -> (status, bytes)
RequestFn = Callable[[str, str, str, Optional[bytes]], "tuple[int, bytes]"]
PrivateKeyInput = Union[HostKeyPair, str, bytes, bytearray]
RecipientInput = Union[RecipientConfig, EnvelopeSealer, Dict[str, Any]]


class RendezvousError(Exception):
    """Check Run 通道不可用、密文不可解封或解封后校验失败。"""


# ---------------------------------------------------------------------------
# HTTP 基础层（标准库；可注入替代实现便于脱网测试）
# ---------------------------------------------------------------------------

def check_run_name(run_id: Union[int, str]) -> str:
    return f"{CHECK_NAME_PREFIX}{run_id}"


def _normalize_repository(repository: str) -> str:
    """校验 owner/repo 并拼进 URL；提前拒绝会把路径/查询注入 URL 的取值。"""
    if not isinstance(repository, str) or repository.count("/") != 1:
        raise RendezvousError("repository 必须是 owner/repo 形式")
    owner, repo = repository.split("/", 1)
    for part in (owner, repo):
        if not part or part in (".", "..") or part.startswith("-") or not part.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise RendezvousError("repository 含非法字符")
    return repository


def _run_id_str(run_id: Union[int, str]) -> str:
    text = str(run_id)
    if not text.isdigit():
        raise RendezvousError("run_id 必须是数字")
    return text


def _repo_url(repository: str, base: str) -> str:
    return f"{base.rstrip('/')}/repos/{_normalize_repository(repository)}"


def _headers(token: str, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers


def urllib_request_fn(method: str, url: str, token: str, body: Optional[bytes] = None,
                      timeout: float = 30.0) -> "tuple[int, bytes]":
    """默认 HTTP 实现：HTTP 错误按状态码返回而不抛错；网络层错误才抛 RendezvousError。"""
    req = urllib.request.Request(url, data=body, headers=_headers(token), method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 0) or 0), resp.read()
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return int(exc.code), raw
    except (urllib.error.URLError, OSError) as exc:
        # 只报类型：URLError.reason 可能带主机名，异常文本里可能夹带 URL 查询串
        raise RendezvousError(f"GitHub 请求失败: {type(exc).__name__}") from None


def _decode_json(status: int, raw: bytes) -> Any:
    if status >= 400:
        raise RendezvousError(f"GitHub 返回 HTTP {status}")
    try:
        return json.loads(raw.decode("utf-8") or "null")
    except (UnicodeDecodeError, ValueError):
        raise RendezvousError(f"GitHub 响应不是合法 JSON (HTTP {status})") from None


# ---------------------------------------------------------------------------
# 明文 payload 构造与校验
# ---------------------------------------------------------------------------

def build_payload(repository: str, run_id: Union[int, str], session_id: str, origin: str,
                  agent_token: str, ttl_seconds: int,
                  now: Optional[float] = None) -> Dict[str, Any]:
    """构造待密封的明文 payload；早失败：明文阶段就把明显不合法的取值拒掉。"""
    if not isinstance(session_id, str) or not session_id:
        raise RendezvousError("session_id 不能为空")
    if not isinstance(origin, str) or not origin.startswith(ORIGIN_PREFIX):
        raise RendezvousError("origin 必须是 https:// 开头")
    if not isinstance(agent_token, str) or not agent_token:
        raise RendezvousError("agent_token 不能为空")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise RendezvousError("ttl_seconds 必须是正整数")
    created = time.time() if now is None else now
    return {
        "v": PAYLOAD_VERSION,
        "repository": _normalize_repository(repository),
        "run_id": _run_id_str(run_id),
        "session_id": session_id,
        "origin": origin,
        "agent_token": agent_token,
        "expires_at": created + ttl_seconds,
    }


def canonical_payload(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def validate_payload(payload: Any, repository: str, run_id: Union[int, str],
                     now: Optional[float] = None,
                     clock_skew_seconds: int = CLOCK_SKEW_SECONDS) -> Dict[str, Any]:
    """解封后的全部校验；任何一项不过都抛 RendezvousError，不做部分返回。"""
    if not isinstance(payload, dict):
        raise RendezvousError("payload 不是 JSON 对象")
    version = payload.get("v")
    if version != PAYLOAD_VERSION or isinstance(version, bool):
        raise RendezvousError("payload 版本不受支持")
    if payload.get("run_id") != _run_id_str(run_id):
        raise RendezvousError("payload run_id 与请求不一致")
    if payload.get("repository") != _normalize_repository(repository):
        raise RendezvousError("payload repository 与请求不一致")
    origin = payload.get("origin")
    if not isinstance(origin, str) or not origin.startswith(ORIGIN_PREFIX):
        raise RendezvousError("payload origin 必须是 https:// 开头")
    agent_token = payload.get("agent_token")
    if not isinstance(agent_token, str) or not agent_token:
        raise RendezvousError("payload agent_token 为空")
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        raise RendezvousError("payload session_id 为空")
    expires_at = payload.get("expires_at")
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        raise RendezvousError("payload expires_at 非法")
    current = time.time() if now is None else now
    if expires_at + clock_skew_seconds <= current:
        raise RendezvousError("payload 已过期")
    return {
        "v": PAYLOAD_VERSION,
        "repository": payload["repository"],
        "run_id": payload["run_id"],
        "session_id": session_id,
        "origin": origin,
        "agent_token": agent_token,
        "expires_at": float(expires_at),
    }


def _resolve_sealer(recipient: RecipientInput,
                    plaintext_schema: str = PLAINTEXT_SCHEMA) -> EnvelopeSealer:
    if isinstance(recipient, EnvelopeSealer):
        # 显式传入的密封器自带 schema，公开 API 无法改写；不一致就让调用方重建
        if recipient.plaintext_schema != plaintext_schema:
            raise RendezvousError(
                f"密封器的 plaintext_schema 必须是 {plaintext_schema}")
        return recipient
    if isinstance(recipient, RecipientConfig):
        if not recipient.configured:
            raise RendezvousError("未配置 Host 公钥")
        # RecipientConfig.sealer() 固定用状态封套的 gha-plain/v1 schema，这里绕开它
        return EnvelopeSealer(recipient.key_id or "", recipient.public_key or "",
                              plaintext_schema=plaintext_schema)
    if isinstance(recipient, dict):
        key_id = recipient.get("key_id")
        public_key = recipient.get("public_key")
        if not key_id or not public_key:
            raise RendezvousError("recipient 文档缺少 key_id 或 public_key")
        if recipient.get("private_key") or recipient.get("private_secret"):
            raise RendezvousError("Runner 侧只能拿公钥，拒绝含私钥的 recipient 文档")
        return EnvelopeSealer(str(key_id), str(public_key), plaintext_schema=plaintext_schema)
    if recipient is None:
        raise RendezvousError("缺少 recipient：需要 Host 公钥配置")
    raise RendezvousError(f"不支持的 recipient 类型: {type(recipient).__name__}")


def _resolve_host_pair(private_key: PrivateKeyInput, sealed: Optional[bytes] = None) -> HostKeyPair:
    """Host 私钥合法输入：Vault 的 HostKeyPair、base64(raw/PKCS8) 私钥字符串、PEM 文本/字节。

    封套解封要求 ``pair.key_id`` 与封套头里的 key_id 相同，而独立私钥/PEM 本身不带
    key_id（Vault 里的 state-recipient.json 才会记录）。所以裸私钥先以占位 key_id
    解析，再按优先级定 key_id：调用方显式期望 > 封套头声明的 > 私钥公钥推出的默认。
    公钥推出的默认值与 ``generate_host_key_pair`` 的缺省 key_id 一致。
    """
    if isinstance(private_key, HostKeyPair):
        return private_key
    if isinstance(private_key, (bytes, bytearray)):
        data = bytes(private_key)
        text = (data.decode("ascii", "strict") if data.lstrip().startswith(b"-----BEGIN")
                else base64.b64encode(data).decode("ascii"))
    elif isinstance(private_key, str):
        text = private_key
    else:
        raise RendezvousError(f"不支持的 Host 私钥类型: {type(private_key).__name__}")
    if not text.strip():
        raise RendezvousError("Host 私钥为空")
    try:
        pair = load_host_key_pair(_PLACEHOLDER_KEY_ID, text)
    except (EnvelopeError, ValueError):
        raise RendezvousError("Host 私钥解析失败") from None
    pair.key_id = (envelope_key_id(sealed or b"")
                   or "x25519-" + pair.public_key.public_bytes_raw()[:8].hex())
    return pair


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except Exception:
        raise RendezvousError("check-run summary 不是合法 base64") from None


# ---------------------------------------------------------------------------
# Runner 侧：发布 / 撤销
# ---------------------------------------------------------------------------

class GitHubRendezvousPublisher:
    """Runner 侧：把已经密封的 rendezvous 记录挂到 Check Run 的 output.summary。"""

    def __init__(self, github_token: str, recipient: Optional[RecipientInput] = None,
                 request_fn: Optional[RequestFn] = None, api_base: str = DEFAULT_API_BASE,
                 plaintext_schema: str = PLAINTEXT_SCHEMA):
        if not isinstance(github_token, str) or not github_token:
            raise RendezvousError("缺少 github_token")
        self._token = github_token
        self.plaintext_schema = plaintext_schema
        # recipient 可以缺省：只做 revoke 的调用方不需要 Host 公钥
        self._sealer = (_resolve_sealer(recipient, plaintext_schema)
                        if recipient is not None else None)
        self._request = request_fn or urllib_request_fn
        self._api_base = api_base

    def seal_payload(self, payload: Dict[str, Any]) -> str:
        """密封 payload 并返回 base64 摘要；只做构建，不发网络请求。"""
        if self._sealer is None:
            raise RendezvousError("未配置 Host 公钥，无法密封")
        sealed = self._sealer.seal(canonical_payload(payload))
        text = _b64encode(sealed)
        # GitHub check-run output.summary 上限 65535 字符；超了宁可直接失败也不截断
        if len(text) > 60000:
            raise RendezvousError("封套摘要超出 check-run summary 长度上限")
        return text

    def publish(self, repository: str, run_id: Union[int, str], session_id: str, origin: str,
                agent_token: str, ttl_seconds: int, github_token: Optional[str] = None,
                sha: Optional[str] = None, now: Optional[float] = None) -> int:
        """密封并发布，返回 check_run id；sha 缺省取同一个 run 的 head_sha。"""
        if github_token:
            self._token = github_token
        token = self._token
        rid = _run_id_str(run_id)
        payload = build_payload(repository, rid, session_id, origin, agent_token, ttl_seconds, now)
        summary = self.seal_payload(payload)
        head_sha = sha or self._resolve_head_sha(repository, rid, token)
        body = {
            "name": check_run_name(rid),
            "head_sha": head_sha,
            "status": "in_progress",
            "output": {
                "title": f"gha rendezvous {rid}",
                "summary": summary,
            },
        }
        status, raw = self._request(
            "POST", _repo_url(repository, self._api_base) + "/check-runs", token,
            json.dumps(body).encode("utf-8"),
        )
        data = _decode_json(status, raw)
        if status not in (200, 201) or not isinstance(data, dict):
            raise RendezvousError(f"发布 check-run 失败: HTTP {status}")
        check_id = data.get("id")
        if not isinstance(check_id, int) or isinstance(check_id, bool):
            raise RendezvousError("GitHub 未返回合法 check_run id")
        return check_id

    def _resolve_head_sha(self, repository: str, rid: str, token: str) -> str:
        url = _repo_url(repository, self._api_base) + f"/actions/runs/{urllib.parse.quote(rid)}"
        status, raw = self._request("GET", url, token)
        data = _decode_json(status, raw)
        sha = data.get("head_sha") if isinstance(data, dict) else None
        if not isinstance(sha, str) or not sha:
            raise RendezvousError(f"无法获取 run head_sha (HTTP {status})")
        return sha

    def revoke(self, check_run_id: int, repository: str,
               github_token: Optional[str] = None) -> bool:
        """删除 check-run；幂等：404（已被删/不存在）也视为成功。"""
        if github_token:
            self._token = github_token
        token = self._token
        if not isinstance(check_run_id, int) or isinstance(check_run_id, bool):
            raise RendezvousError("check_run_id 必须是整数")
        url = _repo_url(repository, self._api_base) + f"/check-runs/{check_run_id}"
        status, _ = self._request("DELETE", url, token)
        if status in (200, 204, 404):
            return True
        raise RendezvousError(f"撤销 check-run 失败: HTTP {status}")


def publish(repository: str, run_id: Union[int, str], session_id: str, origin: str,
            agent_token: str, ttl_seconds: int, github_token: str, sha: Optional[str] = None,
            *, recipient: Optional[RecipientInput] = None,
            request_fn: Optional[RequestFn] = None, api_base: str = DEFAULT_API_BASE,
            now: Optional[float] = None, plaintext_schema: str = PLAINTEXT_SCHEMA) -> int:
    """便捷函数：recipient 缺省时用 Runner 环境里的 GHA_STATE_PUBLIC_KEY 配置。"""
    cfg = recipient if recipient is not None else load_recipient_config()
    pub = GitHubRendezvousPublisher(github_token, cfg, request_fn=request_fn,
                                    api_base=api_base, plaintext_schema=plaintext_schema)
    return pub.publish(repository, run_id, session_id, origin, agent_token, ttl_seconds,
                       github_token=github_token, sha=sha, now=now)


def revoke(check_run_id: int, repository: str, github_token: str, *,
           request_fn: Optional[RequestFn] = None,
           api_base: str = DEFAULT_API_BASE) -> bool:
    pub = GitHubRendezvousPublisher(github_token, None, request_fn=request_fn, api_base=api_base)
    return pub.revoke(check_run_id, repository)


# ---------------------------------------------------------------------------
# Host 侧：轮询取回 / 解封 / 校验
# ---------------------------------------------------------------------------

def _select_latest_check(raw: Any, name: str) -> Optional[Dict[str, Any]]:
    data = raw if isinstance(raw, dict) else {}
    items: List[Dict[str, Any]] = []
    for item in data.get("check_runs") or []:
        if isinstance(item, dict) and item.get("name") == name:
            items.append(item)
    if not items:
        return None
    return max(items, key=lambda it: (it.get("started_at") or "", it.get("id") or 0))


class GitHubRendezvousFetcher:
    """Host 侧：按 run_id 取回 Check Run 摘要、解封并校验。

    ``fetch`` 在 check-run 尚不存在时返回 None（“未发布”），Host 轮询据此继续等待；
    密文存在但不可解封/校验失败时抛 RendezvousError（通常意味着伪造或对账错仓）。
    """

    def __init__(self, github_token: str, private_key: Optional[PrivateKeyInput] = None,
                 request_fn: Optional[RequestFn] = None, api_base: str = DEFAULT_API_BASE,
                 plaintext_schema: str = PLAINTEXT_SCHEMA):
        if not isinstance(github_token, str) or not github_token:
            raise RendezvousError("缺少 github_token")
        self._token = github_token
        self.plaintext_schema = plaintext_schema
        self._private_key = private_key
        self._request = request_fn or urllib_request_fn
        self._api_base = api_base

    def _host_pair(self, private_key: Optional[PrivateKeyInput], sealed: bytes) -> HostKeyPair:
        key = private_key if private_key is not None else self._private_key
        if key is None:
            # 延迟到真正需要解封时才读 Vault，Host 的“未发布”轮询不会触发密钥访问
            from .vault import Vault
            key = Vault().state_keypair()
        return _resolve_host_pair(key, sealed)

    def _resolve_head_sha(self, repository: str, rid: str) -> str:
        url = _repo_url(repository, self._api_base) + f"/actions/runs/{urllib.parse.quote(rid)}"
        status, raw = self._request("GET", url, self._token)
        data = _decode_json(status, raw)
        sha = data.get("head_sha") if isinstance(data, dict) else None
        if not isinstance(sha, str) or not sha:
            raise RendezvousError(f"无法获取 run head_sha (HTTP {status})")
        return sha

    def read_summary(self, repository: str, run_id: Union[int, str]) -> Optional[str]:
        """返回最新 ``gha-rndz-<run_id>`` check-run 的 summary；未发布返回 None。"""
        rid = _run_id_str(run_id)
        repo = _normalize_repository(repository)
        head_sha = self._resolve_head_sha(repo, rid)
        url = (_repo_url(repo, self._api_base) + "/commits/" + urllib.parse.quote(head_sha)
               + "/check-runs?" + urllib.parse.urlencode(
                   {"check_name": check_run_name(rid), "filter": "all", "per_page": "100"}))
        status, raw = self._request("GET", url, self._token)
        data = _decode_json(status, raw)
        latest = _select_latest_check(data, check_run_name(rid))
        if latest is None:
            return None
        output = latest.get("output") if isinstance(latest.get("output"), dict) else {}
        summary = output.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise RendezvousError("check-run 未携带 summary")
        return summary

    def fetch(self, repository: str, run_id: Union[int, str],
              private_key: Optional[PrivateKeyInput] = None,
              github_token: Optional[str] = None,
              request_fn: Optional[RequestFn] = None, *, now: Optional[float] = None,
              clock_skew_seconds: int = CLOCK_SKEW_SECONDS) -> Optional[Dict[str, Any]]:
        """取回并校验 rendezvous 记录；未发布返回 None，其余失败抛 RendezvousError。"""
        if request_fn is not None:
            self._request = request_fn
        if github_token:
            self._token = github_token
        rid = _run_id_str(run_id)
        repo = _normalize_repository(repository)
        summary = self.read_summary(repo, rid)
        if summary is None:
            return None

        sealed = _b64decode(summary)
        pair = self._host_pair(private_key, sealed)
        try:
            plain = decrypt_envelope(pair, sealed, plaintext_schema=self.plaintext_schema)
        except EnvelopeError as exc:
            raise RendezvousError(f"解封失败: {type(exc).__name__}") from None
        try:
            payload = json.loads(plain.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise RendezvousError("解封后明文不是合法 JSON") from None
        return validate_payload(payload, repo, rid, now=now, clock_skew_seconds=clock_skew_seconds)


def fetch(repository: str, run_id: Union[int, str], private_key: PrivateKeyInput,
          github_token: str, request_fn: Optional[RequestFn] = None,
          api_base: str = DEFAULT_API_BASE, *, now: Optional[float] = None,
          clock_skew_seconds: int = CLOCK_SKEW_SECONDS,
          plaintext_schema: str = PLAINTEXT_SCHEMA) -> Optional[Dict[str, Any]]:
    """便捷函数：Host 侧一次性取回；未发布返回 None。"""
    fetcher = GitHubRendezvousFetcher(github_token, private_key,
                                      request_fn=request_fn, api_base=api_base,
                                      plaintext_schema=plaintext_schema)
    return fetcher.fetch(repository, run_id, now=now, clock_skew_seconds=clock_skew_seconds)


__all__ = [
    "API_VERSION",
    "CHECK_NAME_PREFIX",
    "CLOCK_SKEW_SECONDS",
    "DEFAULT_API_BASE",
    "GitHubRendezvousFetcher",
    "GitHubRendezvousPublisher",
    "PLAINTEXT_SCHEMA",
    "RequestFn",
    "RendezvousError",
    "build_payload",
    "canonical_payload",
    "check_run_name",
    "fetch",
    "publish",
    "revoke",
    "urllib_request_fn",
    "validate_payload",
]
