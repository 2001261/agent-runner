"""Agent Host 交互客户端（与 Runner 端 Gateway 通信）。

遵循《2.0 迭代.md》第六章与第二十一章规范。
支持通过 Cloudflare Tunnel URL 或 本地回环连接 Runner 网关，
统一维护 Authorization 凭证与错误处理。
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple

# 幂等 GET 的有界重试：Quick Tunnel 间歇返回 530/1033 时，
# Registry 发现后紧接的 /health、/v1/session、/v1/state/manifest 不应直接失败。
GET_RETRY_BUDGET_SECONDS = 60.0
GET_RETRY_BASE_DELAY = 1.0
GET_RETRY_MAX_DELAY = 10.0
# 单次请求的超时上限：整个预算内至少要能再发一次请求，否则会一次卡死 60 秒
GET_MAX_ATTEMPT_TIMEOUT = 10.0
RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530})
# 二进制下载（get_stream/get_raw）与 JSON GET 同构，但隧道冷启动可能更久
BINARY_RETRY_BUDGET_SECONDS = GET_RETRY_BUDGET_SECONDS
# 隧道“未就绪”的 Cloudflare 错误码：Host 侧看到 530，响应体里带 error code: 1033 等。
# 它们与 4xx 不同，属于可等待恢复的状态。
TUNNEL_NOT_READY_ERROR_CODES = frozenset({1033, 1034})


class InteractiveClientError(Exception):
    """网关交互异常

    status 为服务端 HTTP 状态码（网络层失败时为 None）；消息文本仍是
    "HTTP <code>: <body>"，旧的文本匹配不受影响。
    """
    def __init__(self, message: str = "", status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def is_retryable_status(status: Optional[int]) -> bool:
    """True：429/5xx（含 Cloudflare 530 等隧道未就绪）；False：4xx 配置/鉴权错误。"""
    return status in RETRYABLE_HTTP_STATUSES


def is_tunnel_not_ready(exc: BaseException) -> bool:
    """异常是否表示“隧道尚未就绪”或限流（值得继续等），而不是配置/鉴权错误。

    有结构化状态码时只看状态码：4xx（除 429）一律不可重试，即使正文里恰好出现
    “1033” 也不改判。没有状态码时才退回到文本里的 Cloudflare 错误码。
    """
    if not isinstance(exc, InteractiveClientError):
        return False
    if exc.status is not None:
        return exc.status in RETRYABLE_HTTP_STATUSES
    return any(str(code) in str(exc) for code in TUNNEL_NOT_READY_ERROR_CODES)


def is_http_status(exc: BaseException, status: int) -> bool:
    """调用方判断异常是否由指定 HTTP 状态码引起（优先结构化 status，兼容旧文本）"""
    if isinstance(exc, InteractiveClientError) and getattr(exc, "status", None) is not None:
        return exc.status == status
    return isinstance(exc, InteractiveClientError) and f"HTTP {status}" in str(exc)


class _RetryableHTTPError(Exception):
    """内部信号：本次请求值得重试（不对外暴露，失败时仍抛 InteractiveClientError）"""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _retry_after_seconds(err: urllib.error.HTTPError) -> Optional[float]:
    try:
        raw = err.headers.get("Retry-After") if err.headers else None
        if raw is None:
            return None
        value = float(str(raw).strip())
    except (AttributeError, TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRYABLE_HTTP_STATUSES
    # URLError / 连接被重置 / 读超时等网络层失败；配置类错误（URL 非法）不重试
    return isinstance(exc, (urllib.error.URLError, http.client.HTTPException,
                            ConnectionError, TimeoutError, socket.timeout))


class InteractiveClient:
    """网关通信客户端"""

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 15.0,
                 retry_budget: Optional[float] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        # None 表示沿用默认预算；0 表示禁止重试
        self.retry_budget = GET_RETRY_BUDGET_SECONDS if retry_budget is None else max(0.0, float(retry_budget))
        # 二进制下载沿用同一预算参数（retry_budget=0 同样禁止重试）
        self.binary_retry_budget = self.retry_budget
        self._sleep = time.sleep

    def _headers(self, custom: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "User-Agent": "gha-runner/2.0-host",
            "Accept": "application/json",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if custom:
            h.update(custom)
        return h

    def _redact(self, text: str) -> str:
        """兜底脱敏：异常文本里若混入 token 或网关地址，一律替换掉。"""
        for secret in (self.token, self.base_url):
            if secret:
                text = text.replace(secret, "***")
        return text

    def _get_attempt_timeout(self) -> float:
        if self.retry_budget <= 0:
            return self.timeout
        return min(self.timeout, GET_MAX_ATTEMPT_TIMEOUT)

    def _get_once(self, req: urllib.request.Request, endpoint: str) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=self._get_attempt_timeout()) as resp:
                data = resp.read()
        except urllib.error.HTTPError as e:
            try:
                msg = e.read().decode("utf-8", "replace")
            except Exception:
                msg = str(e.reason or "")
            message = f"HTTP {e.code}: {msg}"
            if _is_retryable(e):
                raise _RetryableHTTPError(e.code, message) from e
            raise InteractiveClientError(message, status=e.code) from e
        except Exception as e:
            if _is_retryable(e):
                raise _RetryableHTTPError(0, f"请求失败 ({endpoint}): {e}") from e
            raise InteractiveClientError(f"请求失败 ({endpoint}): {e}") from e
        # 响应体已读到：解析失败属于协议错误，重试同样的网关也没有意义
        try:
            return json.loads(data.decode("utf-8"))
        except ValueError as e:
            raise InteractiveClientError(f"响应解析失败 ({endpoint}): {e}") from e

    def get(self, endpoint: str, params: Optional[Dict[str, str]] = None,
            headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """幂等 GET：对 429/5xx 与网络层失败做有界指数退避重试。

        总重试时长受 retry_budget（默认 60 秒）约束；4xx（404/401/405 等）不重试。
        最终失败仍抛 InteractiveClientError，HTTP 状态码相同者保留原消息格式。
        """
        url = f"{self.base_url}{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self._headers(headers), method="GET")

        # 按计划等待时长累计预算（不依赖单调时钟），保证总重试时长严格有界
        spent = 0.0
        delay = GET_RETRY_BASE_DELAY
        attempt = 0
        while True:
            attempt += 1
            try:
                return self._get_once(req, endpoint)
            except _RetryableHTTPError as e:
                status, message = e.status, e.message
                cause = e.__cause__
                retry_after = _retry_after_seconds(cause) if isinstance(cause, urllib.error.HTTPError) else None
            wait = max(delay, retry_after) if retry_after is not None else delay
            if self.retry_budget <= 0 or spent + wait > self.retry_budget:
                if attempt > 1:
                    message += "（已重试 %d 次，%.0fs 内未恢复）" % (attempt - 1, spent)
                raise InteractiveClientError(self._redact(message), status=status or None)
            self._sleep(wait)
            spent += wait
            delay = min(delay * 2, GET_RETRY_MAX_DELAY)

    def post(self, endpoint: str, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        data = json.dumps(body or {}).encode("utf-8")
        h = self._headers({"Content-Type": "application/json"})
        if headers:
            h.update(headers)

        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        # 非幂等：任何失败（含 429/5xx）都直接抛错，绝不自动重放
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")
            raise InteractiveClientError(self._redact(f"HTTP {e.code}: {msg}"), status=e.code) from e
        except Exception as e:
            raise InteractiveClientError(self._redact(f"请求失败 ({endpoint}): {e}")) from e

    def _binary_attempt_timeout(self) -> float:
        if self.binary_retry_budget <= 0:
            return self.timeout
        return min(self.timeout, GET_MAX_ATTEMPT_TIMEOUT)

    def _open_binary(self, req: urllib.request.Request, endpoint: str) -> Any:
        """打开二进制响应；可重试失败抛 _RetryableHTTPError，4xx（除 429）直接抛错。

        这里只完成请求头阶段：失败时响应体（错误页）被丢弃，不会为了一次重试把
        正文读进内存；成功时把响应对象交给调用方流式读取。
        """
        try:
            resp = urllib.request.urlopen(req, timeout=self._binary_attempt_timeout())
        except urllib.error.HTTPError as e:
            if _is_retryable(e):
                raise _RetryableHTTPError(e.code, f"HTTP {e.code}: {e.reason or ''}") from e
            raise InteractiveClientError(f"二进制下载失败 ({endpoint}): HTTP {e.code}: {e.reason or ''}",
                                         status=e.code) from e
        except Exception as e:
            if _is_retryable(e):
                raise _RetryableHTTPError(0, f"二进制下载失败 ({endpoint}): {e}") from e
            raise InteractiveClientError(f"二进制下载失败 ({endpoint}): {e}") from e
        return resp

    def _binary_with_retry(self, endpoint: str, range_header: Optional[str], consume) -> Any:
        """幂等二进制 GET：对网络错误/超时、429、5xx（含 530/1033）做有界指数退避。

        每次重试都重新发出同一个 Range 请求，不扩大请求范围；consume 在响应打开后
        执行，可抛出 _RetryableHTTPError 请求整次重试（丢弃已读到的部分字节）。
        """
        url = f"{self.base_url}{endpoint}"
        h = self._headers({"Accept": "application/octet-stream"})
        if range_header:
            h["Range"] = range_header
        req = urllib.request.Request(url, headers=h, method="GET")

        spent = 0.0
        delay = GET_RETRY_BASE_DELAY
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self._open_binary(req, endpoint)
                if not hasattr(resp, "read"):
                    # 半成品实现（例如绑定到错误对象的同名方法）会让上层误以为拿到了流；
                    # 明确失败，绝不静默退化。
                    raise TypeError(f"{endpoint}: 二进制 GET 未返回可读响应")
                return consume(resp)
            except _RetryableHTTPError as e:
                status, message = e.status, e.message
                cause = e.__cause__
                retry_after = _retry_after_seconds(cause) if isinstance(cause, urllib.error.HTTPError) else None
            wait = max(delay, retry_after) if retry_after is not None else delay
            if self.binary_retry_budget <= 0 or spent + wait > self.binary_retry_budget:
                if attempt > 1:
                    message += "（已重试 %d 次，%.0fs 内未恢复）" % (attempt - 1, spent)
                raise InteractiveClientError(self._redact(message), status=status or None)
            self._sleep(wait)
            spent += wait
            delay = min(delay * 2, GET_RETRY_MAX_DELAY)

    def get_raw(self, endpoint: str, range_header: Optional[str] = None) -> Tuple[bytes, Dict[str, str]]:
        """一次性读取二进制响应；打开响应与读取正文时的网络失败都会重试。

        只用于小对象：重试会丢弃已读到的部分并重发同一个 Range，不会把整包放大。
        """
        def consume(resp: Any) -> Tuple[bytes, Dict[str, str]]:
            try:
                return resp.read(), dict(resp.headers)
            except Exception as e:
                if _is_retryable(e):
                    raise _RetryableHTTPError(0, f"二进制下载失败 ({endpoint}): {e}") from e
                raise InteractiveClientError(f"二进制下载失败 ({endpoint}): {e}") from e
            finally:
                close = getattr(resp, "close", None)
                if close is not None:
                    close()

        return self._binary_with_retry(endpoint, range_header, consume)

    def get_stream(self, endpoint: str, range_header: Optional[str] = None) -> Tuple[Any, Dict[str, str]]:
        """流式下载：返回 (只读响应对象, 响应头)，调用方负责关闭。

        大对象下载不要用 get_raw：它会把整个响应读进内存。打开响应阶段的
        网络错误/超时/429/5xx 会按同一个 Range 有限重试；正文读取中的断线
        由调用方（StateClient）按落盘偏移续传，这里不缓冲正文。
        """
        return self._binary_with_retry(
            endpoint, range_header, lambda resp: (resp, dict(resp.headers)))

    def post_raw(
        self,
        endpoint: str,
        data: bytes,
        headers: Dict[str, str],
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        h = self._headers(headers)
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:500]
            raise InteractiveClientError(f"二进制上传失败 ({endpoint}): HTTP {e.code}: {detail}") from e
        except Exception as e:
            raise InteractiveClientError(f"二进制上传失败 ({endpoint}): {e}") from e

    # 快捷方法
    def health(self) -> Dict[str, Any]:
        return self.get("/health")

    def session_status(self) -> Dict[str, Any]:
        return self.get("/v1/session")

    def finish_task(self) -> Dict[str, Any]:
        return self.post("/v1/task/finish")
