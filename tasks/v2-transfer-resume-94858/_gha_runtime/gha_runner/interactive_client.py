"""Agent Host 交互客户端（与 Runner 端 Gateway 通信）。

遵循《2.0 迭代.md》第六章与第二十一章规范。
支持通过 Cloudflare Tunnel URL 或 本地回环连接 Runner 网关，
统一维护 Authorization 凭证与错误处理。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


class InteractiveClientError(Exception):
    """网关交互异常"""
    pass


class InteractiveClient:
    """网关通信客户端"""

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

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

    def get(self, endpoint: str, params: Optional[Dict[str, str]] = None,
            headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url, headers=self._headers(headers), method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()
                return json.loads(data.decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")
            raise InteractiveClientError(f"HTTP {e.code}: {msg}") from e
        except Exception as e:
            raise InteractiveClientError(f"请求失败 ({endpoint}): {e}") from e

    def post(self, endpoint: str, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        data = json.dumps(body or {}).encode("utf-8")
        h = self._headers({"Content-Type": "application/json"})
        if headers:
            h.update(headers)

        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_bytes = resp.read()
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")
            raise InteractiveClientError(f"HTTP {e.code}: {msg}") from e
        except Exception as e:
            raise InteractiveClientError(f"请求失败 ({endpoint}): {e}") from e

    def get_raw(self, endpoint: str, range_header: Optional[str] = None) -> Tuple[bytes, Dict[str, str]]:
        url = f"{self.base_url}{endpoint}"
        h = self._headers({"Accept": "application/octet-stream"})
        if range_header:
            h["Range"] = range_header

        req = urllib.request.Request(url, headers=h, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_headers = dict(resp.headers)
                return resp.read(), resp_headers
        except Exception as e:
            raise InteractiveClientError(f"二进制下载失败 ({endpoint}): {e}") from e

    def get_stream(self, endpoint: str, range_header: Optional[str] = None) -> Tuple[Any, Dict[str, str]]:
        """流式下载：返回 (只读响应对象, 响应头)，调用方负责关闭。

        大对象下载不要用 get_raw：它会把整个响应读进内存。
        """
        url = f"{self.base_url}{endpoint}"
        h = self._headers({"Accept": "application/octet-stream"})
        if range_header:
            h["Range"] = range_header

        req = urllib.request.Request(url, headers=h, method="GET")
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
        except Exception as e:
            raise InteractiveClientError(f"二进制下载失败 ({endpoint}): {e}") from e
        return resp, dict(resp.headers)

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
