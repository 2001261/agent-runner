"""State 状态持久化与双向文件同步客户端。

遵循《2.0 迭代.md》第十章、第十五章与第二十一章 21.2。
支持：
- gha state list <task-id>
- gha state checkpoint <task-id>
- gha state export <task-id>
- gha state import <task-id>
- gha state restore <task-id>
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from .interactive_client import InteractiveClient, InteractiveClientError
from .state_envelope import (
    EnvelopeError,
    HostKeyPair,
    decrypt_envelope,
    decrypt_envelope_to_file,
    is_sensitive_category,
)
from .vault import HAS_CRYPTOGRAPHY, Vault, VaultError
from .restore_verify import (
    build_compatibility,
    canonical_archive,
    canonical_storage_state,
    storage_state_items,
)

CHUNK_SIZE = 4 * 1024 * 1024


class StateDecryptError(ValueError):
    """Runner 回传对象无法解封/校验（继承 ValueError，便于既有调用方统一捕获）。"""


class StateClient:
    """状态回传与恢复客户端"""

    # 大对象上传/持久化校验远超普通 API 超时
    UPLOAD_TIMEOUT = 300.0
    DOWNLOAD_ATTEMPTS = 3
    UPLOAD_ATTEMPTS = 3
    # 单次下载的 Range 请求硬上限（有进展的续传远低于此）
    MAX_RANGE_REQUESTS = 100000
    # 流式读写块大小：下载时边收边落盘，不把分块整体读进内存
    _COPY_BLOCK = 256 * 1024
    # 超过该大小的对象下载后从磁盘解封/归档，而不是整包进内存
    SPILL_THRESHOLD = 16 * 1024 * 1024

    def __init__(self, client: InteractiveClient, vault: Optional[Vault] = None,
                 chunk_size: int = CHUNK_SIZE, host_keys: Optional[HostKeyPair] = None,
                 generation: Optional[str] = None, session_id: Optional[str] = None):
        self.client = client
        self.vault = vault or Vault()
        self.chunk_size = chunk_size
        self._host_keys = host_keys
        # Runner 会话代际：None 表示首次探测时采纳 Runner 当前值；续传时不一致即拒绝
        self._generation = generation
        self._session_id = session_id
        # 可选的降级通道：状态/进度端点不存在时，用它重新发现 Runner 版本
        self.asks_runner: Optional[Any] = None
        # 本次导出中未经封套加密的敏感对象（仅用于调用方审计，不影响 ACK）
        self.plaintext_objects: List[str] = []
        # 最近一次上传实际按序发出的 (X-Offset, 字节数)，供断点续传取证
        self.last_upload_offsets: List[Tuple[int, int]] = []
        # 本轮 status 见过的最大 received：服务端偶发欠载时不能把它当成真实进度
        self._known_received = 0

    def list_manifest(self) -> Dict[str, Any]:
        """获取 Runner 当前所有可回传对象清单"""
        return self.client.get("/v1/state/manifest")

    def create_checkpoint(self, checkpoint_type: str = "AUTH", checkpoint_id: Optional[str] = None) -> Dict[str, Any]:
        """触发生成指定类型的检查点"""
        body = {"type": checkpoint_type}
        if checkpoint_id:
            body["checkpoint_id"] = checkpoint_id
        return self.client.post("/v1/state/checkpoint", body)

    def _require_crypto(self) -> None:
        """缺 cryptography 时 encrypt_data 必然失败；在下载/覆盖任何状态前就拒绝。"""
        if not HAS_CRYPTOGRAPHY:
            raise VaultError("缺少 cryptography，无法使用 AES-256-GCM 加密落盘；请安装后重试")

    def _part_path(self, obj_id: str) -> Any:
        return self.vault.transfers_dir / "partial" / f"{self.vault._path_component(obj_id)}.part"

    @staticmethod
    def _content_range(headers: Dict[str, str]) -> Optional[Any]:
        """解析 Content-Range: bytes start-end/total；通配符或不可解析返回 None。"""
        for key, value in headers.items():
            if key.lower() == "content-range":
                try:
                    unit, _, span = value.strip().partition(" ")
                    if unit.lower() != "bytes":
                        return None
                    s, e = span.split("/")[0].split("-", 1)
                    return int(s), int(e)
                except ValueError:
                    return None
        return None

    def host_keys(self) -> HostKeyPair:
        """懒加载 Host X25519 私钥（首次调用时在 Vault keys 目录生成，0600）。"""
        if self._host_keys is None:
            self._host_keys = self.vault.state_keypair()
        return self._host_keys

    def _unwrap_object(self, obj: Dict[str, Any], payload: bytes) -> bytes:
        """对象声明 encrypted=True 时用 Host 私钥解封；返回明文并校验内容一致性。"""
        obj_id = obj["id"]
        if not obj.get("encrypted"):
            if is_sensitive_category(obj.get("category", "")):
                self.plaintext_objects.append(obj_id)
            return payload

        envelope = obj.get("envelope")
        if envelope and envelope != "gha-state-envelope":
            raise StateDecryptError(f"对象 {obj_id} 使用不支持的封套格式: {envelope}")
        key_id = obj.get("key_id") or self.vault.state_key_id()
        pair = self.host_keys()
        if key_id != pair.key_id:
            raise StateDecryptError(
                f"对象 {obj_id} 用 key_id={key_id} 加密，本地私钥为 {pair.key_id}；"
                "请确认 GHA_STATE_PUBLIC_KEY 与 Vault 中的 Host 密钥是同一对"
            )
        try:
            plaintext = decrypt_envelope(pair, payload, key_id=key_id)
        except EnvelopeError as exc:
            raise StateDecryptError(f"对象 {obj_id} 解封失败：{exc}") from exc

        expected_sha = obj.get("plaintext_sha256")
        if expected_sha:
            actual = hashlib.sha256(plaintext).hexdigest()
            if actual != expected_sha:
                raise StateDecryptError(
                    f"对象 {obj_id} 解密后内容 SHA-256 不匹配：期望 {expected_sha}，实际 {actual}")
        expected_size = obj.get("plaintext_size")
        if isinstance(expected_size, int) and expected_size != len(plaintext):
            raise StateDecryptError(
                f"对象 {obj_id} 解密后长度 {len(plaintext)} 与清单声明 {expected_size} 不一致")
        return plaintext

    def _fetch_range(self, obj_id: str, offset: int, length: int) -> Any:
        """取一个分块；客户端支持流式时返回 (响应, 响应头)，否则退化为一次性读取。"""
        # 只认客户端类上定义的 get_stream：instance/self 上的残缺可调用对象不能
        # 静默退化成整包 get_raw（大对象会撑爆内存）。
        stream = getattr(type(self.client), "get_stream", None)
        if stream is not None:
            resp, headers = stream(self.client, f"/v1/state/objects/{obj_id}",
                                   range_header=f"bytes={offset}-{offset + length - 1}")
            return resp, headers
        data, headers = self.client.get_raw(f"/v1/state/objects/{obj_id}",
                                            range_header=f"bytes={offset}-{offset + length - 1}")
        return io.BytesIO(data), headers

    def _download_to_part(self, obj: Dict[str, Any], part: Any) -> None:
        """按 Range 分块、逐块流式写入 .part；断线时从服务端已确认的偏移继续。

        不把分块整体读进内存：响应体按 _COPY_BLOCK 边读边写且每块都 fsync，
        断线时磁盘上的长度就是下一次续传的起点。
        """
        obj_id = obj["id"]
        total = int(obj.get("size", 0))
        if total == 0:
            raise ValueError(f"对象 {obj_id} 大小未声明，拒绝下载")
        self._part_path(obj_id).parent.mkdir(parents=True, exist_ok=True)
        self._range_requests = 0
        offset = part.stat().st_size if part.exists() else 0
        if offset > total:
            part.unlink()
            offset = 0
        # offset == total：已下满但尚未校验，直接交给调用方做最终摘要，无需再拉取
        while offset < total:
            length = min(self.chunk_size, total - offset)
            last_error = None
            attempt = 0
            progressed = False
            while attempt < self.DOWNLOAD_ATTEMPTS:
                attempt += 1
                start = offset
                # 只要在前进就重置计数，但绝不允许无限重下：同一分块上的请求次数有硬上限
                self._range_requests += 1
                if self._range_requests > self.MAX_RANGE_REQUESTS:
                    raise ValueError(
                        f"对象 {obj_id} 分块请求超过 {self.MAX_RANGE_REQUESTS} 次（偏移 {offset}），拒绝无限重试")
                try:
                    resp, headers = self._fetch_range(obj_id, start, length)
                    try:
                        if start > 0:
                            span = self._content_range(dict(headers or {}))
                            if span is None:
                                raise ValueError("服务端未按 Range 返回分块")
                            if span[0] != start:
                                raise ValueError(
                                    f"Content-Range 起点 {span[0]} 与请求偏移 {start} 不一致")
                        offset, overflow = self._copy_body(resp, part, start, start + length)
                        if overflow:
                            raise ValueError(f"服务端返回超出请求范围 {length} 字节的分块")
                    finally:
                        close = getattr(resp, "close", None)
                        if close is not None:
                            close()
                        last_error = last_error or "interrupted"
                    short = length - (offset - start)
                    if 0 < short < self._COPY_BLOCK:
                        # 传输在最后几 KB 断线（真实隧道最常见）：Content-Length 声明的
                        # 范围内只少了不足一个读块，这是断线残尾而不是协议错误 ——
                        # 已落盘前缀保留，下一轮从真实偏移续传；反复短读由尝试计数兜住。
                        raise ValueError(f"分块在偏移 {offset} 提前结束，尚缺 {short} 字节")
                    if offset != start + length:
                        # 截断/越界都以服务端声明的范围为准，绝不写入多余字节
                        raise ValueError(f"分块长度 {offset - start} 与请求范围 {length} 不一致")
                    progressed = True
                    break
                except Exception as exc:
                    last_error = last_error if last_error is not None and not isinstance(last_error, str) else exc
                    # 保留已完整写入的前缀，在下一个未写位置重试
                    written = part.stat().st_size if part.exists() else 0
                    if written > offset:
                        # 有进展就重新计数：千兆级对象经隧道每块都可能断一次，
                        # 固定总次数会让「一直在前进」的续传在第 3 块后放弃
                        attempt = 0
                    offset = written
                    if offset >= total:
                        break
            if not progressed and offset < total:
                raise ValueError(f"对象 {obj_id} 在偏移 {offset} 下载失败，已保留断点：{last_error}")

    def _copy_body(self, resp: Any, part: Any, start: int, end: int) -> Tuple[int, bool]:
        """把 resp 的正文从 start 起覆盖写入 part（最多到 end）。

        返回 (写到的偏移, 是否还有多余字节)。每次写完都截断到 pos，失败重试时
        不会把缩水的分块拼在旧尾巴后面。
        """
        # 每读到一块就写盘并 fsync：断线时已收到的字节不会退回服务端最后确认的位置，
        # 下一轮续传从真实落盘偏移接上（真实隧道断在中途时这是常态）。
        with open(part, "r+b" if part.exists() else "w+b") as f:
            f.seek(start)
            pos = start
            try:
                while pos < end:
                    block = resp.read(min(self._COPY_BLOCK, end - pos))
                    if not block:
                        break
                    f.write(block)
                    pos += len(block)
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                f.truncate(pos)
                f.flush()
                os.fsync(f.fileno())
        return pos, bool(resp.read(min(self._COPY_BLOCK, 64 * 1024)))

    def _verified_part(self, obj: Dict[str, Any]) -> Any:
        """下载并校验；通过返回 .part 路径，校验失败丢弃 .part 并抛 ValueError。"""
        obj_id = obj["id"]
        if int(obj.get("size", 0)) == 0:
            raise ValueError(f"对象 {obj_id} 大小未声明，拒绝下载")
        part = self._part_path(obj_id)
        self._download_to_part(obj, part)
        expected = obj.get("sha256", "")
        actual = self._sha256_file(part) if part.exists() else hashlib.sha256(b"").hexdigest()
        if actual != expected:
            part.unlink()
            raise ValueError(f"对象 {obj_id} SHA-256 校验失败：期望 {expected}，实际 {actual}（已丢弃断点）")
        return part

    def _download_object(self, obj: Dict[str, Any]) -> bytes:
        """下载并校验对象，全程流式；校验通过才读回（解封前的）密文字节。"""
        part = self._verified_part(obj)
        return part.read_bytes()

    def _download_to_file(self, obj: Dict[str, Any]) -> Any:
        """把校验通过的大对象移到独立临时文件并返回其路径，避免整包进内存。

        调用方负责删除返回的文件；校验失败时 .part 被丢弃，坏数据不会交给解包/解密。
        """
        part = self._verified_part(obj)
        fd, tmp_name = tempfile.mkstemp(prefix=f"{self.vault._path_component(obj['id'])}-", suffix=".bin")
        os.close(fd)
        os.replace(part, tmp_name)
        return tmp_name

    @staticmethod
    def _sha256_file(path: Any) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    @staticmethod
    def _runner_meta(obj: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """记录 Runner 侧加密来源，便于日后审计（不含任何密钥材料）。"""
        return {
            "runner_encrypted": bool(obj.get("encrypted")),
            "runner_key_id": obj.get("key_id"),
            "runner_key_fingerprint": obj.get("key_fingerprint"),
            "envelope_version": obj.get("envelope_version"),
            "plaintext_sha256": hashlib.sha256(data).hexdigest(),
        }

    @staticmethod
    def _parse_json_object(obj: Dict[str, Any], data: bytes) -> Dict[str, Any]:
        """解密后的 JSON 类别必须能解析成对象；损坏或格式不符直接拒绝落盘。"""
        obj_id = obj["id"]
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateDecryptError(f"对象 {obj_id} 解密后不是合法 UTF-8 JSON：{type(exc).__name__}") from exc
        if not isinstance(parsed, dict):
            raise StateDecryptError(f"对象 {obj_id} 解密后 JSON 顶层不是对象")
        return parsed

    def _store_downloaded_object(self, project: str, obj: Dict[str, Any], data: bytes,
                                 compatibility: Optional[Dict[str, Any]] = None) -> None:
        obj_id = obj["id"]
        category = obj["category"]
        extra = self._runner_meta(obj, data)
        if category == "auth_state":
            state_dict = self._parse_json_object(obj, data)
            self.vault.store_auth_state(project=project, name=obj_id, state_dict=state_dict,
                                        compatibility=compatibility, extra=extra)
        elif category == "browser_profile":
            incoming = self.vault.transfers_dir / "incoming"
            incoming.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                prefix=f"{self.vault._path_component(obj_id)}-", suffix=".tar.gz", dir=str(incoming))
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                self.vault.store_profile_archive(
                    project=project, name=obj_id, archive_path=tmp_name,
                    compatibility=compatibility, extra=extra,
                )
            finally:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        elif category == "compatibility_meta":
            # 仅用于 X-Compatibility，不单独落盘
            self._parse_json_object(obj, data)
            return
        else:
            self.vault.store_binary_object(project=project, name=obj_id, data=data,
                                           category=category, compatibility=compatibility,
                                           extra=extra)

    def _store_spilled_object(self, project: str, obj: Dict[str, Any], path: str,
                              plaintext_sha256: str,
                              compatibility: Optional[Dict[str, Any]] = None) -> None:
        """大对象降盘路径：密文已在磁盘上，按需解封到临时文件后从文件归档，避免整包进内存。"""
        obj_id = obj["id"]
        category = obj["category"]
        extra = {
            "runner_encrypted": bool(obj.get("encrypted")),
            "runner_key_id": obj.get("key_id"),
            "runner_key_fingerprint": obj.get("key_fingerprint"),
            "envelope_version": obj.get("envelope_version"),
            "plaintext_sha256": plaintext_sha256,
        }
        if category == "compatibility_meta":
            return
        if category == "browser_profile":
            if not obj.get("encrypted"):
                if is_sensitive_category(category):
                    self.plaintext_objects.append(obj_id)
                self.vault.store_profile_archive(project=project, name=obj_id, archive_path=path,
                                                 compatibility=compatibility, extra=extra)
                return
            plain = self._decrypt_to_file(obj, path)
            try:
                self._check_plaintext_file(obj, plain)
                self.vault.store_profile_archive(project=project, name=obj_id, archive_path=plain,
                                                 compatibility=compatibility, extra=extra)
            finally:
                if os.path.exists(plain):
                    os.unlink(plain)
            return
        data = self._unwrap_object(obj, path.read_bytes())
        self._store_downloaded_object(project, obj, data, compatibility=compatibility)

    def _decrypt_to_file(self, obj: Dict[str, Any], sealed_path: str) -> str:
        """解封大对象密文到临时文件；明文摘要与长度由调用方在落盘前再校验。"""
        obj_id = obj["id"]
        key_id = obj.get("key_id") or self.vault.state_key_id()
        pair = self.host_keys()
        if key_id != pair.key_id:
            raise StateDecryptError(
                f"对象 {obj_id} 用 key_id={key_id} 加密，本地私钥为 {pair.key_id}；"
                "请确认 GHA_STATE_PUBLIC_KEY 与 Vault 中的 Host 密钥是同一对"
            )
        fd, out_name = tempfile.mkstemp(prefix=f"{self.vault._path_component(obj_id)}-", suffix=".plain")
        os.close(fd)
        try:
            decrypt_envelope_to_file(pair, sealed_path, out_name, key_id=key_id)
        except EnvelopeError as exc:
            raise StateDecryptError(f"对象 {obj_id} 解封失败：{exc}") from exc
        except Exception:
            if os.path.exists(out_name):
                os.unlink(out_name)
            raise
        return out_name

    def _check_plaintext_file(self, obj: Dict[str, Any], path: str) -> str:
        """流式核对解封后文件的长度与 SHA-256，返回摘要。"""
        obj_id = obj["id"]
        actual = self._sha256_file(path)
        expected_sha = obj.get("plaintext_sha256")
        if expected_sha and actual != expected_sha:
            raise StateDecryptError(
                f"对象 {obj_id} 解密后内容 SHA-256 不匹配：期望 {expected_sha}，实际 {actual}")
        expected_size = obj.get("plaintext_size")
        actual_size = os.path.getsize(path)
        if isinstance(expected_size, int) and expected_size != actual_size:
            raise StateDecryptError(
                f"对象 {obj_id} 解密后长度 {actual_size} 与清单声明 {expected_size} 不一致")
        return actual

    def _ack(self, obj_id: str, status: str) -> None:
        """ACK 是断点文件清理的唯一依据：服务端明确接收才删除。"""
        res = self.client.post("/v1/state/ack", {"object_id": obj_id, "status": status})
        if not isinstance(res, dict) or res.get("status") != "acknowledged":
            raise ValueError(f"Runner 未确认对象 {obj_id} 的 ACK：{res}")

    def export_state_to_vault(self, project: str = "default",
                              objects: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """分块下载、SHA-256 校验、解封验真、Vault 加密原子落盘，最后才回复 PERSISTED ACK。

        传输 SHA-256 针对密文字节；解封后再按清单声明的 plaintext_sha256 与内容格式校验，
        两者都通过才写 Vault 并 ACK。任何一步失败都不 ACK、不留明文。
        objects 给出时只回传这批对象（仍走同一套校验/落盘/ACK 流程）。
        """
        self._require_crypto()
        self.plaintext_objects = []
        if objects is None:
            manifest = self.list_manifest()
            objects = manifest.get("objects", [])
        else:
            manifest = {"objects": objects, "encryption_available": True}
        compatibility = None
        for obj in objects:
            if obj.get("category") == "compatibility_meta":
                raw = self._download_object(obj)
                compatibility = self._parse_json_object(obj, self._unwrap_object(obj, raw))
        synced = []
        for obj in objects:
            if int(obj.get("size", 0)) > self.SPILL_THRESHOLD:
                # 大对象：校验通过后从磁盘直接归档，不整包进入内存
                spilled = self._download_to_file(obj)
                try:
                    # 传输摘要已由 _download_to_file 校验；明文摘要在解封后按文件再核对
                    self._store_spilled_object(project, obj, spilled,
                                               obj.get("plaintext_sha256") or "",
                                               compatibility=compatibility)
                finally:
                    if os.path.exists(spilled):
                        os.unlink(spilled)
            else:
                raw = self._download_object(obj)
                data = self._unwrap_object(obj, raw)
                self._store_downloaded_object(project, obj, data, compatibility=compatibility)
            self._ack(obj["id"], "PERSISTED")
            part = self._part_path(obj["id"])
            if part.exists():
                part.unlink()
            synced.append(obj["id"])
        result: Dict[str, Any] = {
            "status": "completed",
            "total_objects": len(objects),
            "synced_objects": synced,
            "encryption_available": manifest.get("encryption_available"),
            "plaintext_objects": list(self.plaintext_objects),
        }
        if self.plaintext_objects:
            result["warning"] = "SOME_SENSITIVE_OBJECTS_WERE_PLAINTEXT"
        return result

    @staticmethod
    def _is_http_status(exc: BaseException, status: int) -> bool:
        return isinstance(exc, InteractiveClientError) and f"HTTP {status}" in str(exc)

    def _upload_progress(self, headers: Dict[str, str], total: int) -> Tuple[int, Optional[str]]:
        """查询 Runner 真实已接收字节；返回 (received, 说明)。

        说明为 "ASK_RUNNER" 表示 Runner 没有该接口（旧版 Gateway 404/405），
        由调用方决定兼容回退；任何情况下都不会把本地猜测当作服务端进度。
        进度不是越小越可信：平局时保留本轮已知的更大值，避免欠载被当成事实。
        """
        if self._known_received > total:
            # 换对象（例如 import-auth 之后再来 import-profile）时重置
            self._known_received = 0
        try:
            try:
                res = self.client.get("/v1/state/import/status", headers=dict(headers))
            except TypeError:
                # 只支持 params 的旧客户端：放 query 里（旧 Gateway 一样 404，走兼容回退）
                res = self.client.get("/v1/state/import/status", params=headers)
        except Exception as exc:
            if self._is_http_status(exc, 404) or self._is_http_status(exc, 405):
                return 0, "ASK_RUNNER"
            raise
        if not isinstance(res, dict):
            raise ValueError(f"上传进度响应格式非法：{res!r}")
        remote_generation = res.get("generation")
        local_generation = self._generation
        if local_generation is None:
            # 首次探测即采纳 Runner 会话代际，后续分块/续传都带同一值
            self._generation = remote_generation or local_generation
        elif remote_generation and str(remote_generation) != str(local_generation):
            raise ValueError(
                f"Runner 会话代际已从 {local_generation} 变为 {remote_generation}："
                "上次上传的进度已不属于当前 Runner，请先读取 Runner 状态确认，再从头上传")
        if res.get("session_id") and self._session_id is not None \
                and res.get("session_id") != self._session_id:
            raise ValueError(
                f"Runner 会话已更换（{self._session_id} -> {res.get('session_id')}）："
                "旧断点进度不可复用，请先读取 Runner 状态确认，再从头上传")
        try:
            received = int(res.get("received", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError(f"上传进度 received 非整数：{res!r}")
        if res.get("status") == "reset" and res.get("reason"):
            return 0, f"Runner 已作废旧断点（{res.get('reason')}），从头上传"
        if received < 0 or received > total:
            raise ValueError(f"Runner 报告已接收 {received} 字节，超出对象总长 {total}：{res}")
        received = max(received, self._known_received)
        self._known_received = received
        return received, None

    def _legacy_status_note(self, obj_id: str) -> str:
        """Runner 没有进度查询接口时的兼容回退说明；永远不带本地猜测的偏移。"""
        rerun = self.asks_runner() if self.asks_runner else None
        if rerun and rerun._generation is not None:
            self._generation = rerun._generation
            self._session_id = rerun._session_id
        return (f"对象 {obj_id}：Runner 不支持 /v1/state/import/status（旧版 Gateway），"
                "本次从偏移 0 上传；若 Runner 上有未完成的导入快照会被覆盖，无法断点续传")

    def _push_object(self, obj_id: str, category: str, data: Any,
                     compatibility: Optional[Dict[str, Any]] = None,
                     sha256: Optional[str] = None) -> Dict[str, Any]:
        """按 X-Offset 分块上传（data 可以是 bytes 或可 seek 的二进制文件）。

        起始偏移取自 Runner 的 /v1/state/import/status 真实 received；断线后用同一接口
        重新对齐，已接收的前段不会重发。仅返回 verified=True 才算恢复成功。
        """
        total = len(data) if isinstance(data, (bytes, bytearray)) else os.fstat(data.fileno()).st_size
        sha256 = sha256 or (hashlib.sha256(data).hexdigest() if isinstance(data, (bytes, bytearray))
                            else self._sha256_file_path(data))
        meta = {
            "X-Object-ID": obj_id,
            "X-Total-Size": str(total),
            "X-SHA256": sha256,
            "X-Category": category,
        }
        if self._generation:
            meta["X-GHA-Generation"] = str(self._generation)
        base = dict(meta, **{"Content-Type": "application/octet-stream"})
        if compatibility:
            base["X-Compatibility"] = json.dumps(compatibility, ensure_ascii=False)

        if total == 0:
            raise ValueError(f"对象 {obj_id} 为空，拒绝上传")

        if isinstance(data, (bytes, bytearray)):
            data = io.BytesIO(bytes(data))
        if hasattr(data, "seek"):
            data.seek(0)

        notes: List[str] = []
        # 每块实际发出的 (起始偏移, 字节数)；用于证明断线后没有重发已确认前段
        self.last_upload_offsets = []
        offset, note = self._upload_progress(meta, total)
        if note == "ASK_RUNNER":
            offset, note = 0, self._legacy_status_note(obj_id)
        if note:
            notes.append(note)
        uploaded_from = offset
        while offset < total:
            length = min(self.chunk_size, total - offset)
            if hasattr(data, "seek"):
                data.seek(offset)
                chunk = data.read(length)
            else:
                chunk = data[offset:offset + length]
            sent_from = offset
            resend_allowed = False
            while True:
                self.last_upload_offsets.append((sent_from, len(chunk)))
                try:
                    res = self._post_raw("/v1/state/import", chunk,
                                         dict(base, **{"X-Offset": str(sent_from)}))
                    res = res if isinstance(res, dict) else {"status": "invalid_response", "raw": str(res)}
                except Exception as exc:
                    # 断线：分块可能已落盘，也可能整体丢失。以 Runner 真实进度为准：
                    # 等于本次末尾说明已收到；仍等于本次起点说明整块丢失，最多重发一次；
                    # 落在区间中间是协议异常，只补齐尾部，绝不重发已确认的前段。
                    received, note = self._upload_progress(meta, total)
                    if note == "ASK_RUNNER":
                        raise ValueError(
                            f"对象 {obj_id} 在偏移 {sent_from} 上传中断且无法确认 Runner 进度：{exc}") from exc
                    if received == sent_from + len(chunk):
                        # 分块已完整落盘（也可能是 Runner 已收满并完成导入）
                        offset = received
                        break
                    if received < sent_from:
                        raise ValueError(
                            f"对象 {obj_id} 上传中断：Runner 进度 {received} 落后于本地偏移 "
                            f"{sent_from}，拒绝重复上传已确认前段：{exc}") from exc
                    if received == sent_from:
                        if resend_allowed:
                            raise ValueError(
                                f"对象 {obj_id} 在偏移 {sent_from} 重发后仍失败：{exc}") from exc
                        resend_allowed = True
                        continue
                    chunk = chunk[received - sent_from:]
                    sent_from = received
                    continue
                if res.get("verified") is True:
                    if res.get("status") != "completed":
                        raise ValueError(f"对象 {obj_id} 导入结果自相矛盾：{res}")
                    return dict(res, uploaded_from=uploaded_from, notes=notes)
                if res.get("status") != "chunk_received":
                    raise ValueError(f"对象 {obj_id} 在偏移 {sent_from} 上传中断：{res}")
                try:
                    received = int(res.get("received", sent_from + len(chunk)))
                except (TypeError, ValueError):
                    raise ValueError(f"对象 {obj_id} 在偏移 {sent_from} 的响应非法：{res}")
                if received == sent_from + len(chunk):
                    offset = received
                    break
                if received <= sent_from or received > sent_from + len(chunk):
                    # 进度对不上：只允许按服务端声明的偏移补齐，绝不跳段或重复
                    raise ValueError(
                        f"对象 {obj_id} 在偏移 {sent_from} 的服务端进度 {received} 不一致：{res}")
                chunk = chunk[received - sent_from:]
                sent_from = received
        # 最后一块的响应丢失、但 Runner 已收满并完成导入：本次无法重放完成响应，
        # 也不能重发前段，只能如实返回未确认，由调用方决定是否重新推送复核。
        notes.append(f"对象 {obj_id} 的最后一块响应丢失，Runner 已收满 {total} 字节但未回传 verified")
        return self._retry_for_verified(meta, total, uploaded_from, notes)

    def _post_raw(self, endpoint: str, data: bytes, headers: Dict[str, str]) -> Any:
        """上传分块：完成后响应丢失后的补验也走这里，测试与调用方只需覆写一处。"""
        return self.client.post_raw(endpoint, data, headers, timeout=self.UPLOAD_TIMEOUT)

    def _retry_for_verified(self, meta: Dict[str, str], total: int,
                            uploaded_from: int, notes: List[str]) -> Dict[str, Any]:
        """收满但完成响应丢失：重推一次空尾块，让 Runner 回传 verified，绝不重发前段。"""
        try:
            res = self._post_raw("/v1/state/import", b"",
                                 dict(meta, **{"X-Offset": str(total),
                                               "Content-Type": "application/octet-stream"}))
        except Exception as exc:
            res = {"status": "chunk_error", "error": str(exc)}
        if isinstance(res, dict) and res.get("verified") is True and res.get("status") == "completed":
            return dict(res, uploaded_from=uploaded_from, notes=notes)
        raise ValueError(f"对象 {meta['X-Object-ID']} 上传结束但 Runner 未确认恢复（共 {total} 字节）：{res}")

    def _sha256_file_path(self, f: Any) -> str:
        pos = f.tell()
        try:
            f.seek(0)
            h = hashlib.sha256()
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
            return h.hexdigest()
        finally:
            f.seek(pos)

    def export_selected(self, objects: List[Dict[str, Any]], project: str = "default") -> Dict[str, Any]:
        """只回传给定的对象（走同一套下载 / 摘要校验 / 解封 / Vault / ACK 流程）。"""
        return self.export_state_to_vault(project=project, objects=objects)

    def import_state_from_vault(self, project: str, object_name: str, category: str = "auth_state") -> Dict[str, Any]:
        """从本地 Vault 读取状态并推送至 Runner（Profile 归档直接从磁盘流式上传）。

        推送前把内容规范化并带上 restore_sha256（Profile 另带归档内元数据文件摘要），
        Runner 侧用 gha_runner.restore_verify 的同一规则复核后才恢复，
        摘要不一致时返回 verified=false 而不是把未校验内容当作已验证。
        """
        extra: Dict[str, Any] = {}
        if category == "auth_state":
            state_dict, meta = self.vault.get_auth_state(project, object_name)
            if not state_dict or not meta:
                raise ValueError(f"Vault 中不存在认证状态: {project}/{object_name}")
            data: Any = json.dumps(state_dict).encode("utf-8")
            obj_id = f"import-auth-{object_name}"
            extra = {
                "restore_sha256": hashlib.sha256(canonical_storage_state(state_dict)).hexdigest(),
                "storage_state_items": storage_state_items(state_dict),
            }
        elif category == "browser_profile":
            raw_archive = self.vault.transfers_dir / "outgoing" / f"{self.vault._path_component(object_name)}.raw.tar.gz"
            archive = self.vault.transfers_dir / "outgoing" / f"{self.vault._path_component(object_name)}.tar.gz"
            meta = self.vault.extract_profile_archive(project, object_name, str(raw_archive))
            if not meta:
                raise ValueError(f"Vault 中不存在 Profile: {project}/{object_name}")
            canonical_path, digest, metadata = canonical_archive(str(raw_archive))
            if raw_archive == archive:
                os.unlink(canonical_path)
            else:
                try:
                    os.replace(canonical_path, archive)
                finally:
                    if os.path.exists(canonical_path):
                        os.unlink(canonical_path)
                    if raw_archive.exists():
                        raw_archive.unlink()
            obj_id = f"import-profile-{object_name}"
            extra = {"restore_sha256": digest, "archive_metadata_sha256": metadata}
        else:
            raise NotImplementedError(f"暂不支持直接推送分类: {category}")

        compatibility = build_compatibility(meta.compatibility if meta else None, extra)
        handle = None
        try:
            if category == "browser_profile":
                handle = open(archive, "rb")
                data = handle
            return self._push_object(obj_id, category, data, compatibility=compatibility)
        finally:
            if handle is not None:
                handle.close()
            if category == "browser_profile":
                try:
                    archive.unlink()
                except OSError:
                    pass

        handle = None
        try:
            if category == "browser_profile":
                handle = open(archive, "rb")
                data = handle
            return self._push_object(obj_id, category, data,
                                     compatibility=meta.compatibility if meta else None)
        finally:
            if handle is not None:
                handle.close()
            if category == "browser_profile":
                try:
                    archive.unlink()
                except OSError:
                    pass
