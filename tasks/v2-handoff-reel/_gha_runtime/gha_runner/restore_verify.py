"""Host → Runner 状态推送的完整性校验。

Host 推送 Profile 归档 / auth_state 时，在 X-Compatibility 里带上按固定规则重新
归一化后的 SHA-256（`restore_sha256`）。Runner 解包/应用前用同一规则复核：
- Profile：只收普通文件、按路径排序、mtime 归零重打包后比对整包摘要，再比对归档内
  Preferences / Local State / Last Version 三个元数据文件的摘要；
- auth_state：Cookie 排序、origins/localStorage 按名排序后序列化为紧凑 JSON 比对摘要，
  并比较 Cookie/Storage（含 IndexedDB）集合。

这样“传输 SHA-256 通过”之外，Runner 还能证明收到的内容与 Host Vault 中那份一致；
不一致时拒绝恢复并回报 verified=false。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Tuple

DIGEST_FIELD = "restore_sha256"
DIGEST_SCHEME = "gha-restore/v1"
# 归档内参与比对的元数据键（只比摘要，不暴露值）
ARCHIVE_DIGEST_SOURCE = ("Preferences", "Local State", "Last Version")


def canonical_archive(archive_path: str) -> Tuple[str, str, Dict[str, str]]:
    """规范化 Profile 归档：只收普通文件，按路径排序重打包。

    返回 (临时归档路径, sha256, 归档内元数据文件摘要表)；调用方负责删除临时文件。
    """
    entries: List[Tuple[str, bytes]] = []
    metadata_digests: Dict[str, str] = {}
    with tarfile.open(archive_path, "r:*") as tar:
        for member in sorted(tar.getmembers(), key=lambda m: m.name):
            if not member.isfile():
                continue
            name = member.name.replace("\\", "/")
            while name.startswith("./"):
                name = name[2:]
            if not name or name.startswith("/") or ".." in name.split("/"):
                raise ValueError("归档成员路径非法: %r" % name)
            data = tar.extractfile(member).read()  # type: ignore[union-attr]
            entries.append((name, data))
            base = name.rsplit("/", 1)[-1]
            if base in ARCHIVE_DIGEST_SOURCE:
                metadata_digests[name] = hashlib.sha256(data).hexdigest()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    raw = out.getvalue()
    fd, path = tempfile.mkstemp(suffix=".canonical.tar")
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return path, hashlib.sha256(raw).hexdigest(), metadata_digests


def canonical_storage_state(state_dict: Dict[str, Any]) -> bytes:
    """规范化 storage_state（排序、紧凑 JSON），返回稳定字节序列。"""
    cookies = sorted(
        (dict(c) for c in state_dict.get("cookies") or []),
        key=lambda c: (str(c.get("domain")), str(c.get("path")), str(c.get("name"))),
    )
    origins = []
    for origin in sorted(state_dict.get("origins") or [], key=lambda o: str(o.get("origin"))):
        item = dict(origin)
        item["localStorage"] = sorted(item.get("localStorage") or [], key=lambda kv: str(kv.get("name")))
        if item.get("indexedDB") is not None:
            item["indexedDB"] = sorted(item["indexedDB"], key=lambda kv: str(kv.get("name")))
        origins.append(item)
    return json.dumps({"cookies": cookies, "origins": origins}, ensure_ascii=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def storage_state_items(state_dict: Dict[str, Any]) -> Dict[str, Any]:
    """提取用于集合比对的键名（不含值）。"""
    return {
        "cookies": sorted(str(c.get("name")) for c in state_dict.get("cookies") or []),
        "origins": sorted(str(o.get("origin")) for o in state_dict.get("origins") or []),
        "local_storage_keys": sorted(
            "%s|%s" % (o.get("origin"), kv.get("name"))
            for o in state_dict.get("origins") or [] for kv in o.get("localStorage") or []
        ),
        "indexed_db": sorted(
            "%s|%s" % (o.get("origin"), kv.get("name"))
            for o in state_dict.get("origins") or [] for kv in o.get("indexedDB") or []
        ),
    }


def check_archive(archive_path: str, expected: Dict[str, Any]) -> Tuple[bool, str]:
    """Runner 侧校验 Profile 归档是否与 Host Vault 内容一致。"""
    want = expected.get(DIGEST_FIELD)
    if not want:
        return False, "Host 未提供 restore_sha256，拒绝把未校验的归档当作已验证"
    path, digest, metadata = canonical_archive(archive_path)
    try:
        if digest != want:
            return False, "Profile 归档内容摘要与 Host Vault 不一致"
        if isinstance(expected.get("archive_metadata_sha256"), dict):
            for name, value in expected["archive_metadata_sha256"].items():
                if metadata.get(name) != value:
                    return False, "Profile 归档内元数据文件摘要不一致: %s" % name
        return True, "ok"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def check_storage_state(state_dict: Dict[str, Any], expected: Dict[str, Any]) -> Tuple[bool, str]:
    """Runner 侧校验即将应用的 auth_state 是否与 Host 推送的一致。"""
    want = expected.get(DIGEST_FIELD)
    if not want:
        return False, "Host 未提供 restore_sha256，拒绝把未校验的 auth_state 当作已验证"
    actual = hashlib.sha256(canonical_storage_state(state_dict)).hexdigest()
    if actual != want:
        return False, "auth_state 内容摘要与 Host 推送不一致"
    expected_items = expected.get("storage_state_items")
    if isinstance(expected_items, dict):
        actual_items = storage_state_items(state_dict)
        for key, value in expected_items.items():
            if actual_items.get(key) != value:
                return False, "auth_state 的 %s 与 Host 推送不一致" % key
    return True, "ok"


def build_compatibility(compat: Optional[Dict[str, Any]], extra: Dict[str, Any]) -> Dict[str, Any]:
    """合并原 compatibility 与校验字段，供 X-Compatibility 头部传输。"""
    out = dict(compat or {})
    out.update({k: v for k, v in extra.items() if v is not None})
    out["restore_schema"] = DIGEST_SCHEME
    return out
