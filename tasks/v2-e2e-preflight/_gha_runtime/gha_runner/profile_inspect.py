"""Host 侧辅助：校验 Runner 回传的 Profile 归档确实来自 Vault 里那份内容。"""

from __future__ import annotations

import hashlib
import os
import tarfile
import tempfile
from typing import Any, Dict

PREF_KEY = "gha_e2e_phase1_marker"
PREF_VALUE = "phase1-pref-ok"
COOKIE_NAME = "gha_e2e_public"


def inspect_profile(archive_path: str) -> Dict[str, Any]:
    """返回归档统计与关键标记（只输出布尔/摘要，不含 Cookie 值）。"""
    out: Dict[str, Any] = {"preferences_marker": False, "preferences_files": 0,
                           "cookie_files": 0, "members": 0, "preferences_sha256": ""}
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            out["members"] += 1
            if not member.isfile():
                continue
            base = member.name.rsplit("/", 1)[-1]
            if base == "Preferences" or base == "Secure Preferences":
                raw = tar.extractfile(member).read()  # type: ignore[union-attr]
                out["preferences_files"] += 1
                out["preferences_sha256"] = hashlib.sha256(raw).hexdigest()
                text = raw.decode("utf-8", "replace")
                if PREF_KEY in text and PREF_VALUE in text:
                    out["preferences_marker"] = True
            elif base == "Cookies":
                out["cookie_files"] += 1
    return out


def inspect_vault_profile(vault: Any, name: str, project: str = "default") -> Dict[str, Any]:
    """从 Vault 解密出 Profile 归档再检查；返回统计 + Vault 元数据摘要。"""
    tmpdir = tempfile.mkdtemp(prefix="gha-inspect-")
    target = os.path.join(tmpdir, "profile.tar.gz")
    try:
        meta = vault.extract_profile_archive(project, name, target)
        if meta is None:
            raise RuntimeError("Vault 中没有 Profile 归档 %s" % name)
        info = inspect_profile(target)
        with open(target, "rb") as f:
            info["archive_sha256"] = hashlib.sha256(f.read()).hexdigest()
        info["vault_version"] = meta.version
        info["vault_size"] = meta.size
        info["vault_sha256"] = meta.sha256
        info["runner_key_id"] = (meta.extra or {}).get("runner_key_id")
        info["runner_encrypted"] = (meta.extra or {}).get("runner_encrypted")
        info["compatibility_keys"] = sorted((meta.compatibility or {}).keys())
        return info
    finally:
        for path in (target,):
            if os.path.exists(path):
                os.unlink(path)
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def summarize_auth_state(vault: Any, name: str, project: str = "default") -> Dict[str, Any]:
    """Vault 中 auth_state 的键名摘要（不含 Cookie 值）。"""
    state, meta = vault.get_auth_state(project, name)
    if state is None:
        raise RuntimeError("Vault 中没有 auth_state %s" % name)
    return {
        "cookies": sorted(str(c.get("name")) for c in state.get("cookies") or []),
        "origins": sorted(str(o.get("origin")) for o in state.get("origins") or []),
        "sample_cookie_present": any(c.get("name") == COOKIE_NAME for c in state.get("cookies") or []),
        "vault_version": meta.version if meta else None,
    }
