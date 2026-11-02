"""运行时状态导出与 Checkpoint 制造器。

遵循《2.0 迭代.md》第十章、第十一章、第十二章与第十六章。
支持生成五种 Checkpoint：
- AUTH_CHECKPOINT：浏览器认证状态（Cookie/LocalStorage/IndexedDB）；
- BROWSER_CHECKPOINT：当前打开标签页、URL及DOM；
- DESKTOP_CHECKPOINT：桌面窗口与截屏；
- TASK_CHECKPOINT：业务中间产物；
- FINAL_CHECKPOINT：优雅关闭浏览器后完整 Profile 归档。
"""

from __future__ import annotations

import json
import os
import platform
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple

from gha_runner.state_envelope import (
    EnvelopeError,
    EnvelopeSealer,
    RecipientConfig,
    is_sensitive_category,
    load_recipient_config,
)

from .browser import BrowserManager
from .desktop import DesktopManager
from .transfer import ChunkedTransferEngine

# 敏感对象加密后落盘的临时密文后缀；标记为私密文件，任务结束后由 cleanup 清理整个目录
SEALED_SUFFIX = ".ghse"

# 显式声明 false 时才允许在非生产环境回传明文敏感对象；其余任何取值都按 fail-closed 处理
_PLAINTEXT_OPT_IN_VALUES = {"1", "true", "yes", "on"}


class SecretExportError(Exception):
    """敏感状态无法以加密形式回传（无公钥 / 加密失败 / 配置错误）"""


def is_production_environment(env: Optional[Dict[str, str]] = None) -> bool:
    """GitHub Actions 内或显式声明生产 flag 时一律按生产处理（明文回传不可用）。"""
    env = os.environ if env is None else env
    if env.get("GITHUB_ACTIONS", "").lower() == "true":
        return True
    return env.get("GHA_PRODUCTION", "").strip().lower() in _PLAINTEXT_OPT_IN_VALUES


class StateExporter:
    """状态导出管理器

    敏感类别（auth_state / browser_profile / browser_video / playwright_trace / browser_state /
    desktop_state / desktop_screenshot / desktop_video 以及任何未列入非敏感清单的类别）在注册为
    回传对象之前，先用 Host 公钥封装成密文（见 gha_runner.state_envelope），Manifest 记录
    encrypted=True 与 key_id 等元数据，传输 SHA-256 针对密文。
    compatibility_meta 不含秘密，保持明文。
    """

    def __init__(
        self,
        transfer_engine: ChunkedTransferEngine,
        browser_mgr: BrowserManager,
        desktop_mgr: DesktopManager,
        storage_dir: str,
        recipient: Optional[RecipientConfig] = None,
        environment: Optional[Dict[str, str]] = None,
        sealer: Optional[EnvelopeSealer] = None,
    ):
        self.transfer = transfer_engine
        self.browser = browser_mgr
        self.desktop = desktop_mgr
        self.storage_dir = storage_dir
        self._checkpoints: List[Dict[str, Any]] = []
        # 最近一次 FINAL checkpoint 的录像/Trace 采集结果（缺失原因不得静默吞掉）
        self.capture_status: Dict[str, List[str]] = {"objects": [], "missing": [], "errors": []}
        os.makedirs(self.storage_dir, exist_ok=True)

        self.environment = dict(os.environ if environment is None else environment)
        self.production = is_production_environment(self.environment)
        # 配置错误在构造期就暴露（启动失败），而不是等到首个 checkpoint
        self.recipient = recipient if recipient is not None else load_recipient_config(self.environment)
        self.sealer = sealer if sealer is not None else (
            self.recipient.sealer() if self.recipient.configured else None
        )
        self._sealed_paths: Dict[str, str] = {}

    # ---- 加密回传 ----
    @property
    def allow_plaintext_sensitive(self) -> bool:
        """仅在非生产环境显式 opt-in 时才允许明文敏感对象。"""
        if self.production:
            return False
        return self.environment.get("GHA_ALLOW_PLAINTEXT_STATE", "").strip().lower() in _PLAINTEXT_OPT_IN_VALUES

    def _remove_plaintext(self, path: str) -> None:
        """密文生成后立即删除 Runner 上的明文副本。"""
        try:
            if os.path.exists(path):
                os.unlink(path)
        except OSError:
            pass

    def _seal(self, obj_id: str, path: str) -> Tuple[str, str, int]:
        """流式封装成密文文件并删除明文，返回 (密文路径, 明文 SHA-256, 明文字节数)。"""
        if self.sealer is None:
            raise EnvelopeError("未配置 Host 公钥")
        out = os.path.join(self.storage_dir, f"{obj_id}{SEALED_SUFFIX}")
        tmp = f"{out}.tmp"
        try:
            sha_before, size_before = self.sealer.seal_stream(path, tmp)
            os.chmod(tmp, 0o600)
            os.replace(tmp, out)
        except Exception:
            self._remove_plaintext(tmp)
            raise
        self._remove_plaintext(path)
        return out, sha_before, size_before

    def register_object(self, obj_id: str, path: str, category: str) -> Dict[str, Any]:
        """敏感类别先加密再注册；返回带 encrypted/key_id/envelope 元数据的对象描述。

        传输 SHA-256/size 始终针对真实回传的字节（密文）。plaintext_* 只用于 Host 解密后
        校验内容一致，不参与传输完整性判断。
        """
        if not is_sensitive_category(category):
            return self.transfer.register_outgoing_object(obj_id, path, category=category, encrypted=False)

        if self.sealer is not None:
            try:
                sealed_path, sha_before, size_before = self._seal(obj_id, path)
            except SecretExportError:
                raise
            except Exception as exc:
                # 加密失败即放弃回传：Runner 上也不留明文副本
                self._remove_plaintext(path)
                raise SecretExportError(
                    f"对象 {obj_id} 加密失败，拒绝明文回传：{type(exc).__name__}"
                ) from exc
            meta = self.transfer.register_outgoing_object(obj_id, sealed_path, category=category, encrypted=True)
            meta.update(self.sealer.metadata())
            meta["plaintext_sha256"] = sha_before
            meta["plaintext_size"] = size_before
            prior = self._sealed_paths.get(obj_id)
            self._sealed_paths[obj_id] = sealed_path
            if prior and prior != sealed_path and os.path.exists(prior):
                # 同 id 的 checkpoint 被重新生成：旧密文不再被任何清单引用
                self._remove_plaintext(prior)
            return meta

        if self.allow_plaintext_sensitive:
            meta = self.transfer.register_outgoing_object(obj_id, path, category=category, encrypted=False)
            meta["warning"] = "PLAINTEXT_STATE_NOT_ALLOWED"
            return meta

        self._remove_plaintext(path)
        raise SecretExportError(
            f"对象 {obj_id} 属于敏感类别 {category}，但未配置 Host 公钥 "
            "(GHA_STATE_PUBLIC_KEY / GHA_STATE_KEY_ID 或 GHA_STATE_SECRETS)；"
            "生产环境禁止明文敏感对象回传"
        )

    def get_public_key_document(self) -> Dict[str, Any]:
        """只输出公钥文档，供宿主机核对 key_id；绝不包含私钥。"""
        if self.sealer is None:
            return {"configured": False, "production": self.production}
        return {
            "configured": True,
            "production": self.production,
            "encryption": self.sealer.metadata(),
            "allows_plaintext_sensitive": self.allow_plaintext_sensitive,
        }

    async def create_auth_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成认证状态检查点（含 Cookie，必须先加密再注册）"""
        state_data = await self.browser.export_storage_state()
        fn = f"auth-{checkpoint_id}.json"
        fp = os.path.join(self.storage_dir, fn)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(state_data, f, ensure_ascii=False, indent=2)

        obj_id = f"obj-auth-{checkpoint_id}"
        meta = self.register_object(obj_id, fp, "auth_state")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "AUTH_CHECKPOINT",
            "created_at": time.time(),
            "objects": [meta],
        }
        self._checkpoints.append(record)
        return record

    async def create_browser_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成浏览器当前运行视图检查点（DOM/页面内容同样按敏感数据处理）"""
        snap = await self.browser.snapshot()
        fn = f"browser-{checkpoint_id}.json"
        fp = os.path.join(self.storage_dir, fn)
        with open(fp, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)

        obj_id = f"obj-browser-{checkpoint_id}"
        meta = self.register_object(obj_id, fp, "browser_state")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "BROWSER_CHECKPOINT",
            "created_at": time.time(),
            "objects": [meta],
        }
        self._checkpoints.append(record)
        return record

    async def create_desktop_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成桌面状态检查点（含截图与窗口表）"""
        snap = self.desktop.snapshot()
        ss = self.desktop.screenshot()

        fn_snap = f"desktop-snap-{checkpoint_id}.json"
        fp_snap = os.path.join(self.storage_dir, fn_snap)
        with open(fp_snap, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)

        fn_ss = f"desktop-screen-{checkpoint_id}.png"
        fp_ss = os.path.join(self.storage_dir, fn_ss)
        with open(fp_ss, "wb") as f:
            f.write(ss)

        obj_snap = self.register_object(f"obj-desk-snap-{checkpoint_id}", fp_snap, "desktop_state")
        obj_ss = self.register_object(f"obj-desk-screen-{checkpoint_id}", fp_ss, "desktop_screenshot")

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "DESKTOP_CHECKPOINT",
            "created_at": time.time(),
            "objects": [obj_snap, obj_ss],
        }
        self._checkpoints.append(record)
        return record

    async def create_final_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """
        生成最终归档检查点：
        1. 导出最新 auth_state；
        2. 优雅退出 Chromium 进程确保 sqlite 数据落盘；
        3. 打包完整 user-data-dir Profile 目录；
        4. 记录平台与环境兼容性元数据。
        """
        # 1. 认证状态
        auth_rec = await self.create_auth_checkpoint(checkpoint_id + "-final")

        # 2. 优雅退出浏览器（关闭 Context 后录像与 Trace 才落盘）
        await self.browser.close()

        # 2.1 注册浏览器录像与 Playwright Trace（未开启配置时为空，行为不变）
        capture_objects = await self._register_browser_capture(checkpoint_id)

        # 3. 打包 Profile
        profile_dir = self.browser.user_data_dir
        archive_name = f"profile-{checkpoint_id}.tar.gz"
        archive_path = os.path.join(self.storage_dir, archive_name)

        if os.path.isdir(profile_dir):
            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(profile_dir, arcname="chrome-profile")
        else:
            # 兼容空目录
            with tarfile.open(archive_path, "w:gz") as tar:
                pass

        obj_profile = self.register_object(
            f"obj-profile-{checkpoint_id}",
            archive_path,
            "browser_profile",
        )

        # 4. 环境元数据（恢复时用于兼容性判断；不包含任何秘密）
        chromium_version = ""
        last_version = os.path.join(profile_dir, "Last Version")
        if os.path.isfile(last_version):
            with open(last_version, encoding="utf-8", errors="replace") as f:
                chromium_version = f.read().strip()
        try:
            from importlib.metadata import version as package_version
            playwright_version = package_version("playwright")
        except Exception:
            playwright_version = ""
        compat_info = {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "chromium_version": chromium_version,
            "playwright_version": playwright_version,
            "locale": os.environ.get("LANG", ""),
            "browser_flags": ["--force-renderer-accessibility", "--disable-dev-shm-usage"],
            "encryption_backend": "host-vault-AES-256-GCM",
            "transport_encryption": "X25519-HKDF-SHA256-AES-256-GCM" if self.sealer else "none",
            "state_key_id": self.sealer.key_id if self.sealer else None,
            "schema_version": "2.0",
        }
        compat_fn = f"compat-{checkpoint_id}.json"
        compat_fp = os.path.join(self.storage_dir, compat_fn)
        with open(compat_fp, "w", encoding="utf-8") as f:
            json.dump(compat_info, f, ensure_ascii=False, indent=2)
        # 非敏感类别：不含秘密，保持明文，便于 Host 在任何密钥状态下读取兼容性信息
        obj_compat = self.register_object(
            f"obj-compat-{checkpoint_id}",
            compat_fp,
            "compatibility_meta",
        )

        record = {
            "checkpoint_id": checkpoint_id,
            "type": "FINAL_CHECKPOINT",
            "created_at": time.time(),
            "objects": auth_rec["objects"] + [obj_profile, obj_compat] + capture_objects,
        }
        self._checkpoints.append(record)
        return record

    async def _register_browser_capture(self, checkpoint_id: str) -> List[Dict[str, Any]]:
        """注册已落盘的浏览器录像与 Trace，并记录采集失败原因。

        只登记真实存在的文件；未开启录像/Trace 时不产生任何对象或目录副作用。
        """
        objects: List[Dict[str, Any]] = []
        self.capture_status = {"objects": [], "missing": [], "errors": []}
        if not getattr(self.browser, "capture_enabled", False):
            return objects
        artifacts = await self.browser.capture_artifacts()
        for index, item in enumerate(artifacts, start=1):
            kind = item["kind"]
            suffix = f"-{index}" if len(artifacts) > 1 else ""
            obj_id = f"obj-{kind}-{checkpoint_id}{suffix}"
            try:
                # 录像/Trace 含页面内容，与 auth_state 同等加密；失败只记录原因，不登记明文对象
                objects.append(self.register_object(obj_id, item["path"], kind))
            except Exception as exc:
                self.capture_status["errors"].append(f"{kind}: {type(exc).__name__}: {str(exc)[:200]}")
        missing = []
        if self.browser.video_enabled and not any(a["kind"] == "browser_video" for a in artifacts):
            missing.append("browser_video")
        if self.browser.trace_enabled and not any(a["kind"] == "playwright_trace" for a in artifacts):
            missing.append("playwright_trace")
        self.capture_status["objects"] = [o["id"] for o in objects]
        self.capture_status["missing"] = missing
        self.capture_status["errors"].extend(self.browser.capture_errors)
        return objects

    _MANIFEST_OBJECT_FIELDS = (
        "id", "category", "size", "sha256", "encrypted",
        "envelope", "envelope_version", "envelope_algorithm",
        "key_id", "key_fingerprint", "plaintext_sha256", "plaintext_size", "warning",
    )

    @classmethod
    def _manifest_object(cls, obj: Dict[str, Any]) -> Dict[str, Any]:
        """清单只暴露协议字段，绝不包含 Runner 本地 file_path。"""
        item = {k: obj[k] for k in cls._MANIFEST_OBJECT_FIELDS if obj.get(k) is not None}
        item["persistence_state"] = obj.get("persistence_state", "PENDING")
        return item

    def get_manifest(self) -> Dict[str, Any]:
        """汇总当前所有可回传对象清单（size/sha256 针对实际传输字节，敏感对象为密文）"""
        all_objects = []
        checkpoints = []
        for cp in self._checkpoints:
            checkpoints.append(dict(cp, objects=[self._manifest_object(o) for o in cp.get("objects", [])]))
            for obj in cp.get("objects", []):
                all_objects.append(self._manifest_object(obj))
        manifest: Dict[str, Any] = {
            "schema": "gha-state/v2",
            "total_checkpoints": len(self._checkpoints),
            "checkpoints": checkpoints,
            "objects": all_objects,
            "encryption_required": True,
            "encryption_available": self.sealer is not None,
        }
        if not self.sealer:
            manifest["encryption_missing_reason"] = "HOST_PUBLIC_KEY_NOT_CONFIGURED"
        return manifest
