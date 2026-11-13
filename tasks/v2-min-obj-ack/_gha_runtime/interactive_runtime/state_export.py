"""运行时状态导出与 Checkpoint 制造器。

遵循《2.0 迭代.md》第十章、第十一章、第十二章与第十六章。
支持生成五种 Checkpoint：
- AUTH_CHECKPOINT：浏览器认证状态（Cookie/LocalStorage/IndexedDB）；
- BROWSER_CHECKPOINT：当前打开标签页、URL及DOM；
- DESKTOP_CHECKPOINT：桌面窗口、截屏与分段录像；
- TASK_CHECKPOINT：业务中间产物（只限任务目录内的文件/目录）；
- FINAL_CHECKPOINT：优雅关闭浏览器后完整 Profile 归档。

TASK checkpoint 的安全边界（见 TaskStateError 与 resolve_task_state_path）：
调用方给的是**任务目录内的逻辑路径**，不是任意 Runner 路径；绝对路径必须落在
GHA_TASK_STATE_DIR / GHA_TASK_DIR 里，`..`、符号链接逃逸、运行时私有目录
（Token、密文、录像）与公开结果目录（GHA_OUTPUT_DIR）一律拒绝。目录会先按
大小/文件数限制扫描，再打包成 tar.gz 并按敏感类别加密回传。
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
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

# ---- TASK_CHECKPOINT 安全策略 ----
# 单文件明文上限；目录归档按总明文与文件数再限一层，防止把 Runner 磁盘整个搬走
TASK_STATE_MAX_FILE_BYTES = 64 * 1024 * 1024
TASK_STATE_MAX_TOTAL_BYTES = 256 * 1024 * 1024
TASK_STATE_MAX_FILES = 2000
TASK_STATE_MAX_PATH_LENGTH = 4096

# checkpoint_id 会拼进回传对象 ID 与密文文件名：只允许安全字符，长度留出 "-final" 余量
_CHECKPOINT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")

# 任务状态目录的候选环境变量；按顺序取，允许 os.pathsep 分隔多个根
_TASK_STATE_ROOT_ENVS = ("GHA_TASK_STATE_DIR", "GHA_TASK_DIR")
_TASK_STATE_PATH_ENV = "GHA_TASK_STATE_PATH"
# 这些是 GitHub 步骤的输出通道，不是业务状态；混进加密回传只会扩大泄漏面
_GITHUB_OUTPUT_ENVS = ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_STEP_SUMMARY", "GITHUB_PATH")


class SecretExportError(Exception):
    """敏感状态无法以加密形式回传（无公钥 / 加密失败 / 配置错误）"""


class TaskStateError(Exception):
    """任务状态路径或内容不满足 TASK checkpoint 安全策略。"""

    def __init__(self, message: str, code: str = "INVALID_TASK_STATE_PATH", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class CheckpointConflictError(ValueError):
    """同一个 checkpoint_id 正在生成中（并发请求不重复创建对象）"""


def validate_checkpoint_id(checkpoint_id: str) -> str:
    """checkpoint_id 只允许安全字符，避免拼出越界对象 ID 或文件名。"""
    if not isinstance(checkpoint_id, str) or not _CHECKPOINT_ID_RE.match(checkpoint_id):
        raise ValueError("checkpoint_id 必须匹配 [A-Za-z0-9][A-Za-z0-9._-]{0,95}")
    return checkpoint_id


def _inside(path: str, root: str) -> bool:
    """path 是否等于 root 或位于 root 之下（两者都应已 realpath 化）。"""
    root = root.rstrip(os.sep) or os.sep
    return path == root or path.startswith(root + os.sep)


def is_production_environment(env: Optional[Dict[str, str]] = None) -> bool:
    """GitHub Actions 内或显式声明生产 flag 时一律按生产处理（明文回传不可用）。"""
    env = os.environ if env is None else env
    if env.get("GITHUB_ACTIONS", "").lower() == "true":
        return True
    return env.get("GHA_PRODUCTION", "").strip().lower() in _PLAINTEXT_OPT_IN_VALUES


class StateExporter:
    """状态导出管理器

    敏感类别（auth_state / browser_profile / browser_video / playwright_trace / browser_state /
    desktop_state / desktop_screenshot / desktop_video / task_state 以及任何未列入非敏感清单
    的类别）在注册为回传对象之前，先用 Host 公钥封装成密文（见 gha_runner.state_envelope），
    Manifest 记录 encrypted=True 与 key_id 等元数据，传输 SHA-256 针对密文。
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
        task_state_roots: Optional[List[str]] = None,
        recorder: Optional[Any] = None,
    ):
        self.transfer = transfer_engine
        # 桌面录像（DesktopRecorder）。None = 未启用录像，DESKTOP checkpoint 与之前一样。
        self.recorder = recorder
        self.browser = browser_mgr
        self.desktop = desktop_mgr
        self.storage_dir = storage_dir
        self._checkpoints: List[Dict[str, Any]] = []
        # checkpoint_id+类型 -> 已生成记录；同 ID 重复请求复用记录而不是再造对象
        self._checkpoint_index: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._pending_checkpoints: set = set()
        # 最近一次敏感对象无法加密的原因短码（只含短码，不含内容）；随清单交给宿主
        self._last_sensitive_failure: Optional[str] = None
        # 最近一次 FINAL checkpoint 的录像/Trace 采集结果（缺失原因不得静默吞掉）
        self.capture_status: Dict[str, List[str]] = {"objects": [], "missing": [], "errors": []}
        # 最近一次 DESKTOP checkpoint 的录像采集结果
        self.video_status: Dict[str, List[str]] = {"objects": [], "errors": []}
        os.makedirs(self.storage_dir, exist_ok=True)

        self.environment = dict(os.environ if environment is None else environment)
        self.production = is_production_environment(self.environment)
        # 配置错误在构造期就暴露（启动失败），而不是等到首个 checkpoint
        self.recipient = recipient if recipient is not None else load_recipient_config(self.environment)
        self.sealer = sealer if sealer is not None else (
            self.recipient.sealer() if self.recipient.configured else None
        )
        self._sealed_paths: Dict[str, str] = {}

        roots = task_state_roots if task_state_roots is not None else self._env_task_state_roots()
        self.task_state_roots = self._sanitize_task_state_roots(roots)

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

    def _seal(self, obj_id: str, path: str) -> Tuple[str, str, int, str]:
        """流式封装成密文文件并删除明文。

        返回 (密文路径, 明文 SHA-256, 明文字节数, 密文 SHA-256)。
        明文摘要只描述被加密的字节，密文摘要只描述实际回传的封套字节。
        """
        if self.sealer is None:
            raise EnvelopeError("未配置 Host 公钥")
        out = os.path.join(self.storage_dir, f"{obj_id}{SEALED_SUFFIX}")
        tmp = f"{out}.tmp"
        try:
            sha_before, size_before, sealed_sha = self.sealer.seal_stream_verified(path, tmp)
            os.chmod(tmp, 0o600)
            os.replace(tmp, out)
        except Exception:
            self._remove_plaintext(tmp)
            raise
        self._remove_plaintext(path)
        return out, sha_before, size_before, sealed_sha

    def register_object(self, obj_id: str, path: str, category: str) -> Dict[str, Any]:
        """敏感类别先加密再注册；返回带 encrypted/key_id/envelope 元数据的对象描述。

        传输 SHA-256/size 始终针对真实回传的字节（密文）。plaintext_sha256/plaintext_size
        只来自加密前实际读入的明文字节，用于 Host 解密后校验内容一致；两套摘要来自不同
        字节流，相等即说明有一方写错，这里直接拒绝登记。
        """
        if not is_sensitive_category(category):
            return self.transfer.register_outgoing_object(obj_id, path, category=category, encrypted=False)

        if self.sealer is not None:
            try:
                sealed_path, sha_before, size_before, sealed_sha = self._seal(obj_id, path)
            except SecretExportError:
                self._last_sensitive_failure = "SEAL_FAILED"
                raise
            except Exception as exc:
                # 加密失败即放弃回传：Runner 上也不留明文副本
                self._last_sensitive_failure = "SEAL_FAILED:%s" % type(exc).__name__
                self._remove_plaintext(path)
                raise SecretExportError(
                    f"对象 {obj_id} 加密失败，拒绝明文回传：{type(exc).__name__}"
                ) from exc
            meta = self.transfer.register_outgoing_object(obj_id, sealed_path, category=category, encrypted=True)
            meta.update(self.sealer.metadata())
            # 封套里算的密文摘要必须与注册时对落盘密文重算的一致，否则传输摘要不可信
            if meta.get("sha256") != sealed_sha or meta.get("size") != os.path.getsize(sealed_path):
                self._remove_plaintext(sealed_path)
                self._last_sensitive_failure = "SEALED_DIGEST_MISMATCH"
                raise SecretExportError(f"对象 {obj_id} 密文摘要与封套写入结果不一致，拒绝登记")
            if size_before <= 0 or sha_before == sealed_sha:
                self._remove_plaintext(sealed_path)
                self._last_sensitive_failure = "PLAINTEXT_DIGEST_INVALID"
                raise SecretExportError(f"对象 {obj_id} 明文摘要与密文摘要不可区分，拒绝登记")
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
        self._last_sensitive_failure = "HOST_PUBLIC_KEY_NOT_CONFIGURED"
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

    # ---- checkpoint 去重 ----
    def _begin_checkpoint(self, checkpoint_id: str, cp_type: str) -> Optional[Dict[str, Any]]:
        """同 ID 已生成过就复用（返回带 reused 标记的副本）；正在生成中则拒绝并发重复创建。"""
        key = (checkpoint_id, cp_type)
        existing = self._checkpoint_index.get(key)
        if existing is not None:
            return dict(existing, reused=True)
        if key in self._pending_checkpoints:
            raise CheckpointConflictError(f"checkpoint {checkpoint_id} 正在生成中")
        self._pending_checkpoints.add(key)
        return None

    def _end_checkpoint(self, checkpoint_id: str, cp_type: str) -> None:
        self._pending_checkpoints.discard((checkpoint_id, cp_type))

    def _finish_checkpoint(self, record: Dict[str, Any]) -> Dict[str, Any]:
        self._checkpoints.append(record)
        self._checkpoint_index[(record["checkpoint_id"], record["type"])] = record
        # 同名 checkpoint 重新生成会替换旧对象；清单只保留最新记录，避免旧条目继续引用
        # 已被清理的旧密文（Host 拉到 404 会反复重试）。
        superseded = [cp for cp in self._checkpoints
                      if cp is not record and cp.get("checkpoint_id") == record.get("checkpoint_id")
                      and cp.get("type") == record.get("type")]
        if superseded:
            self._checkpoints = [cp for cp in self._checkpoints if cp not in superseded]
            for old in superseded:
                for obj in old.get("objects", []):
                    if any(o.get("id") == obj.get("id") for o in record.get("objects", [])):
                        continue
                    path = self._sealed_paths.pop(obj.get("id"), None)
                    if path and os.path.exists(path):
                        self._remove_plaintext(path)
        return record

    # ---- TASK checkpoint 路径策略 ----
    def _env_task_state_roots(self) -> List[str]:
        roots: List[str] = []
        for name in _TASK_STATE_ROOT_ENVS:
            raw = (self.environment.get(name) or "").strip()
            if not raw:
                continue
            for part in raw.split(os.pathsep):
                part = part.strip()
                if part:
                    roots.append(part)
        return roots

    def _sanitize_task_state_roots(self, roots: List[str]) -> List[str]:
        """剔除会扩大暴露面的根：整机根目录、运行时私有目录及其祖先。"""
        private = os.path.realpath(self.storage_dir)
        result: List[str] = []
        for raw in roots or []:
            if not isinstance(raw, str) or not raw.strip():
                continue
            real = os.path.realpath(raw)
            if real == os.sep:
                continue
            if _inside(private, real) or _inside(real, private):
                continue
            if real not in result:
                result.append(real)
        return result

    def _denied_task_state_paths(self) -> List[str]:
        """运行时私有目录与公开结果目录永远不能作为任务状态来源。"""
        denied = [os.path.realpath(self.storage_dir)]
        public = (self.environment.get("GHA_OUTPUT_DIR") or "").strip()
        if public:
            denied.append(os.path.realpath(public))
        return denied

    def _denied_task_state_files(self) -> set:
        return {
            os.path.realpath(self.environment[name])
            for name in _GITHUB_OUTPUT_ENVS
            if (self.environment.get(name) or "").strip()
        }

    @staticmethod
    def _assert_no_symlink_components(root: str, target: str) -> None:
        """从根到目标逐段检查，任何一段是符号链接都拒绝（逃逸已在 realpath 阶段拦下）。"""
        rel = os.path.relpath(target, root)
        if rel == os.curdir:
            return
        cursor = root
        for part in rel.split(os.sep):
            cursor = os.path.join(cursor, part)
            if os.path.islink(cursor):
                raise TaskStateError(
                    "任务状态路径经过符号链接，已拒绝",
                    "TASK_STATE_SYMLINK_REJECTED",
                    403,
                )

    def resolve_task_state_path(self, raw_path: Optional[str]) -> Tuple[str, str, str]:
        """解析任务状态路径，返回 (realpath, 根目录, 相对逻辑名)。

        只接受：
        - 相对路径：按 GHA_TASK_STATE_DIR → GHA_TASK_DIR 顺序解析，必须真实存在；
        - 绝对路径：realpath 后必须落在上述根目录内。
        拒绝：`..`、NUL、超长路径、符号链接逃逸/叶子链接、运行时私有目录、
        公开结果目录（GHA_OUTPUT_DIR）与 GitHub 输出/环境文件。
        """
        if raw_path is None or not str(raw_path).strip():
            raise TaskStateError(
                "TASK checkpoint 需要 task_state_path（或配置 persistence.task_state_path）",
                "MISSING_TASK_STATE_PATH",
            )
        text = str(raw_path).strip()
        if "\x00" in text:
            raise TaskStateError("任务状态路径包含非法字符", "UNSAFE_TASK_STATE_PATH")
        if len(text) > TASK_STATE_MAX_PATH_LENGTH:
            raise TaskStateError("任务状态路径过长", "UNSAFE_TASK_STATE_PATH")
        if not self.task_state_roots:
            raise TaskStateError(
                "未配置任务状态目录（GHA_TASK_STATE_DIR / GHA_TASK_DIR），拒绝读取任意 Runner 路径",
                "TASK_STATE_ROOT_NOT_CONFIGURED",
            )

        root = ""
        logical = ""
        if os.path.isabs(text):
            if os.path.islink(text):
                raise TaskStateError("任务状态路径不得是符号链接", "TASK_STATE_SYMLINK_REJECTED", 403)
            real = os.path.realpath(text)
            matching = [r for r in self.task_state_roots if _inside(real, r)]
            if not matching:
                raise TaskStateError("任务状态路径不在允许的任务目录内", "TASK_STATE_PATH_DENIED", 403)
            root = max(matching, key=len)
            logical = os.path.relpath(real, root)
            self._assert_no_symlink_components(root, real)
        else:
            normalized = text.replace("\\", "/")
            parts = [p for p in normalized.split("/") if p not in ("", ".")]
            if not parts or any(p == ".." for p in parts):
                raise TaskStateError("任务状态路径不得为空或包含 ..", "UNSAFE_TASK_STATE_PATH")
            logical = os.path.join(*parts)
            resolved: Optional[Tuple[str, str, str]] = None
            for candidate_root in self.task_state_roots:
                lexical = os.path.join(candidate_root, logical)
                if not os.path.lexists(lexical):
                    continue
                if os.path.islink(lexical):
                    raise TaskStateError("任务状态路径不得是符号链接", "TASK_STATE_SYMLINK_REJECTED", 403)
                real = os.path.realpath(lexical)
                if not _inside(real, candidate_root):
                    raise TaskStateError(
                        "符号链接指向任务状态目录之外，已拒绝",
                        "TASK_STATE_SYMLINK_ESCAPE",
                        403,
                    )
                self._assert_no_symlink_components(candidate_root, real)
                resolved = (real, candidate_root, os.path.relpath(real, candidate_root))
                break
            if resolved is None:
                raise TaskStateError("任务状态路径不存在于允许的任务目录内", "TASK_STATE_NOT_FOUND", 404)
            real, root, logical = resolved

        if not os.path.exists(real):
            raise TaskStateError("任务状态路径不存在", "TASK_STATE_NOT_FOUND", 404)
        for denied in self._denied_task_state_paths():
            if _inside(real, denied):
                raise TaskStateError(
                    "运行时私有目录与公开结果目录不得作为任务状态来源",
                    "TASK_STATE_PATH_DENIED",
                    403,
                )
        if real in self._denied_task_state_files():
            raise TaskStateError(
                "GitHub 输出/环境文件不得作为任务状态来源",
                "TASK_STATE_PATH_DENIED",
                403,
            )
        if not os.path.isfile(real) and not os.path.isdir(real):
            raise TaskStateError("只支持普通文件或目录作为任务状态", "UNSUPPORTED_TASK_STATE")
        return real, root, logical

    def _assert_storage_not_public(self) -> None:
        """密文落点必须仍在 Runner 私有目录里，绝不允许写进公开 Artifact 目录。"""
        storage = os.path.realpath(self.storage_dir)
        public = (self.environment.get("GHA_OUTPUT_DIR") or "").strip()
        if public and _inside(storage, os.path.realpath(public)):
            raise TaskStateError(
                "运行时私有目录位于公开结果目录内，拒绝写入任务状态",
                "TASK_STATE_PUBLIC_STORAGE",
                500,
            )

    def _scan_task_tree(self, root: str) -> Tuple[int, int]:
        """扫描目录：拒绝符号链接/特殊文件，统计文件数与明文总字节并按限制 fail-closed。"""
        file_count = 0
        total = 0
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            filenames.sort()
            for name in list(dirnames):
                if os.path.islink(os.path.join(current, name)):
                    raise TaskStateError(
                        "任务状态目录内包含符号链接，已拒绝",
                        "TASK_STATE_SYMLINK_REJECTED",
                        403,
                    )
            for name in filenames:
                path = os.path.join(current, name)
                if os.path.islink(path):
                    raise TaskStateError(
                        "任务状态目录内包含符号链接，已拒绝",
                        "TASK_STATE_SYMLINK_REJECTED",
                        403,
                    )
                if not os.path.isfile(path):
                    raise TaskStateError(
                        "任务状态目录内包含非普通文件（FIFO/设备/套接字）",
                        "UNSUPPORTED_TASK_STATE",
                    )
                size = os.path.getsize(path)
                if size > TASK_STATE_MAX_FILE_BYTES:
                    raise TaskStateError(
                        f"任务状态单个文件超过 {TASK_STATE_MAX_FILE_BYTES} 字节上限",
                        "TASK_STATE_TOO_LARGE",
                        413,
                    )
                file_count += 1
                total += size
                if file_count > TASK_STATE_MAX_FILES:
                    raise TaskStateError(
                        f"任务状态文件数超过 {TASK_STATE_MAX_FILES} 上限",
                        "TASK_STATE_TOO_MANY_FILES",
                        413,
                    )
                if total > TASK_STATE_MAX_TOTAL_BYTES:
                    raise TaskStateError(
                        f"任务状态明文总量超过 {TASK_STATE_MAX_TOTAL_BYTES} 字节上限",
                        "TASK_STATE_TOO_LARGE",
                        413,
                    )
        return file_count, total

    @staticmethod
    def _stage_file(source: str, staged: str) -> None:
        try:
            with open(source, "rb") as fin, open(staged, "wb") as fout:
                shutil.copyfileobj(fin, fout, 1024 * 1024)
            os.chmod(staged, 0o600)
        except OSError as exc:
            raise TaskStateError(
                f"任务状态文件读取失败：{type(exc).__name__}",
                "TASK_STATE_READ_FAILED",
            ) from exc

    @staticmethod
    def _archive_task_dir(source: str, staged: str) -> None:
        try:
            with tarfile.open(staged, "w:gz") as tar:
                tar.add(source, arcname=os.path.basename(source) or "task-state")
        except (OSError, tarfile.TarError) as exc:
            raise TaskStateError(
                f"任务状态目录打包失败：{type(exc).__name__}",
                "TASK_STATE_READ_FAILED",
            ) from exc
        try:
            os.chmod(staged, 0o600)
        except OSError:
            pass

    async def create_task_checkpoint(
        self,
        checkpoint_id: str,
        task_state_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """生成业务任务状态检查点。

        - `task_state_path` 缺省时取 GHA_TASK_STATE_PATH；
        - 文件按原样、目录打包成 tar.gz 后立即按敏感类别加密，Runner 上只留密文；
        - 记录只含逻辑名与统计信息，绝不返回绝对路径；
        - 同 checkpoint_id 重复请求复用既有记录，不重复创建对象。
        """
        checkpoint_id = validate_checkpoint_id(checkpoint_id)
        existing = self._begin_checkpoint(checkpoint_id, "TASK_CHECKPOINT")
        if existing is not None:
            return existing
        try:
            raw_path = task_state_path if task_state_path is not None else self.environment.get(_TASK_STATE_PATH_ENV)
            real, _root, logical = self.resolve_task_state_path(raw_path)
            self._assert_storage_not_public()

            staging_dir = os.path.join(self.storage_dir, "task-state-staging")
            try:
                os.makedirs(staging_dir, mode=0o700, exist_ok=True)
            except OSError as exc:
                raise TaskStateError(
                    "无法创建任务状态暂存目录",
                    "TASK_STATE_STAGING_FAILED",
                    500,
                ) from exc
            obj_id = f"obj-task-{checkpoint_id}"
            staged = ""
            try:
                if os.path.isdir(real):
                    file_count, total = self._scan_task_tree(real)
                    staged = os.path.join(staging_dir, f"{obj_id}.tar.gz")
                    self._archive_task_dir(real, staged)
                    kind = "directory"
                else:
                    total = os.path.getsize(real)
                    if total > TASK_STATE_MAX_FILE_BYTES:
                        raise TaskStateError(
                            f"任务状态文件超过 {TASK_STATE_MAX_FILE_BYTES} 字节上限",
                            "TASK_STATE_TOO_LARGE",
                            413,
                        )
                    staged = os.path.join(staging_dir, f"{obj_id}.bin")
                    self._stage_file(real, staged)
                    file_count, kind = 1, "file"

                if os.path.getsize(staged) > TASK_STATE_MAX_TOTAL_BYTES:
                    raise TaskStateError(
                        f"任务状态对象超过 {TASK_STATE_MAX_TOTAL_BYTES} 字节上限",
                        "TASK_STATE_TOO_LARGE",
                        413,
                    )
                try:
                    meta = self.register_object(obj_id, staged, "task_state")
                finally:
                    self._remove_plaintext(staged)
            except TaskStateError:
                if staged:
                    self._remove_plaintext(staged)
                raise
            except OSError as exc:
                if staged:
                    self._remove_plaintext(staged)
                raise TaskStateError(
                    f"任务状态读取失败：{type(exc).__name__}",
                    "TASK_STATE_READ_FAILED",
                ) from exc

            record = {
                "checkpoint_id": checkpoint_id,
                "type": "TASK_CHECKPOINT",
                "created_at": time.time(),
                "task_state": {
                    "kind": kind,
                    "name": logical,
                    "files": file_count,
                    "plaintext_bytes": total,
                },
                "objects": [meta],
            }
            return self._finish_checkpoint(record)
        finally:
            self._end_checkpoint(checkpoint_id, "TASK_CHECKPOINT")
            # 空的分段目录不留在私有存储里；并发 checkpoint 仍在用时会 rmdir 失败，忽略即可
            self._remove_empty_dir(os.path.join(self.storage_dir, "task-state-staging"))

    @staticmethod
    def _remove_empty_dir(path: str) -> None:
        try:
            os.rmdir(path)
        except OSError:
            pass

    async def create_auth_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成认证状态检查点（含 Cookie，必须先加密再注册）"""
        checkpoint_id = validate_checkpoint_id(checkpoint_id)
        existing = self._begin_checkpoint(checkpoint_id, "AUTH_CHECKPOINT")
        if existing is not None:
            return existing
        try:
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
            return self._finish_checkpoint(record)
        finally:
            self._end_checkpoint(checkpoint_id, "AUTH_CHECKPOINT")

    async def create_browser_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成浏览器当前运行视图检查点（DOM/页面内容同样按敏感数据处理）"""
        checkpoint_id = validate_checkpoint_id(checkpoint_id)
        existing = self._begin_checkpoint(checkpoint_id, "BROWSER_CHECKPOINT")
        if existing is not None:
            return existing
        try:
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
            return self._finish_checkpoint(record)
        finally:
            self._end_checkpoint(checkpoint_id, "BROWSER_CHECKPOINT")

    @staticmethod
    def _probe_video_duration(path: str) -> Optional[float]:
        try:
            res = subprocess.run(
                ["ffprobe", "-v", "error", "-show_entries", "format=duration",
                 "-of", "default=noprint_wrappers=1:nokey=1", path],
                capture_output=True, text=True, timeout=30,
            )
            if res.returncode == 0:
                return float(res.stdout.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        return None

    def _register_desktop_video(self, checkpoint_id: str) -> List[Dict[str, Any]]:
        """把已收尾的录像片段注册成 desktop_video 对象（敏感类别，先加密）。

        运行中的采集文件不可读（没有 moov），所以先让录制器把当前内容收尾成片段；
        录制失败只记原因，不伪造对象。
        """
        rec = self.recorder
        self.video_status = {"objects": [], "errors": []}
        if rec is None:
            self.video_status["errors"].append("recorder: 未挂载桌面录像器")
            return []
        was_capturing = bool(getattr(rec, "is_recording", False) or getattr(rec, "is_paused", False))
        if not was_capturing and not hasattr(rec, "is_recording") and not hasattr(rec, "is_paused"):
            was_capturing = True  # 替身/旧录制器没有状态位：按"应当有录像"处理，宁可报原因
        try:
            # 录制中的采集文件没有 moov 读不了，每次都让它收尾（录制器随后用同一参数重启）；
            # 已收尾的片段按"未认领"交付，重复检查点不会把同一段录像登记两次。
            if rec.unfinished_segment():
                rec.finalize_for_checkpoint()
            segments = rec.pending_segments()
        except Exception as exc:  # 录像失败不阻断 checkpoint 其余对象
            self.video_status["errors"].append(f"finalize: {type(exc).__name__}: {str(exc)[:200]}")
            # finalize 中途失败可能已经写了 moov：重试一次让它收尾，已认领的片段不会重复登记
            try:
                if rec.unfinished_segment():
                    rec.finalize_for_checkpoint()
            except Exception:
                pass
            try:
                segments = rec.pending_segments()
            except Exception as exc2:
                self.video_status["errors"].append(
                    f"segments: {type(exc2).__name__}: {str(exc2)[:200]}")
                segments = []
        # 录制器仍在采集却一段都没交：录像没真正落盘（未启动 / ffmpeg 未产出），
        # 把原因写进 manifest，而不是只留下一个没有 desktop_video 的检查点。
        if not segments and not self.video_status["errors"] and was_capturing:
            self.video_status["errors"].append(
                "no_segment: 录像没有落盘任何非空片段（录制未启动或 ffmpeg 未产出）")
        objects = []
        for index, path in enumerate(segments):
            obj_id = f"obj-desk-video-{checkpoint_id}-{index:03d}"
            try:
                duration = self._probe_video_duration(path)
                meta = self.register_object(obj_id, path, "desktop_video")
                if duration is not None:
                    meta["duration_seconds"] = duration
                objects.append(meta)
            except Exception as exc:
                self.video_status["errors"].append(f"{obj_id}: {type(exc).__name__}: {str(exc)[:200]}")
        self.video_status["objects"] = [o["id"] for o in objects]
        return objects

    async def create_desktop_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """生成桌面状态检查点（窗口表 + 截图 + 已落盘的桌面录像片段）"""
        checkpoint_id = validate_checkpoint_id(checkpoint_id)
        existing = self._begin_checkpoint(checkpoint_id, "DESKTOP_CHECKPOINT")
        if existing is not None:
            return existing
        try:
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
            video_objects = self._register_desktop_video(checkpoint_id)

            record = {
                "checkpoint_id": checkpoint_id,
                "type": "DESKTOP_CHECKPOINT",
                "created_at": time.time(),
                "objects": [obj_snap, obj_ss] + video_objects,
            }
            if getattr(self, "video_status", None) and self.video_status.get("errors"):
                record["video_errors"] = list(self.video_status["errors"])
            return self._finish_checkpoint(record)
        finally:
            self._end_checkpoint(checkpoint_id, "DESKTOP_CHECKPOINT")

    async def create_final_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        """
        生成最终归档检查点：
        1. 导出最新 auth_state；
        2. 优雅退出 Chromium 进程确保 sqlite 数据落盘；
        3. 打包完整 user-data-dir Profile 目录；
        4. 记录平台与环境兼容性元数据。
        """
        checkpoint_id = validate_checkpoint_id(checkpoint_id)
        existing = self._begin_checkpoint(checkpoint_id, "FINAL_CHECKPOINT")
        if existing is not None:
            return existing
        try:
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
            return self._finish_checkpoint(record)
        finally:
            self._end_checkpoint(checkpoint_id, "FINAL_CHECKPOINT")

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
        "key_fingerprint", "plaintext_sha256", "plaintext_size", "duration_seconds", "warning",
    )

    @classmethod
    def _manifest_object(cls, obj: Dict[str, Any]) -> Dict[str, Any]:
        """清单只暴露协议字段，绝不包含 Runner 本地 file_path。

        也不带 key_id：它就是 GHA_STATE_KEY_ID 的值，而公开产物要经"已注册凭证值字面
        比对"扫描。封套头里本来就写着 key_id，Host 解封从密文里取（Vault 有本地副本可回退）。
        """
        item = {k: obj[k] for k in cls._MANIFEST_OBJECT_FIELDS if obj.get(k) is not None}
        item["persistence_state"] = obj.get("persistence_state", "PENDING")
        return item

    def public_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """API 返回给调用方的 checkpoint 记录：对象字段与 Manifest 同构，不含 Runner 路径。"""
        public = {k: v for k, v in record.items() if k != "objects"}
        public["objects"] = [self._manifest_object(o) for o in record.get("objects", [])]
        return public

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
            # 本次运行的最小标识：宿主据此把回传对象关联到它提交的那次 run，
            # 而不是 private 目录里残留的改名原件（只含公开的 run 上下文，不含任何凭证）。
            "run_context": {
                "run_id": self.environment.get("GITHUB_RUN_ID", ""),
                "session_id": getattr(self.browser, "session_id", "") or "",
                "repository": self.environment.get("GITHUB_REPOSITORY", ""),
                "created_at": time.time(),
            },
        }
        if not self.sealer:
            manifest["encryption_missing_reason"] = "HOST_PUBLIC_KEY_NOT_CONFIGURED"
        elif self._last_sensitive_failure:
            # 密文生成失败（例如 Runner 缺 cryptography）：清单为空不是“任务没产出”，
            # 必须把原因带给宿主，否则宿主只能等到导出窗口耗尽才知道。
            manifest["encryption_missing_reason"] = self._last_sensitive_failure
        return manifest
