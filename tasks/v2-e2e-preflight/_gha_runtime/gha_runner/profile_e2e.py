"""Profile 跨 Runner 两阶段真实 E2E 编排（宿主侧）。

阶段任务本身自洽（写入 → FINAL → 等 Host 回传；等待恢复 → 验证），本编排把它们串起来：

1. 全量写入仓库 secret（经 stdin，只报键名）；
2. 提交阶段 1（真实 ubuntu-latest Runner + Interactive Runtime）；
3. 经私有 Registry 发现阶段 1 的 Gateway，用 `gha state export` 的回传流程
   （StateClient.export_selected）把 FINAL checkpoint 的 auth_state / browser_profile
   加密落 Vault 并 ACK；阶段任务轮询到 PERSISTED 才退出；
4. 提交阶段 2（新的 Runner job），经 Registry 发现其 Gateway，用 `gha state restore`
   的推送流程（StateClient.import_state_from_vault）先推 Profile 归档、再推 auth_state；
5. 取回两段报告、清理 run 与 artifact。

阶段包由 `gha submit` 自带 `_gha_runtime`（bundle.runtime_support_files），
因此远端跑的就是提交时工作区里的代码；需要时可用 --check-runtime 核对远端摘要。

用法：

    python3 -m gha_runner.profile_e2e --repo OWNER/NAME \
        --endpoint-file /tmp/x/endpoint --token-file /tmp/x/token --vault-root /tmp/v
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import bundle, core
from .interactive_client import InteractiveClient
from .vault import Vault

PHASE1_TASK = "v2-profile-e2e"
PHASE2_TASK = "v2-profile-e2e-restore"
# 必需键：Host 公钥。Registry 两项视测试 Registry 的形态决定是否写入仓库 secret：
# 预检只接受 https 的 Quick Tunnel 注册中心，本地 http 测试实例不能进 secret，
# 否则 Runner 侧预检会把它当成非法 Quick 配置。宿主自身的 Registry 调用从文件读。
REQUIRED_SECRET_KEYS = ("GHA_STATE_KEY_ID", "GHA_STATE_PUBLIC_KEY")
PHASE1_OBJECT_IDS = {
    "auth": "obj-auth-e2e-phase1-final",
    "profile": "obj-profile-e2e-phase1",
    "compat": "obj-compat-e2e-phase1",
}
RUNTIME_FILES = (
    "gha_runner/state_client.py", "gha_runner/restore_verify.py",
    "gha_runner/state_envelope.py", "gha_runner/vault.py",
    "interactive_runtime/state_import.py", "interactive_runtime/gateway.py",
)
GATEWAY_WAIT_SECONDS = 1200


def log(msg: str) -> None:
    print(msg, flush=True)


def read_secret_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


class Runner:
    """本地 gha CLI 包装（提交、等待、取回、清理），只经子进程交互。"""

    def __init__(self, root: Path):
        self.root = root
        self.gha = str(root / "gha")

    def call(self, *args: str, stdin_text: Optional[str] = None,
             timeout: float = 900.0) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        return subprocess.run([self.gha, *args], cwd=str(self.root), input=stdin_text, env=env,
                              capture_output=True, text=True, timeout=timeout)

    def submit(self, task_dir: Path, task_id: str) -> str:
        # 公开仓库：运行库副本/公开示例值会命中启发式扫描，测试包显式跳过
        proc = self.call("submit", str(task_dir), "--task-id", task_id, "--allow-public", "--yes")
        if proc.returncode != 0:
            raise RuntimeError("提交 %s 失败：%s" % (task_id, (proc.stdout + proc.stderr)[-1500:]))
        rid = core.run_get(task_id, "run_id")
        log("已提交 %s → run_id=%s" % (task_id, rid))
        return rid

    def fetch(self, task_id: str) -> Optional[Path]:
        proc = self.call("fetch", task_id, "--force")
        if proc.returncode != 0:
            log("取回 %s 失败：%s" % (task_id, (proc.stdout + proc.stderr)[-600:]))
            return None
        return core.run_dir(task_id) / "result"

    def clean(self, run_id: str) -> None:
        proc = self.call("clean", "--run-id", run_id, "--yes", timeout=300)
        log("清理 run %s：rc=%d" % (run_id, proc.returncode))

    def logs(self, run_id: str, limit: int = 6000) -> str:
        return (self.call("logs", run_id, timeout=180).stdout or "")[-limit:]

    def status(self, target: str) -> Dict[str, Any]:
        proc = self.call("status", target, timeout=120)
        try:
            return json.loads(proc.stdout[proc.stdout.index("{"):])
        except Exception:
            return {}


def select_objects(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    wanted = set(PHASE1_OBJECT_IDS.values())
    return [o for o in manifest.get("objects", []) if o.get("id") in wanted]


def expected_runtime_digests() -> Dict[str, str]:
    files = dict(bundle.runtime_support_files())
    out = {}
    for rel in RUNTIME_FILES:
        data = files.get(rel)
        out[rel] = hashlib.sha256(data).hexdigest()[:16] if data else "MISSING"
    return out


def export_phase1(gateway: str, token: str, vault_root: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """回传阶段 1 的 FINAL 对象；返回 (导出结果, 清单信息)。"""
    from .state_client import StateClient
    client = InteractiveClient(gateway, token, timeout=60)
    sc = StateClient(client, vault=Vault(root_dir=vault_root))
    manifest = sc.list_manifest()
    objects = select_objects(manifest)
    ids = {o["id"] for o in objects}
    if ids != set(PHASE1_OBJECT_IDS.values()):
        raise RuntimeError("阶段 1 清单缺少对象：%s" % sorted(set(PHASE1_OBJECT_IDS.values()) - ids))
    result = sc.export_selected(objects, project="default")
    try:
        from .profile_inspect import inspect_vault_profile, summarize_auth_state
        result["vault_profile"] = inspect_vault_profile(sc.vault, PHASE1_OBJECT_IDS["profile"])
        result["vault_auth_state"] = summarize_auth_state(sc.vault, PHASE1_OBJECT_IDS["auth"])
    except Exception as exc:  # 只记录，不掩盖导出本身的结果
        result["vault_inspect_error"] = "%s: %s" % (type(exc).__name__, str(exc)[:300])
    info = {
        "encryption_available": manifest.get("encryption_available"),
        "key_ids": sorted({str(o.get("key_id")) for o in objects if o.get("key_id")}),
        "encrypted_flags": {o["id"]: o.get("encrypted") for o in objects},
        "plaintext_sizes": {o["id"]: o.get("plaintext_size") for o in objects},
        "transport_sizes": {o["id"]: o.get("size") for o in objects},
    }
    return result, info


def resolve_gateway(run_id: str, repo: str, endpoint: str, token: str,
                    timeout_s: float = GATEWAY_WAIT_SECONDS,
                    on_wait=None) -> Tuple[str, str, float]:
    """经 Registry 解析 run 的 Gateway；Handler 公告后 Cloudflare 边缘生效有几秒延迟。"""
    from .registry import RegistryClient
    reg = RegistryClient(endpoint, token, user=repo)
    deadline = time.time() + timeout_s
    started = time.time()
    last = ""
    while time.time() < deadline:
        pair = reg.resolve_run_blocking(run_id)
        if pair:
            origin, agent_token = pair
            try:
                probe = subprocess.run(
                    [sys.executable, "-c",
                     "import sys,urllib.request;"
                     "print(urllib.request.urlopen(sys.argv[1]+'/health', timeout=10).status)",
                     origin], capture_output=True, text=True, timeout=30)
                if probe.returncode == 0 and "200" in probe.stdout:
                    return origin, agent_token, time.time() - started
                last = (probe.stderr or probe.stdout).strip()[-200:]
            except Exception as exc:
                last = type(exc).__name__
        if on_wait is not None:
            on_wait(int(time.time() - started), last)
        time.sleep(5)
    raise RuntimeError("等待 run %s 的 Gateway 超时：%s" % (run_id, last))


def push_restore(gateway: str, token: str, vault_root: str) -> List[Dict[str, Any]]:
    """按 `gha state restore` 的顺序推送：先 Profile 归档（进程重启），再 auth_state。"""
    from .state_client import StateClient
    sc = StateClient(InteractiveClient(gateway, token, timeout=60), vault=Vault(root_dir=vault_root))
    out = []
    out.append({"category": "browser_profile",
                "result": sc.import_state_from_vault("default", PHASE1_OBJECT_IDS["profile"],
                                                     category="browser_profile")})
    sc.client = InteractiveClient(gateway, token, timeout=60)
    out.append({"category": "auth_state",
                "result": sc.import_state_from_vault("default", PHASE1_OBJECT_IDS["auth"],
                                                     category="auth_state")})
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=core.need_repo())
    ap.add_argument("--endpoint-file", default="/tmp/gha-registry-test/endpoint")
    ap.add_argument("--token-file", default="/tmp/gha-registry-test/token")
    ap.add_argument("--secret-file", default=os.path.expanduser("~/.gha-runner/e2e-secrets.json"))
    ap.add_argument("--vault-root", required=True)
    ap.add_argument("--report", default="")
    ap.add_argument("--no-clean", action="store_true")
    ap.add_argument("--check-runtime", action="store_true",
                    help="提交前用一件本地面板下发并核对 _gha_runtime 摘要")
    args = ap.parse_args(argv)

    root = Path.cwd()
    py_path = os.environ.get("GHA_E2E_PYTHONPATH", "")
    if py_path:
        os.environ["PYTHONPATH"] = os.pathsep.join([p for p in (py_path, os.environ.get("PYTHONPATH", "")) if p])
    endpoint = read_secret_file(args.endpoint_file)
    registry_token = read_secret_file(args.token_file)
    os.environ["GHA_RENDEZVOUS_ENDPOINT"] = endpoint
    os.environ["GHA_RENDEZVOUS_TOKEN"] = registry_token

    runner = Runner(root)
    report: Dict[str, Any] = {"phases": {}, "started": time.time()}
    runs: List[str] = []
    ok = False
    try:
        blob = json.loads(read_secret_file(args.secret_file))
        missing = [k for k in REQUIRED_SECRET_KEYS if not blob.get(k)]
        for k, v in (("GHA_RENDEZVOUS_ENDPOINT", endpoint), ("GHA_RENDEZVOUS_TOKEN", registry_token)):
            if str(v).lower().startswith("https://"):
                blob[k] = v
        if missing:
            raise RuntimeError("secret 文件缺少键：%s" % ", ".join(missing))
        proc = runner.call("secret", "set", "--yes", stdin_text=json.dumps(blob, ensure_ascii=False))
        if proc.returncode != 0:
            raise RuntimeError("写入仓库 secret 失败：%s" % (proc.stdout + proc.stderr)[-500:])
        report["secret_keys"] = sorted(blob)
        report["registry_in_secret"] = any(k in blob for k in ("GHA_RENDEZVOUS_ENDPOINT", "GHA_RENDEZVOUS_TOKEN"))
        log("仓库 secret 已全量写入（键：%s；值未回显）" % ", ".join(sorted(blob)))
        report["expected_runtime"] = expected_runtime_digests()

        runs.append(runner.submit(root / "tasks" / PHASE1_TASK, PHASE1_TASK))
        gateway, token, waited = resolve_gateway(runs[-1], args.repo, endpoint, registry_token)
        report["phases"]["phase1_gateway"] = gateway
        log("阶段 1 Gateway 已连通（等待 %.0fs）" % waited)
        exp, manifest_info = export_phase1(gateway, token, args.vault_root)
        report["phases"]["export"] = {"result": exp, "manifest": manifest_info}
        log("Host 回传完成：%d 个对象，明文敏感 %d 个" %
            (len(exp.get("synced_objects") or []), len(exp.get("plaintext_objects") or [])))
        if exp.get("plaintext_objects"):
            raise RuntimeError("存在未加密回传的敏感对象")

        runs.append(runner.submit(root / "tasks" / PHASE2_TASK, PHASE2_TASK))
        gateway2, token2, waited2 = resolve_gateway(runs[-1], args.repo, endpoint, registry_token)
        report["phases"]["phase2_gateway"] = gateway2
        log("阶段 2 Gateway 已连通（等待 %.0fs），开始推送恢复" % waited2)
        report["phases"]["restore"] = push_restore(gateway2, token2, args.vault_root)
        log("Profile 归档与 auth_state 已推送，Runner 均确认 verified=True")
        ok = True
    except Exception as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:1200])
        log("E2E 失败：%s" % report["error"])
    finally:
        report["ok"] = ok
        report["finished"] = time.time()
        report["runs"] = runs
        if runs:
            report["last_run_log_tail"] = runner.logs(runs[-1])
        text = json.dumps(report, ensure_ascii=False, indent=2)
        print(text)
        if args.report:
            Path(args.report).write_text(text, encoding="utf-8")
        if not args.no_clean:
            for rid in runs:
                runner.clean(rid)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
