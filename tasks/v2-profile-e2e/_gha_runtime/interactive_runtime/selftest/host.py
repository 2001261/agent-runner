"""真实 Runner 上跑交接闭环自查（宿主侧编排）。

与 ``gha_runner/profile_e2e.py`` 同一形态：宿主准备密钥与包外静态件 → ``gha submit`` →
经私有 Registry 发现 Gateway → 拉取录像并解封校验 → 取回结果 → 清理 run。

    python3 -m interactive_runtime.selftest.host --platform linux-x64

``--platform`` 与 ``--runner`` 必须指向同一平台（浏览器壳按平台取件，见 bundle.py）。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
TASK_SRC = HERE / "task"
DEFAULT_TASK_DIR = Path("/tmp/e2e-tasks/loop-e2e")
RUNTIME_FILES = (
    "interactive_runtime/gateway.py", "interactive_runtime/selftest/handoff_loop.py",
    "interactive_runtime/selftest/bundle.py", "interactive_runtime/selftest/marker.py",
    "interactive_runtime/selftest/site.js", "interactive_runtime/selftest/task/task.py",
    "interactive_runtime/selftest/task/task.sh", "interactive_runtime/preflight.py",
)


def log(msg: str) -> None:
    print(msg, flush=True)


def prepare_task(task_dir: Path, platform_key: str, npm_dep: str) -> Dict[str, Any]:
    """把自查任务铺到任务目录（必须是新建目录：任务目录会被整体打包并进 git 历史）。"""
    from . import bundle

    if task_dir.exists() and any(task_dir.iterdir()):
        raise SystemExit(f"任务目录非空，拒绝覆盖：{task_dir}")
    shutil.copytree(TASK_SRC, task_dir)
    static_root = task_dir / "static" / platform_key
    sizes = bundle.build_static(str(static_root), platform_key, npm_dep)
    return sizes


def write_secrets(path: Path, endpoint: str, token: str, public_key: Dict[str, str],
                  registry_values_unknown: bool = False) -> None:
    """仓库 secret 全量 JSON；键名之外绝不打印任何值。"""
    blob = {
        "GHA_RENDEZVOUS_ENDPOINT": endpoint,
        "GHA_RENDEZVOUS_TOKEN": token,
        "GHA_STATE_KEY_ID": public_key["key_id"],
        "GHA_STATE_PUBLIC_KEY": public_key["public_key"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(blob, fh)
    os.chmod(path, 0o600)
    log(f"secret 文件已写入 {path}（键：{', '.join(sorted(blob))}）")


def runtime_digests() -> Dict[str, str]:
    import hashlib

    from gha_runner.bundle import runtime_support_files

    files = runtime_support_files()
    return {rel: hashlib.sha256(files[rel]).hexdigest()[:16] if rel in files else "MISSING"
            for rel in RUNTIME_FILES}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="在真实 Runner 上跑 noVNC 交接 + 录像加密回传闭环自查")
    ap.add_argument("--repo", default="")
    ap.add_argument("--task-id", default="v2-loop-e2e")
    ap.add_argument("--task-dir", default=str(DEFAULT_TASK_DIR))
    ap.add_argument("--platform", default="linux-x64")
    ap.add_argument("--runner", default="ubuntu-latest")
    ap.add_argument("--secret-file", default=os.path.expanduser("~/.gha-runner/e2e-secrets.json"))
    ap.add_argument("--npm", default="jsdom@25.0.1")
    ap.add_argument("--keep", action="store_true", help="不清理 run（默认跑完即清理）")
    ap.add_argument("--prepare-only", action="store_true")
    args = ap.parse_args(argv)

    repo = args.repo or os.environ.get("GHA_REPO", "")
    if not repo:
        raise SystemExit("需要 --repo OWNER/NAME（或环境变量 GHA_REPO）")

    sys.path.insert(0, str(HERE.parent.parent))
    from gha_runner import core
    from gha_runner.interactive_client import InteractiveClient
    from gha_runner.state_client import StateClient
    from gha_runner.state_envelope import load_or_create_host_keys
    from gha_runner.vault import Vault

    vault_root = Path(os.environ.get("GHA_SELFTEST_VAULT_ROOT", os.path.expanduser("~/.gha-runner/selftest-vault")))
    keys = load_or_create_host_keys(vault_root / "state-keys")
    public = {"key_id": keys.key_id, "public_key": keys.public_b64()}
    log(f"Host 状态公钥 key_id={keys.key_id}")

    task_dir = Path(args.task_dir)
    if not (task_dir / "task.sh").exists():
        sizes = prepare_task(task_dir, args.platform, args.npm)
        log(f"任务目录已生成：{task_dir}（{json.dumps(sizes, ensure_ascii=False)}）")
    if args.prepare_only:
        return 0

    secret_path = Path(args.secret_file)
    if not secret_path.is_file():
        raise SystemExit(f"缺少 secret 文件（需含 Registry 两项）：{secret_path}")
    existing = json.loads(secret_path.read_text(encoding="utf-8"))
    for key in ("GHA_RENDEZVOUS_ENDPOINT", "GHA_RENDEZVOUS_TOKEN"):
        if not existing.get(key):
            raise SystemExit(f"secret 文件缺少 {key}")
    write_secrets(secret_path, existing["GHA_RENDEZVOUS_ENDPOINT"],
                  existing["GHA_RENDEZVOUS_TOKEN"], public)

    digests = runtime_digests()
    log("远端运行库摘要：" + json.dumps(digests, ensure_ascii=False))
    missing = [k for k, v in digests.items() if v == "MISSING"]
    if missing:
        raise SystemExit(f"运行库缺少文件，无法打包：{missing}")

    runner = Path(__file__).resolve().parents[2]
    run_id = ""

    def gha(*cmd: str, stdin_text: Optional[str] = None, timeout: int = 900) -> Any:
        import subprocess

        return subprocess.run([str(runner / "gha"), *cmd], cwd=str(runner), input=stdin_text,
                              capture_output=True, text=True, timeout=timeout)

    log("写入仓库 secret（全量 JSON，经 stdin）")
    proc = gha("secret", "set", stdin_text=secret_path.read_text(encoding="utf-8"), timeout=300)
    if proc.returncode != 0:
        log((proc.stdout + proc.stderr)[-1500:])
        raise SystemExit("secret set 失败")
    log((proc.stdout or "").strip().splitlines()[-1] if proc.stdout else "secret set ok")

    log(f"提交 {args.task_id} → {repo}")
    proc = gha("submit", str(task_dir), "--task-id", args.task_id, "--runner", args.runner,
               "--interactive", "--allow-public", "--yes", "--timeout", "60")
    if proc.returncode != 0:
        log((proc.stdout + proc.stderr)[-2000:])
        raise SystemExit("submit 失败")
    run_id = core.run_get(args.task_id, "run_id")
    log(f"run_id={run_id}  https://github.com/{repo}/actions/runs/{run_id}")

    report: Dict[str, Any] = {"run_id": run_id, "repo": repo, "runtime_digests": digests}
    video_ok = False
    pulled = None
    returncode = -1
    entry: Optional[Dict[str, Any]] = None
    try:
        entry = wait_registry(existing["GHA_RENDEZVOUS_ENDPOINT"], existing["GHA_RENDEZVOUS_TOKEN"],
                              run_id, repo=repo, timeout=1800)
        report["registry"] = {"origin_host": entry["origin"].split("://", 1)[-1].split("/")[0],
                              "found": True}
        log(f"Registry 发现入口：{report['registry']['origin_host']}")
    except SystemExit as exc:
        report["registry_error"] = str(exc)

    if args.keep:
        log("--keep：不等待与清理，run 保留供排查")
        print(json.dumps(report, ensure_ascii=False))
        return 0

    if entry is not None:
        pulled, fetched = pull_videos(entry, vault_root, StateClient, InteractiveClient, Vault, timeout=900)
        if pulled is None:
            report["pull_error"] = fetched
        else:
            report["pull"] = {k: v for k, v in pulled.items() if k != "paths"}
            report["ffprobe"] = ffprobe_all(pulled["paths"])
            video_ok = all(item["rc"] == 0 for item in report["ffprobe"])

    proc = gha("wait", run_id, "--timeout", "1800", timeout=1900)
    proc = gha("fetch", args.task_id, "--force")
    result_dir = core.run_dir(args.task_id) / "result"
    report["fetch_rc"] = proc.returncode
    report["result_dir"] = str(result_dir)
    handoff = result_dir / "output" / "handoff-loop.json"
    if handoff.is_file():
        report["handoff_loop"] = json.loads(handoff.read_text(encoding="utf-8"))
    loop_report = result_dir / "output" / "loop-report.json"
    if loop_report.is_file():
        report["remote_report"] = json.loads(loop_report.read_text(encoding="utf-8"))
    returncode = _exit_code(result_dir)

    if not args.keep:
        proc = gha("clean", "--run-id", run_id, "--yes", timeout=300)
        report["cleaned"] = proc.returncode == 0
        log(f"已清理 run {run_id}：rc={proc.returncode}")

    ok = (returncode == 0
          and (report.get("handoff_loop") or {}).get("ok") is True
          and video_ok)
    report["ok"] = ok
    out = runner / ".gha-runs" / args.task_id / "loop-summary.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log(json.dumps({"ok": ok, "run_id": run_id, "exit_code": returncode,
                    "video_ok": video_ok, "summary": str(out)}, ensure_ascii=False))
    return 0 if ok else 1


def _exit_code(result_dir: Path) -> int:
    path = result_dir / "exit_code"
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return -1


def wait_registry(endpoint: str, token: str, run_id: str, repo: str = "",
                  timeout: float = 1800) -> Dict[str, Any]:
    """Host 的发现路径：产品 Registry 客户端 ``resolve_run``（与 CLI 同一实现）。"""
    import asyncio

    from gha_runner.registry import RegistryClient

    client = RegistryClient(endpoint, token, user=repo or None)
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            entry = asyncio.run(client.resolve_run(run_id))
        except Exception as exc:
            entry = None
            last = f"{type(exc).__name__}: {str(exc)[:120]}"
        if entry:
            return entry
        time.sleep(10)
    raise SystemExit(f"Registry 在 {int(timeout)}s 内没有本 run 的会话：{last}")


def pull_videos(entry: Dict[str, Any], vault_root: Path, StateClient, InteractiveClient, Vault,
                timeout: float = 900) -> Any:
    """等到任务生成 DESKTOP 检查点，再按产品路径拉取解密。"""
    origin = entry.get("origin") or ""
    token = entry.get("agent_token") or ""
    if not origin or not token:
        return None, "Registry 记录缺少 origin/agent_token"
    vault = Vault(root_dir=str(vault_root / "pull"))
    client = InteractiveClient(origin, token, timeout=60)
    state = StateClient(client, vault=vault)
    deadline = time.time() + timeout
    objects: List[Dict[str, Any]] = []
    while time.time() < deadline:
        try:
            manifest = client.get("/v1/state/manifest")
        except Exception:
            manifest = {"objects": []}
        objects = [o for o in manifest.get("objects", []) if o.get("category") == "desktop_video"]
        if objects:
            break
        time.sleep(15)
    if not objects:
        return None, "任务结束前没有出现 desktop_video 对象"
    state.export_selected(objects, project="host")
    out = {"videos": [], "paths": [], "plaintext_objects": state.plaintext_objects}
    for obj in objects:
        path = str(vault_root / "pull" / f"{obj['id']}.mp4")
        reader, meta = vault.open_decrypted_binary_object("host", obj["id"])
        if reader is None:
            return None, f"Vault 未存下 {obj['id']}"
        with open(path, "wb") as fh:
            shutil.copyfileobj(reader, fh)
        out["videos"].append({"id": obj["id"], "bytes": os.path.getsize(path),
                              "ciphertext_bytes": obj.get("size"),
                              "encrypted": obj.get("encrypted"), "key_id": obj.get("key_id"),
                              "vault_sha256": meta.sha256 if meta else None})
        out["paths"].append(path)
    return out, ""


def ffprobe_all(paths: List[str]) -> List[Dict[str, Any]]:
    import subprocess

    out = []
    for path in paths:
        probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                                "stream=codec_name:format=duration", "-of", "json", path],
                               capture_output=True, text=True)
        out.append({"file": os.path.basename(path), "rc": probe.returncode,
                    "info": json.loads(probe.stdout or "{}") if probe.returncode == 0 else None})
    return out


def verify_run(argv: Optional[List[str]] = None) -> int:
    """只做 Host 侧复核：Registry 发现 → 产品 StateClient 拉取 → 用本机 Vault 解封 → ffprobe。

    Runner 侧没有、也不该有 Host 私钥，所以"解密后 SHA/时长一致"必须在这里证明。
    输出只含摘要、长度与时长，不含 key_id / 本地路径。
    """
    import argparse
    import hashlib

    ap = argparse.ArgumentParser(description="Host 侧复核某次 run 的加密录像回传")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--repo", default=os.environ.get("GHA_REPO", ""))
    ap.add_argument("--endpoint", default=os.environ.get("GHA_RENDEZVOUS_ENDPOINT", ""))
    ap.add_argument("--token", default=os.environ.get("GHA_RENDEZVOUS_TOKEN", ""))
    ap.add_argument("--vault-root", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--sealed-dir", default="",
                    help="离线复核：直接解封该目录下的 .ghse 密文（隧道不可用时的补证）")
    args = ap.parse_args(argv)

    from gha_runner.interactive_client import InteractiveClient
    from gha_runner.state_client import StateClient
    from gha_runner.vault import Vault

    if args.sealed_dir:
        return verify_sealed(args.sealed_dir, args.run_id, args.vault_root, args.out)

    entry = wait_registry(args.endpoint, args.token, args.run_id, repo=args.repo, timeout=300)
    vault_root = Path(args.vault_root or os.path.expanduser("~/.gha-runner"))
    vault = Vault(root_dir=str(vault_root))
    client = InteractiveClient(entry["origin"], entry["agent_token"], timeout=60)
    state = StateClient(client, vault=vault)
    manifest = client.get("/v1/state/manifest")
    objects = [o for o in manifest.get("objects", []) if o.get("category") == "desktop_video"]
    if not objects:
        print(json.dumps({"ok": False, "error": "no desktop_video object"}, ensure_ascii=False))
        return 1
    state.export_selected(objects, project="host-verify")
    work = vault_root / "host-verify"
    work.mkdir(parents=True, exist_ok=True)
    videos = []
    for obj in objects:
        data, stored = vault.get_binary_object("host-verify", obj["id"])
        if data is None:
            print(json.dumps({"ok": False, "error": "vault miss", "id": obj["id"]}))
            return 1
        path = work / f"{obj['id']}.mp4"
        path.write_bytes(data)
        probe = ffprobe_all([str(path)])[0]
        duration = float(((probe.get("info") or {}).get("format") or {}).get("duration") or 0)
        videos.append({
            "id": obj["id"],
            "encrypted": bool(obj.get("encrypted")),
            "transfer_size": obj.get("size"),
            "transfer_sha256": obj.get("sha256"),
            "plaintext_size": len(data),
            "plaintext_sha256": hashlib.sha256(data).hexdigest(),
            "declared_plaintext_sha256": obj.get("plaintext_sha256"),
            "vault_sha256": getattr(stored, "sha256", None),
            "declared_duration_s": obj.get("duration_seconds"),
            "ffprobe_duration_s": round(duration, 2),
            "ffprobe_rc": probe.get("rc"),
            "path": str(path),
        })
    ok = all(v["encrypted"] and (v["plaintext_size"] or 0) > 0
             and v["plaintext_sha256"] == v["declared_plaintext_sha256"] == v["vault_sha256"]
             and v["ffprobe_rc"] == 0 and v["ffprobe_duration_s"] > 0
             and (v["declared_duration_s"] is None
                  or abs(v["ffprobe_duration_s"] - float(v["declared_duration_s"])) <= 1.0)
             for v in videos)
    report = {"ok": ok, "run_id": args.run_id, "object_count": len(videos),
              "plaintext_objects": state.plaintext_objects,
              "origin_host": str(entry["origin"]).split("://", 1)[-1].split("/", 1)[0],
              "videos": videos}
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(blob + "\n", encoding="utf-8")
    print(blob)
    return 0 if ok else 1


def verify_sealed(sealed_dir: str, run_id: str, vault_root: str, out: str) -> int:
    """解封本地 .ghse 密文（Host 私钥）并核对长度/摘要/时长；不认识的对象一律跳过。"""
    import hashlib

    from gha_runner.state_envelope import decrypt_envelope
    from gha_runner.vault import Vault

    vault = Vault(root_dir=str(Path(vault_root or os.path.expanduser("~/.gha-runner"))))
    pair = vault.state_keypair()
    files = sorted(p for p in Path(sealed_dir).glob("*.ghse") if p.is_file())
    videos = []
    work = Path(sealed_dir)

    def _probe(path: Path):
        import subprocess

        proc = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                               "stream=codec_name:format=duration", "-of", "json", str(path)],
                              capture_output=True, text=True)
        info = json.loads(proc.stdout or "{}") if proc.returncode == 0 else {}
        return proc.returncode, round(float((info.get("format") or {}).get("duration") or 0), 2)

    for path in files:
        if "video" not in path.name:
            continue
        sealed = path.read_bytes()
        plain = decrypt_envelope(pair, sealed)
        plain_path = work / (path.stem + ".plain.mp4")
        plain_path.write_bytes(plain)
        rc, duration = _probe(plain_path)
        try:
            plain_path.unlink()
        except OSError:
            pass
        videos.append({
            "id": path.name[:-5],
            "ciphertext_size": len(sealed),
            "plaintext_size": len(plain),
            "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
            "ffprobe_rc": rc,
            "ffprobe_duration_s": duration,
        })
    ok = bool(videos) and all(v["plaintext_size"] > 0 and v["ffprobe_rc"] == 0
                              and v["ffprobe_duration_s"] > 0 for v in videos)
    report = {"ok": ok, "run_id": run_id, "mode": "offline-sealed-evidence",
              "sealed_dir": str(work), "object_count": len(videos), "videos": videos}
    blob = json.dumps(report, ensure_ascii=False, indent=2)
    if out:
        Path(out).write_text(blob + "\n", encoding="utf-8")
    print(blob)
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "verify-run":
        sys.exit(verify_run(sys.argv[2:]))
    sys.exit(main())
