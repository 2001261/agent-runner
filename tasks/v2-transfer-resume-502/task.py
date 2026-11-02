#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.environ.get("GHA_TASK_DIR", os.getcwd()), "_gha_runtime"))
from gha_runner.interactive_client import InteractiveClient


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    out = Path(os.environ.get("GHA_OUTPUT_DIR", "./output"))
    out.mkdir(parents=True, exist_ok=True)
    result = {"completed": False}
    profile = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "gha-interactive-private" / "chrome-profile"
    target = profile / "Default" / "resume-large.bin"
    try:
        client = InteractiveClient(
            os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765"),
            os.environ["GHA_INTERACTIVE_TOKEN"], timeout=180,
        )
        deadline = time.time() + 900
        while time.time() < deadline:
            if target.is_file() and target.stat().st_size >= 20 * 1024 * 1024:
                break
            time.sleep(2)
        else:
            raise RuntimeError("等待 Host 上传的大 Profile 超时")
        result["uploaded_size"] = target.stat().st_size
        with open(target, "r+b") as f:
            f.seek(123)
            f.write(b"GHA-DOWNLOAD-MODIFIED")
        append = b"runner-modified-download-resume" * 4096
        with open(target, "ab") as f:
            for _ in range(4):
                f.write(append)
        result["modified_size"] = target.stat().st_size
        result["modified_sha256"] = sha256_file(target)
        cp = client.post("/v1/state/checkpoint", {"type": "FINAL", "checkpoint_id": "resume-final"})
        if cp.get("status") != "ok":
            raise RuntimeError("FINAL checkpoint 失败")
        objects = cp.get("checkpoint", {}).get("objects", [])
        selected = [o for o in objects if o.get("id") == "obj-profile-resume-final"]
        if len(selected) != 1:
            raise RuntimeError("FINAL 缺少 obj-profile-resume-final")
        result["download_object"] = {
            "size": selected[0].get("size"),
            "plaintext_size": selected[0].get("plaintext_size"),
            "encrypted": selected[0].get("encrypted"),
        }
        deadline = time.time() + 600
        while time.time() < deadline:
            manifest = client.get("/v1/state/manifest")
            obj = next((o for o in manifest.get("objects", [])
                        if o.get("id") == "obj-profile-resume-final"), {})
            if obj.get("persistence_state") == "PERSISTED":
                result["ack"] = "PERSISTED"
                result["completed"] = True
                break
            time.sleep(2)
        if not result["completed"]:
            raise RuntimeError("等待 Host PERSISTED ACK 超时")
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
    (out / "resume-report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "_outputs.env").write_text("RESUME=%s\n" % ("success" if result["completed"] else "failure"), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    sys.exit(main())
