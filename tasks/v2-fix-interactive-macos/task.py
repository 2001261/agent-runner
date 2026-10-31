#!/usr/bin/env python3
"""Interactive Runtime 端到端演示：真实 Gateway、浏览器、Checkpoint 与 Host ACK。

任何一步失败都返回非零；禁止在 Gateway 不可用时伪造导航或 persisted 状态。
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from gha_runner.interactive_client import InteractiveClient
from gha_runner.state_client import StateClient
from gha_runner.vault import Vault


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg), flush=True)


def main():
    display = os.environ.get("DISPLAY", "")
    gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
    credential = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
    out_dir = Path(os.environ.get("GHA_OUTPUT_DIR", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "display": display,
        "gateway": gateway,
        "navigation": {},
        "checkpoint": {"checkpoint_id": "demo-cp-001", "status": "PENDING"},
        "completed": False,
    }

    try:
        if not credential:
            raise RuntimeError("GHA_INTERACTIVE_TOKEN 未注入，拒绝以离线模拟代替交互验证")
        client = InteractiveClient(gateway, credential, timeout=20)
        health = client.health()
        if health.get("status") != "ok":
            raise RuntimeError("Interactive Gateway 不健康")
        log("Gateway 健康检查通过")

        generation = client.session_status()["generation"]
        nav = client.post("/v1/browser/command", {
            "cmd": "navigate", "url": "https://example.com", "generation": generation,
        })
        if nav.get("title") != "Example Domain":
            raise RuntimeError("真实浏览器导航失败：%s" % nav)
        result["navigation"] = nav
        log("真实 Chromium 导航成功：%s" % nav.get("title"))

        cp = client.post("/v1/state/checkpoint", {
            "type": "AUTH", "checkpoint_id": "demo-cp-001",
        })
        if cp.get("status") != "ok":
            raise RuntimeError("AUTH_CHECKPOINT 创建失败")
        log("AUTH_CHECKPOINT 已创建")

        vault = Vault(root_dir=tempfile.mkdtemp(prefix="gha-demo-vault-"))
        state = StateClient(client, vault=vault)
        exported = state.export_state_to_vault(project="interactive-demo")
        synced = exported.get("synced_objects", [])
        if not synced:
            raise RuntimeError("宿主机 Vault 未收到任何状态对象")

        manifest = state.list_manifest()
        states = {o["id"]: o.get("persistence_state") for o in manifest.get("objects", [])}
        if any(states.get(obj_id) != "PERSISTED" for obj_id in synced):
            raise RuntimeError("Runner 未收到完整 Host ACK：%s" % states)
        result["checkpoint"].update({
            "type": "AUTH_CHECKPOINT",
            "status": "PERSISTED",
            "synced_objects": len(synced),
        })
        result["completed"] = True
        log("宿主机校验、加密落盘与 Runner ACK 闭环完成")
        rc = 0
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:300])
        log("Interactive Demo 失败：%s" % result["error"])
        rc = 1

    (out_dir / "interactive_summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "_outputs.env").write_text(
        "INTERACTIVE_STATUS=%s\nTARGET_TITLE=%s\nCHECKPOINT_STATE=%s\n" % (
            "success" if result["completed"] else "failure",
            result["navigation"].get("title", ""),
            result["checkpoint"]["status"],
        ), encoding="utf-8")
    return rc


if __name__ == "__main__":
    sys.exit(main())
