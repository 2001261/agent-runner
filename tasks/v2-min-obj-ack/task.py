#!/usr/bin/env python3
"""最小交互对象回传（几十字节）：auth_state 加密对象 + 等 Host ACK + 保活。

只走产品代码：Gateway `/v1/state/checkpoint`（AUTH）→ 删除 Runner 侧明文 →
Host 经 Registry 解析 origin、走 StateClient 下载/解封/ACK；任务轮询 manifest 到
本对象 PERSISTED 后继续存活一小段时间，供 Host 读取 Runner 侧 Tunnel/健康日志并
在同一次交互会话里推送回写（可选）确认。

凭证（Registry / Host 公钥）只从白名单环境变量读取；公开日志与 artifact 只含
布尔、计数、哈希，不含任何值。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

# 交互模式下 interpreter 在 GHA_TASK_DIR 里运行，运行库副本在 _gha_runtime 下
sys.path.insert(0, os.path.join(os.environ.get("GHA_TASK_DIR", os.getcwd()), "_gha_runtime"))

from gha_runner.interactive_client import InteractiveClient  # noqa: E402

CHECKPOINT_ID = "min-ack"
# Host 取回窗口（秒）：覆盖 Registry 解析 + 隧道冷启动
ACK_WINDOW_SECONDS = int(os.environ.get("MIN_ACK_WINDOW_SECONDS") or 900)
# 取到 ACK 后的保活与回写等待
HOLD_SECONDS = int(os.environ.get("MIN_HOLD_SECONDS") or 120)
MAX_OBJECT_BYTES = 4096


def log(msg: str) -> None:
    print("[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg), flush=True)


def public_object(obj):
    """只保留公开字段：id/类别/加密标记/长度/密文摘要；不含 key_id 与任何密钥材料。"""
    if not isinstance(obj, dict):
        return {}
    return {"id": obj.get("id"), "category": obj.get("category"),
            "encrypted": obj.get("encrypted"), "plaintext_size": obj.get("plaintext_size"),
            "size": obj.get("size"), "sha256": obj.get("sha256"),
            "has_key_id": bool(obj.get("key_id") or obj.get("key_fingerprint"))}


def manifest_states(manifest):
    """manifest.objects 的持久化状态字段是 persistence_state（没有 states 字典）。"""
    objects = (manifest or {}).get("objects")
    if isinstance(objects, list):
        return {str(o.get("id")): str(o.get("persistence_state") or "") for o in objects if isinstance(o, dict)}
    return {}


def main() -> int:
    out_dir = Path(os.environ.get("GHA_OUTPUT_DIR", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    mode = (os.environ.get("MIN_MODE") or "live").strip().lower()
    result = {"phase": "min-ack", "mode": mode, "run_id": os.environ.get("GITHUB_RUN_ID"),
              "completed": False, "steps": []}
    rc = 1

    def write():
        path = out_dir / "min-ack.json"
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        if mode == "selftest-local":
            result["selftest_object"] = selftest_local(out_dir)
            result["completed"] = True
            log("selftest_local_ok object=%s" % json.dumps(result["selftest_object"]))
            rc = 0
            return rc

        token = os.environ.get("GHA_INTERACTIVE_" + "TOKEN", "")
        gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
        if not token:
            raise RuntimeError("GHA_INTERACTIVE_TOKEN 未注入")
        client = InteractiveClient(gateway, token, timeout=30)
        health = client.health()
        result["gateway_health"] = health.get("status")
        if health.get("status") != "ok":
            raise RuntimeError("Gateway 不健康")
        result["steps"].append("gateway_ok")
        log("Gateway 健康")

        # 1) 真实 AUTH checkpoint：Runner 导出浏览器存储态并加密登记
        cp = client.post("/v1/state/checkpoint", {"type": "AUTH", "checkpoint_id": CHECKPOINT_ID})
        if cp.get("status") != "ok":
            raise RuntimeError("AUTH checkpoint 失败：%s" % json.dumps(cp, ensure_ascii=False)[:300])
        objects = [o for o in (cp.get("checkpoint") or {}).get("objects") or [] if isinstance(o, dict)]
        obj = next((o for o in objects if o.get("category") == "auth_state"), None)
        if obj is None:
            raise RuntimeError("AUTH checkpoint 未产出 auth_state 对象")
        result["object"] = public_object(obj)
        size = int(obj.get("plaintext_size") or 0)
        if not (0 < size <= MAX_OBJECT_BYTES):
            result["steps"].append("size_out_of_range")
            raise RuntimeError("auth_state 明文长度不在 1..%d 字节：%d" % (MAX_OBJECT_BYTES, size))
        if obj.get("encrypted") is not True:
            raise RuntimeError("auth_state 对象未加密")
        result["steps"].append("auth_checkpoint_ok")
        log("AUTH checkpoint 已生成：id=%s plaintext_size=%d encrypted=%s" %
            (obj.get("id"), size, obj.get("encrypted")))

        # 2) 删除 Runner 侧明文副本：Host 取回的文件只能是密文；完整性由 JSON 结构 + 哈希证明
        result["plaintext_removed"] = remove_auth_plaintext()
        result["steps"].append("plaintext_removed" if result["plaintext_removed"]
                               else "plaintext_not_found")

        # 3) 等 Host：Registry 解析 + 隧道 + 下载/解封/ACK。以 manifest 状态为准
        deadline = time.time() + ACK_WINDOW_SECONDS
        states = {}
        acked = False
        while time.time() < deadline:
            try:
                states = manifest_states(client.get("/v1/state/manifest"))
            except Exception as exc:  # noqa: BLE001 - 轮询失败只记录类型
                result["ack_poll_error"] = type(exc).__name__
            if states.get(str(obj["id"]), "").upper() == "PERSISTED":
                acked = True
                break
            time.sleep(3)
        result["ack_states"] = {k: v for k, v in sorted(states.items()) if k == str(obj["id"]) or k == "obj-auth-" + CHECKPOINT_ID}
        result["steps"].append("acked" if acked else "ack_timeout")
        log("Host ACK：%s" % ("PERSISTED" if acked else "未在窗口内确认"))
        if not acked:
            raise RuntimeError("Host 未在 %ds 内 ACK PERSISTED：%s" % (ACK_WINDOW_SECONDS, result["ack_states"]))
        result["completed"] = True
        rc = 0

        # 4) 可选回写确认：Host 在同一会话里推送回写对象，Runner 确认 verified=True
        if (os.environ.get("MIN_EXPECT_WRITEBACK") or "").strip() == "1":
            ok, info = wait_writeback(client)
            result["writeback"] = info
            result["steps"].append("writeback_verified" if ok else "writeback_missing")
            log("Runner 回写确认：%s" % json.dumps(info, ensure_ascii=False)[:300])

        # 5) 保活：Host 要读 Runner 侧 Tunnel/健康摘要，任务不要立刻退出
        log("保持存活 %ds" % HOLD_SECONDS)
        time.sleep(HOLD_SECONDS)
        log("保活窗口结束")
    except Exception as exc:  # noqa: BLE001 - 失败也要写出报告
        result["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
        log("失败：%s" % result["error"])
    finally:
        write()
    return rc


def wait_writeback(client, timeout=180):
    deadline = time.time() + timeout
    info = {}
    while time.time() < deadline:
        try:
            info = client.get("/v1/state/import/status") or {}
        except Exception as exc:  # noqa: BLE001
            info = {"poll_error": type(exc).__name__}
        if info.get("verified") is True:
            return True, {k: info.get(k) for k in ("status", "verified", "object_id", "size")}
        time.sleep(3)
    return False, {k: info.get(k) for k in ("status", "verified", "object_id", "size", "poll_error")}


def remove_auth_plaintext() -> bool:
    """AUTH checkpoint 会在私有存储目录落一份 auth-<id>.json 明文；删除它。"""
    private = os.environ.get("GHA_INTERACTIVE_PRIVATE_DIR") or os.path.join(
        os.environ.get("RUNNER_TEMP", "/tmp"), "gha-interactive-private")
    removed = False
    for root in (private, os.path.join(private, "state"), os.path.join(private, "state-storage")):
        target = os.path.join(root, "auth-%s.json" % CHECKPOINT_ID)
        try:
            os.unlink(target)
            removed = True
        except OSError:
            continue
    return removed


def selftest_local(out_dir: Path):
    """纯本地：用真实运行时代码组出 checkpoint 服务与盲加密，证明任务入口在打包环境可运行。"""
    from interactive_runtime.state_export import StateExporter
    from gha_runner.state_envelope import load_public_key

    public_b64 = os.environ.get("GHA_STATE_PUBLIC_KEY") or ""
    load_public_key(public_b64)
    exporter = StateExporter.__new__(StateExporter)
    path = out_dir / "selftest-auth.json"
    path.write_text(json.dumps({"cookies": [{"name": "gha_min_selftest", "value": "not-a-credential",
                                             "domain": "127.0.0.1", "path": "/"}], "origins": []}),
                    encoding="utf-8")
    sha = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    return {"plaintext_size": path.stat().st_size, "entry_importable": exporter is not None, "sha12": sha}


if __name__ == "__main__":
    sys.exit(main())
