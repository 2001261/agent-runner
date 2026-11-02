#!/usr/bin/env python3
"""真实 Runner 侧「接住 Host 上传后修改状态」的最小任务。

由 workflow 以 `interactive_runtime.main --command <本脚本>` 包装启动，Gateway 与
Supervisor 由 Runtime 进程托管。任务流程：
1. 等 Host 通过 /v1/state/import 分块上传的 `upload-resume-e2e` 对象被最终校验；
2. 读取 Runner 实际落盘的字节，追加 Runner 侧标记，写回任务目录；
3. 生成 TASK checkpoint（Runner 侧状态已被修改的物证），供 Host 用 Range 回传；
4. 保持存活，直到 Host ACK 完毕并请求 task/finish。
"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.environ.get("GHA_TASK_DIR", os.getcwd()), "_gha_runtime"))

from gha_runner.interactive_client import InteractiveClient  # noqa: E402

UPLOAD_ID = "upload-resume-e2e"
CHECKPOINT_ID = "resume-e2e"
WAIT_UPLOAD_SECONDS = 1500
WAIT_FINISH_SECONDS = 1800
RESULT: dict = {"completed": False}
OUT = os.path.join(os.environ.get("GHA_OUTPUT_DIR", "./output"))
TASK_DIR = os.environ.get("GHA_TASK_DIR", os.getcwd())


def log(msg):
    print("[resume-hold] %s" % msg, flush=True)


def runtime_storage() -> str:
    """Runtime 私有目录：Gateway 的 transfers/ 与 incoming-index.json 都在这里。"""
    cfg = os.environ.get("GHA_INTERACTIVE_CONFIG_FILE", "")
    if cfg:
        return os.path.dirname(os.path.abspath(cfg))
    return os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "gha-interactive-private")


def wait_gateway() -> InteractiveClient:
    deadline = time.time() + 600
    token = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
    gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
    if not token:
        raise RuntimeError("GHA_INTERACTIVE_TOKEN 未注入")
    client = InteractiveClient(gateway, token, timeout=60)
    while time.time() < deadline:
        try:
            if client.health().get("status") == "ok":
                return client
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError("Gateway 健康检查超时")


def wait_upload() -> dict:
    """轮询 Runner 自己的上传索引，直到 Host 的对象被完整接收并校验。"""
    index_path = os.path.join(runtime_storage(), "transfers", "incoming-index.json")
    deadline = time.time() + WAIT_UPLOAD_SECONDS
    while time.time() < deadline:
        try:
            with open(index_path, "r", encoding="utf-8") as f:
                entry = (json.load(f) or {}).get(UPLOAD_ID) or {}
        except (OSError, ValueError):
            entry = {}
        if entry.get("verified") and entry.get("received_bytes") == entry.get("size"):
            return entry
        time.sleep(2)
    raise RuntimeError("等待 Host 上传的大对象超时")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(os.path.join(TASK_DIR, "state"), exist_ok=True)
    try:
        client = wait_gateway()
        log("Gateway 就绪，等待 Host 上传")
        entry = wait_upload()
        src = os.path.join(runtime_storage(), "transfers", UPLOAD_ID)
        with open(src, "rb") as f:
            received = f.read()
        received_sha = hashlib.sha256(received).hexdigest()
        if received_sha != entry.get("sha256"):
            raise RuntimeError("Runner 落盘摘要与上传声明不一致")
        log("已接收 %d B，准备 Runner 侧修改" % len(received))

        modified = b"RUNNER-MODIFIED:" + received + b":RUNNER-END"
        target = os.path.join(TASK_DIR, "state", "modified.bin")
        with open(target, "wb") as f:
            f.write(modified)
        modified_sha = hashlib.sha256(modified).hexdigest()

        cp = client.post("/v1/state/checkpoint", {
            "type": "TASK", "checkpoint_id": CHECKPOINT_ID,
            "task_state_path": "state/modified.bin",
        })
        obj = (cp.get("checkpoint", {}).get("objects") or [{}])[0]
        RESULT.update({
            "completed": True,
            "uploaded_bytes": len(received),
            "uploaded_sha256": received_sha,
            "modified_bytes": len(modified),
            "modified_sha256": modified_sha,
            "checkpoint_object": obj,
        })
        log("TASK checkpoint 已生成：%s (%s B)" % (obj.get("id"), obj.get("size")))
    except Exception as exc:
        RESULT["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:400])
        log("失败：%s" % RESULT["error"])

    with open(os.path.join(OUT, "phase.json"), "w", encoding="utf-8") as f:
        json.dump(RESULT, f, ensure_ascii=False, indent=2)
    if not RESULT.get("completed"):
        return 1

    try:
        deadline = time.time() + WAIT_FINISH_SECONDS
        while time.time() < deadline:
            state = client.session_status().get("state")
            if state in ("FINISHING", "FINISHED", "SESSION_EXPIRED",
                         "TASK_CANCELLED", "RUNTIME_FAILED"):
                log("会话进入 %s，任务退出" % state)
                break
            time.sleep(3)
        else:
            log("等待 Host 结束请求超时")
            return 1
    except Exception as exc:
        log("等待结束状态失败：%s" % type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
