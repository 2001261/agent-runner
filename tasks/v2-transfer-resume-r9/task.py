#!/usr/bin/env python3
"""真实 Runner 侧「接住 Host 上传后修改状态」的最小任务。

由 workflow 以 `interactive_runtime.main --command <本脚本>` 包装启动，Gateway 与
Supervisor 由 Runtime 进程托管。任务流程：
1. 在任务内网随机端口常驻「渠道」（interactive_runtime.channel），口令取本 run 的
   Host Token（secret 注入到环境变量 GHA_RESUME_HOST_TOKEN），公布端口供 Host 经
   Control Gateway 的 /x 反代访问；
2. 等 Host 经渠道 PUT 分块上传的 `upload-resume-e2e` 对象被传输引擎最终校验；
3. 读取 Runner 实际落盘的字节，追加 Runner 侧标记，写回任务目录；
4. 生成 TASK checkpoint（Runner 侧状态已被修改的物证），供 Host 用 Range 回传；
5. 渠道继续存活：Host 下载断线续传 → ACK（含重复 ACK）→ resume_ok，直到 Host 放行停止。
"""
import hashlib
import json
import asyncio
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.environ.get("GHA_TASK_DIR", os.getcwd()), "_gha_runtime"))

from gha_runner.interactive_client import InteractiveClient  # noqa: E402
from interactive_runtime.channel import (  # noqa: E402
    HOST_TOKEN_ENV, NOTE_ACK, NOTE_STOPPED, NOTE_UPLOADED, TaskChannel, token_from_env,
)
from interactive_runtime.transfer import ChunkedTransferEngine  # noqa: E402

UPLOAD_ID = "upload-resume-e2e-r9110317288a91"
CHECKPOINT_ID = "resume-e2e-r9110317"
CATEGORY = "probe_state"
# 渠道端口必须在 run 进行中就能被 Host 知道：Actions 只在 job 结束后才提供日志，
# 读不到「channel 已发布」这一行，所以任务与驱动用同一个固定端口约定。
CHANNEL_PORT = 18765
WAIT_UPLOAD_SECONDS = 1500
WAIT_HOST_SECONDS = 1800
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


def wait_upload(channel: TaskChannel) -> dict:
    """等渠道收满并以引擎真实状态确认上传；不读索引文件、不信任 Host 的声明。"""
    deadline = time.time() + WAIT_UPLOAD_SECONDS
    while time.time() < deadline:
        note = channel.state.reply(NOTE_UPLOADED)
        if isinstance(note, dict) and note.get("bytes"):
            status, _ = channel.engine.incoming_status(
                UPLOAD_ID, note["bytes"], note.get("sha256", ""), CATEGORY)
            if status.get("status") == "complete":
                return note
        time.sleep(0.5)
    raise RuntimeError("等待 Host 经渠道上传的大对象超时")


def _watch_ack(channel: TaskChannel) -> None:
    """Host 的 resume_ok 回执：把引擎真实看到的接收状态一并回给 Host。"""
    state = channel.state
    handled = None
    while state.stopped is None:
        ack = state.get(NOTE_ACK)
        if isinstance(ack, dict) and ack is not handled:
            handled = ack
            note = state.reply(NOTE_UPLOADED) or {}
            size = int(note.get("bytes") or ack.get("upload_bytes") or 0)
            status, _ = channel.engine.incoming_status(
                UPLOAD_ID, size, ack.get("upload_sha256") or note.get("sha256", ""), CATEGORY)
            current = state.get("resume-e2e-current")
            state.note(NOTE_ACK, dict(ack, runner_upload=status.get("status"),
                                      runner_received=status.get("received"),
                                      runner_progress=(current or {}).get("received")))
        time.sleep(0.5)


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(os.path.join(TASK_DIR, "state"), exist_ok=True)
    channel = None
    try:
        client = wait_gateway()
        host_token = token_from_env()
        if not host_token:
            raise RuntimeError("%s 未注入：本 run 没有可用的渠道口令" % HOST_TOKEN_ENV)
        engine = ChunkedTransferEngine(storage_dir=os.path.join(runtime_storage(), "transfers"))
        channel = TaskChannel(engine, host_token, run_id=os.environ.get("GITHUB_RUN_ID", ""),
                              port=int(os.environ.get("GHA_E2E_CHANNEL_PORT") or CHANNEL_PORT))
        manifest = _start_channel(channel)
        # 清单同时进容器日志：Host 读不到渠道时也能从 artifact 日志核对端口
        log("channel 已发布：%s" % json.dumps(manifest, sort_keys=True))
        threading.Thread(target=_watch_ack, args=(channel,), daemon=True).start()

        note = wait_upload(channel)
        src = os.path.join(runtime_storage(), "transfers", UPLOAD_ID)
        with open(src, "rb") as f:
            received = f.read()
        received_sha = hashlib.sha256(received).hexdigest()
        if received_sha != note.get("sha256"):
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
            "channel_port": manifest["port"],
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
        if channel is not None:
            _stop_channel(channel)
        return 1

    try:
        stopped = _wait_channel(channel, WAIT_HOST_SECONDS, WAIT_HOST_SECONDS)
        RESULT["stopped"] = stopped
        RESULT["ack"] = channel.state.reply(NOTE_ACK)
        RESULT["stopped_note"] = channel.state.reply(NOTE_STOPPED)
        with open(os.path.join(OUT, "phase.json"), "w", encoding="utf-8") as f:
            json.dump(RESULT, f, ensure_ascii=False, indent=2)
        log("渠道停止：%s；ACK 回执 runner_upload=%s runner_received=%s" % (
            stopped, (RESULT["ack"] or {}).get("runner_upload"),
            (RESULT["ack"] or {}).get("runner_received")))
        if stopped.get("reason") not in ("host-request",):
            return 1
    except Exception as exc:
        log("渠道等待失败：%s" % type(exc).__name__)
        return 1
    finally:
        if channel is not None:
            _stop_channel(channel)

    try:
        deadline = time.time() + WAIT_HOST_SECONDS
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


def _start_channel(channel: TaskChannel) -> dict:
    """渠道的事件循环跑在独立线程：任务主线程要阻塞等阶段，不能被渠道自己的服务卡住。"""
    loop = _LOOP[0]
    if loop is None:
        loop = asyncio.new_event_loop()
        threading.Thread(target=loop.run_forever, daemon=True).start()
        _LOOP[0] = loop
    return asyncio.run_coroutine_threadsafe(channel.start(), loop).result(60)


def _stop_channel(channel: TaskChannel) -> None:
    loop = _LOOP[0]
    if loop is not None:
        asyncio.run_coroutine_threadsafe(channel.stop(), loop).result(60)


def _wait_channel(channel: TaskChannel, upload_timeout: float, stop_timeout: float) -> dict:
    loop = _LOOP[0]
    return asyncio.run_coroutine_threadsafe(
        channel.wait_async(upload_timeout=upload_timeout, stop_timeout=stop_timeout),
        loop).result(stop_timeout + 60)


_LOOP: list = [None]


if __name__ == "__main__":
    sys.exit(main())
