#!/usr/bin/env python3
"""Profile 跨 Runner 两阶段 E2E（第一段：写入 + FINAL + 等待 Host 回传）。

真实 Chromium 持久化 Profile 中写入可公开的示例 Cookie / localStorage 与一个
下载偏好，生成 FINAL checkpoint，然后轮询 manifest 直到 Host 把全部敏感
对象 ACK 为 PERSISTED 再退出。状态不随 Runner 丢失：对象由 Host 拉取并存 Vault。

下载偏好不靠运行时配置“预置”来充数：
1. 任务在自己的隔离目录里发起一次真实下载，文件必须出现在该目录（证明偏好生效）；
2. 再注册一条 CDP 下载路由，让定稿前的下载都走验收目录；这只对本次 Chromium 进程
   生效，域级偏好会随 Profile 持久化，由阶段 2 在全新进程里验证。
实测（本机 + 云端 run 42613650131）：Browser.setDownloadBehavior 返回 {}，且关闭后
Default/Preferences 里根本不会出现 download 段，所以不存在“写文件标记”的路径。

公开日志只输出布尔/计数，不输出 Cookie 值。
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

# 交互模式下 interpreter 在 GHA_TASK_DIR 里运行，运行库副本在 _gha_runtime 下
sys.path.insert(0, os.path.join(os.environ.get("GHA_TASK_DIR", os.getcwd()), "_gha_runtime"))

from gha_runner.interactive_client import InteractiveClient  # noqa: E402

COOKIE_NAME = "gha_e2e_public"
COOKIE_VALUE = "sample-not-a-credential"
LOCAL_KEY = "gha_e2e_local"
PREF_KEY = "download.default_directory"
PREF_VALUE = "/tmp/gha-e2e-phase1-downloads"
LOCAL_DOWNLOAD_NAME = "phase1-local-download.bin"
LOCAL_DOWNLOAD_BODY = b"phase1-local-download-ok\n"
PROFILE_DIR_ENV = "GHA_E2E_PROFILE_DIR"
HOLD_BEFORE_HOLD = 60


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg), flush=True)


TASK_STATE_DIR = "task-state"
TASK_STATE_FILE = "progress.txt"
PERIODIC_LEAD = 10


class Handler(BaseHTTPRequestHandler):
    # Gateway 只暴露 navigate / storage_state / snapshot / screenshot，没有 evaluate。
    # 因此同源写入走真实 HTTP 响应：服务器 Set-Cookie 种 Cookie，页面内联脚本写 localStorage。
    PAGE = (b"<html><head><title>gha-e2e-page</title></head><body><h1>phase page</h1>"
            b"<script>localStorage.setItem('gha_e2e_local','phase1-local-ok');</script>"
            b"</body></html>")

    def do_GET(self):
        if self.path.startswith("/file/"):
            if self.path == "/file/" + LOCAL_DOWNLOAD_NAME:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(LOCAL_DOWNLOAD_BODY)))
                self.end_headers()
                self.wfile.write(LOCAL_DOWNLOAD_BODY)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        if self.path.startswith("/download"):
            # 真实页面点击触发的下载（用户手势路径），证明下载偏好确实生效
            body = (b"<html><head><title>gha-e2e-download</title></head><body>"
                    b"<a id='dl' href='/file/%s' download='%s'>dl</a>"
                    b"<script>document.getElementById('dl').click();</script></body></html>"
                    % (LOCAL_DOWNLOAD_NAME.encode(), LOCAL_DOWNLOAD_NAME.encode()))
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        body = self.PAGE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie",
                         "%s=%s; Path=/; Max-Age=86400" % (COOKIE_NAME, COOKIE_VALUE))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 8766), Handler)
    Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def periodic_interval(client):
    """读取运行时配置里的定时检查点间隔（0 表示未启用）。"""
    res = client.get("/v1/session") or {}
    persistence = ((res.get("config") or {}).get("persistence") or {})
    if "checkpoint_interval_seconds" in persistence:
        return int(persistence.get("checkpoint_interval_seconds") or 0)
    text = os.environ.get("GHA_INTERACTIVE_CONFIG_FILE", "")
    try:
        cfg = json.loads(Path(text).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    return int(((cfg.get("persistence") or {}).get("checkpoint_interval_seconds")) or 0)


def persisted_marker(prefs_path):
    """Preferences 中 download.default_directory 的持久值（只记录事实，不参与通过判定）。"""
    try:
        prefs = json.loads(Path(prefs_path).read_text(encoding="utf-8") or "{}")
    except (OSError, ValueError):
        return None
    return (prefs.get("download") or {}).get("default_directory")


def write_task_state(out_dir, note):
    """写任务状态文件；返回相对任务目录的路径（GATEWAY 只接受任务目录内的路径）。"""
    base = Path(os.environ.get("GHA_TASK_DIR", os.getcwd()))
    target = base / TASK_STATE_DIR
    target.mkdir(parents=True, exist_ok=True)
    (target / TASK_STATE_FILE).write_text(
        json.dumps({"note": note, "at": int(time.time())}) + "\n", encoding="utf-8")
    return "%s/%s" % (TASK_STATE_DIR, TASK_STATE_FILE)


def wait_periodic(client, interval, lead=PERIODIC_LEAD):
    """等到定时检查点至少生成一个对象；返回 (等待秒数, 定时对象 ID 列表)。"""
    deadline = time.time() + max(60, interval + lead + 45)
    waited = 0
    while time.time() < deadline:
        manifest = client.get("/v1/state/manifest")
        ids = sorted(o["id"] for o in manifest.get("objects", [])
                     if str(o.get("id", "")).startswith("obj-task-periodic-"))
        if ids:
            return waited, ids
        time.sleep(3)
        waited += 3
    raise RuntimeError("等待定时检查点对象超时（interval=%ss）" % interval)


def wait_persisted(client, rollout=120):
    deadline = time.time() + rollout
    last = {}
    while time.time() < deadline:
        manifest = client.get("/v1/state/manifest")
        objects = [o for o in manifest.get("objects", []) if o.get("category") != "compatibility_meta"]
        last = {o["id"]: o.get("persistence_state") for o in objects}
        if objects and all(v == "PERSISTED" for v in last.values()):
            return True, last
        time.sleep(3)
    return False, last


def main():
    out_dir = Path(os.environ.get("GHA_OUTPUT_DIR", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)
    result = {"phase": "phase1", "completed": False, "steps": []}
    rc = 1
    profile_dir = os.environ.get(PROFILE_DIR_ENV) or os.path.join(
        os.environ.get("RUNNER_TEMP", "/tmp"), "gha-interactive-private", "chrome-profile")
    prefs_path = Path(profile_dir) / "Default" / "Preferences"
    result["profile_dir"] = profile_dir
    local_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "gha-e2e-local-downloads"
    local_dir.mkdir(parents=True, exist_ok=True)
    srv = start_server()
    try:
        token = os.environ.get("GHA_INTERACTIVE_" + "TOKEN", "")
        gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
        if not token:
            raise RuntimeError("GHA_INTERACTIVE_TOKEN 未注入")
        client = InteractiveClient(gateway, token, timeout=30)
        if client.health().get("status") != "ok":
            raise RuntimeError("Gateway 不健康")
        result["steps"].append("gateway_ok")
        log("Gateway 健康")

        # Cookie 由服务端 Set-Cookie 种下，localStorage 由页面内联脚本写入 —— 都发生在真实导航里
        nav1 = client.post("/v1/browser/command", {
            "cmd": "navigate", "url": "http://127.0.0.1:8766/",
            "generation": client.session_status()["generation"],
        })
        if nav1.get("title") != "gha-e2e-page":
            raise RuntimeError("首次导航未到达测试页：title=%r" % nav1.get("title"))
        nav2 = client.post("/v1/browser/command", {
            "cmd": "navigate", "url": "http://127.0.0.1:8766/again",
            "generation": client.session_status()["generation"],
        })
        title = nav2.get("title", "")
        st = client.post("/v1/browser/command", {
            "cmd": "storage_state", "generation": client.session_status()["generation"],
        }).get("storage_state") or {}
        names = {c.get("name") for c in st.get("cookies") or []}
        origins = {o.get("origin") for o in st.get("origins") or []}
        result["cookie_visible_in_page"] = COOKIE_NAME in names
        result["local_origin_present"] = any("127.0.0.1:8766" in (o or "") for o in origins)
        if title != "gha-e2e-page" or COOKIE_NAME not in names:
            raise RuntimeError("页面写入后 Cookie 未生效：title=%r cookie_present=%s" % (title, result["cookie_visible_in_page"]))
        result["steps"].append("page_writes_ok")
        log("同源 Cookie 与 localStorage 已在页面生效（值不回显）")

        # 真实下载证据：先把下载偏好设到隔离目录，再在页面里点击 <a download>。两次都是
        # 真实页面操作，不靠 Host/任务侧“预置配置”来充数。
        local_target = local_dir / LOCAL_DOWNLOAD_NAME
        if local_target.exists():
            local_target.unlink()
        cdp = client.post("/v1/browser/command", {
            "cmd": "set_download_behavior", "download_directory": str(local_dir), "behavior": "allow",
            "generation": client.session_status()["generation"],
        })
        if cdp.get("status") != "ok":
            raise RuntimeError("经 Gateway 设置下载偏好失败：%s" % json.dumps(cdp, ensure_ascii=False)[:300])
        result["prefs_engine_ack"] = isinstance(cdp.get("cdp"), dict) and "error" not in cdp["cdp"]
        if not result["prefs_engine_ack"]:
            raise RuntimeError("Chromium 未确认下载偏好设置：%s" % json.dumps(cdp, ensure_ascii=False)[:300])
        client.post("/v1/browser/command", {
            "cmd": "navigate", "url": "http://127.0.0.1:8766/download",
            "generation": client.session_status()["generation"],
        })
        deadline = time.time() + 60
        while time.time() < deadline and not local_target.is_file():
            time.sleep(2)
        result["local_download"] = {
            "target": str(local_target),
            "present": local_target.is_file(),
            "size": local_target.stat().st_size if local_target.is_file() else 0,
            "expected_size": len(LOCAL_DOWNLOAD_BODY),
        }
        if not (result["local_download"]["present"]
                and result["local_download"]["size"] == len(LOCAL_DOWNLOAD_BODY)):
            raise RuntimeError("真实下载未落到下载偏好指定的目录：%s"
                               % json.dumps(result["local_download"], ensure_ascii=False))
        result["steps"].append("local_download_ok")
        log("Chromium 真实下载已落到偏好目录（size_match=True）")

        # 定稿前的下载一律走验收目录。实测该 CDP 调用不会写进 Default/Preferences，
        # 所以这里只记录事实；Preferences 是否真的随 Profile 恢复，由阶段 2 的真实下载判定。
        cdp = client.post("/v1/browser/command", {
            "cmd": "set_download_behavior", "download_directory": PREF_VALUE, "behavior": "allow",
            "generation": client.session_status()["generation"],
        })
        if cdp.get("status") != "ok":
            raise RuntimeError("经 Gateway 设置验收下载目录失败：%s" % json.dumps(cdp, ensure_ascii=False)[:300])
        result["prefs_file_marker"] = persisted_marker(prefs_path) == PREF_VALUE
        result["steps"].append("preferences_set_in_engine")
        log("Chromium 已确认持有验收下载目录（进程内）")

        timer_interval = periodic_interval(client)
        result["periodic_interval_seconds"] = timer_interval
        task_state = write_task_state(out_dir, "phase1-final")
        if timer_interval:
            # 定时检查点在任务期间至少真实生成一次 TASK checkpoint（加密对象随后由 Host 取回）
            wait, ids = wait_periodic(client, timer_interval)
            result["periodic_wait_seconds"] = wait
            result["periodic_objects"] = ids
            result["steps"].append("periodic_task_checkpoint_ok")
            log("定时检查点已生成并加密注册：%s" % ids)
        cp_task = client.post("/v1/state/checkpoint", {"type": "TASK", "checkpoint_id": "e2e-phase1-task",
                                                       "task_state_path": task_state})
        if cp_task.get("status") != "ok":
            raise RuntimeError("TASK checkpoint 失败：%s" % json.dumps(cp_task, ensure_ascii=False)[:400])
        task_objects = cp_task.get("checkpoint", {}).get("objects", [])
        # 清单刻意不回显 key_id（它是注册凭证值），密文是否存在由 encrypted 与 Host 解封证明
        result["task_objects"] = [{"id": o["id"], "category": o.get("category"), "encrypted": o.get("encrypted"),
                                   "plaintext_size": o.get("plaintext_size"),
                                   "size": o.get("size")} for o in task_objects]
        if not task_objects or not all(o.get("encrypted") for o in task_objects):
            raise RuntimeError("TASK checkpoint 没有产出加密对象")
        result["steps"].append("task_checkpoint_ok")
        log("TASK checkpoint 已生成：%s" % [o["id"] for o in task_objects])

        # 任务状态在生成 FINAL 前更新：归档与加密回传的都是最终版本
        task_state = write_task_state(out_dir, "phase1-before-final")
        cp = client.post("/v1/state/checkpoint", {"type": "FINAL", "checkpoint_id": "e2e-phase1"})
        if cp.get("status") != "ok":
            raise RuntimeError("FINAL checkpoint 失败：%s" % json.dumps(cp, ensure_ascii=False)[:400])
        objects = cp.get("checkpoint", {}).get("objects", [])
        cats = sorted({o.get("category") for o in objects})
        if "browser_profile" not in cats or "auth_state" not in cats:
            raise RuntimeError("FINAL checkpoint 缺少 browser_profile/auth_state：%s" % cats)
        if not all(o.get("encrypted") for o in objects if o.get("category") != "compatibility_meta"):
            raise RuntimeError("存在未加密的敏感对象")
        # key_id 本身是 GHA_STATE_KEY_ID 这个注册 secret 的字面值，公开记录里根本不带；
        # 只保留"信封是否带 key"的布尔，足以证明加密路径生效。
        result["final_objects"] = [{"id": o["id"], "category": o["category"], "encrypted": o.get("encrypted"),
                                    "has_key_id": bool(o.get("key_id") or o.get("key_fingerprint")),
                                    "plaintext_size": o.get("plaintext_size"),
                                    "size": o.get("size")} for o in objects]
        result["steps"].append("final_checkpoint_ok")
        log("FINAL checkpoint 已生成：%s" % cats)

        # 留出 Host 拉取/ACK 的时间窗；仍在轮询确认 PERSISTED（FINAL 与 TASK 全部对象）
        ok, states = wait_persisted(client, rollout=HOLD_BEFORE_HOLD)
        if not ok:
            log("首次轮询未全部 PERSISTED，继续等待：%s" % states)
            ok, states = wait_persisted(client, rollout=300)
        result["persistence"] = states
        if not ok:
            raise RuntimeError("等待 Host PERSISTED ACK 超时：%s" % json.dumps(states))
        result["steps"].append("host_persisted_ok")
        log("Host 已对全部敏感对象回复 PERSISTED：%s" % sorted(states))
        result["completed"] = True
        rc = 0
    except Exception as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:500])
        log("Phase1 失败：%s" % result["error"])
    finally:
        srv.shutdown()
        (out_dir / "phase1.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        (out_dir / "_outputs.env").write_text(
            "PHASE1=%s\nFINAL_OBJECTS=%d\n" % ("success" if result["completed"] else "failure",
                                               len(result.get("final_objects") or [])), encoding="utf-8")
    return rc


if __name__ == "__main__":
    sys.exit(main())
