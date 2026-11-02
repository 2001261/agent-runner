#!/usr/bin/env python3
"""Profile 跨 Runner 两阶段 E2E（第一段：写入 + FINAL + 等待 Host 回传）。

真实 Chromium 持久化 Profile 中写入可公开的示例 Cookie / localStorage 与一个
Preferences 标记，生成 FINAL checkpoint，然后轮询 manifest 直到 Host 把全部敏感
对象 ACK 为 PERSISTED 再退出。状态不随 Runner 丢失：对象由 Host 拉取并存 Vault。

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
PREF_KEY = "gha_e2e_phase1_marker"
PREF_VALUE = "phase1-pref-ok"
PROFILE_DIR_ENV = "GHA_E2E_PROFILE_DIR"
HOLD_BEFORE_HOLD = 60


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), msg), flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>gha-e2e-page</title></head><body><h1>phase page</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 8766), Handler)
    Thread(target=srv.serve_forever, daemon=True).start()
    return srv


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
    result["profile_dir"] = profile_dir
    srv = start_server()
    try:
        token = os.environ.get("GHA_INTERACTIVE_TOKEN", "")
        gateway = os.environ.get("GHA_INTERACTIVE_GATEWAY", "http://127.0.0.1:8765")
        if not token:
            raise RuntimeError("GHA_INTERACTIVE_TOKEN 未注入")
        client = InteractiveClient(gateway, token, timeout=30)
        if client.health().get("status") != "ok":
            raise RuntimeError("Gateway 不健康")
        result["steps"].append("gateway_ok")
        log("Gateway 健康")

        client.post("/v1/browser/command", {
            "cmd": "navigate", "url": "http://127.0.0.1:8766/",
            "generation": client.session_status()["generation"],
        })
        # 在页面内写入 Cookie / localStorage（同源，首次导航本身已建立 cookie jar）
        client.post("/v1/browser/command", {
            "cmd": "evaluate",
            "script": "document.cookie = '%s=%s; path=/; max-age=86400'; "
                      "localStorage.setItem('%s', 'phase1-local-ok'); 'ok'"
                      % (COOKIE_NAME, COOKIE_VALUE, LOCAL_KEY),
            "generation": client.session_status()["generation"],
        })
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

        prefs_path = Path(profile_dir) / "Default" / "Preferences"
        if not prefs_path.is_file():
            raise RuntimeError("真实 Preferences 文件不存在")
        current = json.loads(prefs_path.read_text(encoding="utf-8") or "{}")
        current[PREF_KEY] = PREF_VALUE
        prefs_path.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
        result["prefs_file_written"] = True
        result["steps"].append("preferences_written")
        log("Preferences 标记已写入真实 Profile 的 Default/Preferences")

        cp = client.post("/v1/state/checkpoint", {"type": "FINAL", "checkpoint_id": "e2e-phase1"})
        if cp.get("status") != "ok":
            raise RuntimeError("FINAL checkpoint 失败：%s" % json.dumps(cp, ensure_ascii=False)[:400])
        objects = cp.get("checkpoint", {}).get("objects", [])
        cats = sorted({o.get("category") for o in objects})
        if "browser_profile" not in cats or "auth_state" not in cats:
            raise RuntimeError("FINAL checkpoint 缺少 browser_profile/auth_state：%s" % cats)
        if not all(o.get("encrypted") and o.get("key_id") for o in objects if o.get("category") != "compatibility_meta"):
            raise RuntimeError("存在未加密的敏感对象")
        result["final_objects"] = [{"id": o["id"], "category": o["category"], "encrypted": o.get("encrypted"),
                                    "key_id": o.get("key_id"), "plaintext_size": o.get("plaintext_size"),
                                    "size": o.get("size")} for o in objects]
        result["steps"].append("final_checkpoint_ok")
        log("FINAL checkpoint 已生成：%s" % cats)

        # 留出 Host 拉取/ACK 的时间窗；仍在轮询确认 PERSISTED
        ok, states = wait_persisted(client, rollout=HOLD_BEFORE_HOLD)
        if not ok:
            log("首次轮询未全部 PERSISTED，继续等待：%s" % states)
            ok, states = wait_persisted(client, rollout=240)
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
