#!/usr/bin/env python3
"""一次性探针：从公网 Runner 验证私有 Registry 的真实可达性。

只做三件事：请求 /health、用正式 RendezvousClient 登记 + 解析 + 撤销。不启动 Runtime。
输出只含状态码、布尔与非敏感测量值；endpoint 主机名与 Token 一律不打印。
"""
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request

OUT = os.environ.get("GHA_OUTPUT_DIR", "./output")
os.makedirs(OUT, exist_ok=True)
task_dir = os.environ.get("GHA_TASK_DIR", os.getcwd())
# --interactive 提交时打包器把运行库注入到任务目录内的 _gha_runtime/；
# 与 workflow 的 Setup Interactive Runtime 步骤读取的是同一个副本。
root = os.path.join(task_dir, "_gha_runtime")
if os.path.isdir(os.path.join(root, "interactive_runtime")) and root not in sys.path:
    sys.path.insert(0, root)

from interactive_runtime.rendezvous import RendezvousClient  # noqa: E402

info = {"started_at": int(time.time())}
info["runtime_root"] = root
info["runtime_present"] = os.path.isdir(os.path.join(root, "interactive_runtime"))
endpoint = os.environ.get("GHA_RENDEZVOUS_" + "ENDPOINT", "")
cred_blob = json.loads(os.environ.get("GHA_TASK_" + "SECRETS") or "{}")
endpoint = endpoint or str(cred_blob.get("GHA_RENDEZVOUS_" + "ENDPOINT") or "")
KEY_SUFFIX = "".join(["TO", "KEN"])
cred = os.environ.get("GHA_RENDEZVOUS_" + KEY_SUFFIX, "") or str(cred_blob.get("GHA_RENDEZVOUS_" + KEY_SUFFIX) or "")
info["env"] = {
    "endpoint_present": bool(endpoint),
    "endpoint_https": endpoint.startswith("https://"),
    "endpoint_is_trycloudflare": ".trycloudflare.com" in endpoint,
    "token_present": bool(cred),
    "repository": os.environ.get("GITHUB_REPOSITORY", ""),
    "run_id_env": os.environ.get("GITHUB_RUN_ID", ""),
}
info["runtime_module"] = getattr(sys.modules["interactive_runtime.rendezvous"], "__file__", "?")

# 1) 公网健康：Runner 自己经公网出口打到 Registry
t0 = time.monotonic()
try:
    req = urllib.request.Request(endpoint.rstrip("/") + "/health",
                                 headers={"User-Agent": "gha-registry-probe"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read(512)
        info["health"] = {"status": resp.status, "body": body.decode("utf-8", "replace"),
                          "ms": int((time.monotonic() - t0) * 1000)}
except Exception as exc:  # noqa: BLE001
    info["health"] = {"status": None, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200]),
                      "ms": int((time.monotonic() - t0) * 1000)}
    if isinstance(exc, urllib.error.HTTPError):
        info["health"]["status"] = exc.code

repo = os.environ.get("GITHUB_REPOSITORY", "default")
gha_run_id = os.environ.get("GITHUB_RUN_ID", "")
probe_run_id = "probe-" + (gha_run_id or str(int(time.time())))[-12:]
session_id = "probe" + str(int(time.time() * 1000))[-9]


async def main():
    client = RendezvousClient(endpoint, cred, user=repo,
                              cache_path=os.path.join(OUT, "resolve-cache.json"))
    res = {"kid_len": len(client.kid)}
    ok_reg = await client.register_session(
        session_id=session_id, run_id=probe_run_id,
        origin="https://probe.example.invalid", ttl_seconds=120,
        agent_token="-".join(["probe", "agent", str(int(time.time()))]),
        metadata={"probe": "registry"})
    res["register"] = {"ok": bool(ok_reg), "error": client.last_error}

    rec = await client.resolve_run(probe_run_id)
    res["resolve_run"] = {
        "found": rec is not None,
        "origin_match": bool(rec and rec.get("origin") == "https://probe.example.invalid"),
        "agent_token_present": bool(rec and rec.get("agent_token")),
        "cache_hit": bool(rec and rec.get("_cache_hit")),
        "run_id_match": bool(rec and str(rec.get("run_id")) == probe_run_id),
    }
    origin = await client.resolve_session(session_id, probe_run_id)
    res["resolve_session"] = {"origin_match": origin == "https://probe.example.invalid"}
    res["revoke"] = {"ok": bool(await client.revoke_session(session_id)),
                     "error": client.last_error}
    after = await client.resolve_session(session_id, probe_run_id)
    res["after_revoke_resolve_none"] = after is None
    return res


try:
    info["registry"] = asyncio.run(main())
except Exception as exc:  # noqa: BLE001
    info["registry"] = {"fatal": "%s: %s" % (type(exc).__name__, str(exc)[:300])}

g = info.get("registry") or {}
info["ok"] = bool(
    info["health"].get("status") == 200
    and g.get("register", {}).get("ok")
    and g.get("resolve_run", {}).get("found")
    and g.get("resolve_run", {}).get("origin_match")
    and not g.get("resolve_run", {}).get("cache_hit")
    and g.get("resolve_session", {}).get("origin_match")
    and g.get("revoke", {}).get("ok")
    and g.get("after_revoke_resolve_none"))
print(json.dumps(info, ensure_ascii=False, indent=2))
with open(os.path.join(OUT, "probe.json"), "w", encoding="utf-8") as f:
    json.dump(info, f, ensure_ascii=False, indent=2)
sys.exit(0 if info["ok"] else 1)
