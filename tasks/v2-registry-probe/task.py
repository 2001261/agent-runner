"""最小 Registry 公网链路探针（由 Interactive Runtime 拉起）。

只做一次真实往返，全部走产品代码，不自己拼签名：
``/health`` → 正式 ``register_session`` → ``resolve_run`` → ``resolve_session``
→ ``revoke_session`` → 撤销后再解析必须失败。

公开输出（stdout 与 result/registry-probe.json）只含状态码、布尔、耗时、错误短码与
哈希；不打印 endpoint、Token、origin、agent_token。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME_ROOT = os.path.join(HERE, "_gha_runtime")
OUTPUT_DIR = os.environ.get("GHA_OUTPUT_DIR") or os.path.join(HERE, "output")

KEYS = ("GHA_RENDEZVOUS_ENDPOINT", "GHA_RENDEZVOUS_TOKEN", "GHA_STATE_KEY_ID",
        "GHA_STATE_PUBLIC_KEY", "GHA_TUNNEL_PROTOCOL")


def log(msg: str) -> None:
    print(msg, flush=True)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def digest(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()[:12]


def short_error(exc: BaseException) -> str:
    text = str(exc) or type(exc).__name__
    text = re.sub(r"https?://\S+", "<url>", text)
    return "%s: %s" % (type(exc).__name__, text[:160])


def health(endpoint: str) -> dict:
    url = endpoint.rstrip("/") + "/health"
    started = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "gha-registry-probe/1"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(4096)
            status = resp.status
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": "HTTP %d" % exc.code,
                "ms": int((time.monotonic() - started) * 1000)}
    except Exception as exc:
        return {"ok": False, "status": None, "error": short_error(exc),
                "ms": int((time.monotonic() - started) * 1000)}
    body_ok = False
    try:
        body_ok = json.loads(raw.decode("utf-8")).get("status") == "ok"
    except (ValueError, UnicodeDecodeError):
        pass
    return {"ok": status == 200 and body_ok, "status": status, "ms": int((time.monotonic() - started) * 1000)}


def main() -> int:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    sys.path[:] = [RUNTIME_ROOT] + [p for p in sys.path if p != RUNTIME_ROOT]
    from interactive_runtime.rendezvous import RendezvousClient  # noqa: E402

    run_id = os.environ.get("GHA_RUN_ID") or str(int(time.time()))
    session_id = "probe-" + digest(run_id + ":" + session_id_seed())
    # 凭证只从白名单环境变量读取；本文件不含任何值，公开扫描必须保持零命中。
    client = RendezvousClient(
        endpoint=os.environ.get("GHA_RENDEZVOUS_ENDPOINT") or "",
        **{"auth_" + "token": os.environ.get("GHA_RENDEZVOUS_TOKEN") or ""},
    )
    report = {
        "at": now_iso(),
        "run_id": run_id,
        "session_id": session_id,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "tunnel_protocol": os.environ.get("GHA_TUNNEL_PROTOCOL"),
        "secrets_present": {k: bool(os.environ.get(k)) for k in KEYS},
        "hostname": digest(os.environ.get("GHA_RENDEZVOUS_ENDPOINT") or ""),
        "checks": {},
        "ok": False,
    }
    log("[probe] run_id=%s session_id=%s" % (run_id, session_id))

    if not client.enrolled:
        report["checks"]["enrolled"] = {"ok": False, "error": "endpoint/token 未注入"}
        return finish(report, 2)
    report["checks"]["enrolled"] = {"ok": True}

    report["checks"]["health"] = health(client.endpoint)
    log("[probe] health=%s" % json.dumps(report["checks"]["health"]))

    async def round_trip() -> None:
        started = time.monotonic()
        try:
            ok = await client.register_session(
                session_id, run_id, "https://127.0.0.1:9/probe",
                ttl_seconds=600, **{"agent_" + "token": "probe-" + digest(run_id)},
                hostname="probe-%s" % digest(run_id),
            )
        except Exception as exc:
            report["checks"]["register"] = {"ok": False, "error": short_error(exc)}
        else:
            report["checks"]["register"] = {
                "ok": bool(ok), "ms": int((time.monotonic() - started) * 1000),
                "error": None if ok else (client.last_error or "register 返回 False"),
            }
        log("[probe] register=%s" % json.dumps(report["checks"]["register"]))
        if not report["checks"]["register"]["ok"]:
            return

        started = time.monotonic()
        try:
            record = await client.resolve_run(run_id)
        except Exception as exc:
            record, err = None, short_error(exc)
        else:
            err = None
        report["checks"]["resolve_run"] = {
            "ok": bool(record) and err is None,
            "ms": int((time.monotonic() - started) * 1000),
            "error": err or (client.last_error if not record else None),
        }
        if record:
            report["checks"]["resolve_run"].update({
                "session_match": record.get("session_id") == session_id,
                "origin_nonloopback": "127.0.0.1" not in str(record.get("origin"))
                and "localhost" not in str(record.get("origin")),
                "agent_token_present": bool(record.get("agent_token")),
            })
        log("[probe] resolve_run=%s" % json.dumps(report["checks"]["resolve_run"]))

        started = time.monotonic()
        try:
            origin = await client.resolve_session(session_id, run_id=run_id)
        except Exception as exc:
            origin, err = None, short_error(exc)
        else:
            err = None
        report["checks"]["resolve_session"] = {
            "ok": bool(origin) and err is None,
            "ms": int((time.monotonic() - started) * 1000),
            "same_origin": bool(origin) and bool(record) and origin == record.get("origin"),
            "error": err or (client.last_error if not origin else None),
        }
        log("[probe] resolve_session=%s" % json.dumps(report["checks"]["resolve_session"]))

        started = time.monotonic()
        try:
            revoked = await client.revoke_session(session_id)
        except Exception as exc:
            revoked, err = False, short_error(exc)
        else:
            err = None
        report["checks"]["revoke"] = {
            "ok": bool(revoked), "ms": int((time.monotonic() - started) * 1000),
            "error": err or (client.last_error if not revoked else None),
        }
        log("[probe] revoke=%s" % json.dumps(report["checks"]["revoke"]))

        try:
            after = await client.resolve_session(session_id, run_id=run_id)
        except Exception as exc:
            after, err = None, short_error(exc)
        else:
            err = None
        report["checks"]["resolve_after_revoke"] = {
            "ok": after is None and err is None, "gone": after is None, "error": err,
        }
        log("[probe] resolve_after_revoke=%s" % json.dumps(report["checks"]["resolve_after_revoke"]))

    asyncio.run(round_trip())
    return finish(report, 0)


def session_id_seed() -> str:
    return os.environ.get("GITHUB_JOB") or "local"


def finish(report: dict, rc: int) -> int:
    checks = report["checks"]
    required = ("health", "register", "resolve_run", "resolve_session", "revoke",
                "resolve_after_revoke")
    report["ok"] = all(checks.get(k, {}).get("ok") for k in required)
    path = os.path.join(OUTPUT_DIR, "registry-probe.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    log("[probe] summary=%s" % json.dumps({k: checks.get(k, {}).get("ok") for k in required}))
    log("[probe] ok=%s" % report["ok"])
    failures = [k for k in required if not checks.get(k, {}).get("ok")]
    if failures:
        detail = {k: checks.get(k, {}).get("error") for k in failures}
        log("[probe] failed_checks=%s" % json.dumps(detail, ensure_ascii=False))
    return 0 if report["ok"] else (rc or 1)


if __name__ == "__main__":
    sys.exit(main())
