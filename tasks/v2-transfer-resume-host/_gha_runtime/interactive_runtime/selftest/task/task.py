"""Interactive Runtime 真实链路自查（真实 Runner 内执行）。

打包时本目录就是任务根目录（``gha submit`` 的 task_dir）；``_gha_runtime`` 随包注入。
包内只有 ``static/browsers.json``（几百字节：固定版本的 URL + SHA-256 + 长度 + 可执行
文件摘要）—— 官方 noVNC / Playwright Chromium / jsdom 在 **Runner 侧** 按固定版本下载、
校验后解包（浏览器包 100MB+，打进任务包会被 GitHub 单文件上限拒绝，`git push` 直接失败）。

Runtime（产品 Supervisor：Xvfb + Chromium + Gateway + Tunnel + 私有 Registry 注册）由执行
workflow 用 ``interactive_runtime.main --command`` 拉起本文件，因此这里做四件事：

1. 下载并校验静态件，安装到 Playwright 认的目录（本进程随后启动的浏览器都用它）；
2. 人工端（同一 DISPLAY 上第二个浏览器）打开真实门户，经官方 noVNC 接管：
   真实点击/键入、原生对话框、交还控制权，Agent 用 xdotool 证明输入已回到自己手里；
3. DESKTOP 检查点把录像用 X25519+HKDF+AES-256-GCM 封套加密登记回传；
4. 经私有 Registry 发现本 run 的 Gateway（Host 的同一发现路径），用产品 StateClient
   重新下载、解封并核对 SHA-256 / 长度 / 时长 / 帧数，结论写进 loop-report.json。
"""

from __future__ import annotations

import asyncio
import glob
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME_ROOT = os.path.join(HERE, "_gha_runtime")
OUTPUT_DIR = os.environ.get("GHA_OUTPUT_DIR") or os.path.join(HERE, "output")


def log(msg: str) -> None:
    print(f"[loop-e2e] {msg}", flush=True)


def under_runtime() -> bool:
    """True：由 Runtime 拉起（运行中的 Gateway 可用）；False：任务入口外层进程。"""
    return bool(os.environ.get("GHA_INTERACTIVE_GATEWAY")
                and os.environ.get("GHA_INTERACTIVE_TOKEN"))


def static_root() -> str:
    root = os.path.join(HERE, "static")
    if not os.path.isdir(root):
        raise SystemExit("任务包缺少 static/（提交前先运行 selftest.bundle 生成）")
    return root


def extract(name: str, dest: str, strip_prefix: str = "") -> None:
    """解 tar.gz 到 dest；strip_prefix 去掉 npm 包自带的 ``package/`` 顶层。"""
    root = os.path.realpath(dest)
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(name, "r:gz") as tf:
        for member in tf.getmembers():
            rel = member.name
            if strip_prefix:
                if not rel.startswith(strip_prefix):
                    continue
                rel = rel[len(strip_prefix):]
            if not rel:
                continue
            target = os.path.realpath(os.path.join(dest, rel))
            if target != root and not target.startswith(root + os.sep):
                raise SystemExit(f"静态件条目越界：{member.name}")
            member.name = rel
            tf.extract(member, dest)


def _bundle_mod():
    """按文件路径加载包内的 bundle.py（任务包里它是独立模块，不必在 sys.path 上）。"""
    import importlib.util

    path = os.path.join(RUNTIME_ROOT, "interactive_runtime", "selftest", "bundle.py")
    spec = importlib.util.spec_from_file_location("gha_selftest_bundle", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def fetch_static(manifest: dict) -> dict:
    """Runner 侧按清单下载官方件并校验（SHA-256 + 长度），失败即如实退出。"""
    mod = _bundle_mod()
    work = os.environ.get("RUNNER_TEMP", "/tmp")
    return mod.fetch_static(manifest, os.path.join(work, "gha-selftest-downloads"), log=log)


def install_browsers(fetched: dict) -> dict:
    mod = _bundle_mod()
    work = os.environ.get("RUNNER_TEMP", "/tmp")
    return mod.install_browsers(fetched, os.path.join(work, "gha-selftest-browsers"), log=log)


def prepare_static(fetched: dict) -> dict:
    work = os.environ.get("RUNNER_TEMP", "/tmp")
    files = (fetched or {}).get("files") or {}

    novnc = os.path.join(work, "gha-novnc")
    shutil.rmtree(novnc, ignore_errors=True)
    extract(files["novnc"]["path"], novnc, strip_prefix="package/")
    if not os.path.isfile(os.path.join(novnc, "core", "rfb.js")):
        raise SystemExit("noVNC 包解出来没有 core/rfb.js")

    node_modules = os.path.join(work, "gha-selftest-node", "node_modules")
    shutil.rmtree(os.path.dirname(node_modules), ignore_errors=True)
    os.makedirs(node_modules, exist_ok=True)
    extract(files["npm"]["path"], node_modules, strip_prefix="package/")
    site_script = os.path.join(work, "gha-selftest-site.js")
    shutil.copy(os.path.join(RUNTIME_ROOT, "interactive_runtime", "selftest", "site.js"), site_script)
    return {"novnc": novnc, "node_modules": node_modules, "site_script": site_script}


# --------------------------------------------------------------------- 远端
def registry_lookup(run_id: str, timeout: float = 180) -> dict:
    """产品 Registry 客户端的只读查询：Host 发现 Runner 的同一路径。"""
    sys.path.insert(0, RUNTIME_ROOT)
    from interactive_runtime.rendezvous import RendezvousClient

    client = RendezvousClient(endpoint=os.environ["GHA_RENDEZVOUS_ENDPOINT"],
                              auth_token=os.environ["GHA_RENDEZVOUS_TOKEN"])
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            entry = asyncio.run(client.resolve_run(run_id))
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
            entry = None
        if entry:
            origin = entry.get("origin") or ""
            return {"origin_host": origin.split("://", 1)[-1].split("/")[0], "origin": origin,
                    "agent_token": entry.get("agent_token") or ""}
        time.sleep(3)
    raise SystemExit(f"Registry 未发现本 run 的会话：{last}")


# --------------------------------------------------------------------- 主流程
DIALOG_BINS = ("xdialog", "xmessage", "zenity")


def _pick_dialog_bin() -> str:
    """原生弹窗宿主：优先 xdialog，其次 xmessage（x11-utils 自带）/ zenity；都没有则空。"""
    for name in DIALOG_BINS:
        path = shutil.which(name)
        if path:
            return path
    return ""


def _venv_revision(venv_python: str) -> str:
    """venv 里 playwright 期望的 chromium revision（它才是 import 时认的目录名）。"""
    code = ("import json,pathlib; from playwright._impl._driver import compute_driver_executable as c;"
            "d,l=c(); print(json.load(open(pathlib.Path(d).parent/'package'/'browsers.json'))"
            "['browsers'][0]['revision'])")
    try:
        proc = subprocess.run([venv_python, "-c", code], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip()


def _apply_static_env(paths: dict, browsers: dict, manifest: dict) -> None:
    """把静态件挂上环境：noVNC/portal 用的资源、Node 依赖、Playwright 浏览器目录。

    本进程随后启动的两个浏览器（终止用户页面 + 人工端）都用这里校验过的官方件；
    产品 Runtime 的浏览器在 Supervisor 启动时已用 setup 安装的那份，不受影响。
    """
    os.environ.update({
        "GHA_NOVNC_DIR": paths["novnc"],
        "NODE_PATH": paths["node_modules"],
        "PLAYWRIGHT_BROWSERS_PATH": browsers["root"],
        "GHA_OUTPUT_DIR": OUTPUT_DIR,
    })
    dialog_bin = _pick_dialog_bin()
    host = os.environ.get("SELFTEST_DIALOG_HOST") or ("x11" if dialog_bin else "jsdom")
    os.environ["HANDOFF_SITE_HOST"] = host
    if host == "x11":
        if not dialog_bin:
            raise RuntimeError("没有可用的原生对话框程序（xdialog/xmessage/zenity）")
        os.environ["HANDOFF_DIALOG_BIN"] = dialog_bin


async def _run_handoff() -> dict:
    sys.path.insert(0, RUNTIME_ROOT)
    venv = os.environ.get("GHA_INTERACTIVE_VENV", "")
    for lib in glob.glob(os.path.join(venv, "lib", "python3*", "site-packages")):
        if lib not in sys.path:
            sys.path.insert(1, lib)
    from interactive_runtime.selftest.handoff_loop import HandoffLoopTest, write_report

    test = HandoffLoopTest(run_id=os.environ.get("GITHUB_RUN_ID", "local-selftest"))
    try:
        await test.setup()
        result = await test.run()
    except Exception as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                  "steps": test.steps.items}
    # Agent 交还后的输入核对在 test.run() 内已完成；这里落公开报告（无 key_id / 本地路径）
    write_report(result)
    log("人工端闭环：%s" % ("ok" if result.get("ok") else (result.get("error") or "failed")))
    return result


def main() -> int:
    started = time.time()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not under_runtime():
        # 由执行 workflow 以 `interactive_runtime.main --command` 拉起；没有 Gateway/Token
        # 说明启动路径不对，任何"自查"都会变成自签凭证对 401。
        log("缺少 GHA_INTERACTIVE_GATEWAY / GHA_INTERACTIVE_TOKEN：本任务必须由 Runtime 拉起")
        _write_failure(report_static_failure(RuntimeError("not started by Runtime"), started))
        return 1

    manifest = json.load(open(os.path.join(static_root(), "browsers.json"), encoding="utf-8"))
    report: dict = {"started_at": round(started, 3),
                    "static_manifest": {"schema": manifest.get("schema"),
                                        "chromium_version": manifest["browser"].get("chromium_version"),
                                        "revision": manifest["browser"].get("revision")}}
    try:
        fetched = fetch_static(manifest)
        paths = prepare_static(fetched)
        browsers = install_browsers(fetched)
        _apply_static_env(paths, browsers, manifest)
    except Exception as exc:  # 静态件失败也要落报告，别让 job 只剩一句 traceback
        report["static_error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        _write_failure(report)
        return 1

    venv_python = os.path.join(os.environ["GHA_INTERACTIVE_VENV"], "bin", "python")
    want_rev = _venv_revision(venv_python)
    got_rev = browsers["dirs"]["chromium"].rsplit("-", 1)[-1]
    report["static"] = {
        "files": {k: {"size": v["size"], "sha256": v["sha256"], "source": v["source"],
                      "reused": v["reused"]} for k, v in fetched["files"].items()},
        "executables": browsers["executables"],
        "browser_dirs": browsers["dirs"],
        "dialog_bin": os.environ.get("HANDOFF_DIALOG_BIN", ""),
        "dialog_host": os.environ.get("HANDOFF_SITE_HOST", ""),
        "venv_revision": want_rev,
    }
    if want_rev and want_rev != got_rev:
        report["static_error"] = (f"浏览器 build 不匹配：venv 的 playwright 要 {want_rev}，"
                                  f"装有 {got_rev}")
        _write_failure(report)
        return 1

    try:
        result = asyncio.run(_run_handoff())
    except Exception as exc:  # 闭环里任何未捕获异常都要落成报告，而不是只剩 traceback
        result = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        report["fatal"] = True
    report["handoff"] = result.get("ok")
    report["handoff_error"] = result.get("error") or ""

    checks: dict = {}
    handoff_report_path = os.path.join(OUTPUT_DIR, "handoff-report.json")
    recording = {}
    if os.path.isfile(handoff_report_path):
        with open(handoff_report_path, encoding="utf-8") as fh:
            recording = json.load(fh)
        checks.update(recording.get("recording_checks") or {})
    expected = list(recording.get("videos") or [])

    pulled_ok = False
    if expected:
        try:
            found = registry_lookup(os.environ.get("GITHUB_RUN_ID", ""), timeout=300)
            agent_token = found.pop("agent_token")
            report["registry"] = found
            pull = pull_recording(found["origin"], agent_token, expected)
            report["host_pull"] = pull
            pulled_ok = bool(pull.get("ok"))
        except SystemExit as exc:
            report["registry_error"] = str(exc)
        except Exception as exc:
            report["pull_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"

    ok = (result.get("ok") is True and pulled_ok
          and all(checks.get(k) for k in ("all_encrypted", "all_non_empty", "sha_matches",
                                          "duration_positive", "frames_decoded")))
    report["checks"] = {k: bool(checks.get(k)) for k in
                        ("all_encrypted", "all_non_empty", "sha_matches",
                         "duration_positive", "frames_decoded")}
    report["checks"]["host_pull_ok"] = pulled_ok
    report["ok"] = ok
    report["duration_s"] = round(time.time() - started, 1)

    with open(os.path.join(OUTPUT_DIR, "loop-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    with open(os.path.join(OUTPUT_DIR, "_outputs.env"), "w", encoding="utf-8") as fh:
        fh.write(f"loop_e2e={'ok' if ok else 'failed'}\n")
        for key, value in report["checks"].items():
            fh.write(f"{key}={'true' if value else 'false'}\n")
    log(f"结束：ok={ok} 用时 {report['duration_s']}s checks={report['checks']}")
    return 0 if ok else 1


def pull_recording(origin: str, agent_token: str, expected: list) -> dict:
    """Host 口径：同一 Vault 重新下载并解封，核对 SHA/长度/时长与公开报告一致。"""
    from gha_runner.interactive_client import InteractiveClient
    from gha_runner.state_client import StateClient
    from gha_runner.vault import Vault

    vault_root = os.path.join(os.environ["RUNNER_TEMP"], "gha-selftest-host-vault")
    state = StateClient(InteractiveClient(origin, token=agent_token, timeout=60),
                        vault=Vault(root_dir=vault_root))
    manifest = state.client.get("/v1/state/manifest")
    by_id = {o["id"]: o for o in manifest.get("objects", [])}
    wanted = [by_id[v["id"]] for v in expected if v.get("id") in by_id]
    if len(wanted) != len(expected):
        raise SystemExit("清单里缺少公开报告登记的视频对象")
    state.export_selected(wanted, project="e2e")
    videos, paths = [], []
    for obj in wanted:
        reader, meta = state.vault.open_decrypted_binary_object("e2e", obj["id"])
        if reader is None:
            raise SystemExit(f"Vault 未存下对象 {obj['id']}")
        # 解封后落盘跑 ffprobe（时长/帧数）；公开报告只登记摘要与数字
        with open(os.path.join(OUTPUT_DIR, f"decoded-{obj['id']}.mp4"), "wb") as fh:
            shutil.copyfileobj(reader, fh)
        path = os.path.join(OUTPUT_DIR, f"decoded-{obj['id']}.mp4")
        plain_sha = sha256_file(path)
        want = next(v for v in expected if v.get("id") == obj["id"])
        videos.append({"id": obj["id"], "bytes": os.path.getsize(path),
                       "ciphertext_bytes": obj.get("size"), "encrypted": obj.get("encrypted"),
                       "plaintext_sha256": plain_sha,
                       "reported_plaintext_sha256": want.get("plaintext_sha256"),
                       "vault_sha256": meta.sha256 if meta else None})
        paths.append(path)
    probes = ffprobe_all(paths)
    same = all(abs((probe.get("duration_s") or 0) - (want.get("duration_s") or 0)) <= 0.5
               for probe, want in zip(probes, expected))
    ok = (bool(videos)
          and all(v["encrypted"] and v["plaintext_sha256"] == v["reported_plaintext_sha256"]
                  == v["vault_sha256"] and (probe.get("frames") or 0) > 0
                  for v, probe in zip(videos, probes))
          and same)
    return {"origin_host": origin.split("://", 1)[-1].split("/", 1)[0],
            "plaintext_objects": state.plaintext_objects, "videos": videos,
            "ffprobe": probes, "durations_consistent": same, "ok": ok}


def sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ffprobe_all(paths: list) -> list:
    res = []
    for path in paths:
        probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries",
                                "stream=codec_name,width,height:format=duration", "-of", "json", path],
                               capture_output=True, text=True)
        info = json.loads(probe.stdout or "{}") if probe.returncode == 0 else {}
        decoded = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-f", "framemd5", "-"],
                                 capture_output=True, text=True)
        frames = len([ln for ln in decoded.stdout.splitlines() if ln and not ln.startswith("#")])
        res.append({"file": os.path.basename(path), "rc": probe.returncode,
                    "duration_s": round(float((info.get("format") or {}).get("duration") or 0), 2),
                    "codec": ((info.get("streams") or [{}])[0]).get("codec_name"),
                    "frames": frames})
    return res


def report_static_failure(exc: BaseException, started: float) -> dict:
    return {"selftest_rc": None, "duration_s": round(time.time() - started, 1),
            "static_error": f"{type(exc).__name__}: {str(exc)[:500]}"}


def _write_failure(report: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "loop-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    with open(os.path.join(OUTPUT_DIR, "_outputs.env"), "w", encoding="utf-8") as fh:
        fh.write("loop_e2e=failed\nselftest_rc=none\n")
    log(f"静态件准备失败：{report.get('static_error')}")


if __name__ == "__main__":
    sys.exit(main())
