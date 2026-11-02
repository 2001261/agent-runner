#!/usr/bin/env python3
"""跨平台回归任务（v2-cross-platform）：在 GitHub-hosted runner 上跑全量单测。

submit 只打包任务目录本身，所以被测代码由 tasks/v2-cross-platform-sync.sh 预先镜像到
本目录的 src/（gha_runner/、interactive_runtime/、tests/、templates/agent-dispatch.yml）。
运行时 src/ 整个复制成干净工作副本，在副本根执行

    <venv>/python -m unittest discover -s tests -t .

任务先创建隔离 venv，并按 interactive_runtime/requirements.txt 安装依赖；
不使用 Runner 全局 Python 的第三方包。Windows 上只有 python 没有 python3：
创建 venv 用 sys.executable，后续一律用 venv 内的解释器。

产物（GHA_OUTPUT_DIR）：
  summary.json            平台、Python/os、用例统计、失败清单、安全扫描结论
  dependency-install.log  venv 创建与依赖安装日志
  unittest.log            完整 unittest 输出（失败 traceback 从这里找）
只报告路径与计数，不回显任何凭证值。
"""
import base64
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.abspath(os.environ.get("GHA_OUTPUT_DIR", "./output"))
os.makedirs(OUT, exist_ok=True)


def log(msg):
    print(msg, flush=True)


def write_summary(data):
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


# ------------------------------------------------------------------ 1) 工作副本
# src/payload.json 由 tasks/v2-cross-platform-sync.sh 生成：路径 → 权限位 + base64。
# 先无损还原成 src/restored/，再整棵拷成工作副本（测试里会写文件，不能直接在还原物上跑）。
src_payload = os.path.join(ROOT, "src", "payload.json")
if not os.path.isfile(src_payload):
    log("FATAL: 任务包缺少 src/payload.json —— 提交前先跑 tasks/v2-cross-platform-sync.sh")
    write_summary({"ok": False, "reason": "src_missing", "task_dir": ROOT})
    sys.exit(1)

work_parent = tempfile.mkdtemp(prefix="gha-xplat-")
work = os.path.join(work_parent, "repo")
restored = os.path.join(work_parent, "restored")

with open(src_payload, "r", encoding="utf-8") as f:
    payload = json.load(f)
for rel, entry in sorted(payload["files"].items()):
    target = os.path.join(restored, *rel.split("/"))
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if "link" in entry:
        create = getattr(os, "symlink", None)
        if create is None:
            log("WARN: 无 symlink 权限，跳过 %s" % rel)
            continue
        create(entry["link"], target)
        continue
    with open(target, "wb") as f:
        f.write(base64.b64decode(entry["b64"]))
    mode = int(entry.get("mode", "644"), 8)
    try:
        os.chmod(target, mode)
    except OSError:
        pass


def ignore(dirpath, names):
    skip = set()
    for n in names:
        if n in (".git", "__pycache__", ".pytest_cache", ".DS_Store") or n.startswith("._"):
            skip.add(n)
    return skip


shutil.copytree(restored, work, ignore=ignore, symlinks=True)
log("src = %s（%d 个文件）" % (src_payload, len(payload["files"])))
log("work copy = %s" % work)

# ------------------------------------------------------------------ 2) 隔离 Python 环境
base_py = sys.executable or "python"
venv_dir = os.path.join(work_parent, "venv")
py = os.path.join(venv_dir, "Scripts" if os.name == "nt" else "bin",
                  "python.exe" if os.name == "nt" else "python")
requirements = os.path.join(work, "interactive_runtime", "requirements.txt")
install_log = os.path.join(OUT, "dependency-install.log")
try:
    with open(install_log, "w", encoding="utf-8") as install_out:
        subprocess.run([base_py, "-m", "venv", venv_dir], check=True,
                       stdout=install_out, stderr=subprocess.STDOUT)
        subprocess.run([py, "-m", "pip", "install", "--disable-pip-version-check",
                        "--no-cache-dir", "-r", requirements], check=True,
                       stdout=install_out, stderr=subprocess.STDOUT)
except (OSError, subprocess.CalledProcessError) as exc:
    log("FATAL: 隔离 Python 环境或测试依赖安装失败：%s" % exc)
    write_summary({"ok": False, "reason": "dependency_install_failed",
                   "dependency_install_log": install_log})
    shutil.rmtree(work_parent, ignore_errors=True)
    sys.exit(1)
log("venv = %s" % venv_dir)
log("requirements = %s" % requirements)

# ------------------------------------------------------------------ 3) 环境信息
case_probe = os.path.join(work_parent, "case_probe.tmp")
try:
    with open(case_probe, "w") as f:
        f.write("x")
    upper = case_probe[:-4].upper() + ".TMP"
    case_sensitive = not os.path.exists(upper)
finally:
    try:
        os.remove(case_probe)
    except OSError:
        pass

info = {
    "runner_image": os.environ.get("ImageOS", ""),
    "runner_arch": os.environ.get("RUNNER_ARCH", ""),
    "runner_os": os.environ.get("RUNNER_OS", ""),
    "platform": platform.platform(),
    "machine": platform.machine(),
    "python_executable": py,
    "base_python_executable": base_py,
    "python_version": platform.python_version(),
    "filesystem_case_sensitive": case_sensitive,
    "deps": {},
}
dep_probe = subprocess.run([py, "-c", """
import json
mods = {}
for name in ("aiohttp", "cryptography", "playwright", "yaml"):
    try:
        module = __import__(name)
        mods[name] = getattr(module, "__version__", "installed")
    except Exception as exc:
        mods[name] = "MISSING (%s)" % type(exc).__name__
print(json.dumps(mods))
"""], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
info["deps"] = json.loads(dep_probe.stdout)
site_packages = subprocess.run(
    [py, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
log("env: %s" % json.dumps(info, ensure_ascii=False))
sys.stdout.flush()

# ------------------------------------------------------------------ 4) 跑全量单测
env = dict(os.environ)
env.update({
    "PYTHONHASHSEED": "0",          # 固定集合/字典遍历顺序，让失败可复现
    "PYTHONIOENCODING": "utf-8",    # Windows 默认 cp1252，print 中文会崩
    "PYTHONDONTWRITEBYTECODE": "1",
    # 部分测试用符号链接调用同一解释器；显式指向本 venv，避免退回全局包。
    "PYTHONPATH": site_packages,
})
cmd = [py, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"]
log("run: %s  (cwd=%s)" % (" ".join(cmd), work))

t0 = time.time()
proc = subprocess.run(cmd, cwd=work, env=env, stdout=subprocess.PIPE,
                      stderr=subprocess.STDOUT)
elapsed = time.time() - t0
text = proc.stdout.decode("utf-8", "replace")
with open(os.path.join(OUT, "unittest.log"), "w", encoding="utf-8") as f:
    f.write(text)
sys.stdout.write(text)
log("\nunittest exit=%s in %.1fs" % (proc.returncode, elapsed))

# ------------------------------------------------------------------ 4) 统计
# -v 输出里每个用例有一行 "... <result>"；verbose 换行时结果单独成行。
per_module = {}
failures = []
seen = set()
pending = None
for raw in text.splitlines():
    line = raw.strip()
    name, res = None, None
    m = re.match(r"^(test\w*) \((?P<qual>[^)]+)\)(\s*\.\.\.\s*(?P<res>\w+))?", line)
    if m and "." in m.group("qual"):
        pending = m.group("qual")
        if m.group("res"):
            name, res = pending, m.group("res")
            pending = None
    elif pending and (line.split()[0] if line else "") in ("ok", "FAIL", "ERROR", "skipped"):
        name, res = pending, line.split()[0]
        pending = None
    if name is None:
        if line.startswith(("FAIL:", "ERROR:")):
            failures.append(line)
        continue
    if name in seen:
        continue
    seen.add(name)
    parts = name.split(".")
    module = ".".join(parts[:-2]) if len(parts) >= 3 else name
    st = per_module.setdefault(module, {"ok": 0, "fail": 0, "error": 0, "skip": 0})
    key = {"ok": "ok", "FAIL": "fail", "ERROR": "error"}.get(res, "skip")
    st[key] += 1

summary_line = ""
result_line = ""
for raw in text.splitlines():
    line = raw.strip()
    if re.match(r"^Ran \d+ tests? in ", line):
        summary_line = line
    elif line.startswith("FAILED (") or line == "OK" or line.startswith("OK ("):
        result_line = line

# 总计只采用 unittest 自己的末尾汇总；verbose 逐用例解析可能漏掉 import error，
# 不能再用 per_module 的反推值覆盖原始结果。
totals = {"run": 0, "pass": 0, "fail": 0, "error": 0, "skip": 0}
run_match = re.match(r"^Ran (\d+) tests? in ", summary_line)
if run_match:
    totals["run"] = int(run_match.group(1))
for key, label in (("fail", "failures"), ("error", "errors"), ("skip", "skipped")):
    count = re.search(r"\b%s=(\d+)" % label, result_line)
    if count:
        totals[key] = int(count.group(1))
totals["pass"] = totals["run"] - totals["fail"] - totals["error"] - totals["skip"]

# 安全扫描的"干净"判定：源码里命中 secrets.SKIP 之类模式属正常，只统计自身扫描的命中。
skip_dirs = {OUT, work, work_parent}

# ------------------------------------------------------------------ 5) 安全扫描
scan = {"ok": None, "hits": [], "hits_count": 0, "channel": ""}
try:
    # 按路径加载：`import secrets` 会命中标准库同名模块
    spec = importlib.util.spec_from_file_location(
        "gha_secrets_scan", os.path.join(work, "gha_runner", "secrets.py"))
    gha_secrets = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gha_secrets)
    scan["channel"] = "gha_runner/secrets.py::scan_secrets(work copy)"
    content_hits, name_hits = gha_secrets.scan_secrets(work)
    hits = [str(h) for h in list(content_hits) + list(name_hits)]
    hits = [h for h in hits if not any(d and d in h for d in skip_dirs)]
    scan["hits"] = hits
    scan["hits_count"] = len(hits)
    scan["ok"] = not hits
except Exception as exc:
    # secrets 模块正被并发改动时签名可能变 —— 记为"未完成"，不当成泄露
    scan["channel"] = "gha_runner/secrets.py"
    scan["ok"] = None
    scan["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
log("secret scan: %s" % json.dumps({k: scan[k] for k in
                                    ("channel", "ok", "hits_count", "error")
                                    if k in scan}, ensure_ascii=False))

# ------------------------------------------------------------------ 6) 汇总
result = {
    "ok": proc.returncode == 0,
    "exit_code": proc.returncode,
    "elapsed_s": round(elapsed, 1),
    "unittest_summary_line": summary_line,
    "unittest_result_line": result_line,
    "totals": totals,
    "per_module": dict(sorted(per_module.items())),
    "failures": failures,
    "secret_scan": scan,
    "env": info,
}
write_summary(result)
log("summary: %s" % json.dumps({k: result[k] for k in
                                ("ok", "unittest_summary_line", "totals")},
                               ensure_ascii=False))

shutil.rmtree(work_parent, ignore_errors=True)
# 退出码只反映单测本身：扫描问题记在 summary 里，避免把扫描器自身问题误判成平台失败
sys.exit(0 if result["ok"] else 1)
