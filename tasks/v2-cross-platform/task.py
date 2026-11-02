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

被执行的代码就是本包里的 src/payload.json：先还原成 restored/ 再整棵拷成工作副本。
payload 里每个文件都记 sha256（符号链接记目标），三段对账：payload → restored →
work，跑完再复查 work。任何一处不一致、或 unittest 自己的 "Ran N tests" 与逐用例
结果合计对不上时，判定为"跑的不是本包那一版"（exit 3，不当成测试结论）。
"""
import base64
import collections
import hashlib
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


def manifest(root):
    """路径 → 内容摘要（符号链接记 link:<target>），用来证明"跑的就是 payload 那一版"。"""
    entries = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in ("__pycache__", ".pytest_cache", ".DS_Store"))
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if os.path.islink(path):
                entries[rel] = "link:" + os.readlink(path)
                continue
            with open(path, "rb") as f:
                entries[rel] = hashlib.sha256(f.read()).hexdigest()
    return entries


def manifest_digest(entries):
    """整棵树一个摘要：排序后逐行 (路径, 摘要) 取 sha256，本地树可以用同一算法对比。"""
    digest = hashlib.sha256()
    for rel in sorted(entries):
        digest.update(("%s\0%s\n" % (rel, entries[rel])).encode("utf-8"))
    return digest.hexdigest()


def manifest_diff(expected, actual, limit=20):
    diff = [{"path": rel,
             "state": "missing" if rel not in actual else "extra" if rel not in expected else "changed"}
            for rel in sorted(set(expected) | set(actual))
            if expected.get(rel) != actual.get(rel)]
    return diff[:limit], len(diff)


# 全量对账：payload 声明的摘要 → 还原物 → 工作副本。只比内容（Windows 没有 POSIX 权限位），
# 这样"本地并行改文件 / 打包的是别的版本"一眼可见，而不是只看几个关键文件。
payload_manifest = {
    rel: "link:" + entry["link"] if "link" in entry
    else hashlib.sha256(base64.b64decode(entry["b64"])).hexdigest()
    for rel, entry in payload["files"].items()
}
restored_manifest = manifest(restored)
work_manifest = manifest(work)
restore_diff, restore_mismatch = manifest_diff(payload_manifest, restored_manifest)
copy_diff, copy_mismatch = manifest_diff(restored_manifest, work_manifest)
log("manifest payload=%s files=%d restored=%s work=%s"
    % (manifest_digest(payload_manifest)[:16], len(payload_manifest),
       manifest_digest(restored_manifest)[:16], manifest_digest(work_manifest)[:16]))
if restore_mismatch:
    log("WARN: 还原物与 payload 不一致 %d 处：%s"
        % (restore_mismatch, json.dumps(restore_diff, ensure_ascii=False)))
if copy_mismatch:
    log("WARN: 工作副本与还原物不一致 %d 处：%s"
        % (copy_mismatch, json.dumps(copy_diff, ensure_ascii=False)))

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

# ------------------------------------------------------------------ 4) 统计通道
# 逐用例结果不解析 -v 文本：日志写入器按 100 列截断长行，"用例名 ... 结果"会被截掉，
# 计数就会和 unittest 末尾汇总对不上。也不逐条 append 到文件：Windows 实跑丢过行。
# 现在把结果记在内存里的 result 对象上，跑完一次性原子落盘；`unittest discover` 不接受
# --resultclass，所以用 runner 脚本自己组装 discover + TextTestRunner(resultclass=...)。
RESULT_HOOK = r"""
import json, os, sys, unittest

FOOTER = os.environ["GHA_RESULT_JSON"]


def _case_id(test):
    parent = getattr(test, "test_case", None)   # 失败的 subTest 归到父用例，不另算一个
    return parent.id() if parent is not None else test.id()


class _Recorded(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []
        self.status = {}
        self.subtests = []

    def startTest(self, test):
        super().startTest(test)
        self.started.append(test.id())

    def _mark(self, status, test):
        rank = {"ok": 0, "skip": 1, "expected": 1, "error": 2, "fail": 3, "unexpected": 3}
        cid = _case_id(test)
        if rank[status] >= rank.get(self.status.get(cid), 0):
            self.status[cid] = status

    def addSuccess(self, test):
        super().addSuccess(test); self._mark("ok", test)

    def addFailure(self, test, err):
        super().addFailure(test, err); self._mark("fail", test)

    def addError(self, test, err):
        super().addError(test, err); self._mark("error", test)

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self._mark("skip", test)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err); self._mark("expected", test)

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test); self._mark("unexpected", test)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is None:
            return
        status = "fail" if issubclass(err[0], test.failureException) else "error"
        self.subtests.append({"test": test.id(), "subtest": subtest.id(), "status": status})
        self._mark(status, subtest)


suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
result = unittest.TextTestRunner(verbosity=2, resultclass=_Recorded).run(suite)
footer = {
    "tests_run": result.testsRun,
    "ok": result.wasSuccessful(),
    "started": result.started,
    "status": result.status,
    "subtests": result.subtests,
    "failure_ids": [test.id() for test, _ in result.failures],
    "error_ids": [test.id() for test, _ in result.errors],
    "skip_ids": [test.id() for test, _ in result.skipped],
    "expected_ids": [test.id() for test, _ in result.expectedFailures],
    "unexpected_ids": [test.id() for test in result.unexpectedSuccesses],
}
# 一次性写盘：路径绝对（用例可能改过 cwd），用 os.open/os.fdopen 免被 mock 的 builtins.open 影响
tmp = FOOTER + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(footer, f, ensure_ascii=False)
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, FOOTER)
sys.exit(0 if footer["ok"] else 1)
"""
result_json = os.path.join(work_parent, "results.json")
hook = os.path.join(work_parent, "run_tests.py")
with open(hook, "w", encoding="utf-8") as f:
    f.write(RESULT_HOOK)
env["GHA_RESULT_JSON"] = result_json
cmd = [py, hook]
log("run: %s  (cwd=%s, discover tests, resultclass=_Recorded)" % (" ".join(cmd), work))

t0 = time.time()
proc = subprocess.run(cmd, cwd=work, env=dict(env, PYTHONPATH=site_packages + os.pathsep + work_parent),
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
elapsed = time.time() - t0
text = proc.stdout.decode("utf-8", "replace")
with open(os.path.join(OUT, "unittest.log"), "w", encoding="utf-8") as f:
    f.write(text)
sys.stdout.write(text)
log("\nunittest exit=%s in %.1fs" % (proc.returncode, elapsed))

# ------------------------------------------------------------------ 5) 计数
results = None
try:
    with open(result_json, "r", encoding="utf-8") as f:
        results = json.load(f)
except (OSError, ValueError) as exc:
    log("WARN: 用例结果文件缺失或不可解析：%s: %s" % (type(exc).__name__, exc))

per_module = {}
failures = []
case_counts = {"ok": 0, "fail": 0, "error": 0, "skip": 0}
started, missing, extra, duplicates = [], [], [], []
raw = {"failures": 0, "errors": 0, "skipped": 0, "subtests": 0}
tests_run = 0
if results:
    started = list(results.get("started") or [])
    status = results.get("status") or {}
    tests_run = int(results.get("tests_run") or 0)
    duplicates = sorted(cid for cid, n in collections.Counter(started).items() if n > 1)
    missing = sorted(set(started) - set(status))
    extra = sorted(set(status) - set(started))
    for cid in sorted(status):
        st = status[cid]
        key = {"ok": "ok", "fail": "fail", "error": "error"}.get(st, "skip")
        if st == "unexpected":
            key = "fail"
        # 模块名取到 test_x 为止；subTest 的 id 尾部是 "(changes={...})"，不能参与切分
        module = cid.rsplit(".", 2)[0] if cid.count(".") >= 2 else cid
        bucket = per_module.setdefault(module, {"ok": 0, "fail": 0, "error": 0, "skip": 0})
        bucket[key] += 1
        case_counts[key] += 1
    # 失败清单一律取自同一个 result 对象（含 subTest 明细），不再回文本里抠
    failures = ["FAIL: %s" % cid for cid in results.get("failure_ids") or []]
    failures += ["ERROR: %s" % cid for cid in results.get("error_ids") or []]
    failures += ["UNEXPECTED SUCCESS: %s" % cid for cid in results.get("unexpected_ids") or []]
    raw = {
        "failures": len(results.get("failure_ids") or []),
        "errors": len(results.get("error_ids") or []),
        "skipped": len(results.get("skip_ids") or []),
        "subtests": len(results.get("subtests") or []),
    }

summary_line = ""
result_line = ""
for raw_line in text.splitlines():
    line = raw_line.strip()
    if re.match(r"^Ran \d+ tests? in ", line):
        summary_line = line
    elif line.startswith("FAILED (") or line == "OK" or line.startswith("OK ("):
        result_line = line

# unittest 自己的末尾汇总（"Ran N tests" / "FAILED (failures=N, ...)"）与 result 对象对账，
# 两边任何一边缺失或对不上都不算测试结论。
totals = {
    "run": 0,
    "pass": case_counts["ok"],
    "fail": case_counts["fail"],
    "error": case_counts["error"],
    "skip": case_counts["skip"],
    "subtest_failures": raw["subtests"],
    "unittest_reported": {"failures": raw["failures"], "errors": raw["errors"],
                          "skipped": raw["skipped"]},
}
run_match = re.match(r"^Ran (\d+) tests? in ", summary_line)
if run_match:
    totals["run"] = int(run_match.group(1))
text_counts = {"failures": 0, "errors": 0, "skipped": 0}
for key, label in (("failures", "failures"), ("errors", "errors"), ("skipped", "skipped")):
    count = re.search(r"\b%s=(\d+)" % label, result_line)
    if count:
        text_counts[key] = int(count.group(1))

# 跑完再复查一遍工作副本：用例写到源码树里同样是"跑的已不是 payload 那一版"。
post_manifest = manifest(work)
post_diff, post_mismatch = manifest_diff(work_manifest, post_manifest)

# 安全扫描的"干净"判定：源码里命中 secrets.SKIP 之类模式属正常，只统计自身扫描的命中。
skip_dirs = {OUT, work, work_parent}

logged = sum(case_counts.values())
consistency = {
    "files_ok": restore_mismatch == 0 and copy_mismatch == 0,
    "results_ok": results is not None and tests_run == len(started) and not duplicates,
    "counts_ok": totals["run"] > 0 and totals["run"] == tests_run == logged
    and not missing and not extra,
    "breakdown_ok": text_counts["failures"] == raw["failures"]
    and text_counts["errors"] == raw["errors"]
    and text_counts["skipped"] == raw["skipped"],
    "failures_logged_ok": len(failures) == raw["failures"] + raw["errors"],
    "unittest_ran": proc.returncode in (0, 1),
    "work_unchanged": post_mismatch == 0,
    "logged_cases": logged,
    "missing_cases": missing[:10],
    "unexpected_cases": extra[:10],
    "duplicate_cases": duplicates[:10],
}
consistency["ok"] = all(consistency[k] for k in
                        ("files_ok", "results_ok", "counts_ok", "breakdown_ok",
                         "failures_logged_ok", "unittest_ran", "work_unchanged"))
if not consistency["ok"]:
    log("INCONSISTENT: files_ok=%s results_ok=%s counts_ok=%s(ran=%d tests_run=%d logged=%d "
        "missing=%d extra=%d dup=%d) breakdown_ok=%s failures_logged_ok=%s "
        "work_unchanged=%s unittest_exit=%d"
        % (consistency["files_ok"], consistency["results_ok"], consistency["counts_ok"],
           totals["run"], tests_run, logged, len(missing), len(extra), len(duplicates),
           consistency["breakdown_ok"], consistency["failures_logged_ok"],
           consistency["work_unchanged"], proc.returncode))

# ------------------------------------------------------------------ 6) 安全扫描
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

# ------------------------------------------------------------------ 7) 汇总
# exit 3 = 环境不一致（文件对不上 / 计数对不上 / unittest 没跑起来）：不是测试结论，
# 单测本身失败仍是 exit 1。
exit_code = proc.returncode if consistency["ok"] and proc.returncode != 0 else 0
if not consistency["ok"]:
    exit_code = 3
payload_sha = hashlib.sha256(open(src_payload, "rb").read()).hexdigest()
result = {
    "ok": consistency["ok"] and proc.returncode == 0,
    "exit_code": exit_code,
    "unittest_exit": proc.returncode,
    "elapsed_s": round(elapsed, 1),
    "unittest_summary_line": summary_line,
    "unittest_result_line": result_line,
    "totals": totals,
    "per_module": dict(sorted(per_module.items())),
    "failures": failures,
    "consistency": consistency,
    # 提交/执行的可核对指纹：payload.json 的 sha256 + 整棵树的摘要，本地树用同一算法可比
    "input_manifest": {
        "payload_sha256": payload_sha,
        "payload_digest": manifest_digest(payload_manifest),
        "restored_digest": manifest_digest(restored_manifest),
        "work_digest": manifest_digest(work_manifest),
        "post_run_digest": manifest_digest(post_manifest),
        "files": len(payload_manifest),
        "restore_mismatch": restore_diff,
        "copy_mismatch": copy_diff,
        "post_run_mismatch": post_diff,
    },
    "secret_scan": scan,
    "env": info,
}
write_summary(result)
log("summary: %s" % json.dumps({k: result[k] for k in
                                ("ok", "exit_code", "unittest_summary_line", "totals")},
                               ensure_ascii=False))
log("consistency: %s" % json.dumps(consistency, ensure_ascii=False))

shutil.rmtree(work_parent, ignore_errors=True)
# 退出码只反映单测本身：扫描问题记在 summary 里，避免把扫描器自身问题误判成平台失败
sys.exit(exit_code)
