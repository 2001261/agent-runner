#!/usr/bin/env python3
"""临时阶段任务（v2-e2e-bundlecheck）：验证提交链路按当前工作区代码带上的运行库内容。

只输出布尔与摘要，不输出任何凭证。
"""
import hashlib
import json
import os
import sys
import sysconfig

OUT = os.environ.get("GHA_OUTPUT_DIR", "./output")
os.makedirs(OUT, exist_ok=True)
task_dir = os.environ.get("GHA_TASK_DIR", os.getcwd())
root = os.path.join(task_dir, "_gha_runtime")
sys.path[:] = [root] + [p for p in sys.path if p != root]

info = {
    "python": sys.version.split()[0],
    "task_dir": task_dir,
    "sys_path_head": sys.path[:3],
    "files": {},
}
for rel in ("gha_runner/state_client.py", "gha_runner/restore_verify.py",
            "gha_runner/profile_e2e.py", "interactive_runtime/state_import.py",
            "gha_runner/vault.py", "gha_runner/state_envelope.py",
            "interactive_runtime/gateway.py"):
    path = os.path.join(root, rel)
    info["files"][rel] = (hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]
                          if os.path.isfile(path) else "MISSING")
try:
    import cryptography
    info["cryptography"] = cryptography.__version__
except Exception as exc:
    info["cryptography"] = "ERR %s" % type(exc).__name__
for name in ("gha_runner.state_client", "gha_runner.restore_verify", "interactive_runtime.state_import"):
    try:
        mod = __import__(name, fromlist=["x"])
        info["import_" + name] = os.path.relpath(mod.__file__, task_dir)
    except Exception as exc:
        info["import_" + name] = "ERR %s: %s" % (type(exc).__name__, str(exc)[:120])
print(json.dumps(info, ensure_ascii=False, indent=2))
with open(os.path.join(OUT, "probe.json"), "w", encoding="utf-8") as f:
    json.dump(info, f, ensure_ascii=False, indent=2)
sys.exit(0)
