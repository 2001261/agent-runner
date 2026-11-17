"""自查包的跨平台静态件：官方 noVNC + Playwright 浏览器壳 + Node 依赖。

分发链路是「Runner 内自带、不依赖宿主网络」：这些包外件不再打进任务包 ——
Playwright 浏览器壳解压后 100MB+，超过 GitHub 单文件上限（`git push` 直接拒绝）。
改由 Runner 侧按**固定版本**下载并校验：

- 官方 ``@novnc/novnc@1.7.0`` 原样（含 vendored pako），解到 ``GHA_NOVNC_DIR``，
  门户 ``import()`` 的就是官方 rfb.js；
- Playwright ``chromium-headless-shell``（固定 build 号），解到
  ``PLAYWRIGHT_BROWSERS_PATH`` 并软链成 ``chromium_headless_shell-<revision>``；
- ``jsdom``（弹窗宿主用）。

Host 只生成 ``browsers.json``：每个件的 URL（按顺序回退）、SHA-256 与长度。
Runner 侧 ``fetch_static`` 逐个下载，长度/SHA-256 对不上就整件重下，
下载内容绝不进 git，也不经过任务包。

只供 interactive_runtime/selftest 使用，不参与产品运行时。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

NOVNC_PKG = "@novnc/novnc@1.7.0"
# Playwright 的浏览器 build 号（与 Python 包版本绑定）；未知平台缺省用它拼地址
PLAYWRIGHT_BUILD = 1187
NPM_DEP = "jsdom@25.0.1"

NOVNC_TARBALL = "https://registry.npmjs.org/@novnc/novnc/-/novnc-1.7.0.tgz"
NOVNC_MIRROR = "https://registry.npmmirror.com/@novnc/novnc/-/novnc-1.7.0.tgz"


def npm_tarball_url(spec: str) -> str:
    """npm 下载地址按包名/版本向 registry 解析（scoped 包、版本规范化都交给它）。"""
    name, version = spec.rsplit("@", 1)
    base = "https://registry.npmjs.org/" + name.replace("/", "%2f")
    try:
        with urllib.request.urlopen(f"{base}/{version}", timeout=60) as resp:
            return json.load(resp)["dist"]["tarball"]
    except Exception as exc:
        raise RuntimeError(f"解析 {spec} 的下载地址失败：{type(exc).__name__}") from exc


# Playwright 的官方下载三源（与 `playwright install` 使用的顺序一致）。括号里是
# Playwright 1.55.0（requirements.txt 锁死）实际要的 build：1187 ↔ Chrome 140.0.7339.16。
BROWSER_BASE = (
    "https://cdn.playwright.dev/dbazure/download/playwright/builds/chromium/{build}/{name}",
    "https://playwright.download.prss.microsoft.com/dbazure/download/playwright/builds/chromium/{build}/{name}",
    "https://cdn.playwright.dev/builds/chromium/{build}/{name}",
)

PLATFORMS = {
    "linux-x64": "chromium-headless-shell-linux.zip",
    "linux-arm64": "chromium-headless-shell-linux-arm64.zip",
    "macos-x64": "chromium-headless-shell-mac-x64.zip",
    "macos-arm64": "chromium-headless-shell-mac-arm64.zip",
    "windows-x64": "chromium-headless-shell-win64.zip",
}

# 有头 chromium 的归档名（产品 BrowserManager 用；人工端 headless 用上面的 shell）
CHROMIUM_ARCHIVES = {
    "linux-x64": "chromium-linux.zip",
    "linux-arm64": "chromium-linux-arm64.zip",
    "macos-x64": "chromium-mac-x64.zip",
    "macos-arm64": "chromium-mac-arm64.zip",
    "windows-x64": "chromium-win64.zip",
}

CHROMIUM_VERSION = "140.0.7339.16"

# 固定版本的官方件摘要（2026-11-03 从官方源下载后算得）。Runner 侧按它严格校验，
# 清单里没有摘要时退回这里的常量，绝不"下载成功就当真"。
PINNED_DIGESTS: Dict[str, Dict[str, Dict[str, Any]]] = {
    "linux-x64": {
        "chromium": {
            "sha256": "395e829e88f9ff3fc108cc9a3db49907afd9f5860066e9678694b01a406ee979",
            "size": 182166967,
        },
        "headless_shell": {
            "sha256": "97842c43d49627e893e1498f61554fdfe0223d35daf247e4bedee11e79509b8e",
            "size": 109363841,
        },
        "novnc": {
            "sha256": "32689f18d6abe96bc6530828a6bd0b9ae33bda07c083a6575ed255b5a8f2e903",
            "size": 155185,
        },
        "npm": {
            "sha256": "8544ad13bdef5700bc8dee1443276b19bd37ae2c392ad0793ed9d8d1b64f19e7",
            "size": 352636,
        },
    },
}

PLAYWRIGHT_REVISIONS = {"linux-x64": "1187"}

# 归档内可执行文件的官方摘要：解开归档后先验二进制，再让 Playwright 启动它。
EXECUTABLES: Dict[str, Dict[str, Dict[str, str]]] = {
    "linux-x64": {
        "chromium": {"path": "chrome-linux/chrome",
                     "sha256": "2fa605e3639b8cfbe8037d0b8e0324dbf7f9e6ad7beb345374ecd26764e2d92b"},
        "headless_shell": {"path": "chrome-linux/headless_shell",
                           "sha256": "a6bd350a143a92159c12291f336d2f3cc65ea501e521070d9ebb596c8c90a2a7"},
    },
}

# Playwright 在 PLAYWRIGHT_BROWSERS_PATH 下认的目录名
BROWSER_DIRS = {"chromium": "chromium-{revision}",
                "headless_shell": "chromium_headless_shell-{revision}"}


def browser_archive(platform_key: str) -> str:
    try:
        return PLATFORMS[platform_key]
    except KeyError:
        raise ValueError(f"不支持的平台：{platform_key}（可选 {', '.join(PLATFORMS)}）")


def chromium_archive(platform_key: str) -> str:
    try:
        return CHROMIUM_ARCHIVES[platform_key]
    except KeyError:
        raise ValueError(f"不支持的平台：{platform_key}（可选 {', '.join(CHROMIUM_ARCHIVES)}）")


def current_platform_key() -> str:
    os_name = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system(), "")
    arch = {"x86_64": "x64", "AMD64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(), "")
    return f"{os_name}-{arch}" if os_name and arch else ""


# ------------------------------------------------------------------ 固定版本描述
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _pinned(urls: List[str], digest: str = "", size: int = 0) -> Dict[str, Any]:
    return {"urls": list(urls), "sha256": digest, "size": int(size)}


def static_sources(platform_key: str, npm_dep: str = NPM_DEP,
                   digests: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """描述 Runner 要下载的每个件：固定版本 URL + （已知时）SHA-256 与长度。

    四个件：``chromium``（有头，产品浏览器用）、``headless_shell``（人工端 headless 用）、
    ``novnc``、``npm``。URL 按顺序回退（同一版本的多个官方镜像）；摘要优先取调用方给的，
    其次固定表 ``PINNED_DIGESTS`` —— 都没给就留空，Runner 只校验长度并在报告里标出。
    """
    revision = PLAYWRIGHT_REVISIONS.get(platform_key, str(PLAYWRIGHT_BUILD))
    chromium = _pinned([u.format(build=revision, name=chromium_archive(platform_key))
                        for u in BROWSER_BASE])
    headless = _pinned([u.format(build=revision, name=browser_archive(platform_key))
                        for u in BROWSER_BASE])
    novnc = _pinned([NOVNC_TARBALL, NOVNC_MIRROR])
    npm_urls: List[str] = []
    try:
        npm_urls.append(npm_tarball_url(npm_dep))
    except RuntimeError:
        pass
    name, version = npm_dep.rsplit("@", 1)
    npm_urls.append(f"https://registry.npmmirror.com/{name}/-/{name.split('/')[-1]}-{version}.tgz")
    sources = {"chromium": chromium, "headless_shell": headless,
               "novnc": novnc, "npm": _pinned(npm_urls)}
    pinned = dict(PINNED_DIGESTS.get(platform_key) or {})
    pinned.update(digests or {})
    for key, known in pinned.items():
        if key not in sources:
            continue
        if known.get("sha256"):
            sources[key]["sha256"] = known["sha256"]
        if known.get("size"):
            sources[key]["size"] = int(known["size"])
    return sources


def manifest_for(platform_key: str, npm_dep: str = NPM_DEP,
                 digests: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    revision = os.environ.get("GHA_SELFTEST_CHROMIUM_REVISION") or \
        PLAYWRIGHT_REVISIONS.get(platform_key, str(PLAYWRIGHT_BUILD))
    return {
        "schema": "gha-selftest-static/v3",
        "novnc": {"package": NOVNC_PKG},
        "npm": {"package": npm_dep},
        "browser": {
            "platform": platform_key,
            "playwright_build": revision,
            "revision": revision,
            "chromium_version": CHROMIUM_VERSION,
        },
        "dirs": {"chromium": BROWSER_DIRS["chromium"].format(revision=revision),
                 "headless_shell": BROWSER_DIRS["headless_shell"].format(revision=revision)},
        "executables": dict(EXECUTABLES.get(platform_key) or {}),
        "sources": static_sources(platform_key, npm_dep, digests),
    }


def write_manifest(task_dir: str, platform_key: str, npm_dep: str = NPM_DEP,
                   digests: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """只写清单（几百字节），不写任何大件：任务包进 git 的只有它。"""
    static_root = os.path.join(task_dir, "static")
    os.makedirs(static_root, exist_ok=True)
    manifest = manifest_for(platform_key, npm_dep, digests)
    with open(os.path.join(static_root, "browsers.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return manifest


def official_urls(platform_key: str) -> Dict[str, str]:
    """官方下载地址（与来源清单里的第一顺位一致），供 Host 记录固定版本摘要。"""
    return {key: spec["urls"][0] for key, spec in
            static_sources(platform_key, NPM_DEP).items()}


# ------------------------------------------------------------------ Runner 侧下载
class StaticFetchError(RuntimeError):
    """下载或校验失败：调用方必须如实报错，绝不带着缺失/错误的件继续启动。"""


def verify_file(path: str, expect_sha256: str = "", expect_size: int = 0) -> Tuple[bool, str]:
    """长度与 SHA-256 都对上才算成功；返回 (ok, 原因)。"""
    if not os.path.isfile(path):
        return False, "missing"
    size = os.path.getsize(path)
    if expect_size and size != int(expect_size):
        return False, f"size {size} != {expect_size}"
    if expect_sha256:
        got = _sha256_file(path)
        if got != expect_sha256:
            return False, "sha256 mismatch"
    if size <= 0:
        return False, "empty"
    return True, "ok"


def fetch_file(spec: Dict[str, Any], dest: str, attempts: int = 3,
               timeout: float = 180.0, log=None) -> Dict[str, Any]:
    """按固定版本下载一件并校验：摘要/长度不符就整件重下，下一个源。

    已存在且校验通过的文件直接复用（同一 job 重跑不重复下载）。
    返回 {"path", "sha256", "size", "source", "reused"}；全部失败抛 StaticFetchError。
    """
    want_sha = spec.get("sha256") or ""
    want_size = int(spec.get("size") or 0)
    ok, why = verify_file(dest, want_sha, want_size)
    if ok:
        return {"path": dest, "sha256": _sha256_file(dest), "size": os.path.getsize(dest),
                "source": "cache", "reused": True}

    urls = list(spec.get("urls") or [])
    if not urls:
        raise StaticFetchError("静态件没有下载地址")
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    last = why
    for attempt in range(attempts):
        for url in urls:
            part = dest + ".part"
            try:
                with urllib.request.urlopen(url, timeout=timeout) as resp, open(part, "wb") as fh:
                    shutil.copyfileobj(resp, fh, 1024 * 1024)
                got_ok, why = verify_file(part, want_sha, want_size)
                if not got_ok:
                    last = f"{url}: {why}"
                    continue
                os.replace(part, dest)
                if log:
                    log(f"静态件已就位：{os.path.basename(dest)}（{os.path.getsize(dest)} 字节，"
                        f"sha256 校验通过）")
                return {"path": dest, "sha256": _sha256_file(dest),
                        "size": os.path.getsize(dest), "source": url, "reused": False}
            except Exception as exc:
                last = f"{url}: {type(exc).__name__}: {str(exc)[:160]}"
            finally:
                try:
                    if os.path.exists(part):
                        os.unlink(part)
                except OSError:
                    pass
        time.sleep(min(30.0, 5.0 * (attempt + 1)))
    raise StaticFetchError(f"下载 {os.path.basename(dest)} 失败（最后错误：{last[:300]}）")


STATIC_KEYS = ("chromium", "headless_shell", "novnc", "npm")


def fetch_static(manifest: Dict[str, Any], work_dir: str, log=None) -> Dict[str, Any]:
    """把清单里的四个件下到 work_dir 并逐一校验 SHA-256/长度，返回落盘路径。

    校验不过就整件重下、换下一个官方源；全部失败抛 StaticFetchError（fail-closed）。
    """
    sources = manifest.get("sources") or {}
    missing = [k for k in STATIC_KEYS if k not in sources]
    if missing:
        raise StaticFetchError(f"清单缺少下载描述：{missing}（请用当前版本重新生成 browsers.json）")
    os.makedirs(work_dir, exist_ok=True)
    files: Dict[str, Any] = {}
    for key in STATIC_KEYS:
        files[key] = fetch_file(sources[key], os.path.join(work_dir, f"{key}.zip"
                                                           if key.endswith(("chromium", "shell"))
                                                           else f"{key}.tgz"), log=log)
    browser = manifest.get("browser") or {}
    return {"files": files, "browser": browser,
            "dirs": manifest.get("dirs") or {},
            "executables": manifest.get("executables") or {},
            "revision": browser.get("revision") or "",
            "platform": browser.get("platform") or ""}


def install_browsers(fetched: Dict[str, Any], root: str, log=None) -> Dict[str, Any]:
    """把两个浏览器归档解到 Playwright 认的目录，并核对归档内可执行文件摘要。

    布局：``<root>/chromium-<rev>/`` 与 ``<root>/chromium_headless_shell-<rev>/``，
    各自带 INSTALLATION_COMPLETE 标记（`playwright install` 的产物长这样）。
    """
    import zipfile

    dirs = fetched.get("dirs") or {}
    execs = fetched.get("executables") or {}
    if not dirs.get("chromium") or not dirs.get("headless_shell"):
        raise StaticFetchError("清单缺少浏览器目录名（dirs）")
    os.makedirs(root, exist_ok=True)
    evidence: Dict[str, Any] = {}
    for key, archive_key in (("chromium", "chromium"), ("headless_shell", "headless_shell")):
        target = os.path.join(root, dirs[key])
        if os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)
        os.makedirs(target, exist_ok=True)
        archive = fetched["files"][archive_key]["path"]
        root_real = os.path.realpath(target)
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                dest = os.path.realpath(os.path.join(target, info.filename))
                if dest != root_real and not dest.startswith(root_real + os.sep):
                    raise StaticFetchError(f"浏览器归档条目越界：{info.filename}")
                if info.filename.endswith("/") or info.is_dir():
                    continue
                out = os.path.join(target, info.filename)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with zf.open(info) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                mode = (info.external_attr >> 16) & 0o777
                # 归档里的可执行位不可靠：可执行文件按 0755，其余 0644
                os.chmod(out, 0o755 if mode & 0o111 or out.endswith(("/chrome", "headless_shell"))
                         else 0o644)
        want = execs.get(key) or {}
        rel, digest = want.get("path"), want.get("sha256")
        exe_path = os.path.join(target, rel) if rel else ""
        if rel and digest:
            ok, why = verify_file(exe_path, digest, 0)
            if not ok:
                raise StaticFetchError(f"{key} 可执行文件摘要不符（{why}）：{rel}")
            evidence[key] = {"path": rel, "sha256": digest, "size": os.path.getsize(exe_path)}
        else:
            evidence[key] = {"path": rel, "sha256": "", "size": 0}
        with open(os.path.join(target, "INSTALLATION_COMPLETE"), "w", encoding="utf-8") as fh:
            fh.write("\n")
        with open(os.path.join(target, "DEPENDENCIES_VALIDATED"), "w", encoding="utf-8") as fh:
            fh.write("\n")
        if log:
            log(f"浏览器已就位：{dirs[key]}（可执行文件摘要校验通过）")
    return {"root": root, "dirs": dirs, "executables": evidence}


# ------------------------------------------------------------------ Host 侧
def build_static(root: str, platform_key: str, npm_dep: str = NPM_DEP) -> Dict[str, Any]:
    """Host 侧解析出固定版本的下载地址并算长度摘要（**不**把大件写进任务包）。

    默认地址由恒定版本号拼出（官方 CDN，秒级，不需要下载）；``--verify-download``
    时把每个件真下到 ``<root>/.cache`` 并记录 SHA-256，Runner 侧随即严格校验摘要。
    """
    os.makedirs(root, exist_ok=True)
    sources = static_sources(platform_key, npm_dep)
    digests: Dict[str, Dict[str, Any]] = {}
    if os.environ.get("GHA_SELFTEST_VERIFY_DOWNLOAD") == "1":
        cache = os.path.join(root, ".cache")
        os.makedirs(cache, exist_ok=True)
        names = {"browser": browser_archive(platform_key),
                 "novnc": "novnc.tgz", "npm": "npm.tgz"}
        for key, path in names.items():
            got = fetch_file(sources[key], os.path.join(cache, path))
            digests[key] = {"sha256": got["sha256"], "size": got["size"]}
            sources[key].update(digests[key])
    # 静态件只算清单；.cache 是校验用缓存，不进包
    cache = os.path.join(root, ".cache")
    if os.path.isdir(cache):
        shutil.rmtree(cache, ignore_errors=True)
    manifest = write_manifest(root, platform_key, npm_dep, digests)
    return manifest


def playwright_revision() -> str:
    """本机 playwright 期望的 chromium revision（写进 browsers.json 供 Runner 软链）。"""
    from playwright._impl._driver import compute_driver_executable, get_driver_env  # type: ignore

    driver, cli = compute_driver_executable()
    proc = subprocess.run([driver, cli, "install", "--dry-run", "--only-shell"],
                          capture_output=True, text=True, env=get_driver_env(), timeout=120)
    for line in proc.stdout.splitlines():
        if "headless_shell-" in line:
            return line.rsplit("headless_shell-", 1)[1].strip()
    return ""


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="生成自查任务包的静态件清单（Host 侧执行）")
    ap.add_argument("--out", required=True, help="任务目录（只写 static/browsers.json）")
    ap.add_argument("--platform", default=current_platform_key() or "linux-x64")
    ap.add_argument("--npm", default=NPM_DEP)
    ap.add_argument("--detect-revision", action="store_true",
                    help="按本机 playwright 的 revision 生成清单（换 playwright 版本时用；"
                         "默认用 PINNED_DIGESTS 里已校验的固定 build）")
    args = ap.parse_args(argv)
    if args.detect_revision:
        os.environ.setdefault("GHA_SELFTEST_CHROMIUM_REVISION", playwright_revision())
    manifest = build_static(args.out, args.platform, args.npm)
    revision = (os.environ.get("GHA_SELFTEST_CHROMIUM_REVISION")
                or PLAYWRIGHT_REVISIONS.get(args.platform, ""))
    print(json.dumps({"platform": args.platform, "revision": revision,
                      "sources": {k: {"sha256": v.get("sha256") or "", "size": v.get("size") or 0}
                                  for k, v in manifest["sources"].items()}}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
