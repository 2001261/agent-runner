"""与 GitHub 侧打交道的一切：contents API、dispatch、run 查询、artifact、分支推送。

两条从 bash 版学到的教训贯穿全模块：
  * `gh api` 遇到 404 会把错误 JSON 打到 **stdout**（"gh: Not Found" 才走 stderr），
    所以判成功不能只看 stdout 非空，必须确认目标字段真的存在。
  * dispatch 的 run_id 解析要有多层回退（新版 API 会直接返回 workflow_run_id，
    旧版不会）。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import bundle, core, ui
from .ui import GhaError

# ------------------------------------------------------------------ 仓库元信息

def repo_info(repo: str) -> Optional[Dict[str, Any]]:
    """取仓库基本信息；不可访问返回 None。"""
    return core.gh_json(
        ["repo", "view", repo, "--json", "name,visibility,defaultBranchRef,url"],
    )


def repo_visibility(repo: str) -> str:
    """返回 'public' / 'private'；查不到返回空串。"""
    info = repo_info(repo)
    if not info:
        return ""
    return str(info.get("visibility", "")).lower()


def default_branch(repo: str) -> str:
    info = repo_info(repo)
    if not info:
        return ""
    ref = info.get("defaultBranchRef") or {}
    return str(ref.get("name") or "")


def repo_exists(repo: str) -> bool:
    return repo_info(repo) is not None


def actions_enabled(repo: str) -> Optional[bool]:
    """仓库的 Actions 开关。查不到（权限不足等）返回 None。"""
    res = core.run_gh(["api", f"repos/{repo}/actions/permissions"])
    if not res.ok:
        return None
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    # 404 的错误体也会走到这里，但它没有 enabled 字段
    if "enabled" not in data:
        return None
    return bool(data["enabled"])


def billing_actions(owner: str) -> Optional[Dict[str, int]]:
    """本月分钟数。拿不到返回 None（该端点需要 user scope，本 skill 不要求）。"""
    res = core.run_gh(["api", f"users/{owner}/settings/billing/actions"])
    if not res.ok:
        return None
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    # 必须确认字段真的存在 —— 404 的错误 JSON 也在 stdout 上
    if "total_minutes_used" not in data:
        return None
    return {
        "used": int(data.get("total_minutes_used") or 0),
        "included": int(data.get("included_minutes") or 0),
    }


def create_repo(repo: str, visibility: str, description: str) -> None:
    if visibility not in ("public", "private"):
        raise GhaError(f"visibility 只能是 public 或 private，收到：{visibility}")
    res = core.run_gh([
        "repo", "create", repo, f"--{visibility}", "--description", description,
    ], stdin_text="")
    if not res.ok:
        raise GhaError(
            f"创建仓库失败（rc={res.rc}）：{(res.stderr or res.stdout).strip()[:400]}\n"
            f"    检查账号权限、仓库名是否被占用"
        )


# ------------------------------------------------------------------ contents API

def get_content_sha(repo: str, remote_path: str, ref: str = "") -> str:
    """取远端文件的 git blob sha；不存在返回空串。"""
    endpoint = f"repos/{repo}/contents/{remote_path}"
    if ref:
        endpoint += f"?ref={ref}"
    res = core.run_gh(["api", endpoint])
    if not res.ok:
        return ""
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return ""
    return str(data.get("sha") or "")


def put_contents(repo: str, remote_path: str, local_file: Path,
                 message: str, branch: str = "") -> None:
    """用 contents API 写单个文件（创建或更新）。

    不用 clone+push：单文件场景下不需要本地 git，也就不需要 commit 身份。
    """
    local_file = Path(local_file)
    if not local_file.is_file():
        raise GhaError(f"本地文件不存在：{local_file}")

    data = local_file.read_bytes()
    body: Dict[str, Any] = {
        "message": message,
        "content": core.b64encode_bytes(data),
    }
    sha = get_content_sha(repo, remote_path, branch)
    if sha:
        body["sha"] = sha
    if branch:
        body["branch"] = branch

    res = core.run_gh(
        ["api", "-X", "PUT", f"repos/{repo}/contents/{remote_path}", "--input", "-"],
        stdin_text=json.dumps(body),
    )
    if not res.ok:
        raise GhaError(
            f"写入 {remote_path} 失败（rc={res.rc}）：{(res.stderr or res.stdout).strip()[:400]}"
        )


def dispatcher_up_to_date(repo: str) -> bool:
    """远端 dispatcher 是否与本地模板一致（git blob sha 比对）。

    blob sha = sha1("blob <len>\\0" + content)，用 hashlib 直接算，**不需要 git**。
    """
    if not core.TEMPLATE.is_file():
        return False
    remote_sha = get_content_sha(repo, f".github/workflows/{core.WORKFLOW_NAME}")
    if not remote_sha:
        return False
    return core.git_blob_sha(core.TEMPLATE.read_bytes()) == remote_sha


def push_dispatcher(repo: str, branch: str = "") -> None:
    """把模板推到默认分支的 .github/workflows/。"""
    remote_path = f".github/workflows/{core.WORKFLOW_NAME}"
    msg = "chore: add gha-runner agent-dispatch workflow"
    try:
        put_contents(repo, remote_path, core.TEMPLATE, msg, branch)
        return
    except GhaError as e:
        if branch:
            raise
        ui.warn(f"直接推工作流失败（{e}），尝试先创建 README 引导默认分支")

    # 全新空仓库可能还没有默认分支 —— 先塞个 README 把 main 建出来
    readme = (
        f"# {repo.split('/')[-1]}\n\n"
        "gha-runner 的 scratch 仓库：接收 agent 投递的高强度任务，在 GitHub Actions 上执行，\n"
        "结果以 artifact 形式返回本地。\n\n"
        "> **注意**：本仓库公开时，投递进来的任务脚本（git 历史）与 artifact 都是公开可见的。\n"
    )
    tmp = core.GHA_HOME / ".readme-bootstrap.md"
    try:
        tmp.write_text(readme, encoding="utf-8", newline="\n")
        put_contents(repo, "README.md", tmp, "chore: bootstrap default branch", "")
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    put_contents(repo, remote_path, core.TEMPLATE, msg, "")


# ------------------------------------------------------------------ dispatch

def build_dispatch_body(ref: str, task_id: str, payload_b64: str, task_path: str,
                        runner: str, shell: str, timeout_minutes: int,
                        cache_key: str = "", cache_paths: str = "",
                        interactive: bool = False, interactive_config: str = "") -> Dict[str, Any]:
    """组装 dispatch 请求体。

    用 json.dumps 构造，不需要 bash 版那套"输入净化 + 手工 printf 拼 JSON"。
    所有值仍须先通过 core.valid_* 校验 —— 那是防止把奇怪的东西送进 workflow，
    不是为了防止 JSON 语法错误。
    """
    inputs: Dict[str, Any] = {
        "task_id": task_id,
        "payload_b64": payload_b64,
        "task_path": task_path,
        "runner": runner,
        "shell": shell,
        "timeout_minutes": str(timeout_minutes),
        "cache_key": cache_key,
        "cache_paths": cache_paths,
    }
    if interactive:
        inputs["interactive"] = True
    if interactive_config:
        inputs["interactive_config"] = interactive_config

    return {
        "ref": ref,
        "inputs": inputs,
    }


def dispatch(repo: str, body: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    """触发 workflow_dispatch。返回 (原始响应文本, run_id 或 None)。

    新版 API 返回 200 + workflow_run_id；旧版返回 202 空体。两种都要接得住。
    """
    res = core.run_gh([
        "api", "-X", "POST",
        f"repos/{repo}/actions/workflows/{core.WORKFLOW_NAME}/dispatches",
        "--input", "-",
    ], stdin_text=json.dumps(body))
    if not res.ok:
        detail = (res.stderr or res.stdout).strip()[:800]
        raise GhaError(f"dispatch 失败（rc={res.rc}）：\n{detail}")

    raw = res.stdout.strip()
    rid: Optional[int] = None
    if raw:
        try:
            data = json.loads(raw)
            v = data.get("workflow_run_id") or data.get("run_id")
            if v:
                rid = int(v)
        except (json.JSONDecodeError, TypeError, ValueError):
            rid = None
    return raw, rid


def resolve_dispatch_run_id(repo: str, task_id: str, api_rid: Optional[int],
                            attempts: int = 5, delay: float = 2.0) -> str:
    """三层回退解析 run_id。

    第 1 层：dispatch API 响应里的 workflow_run_id（实测新版 GitHub 会返回，通常直接命中）
    第 2 层：按 run-name（dispatcher 里 run-name: ${{ inputs.task_id }}）在 run 列表里找最新的
    """
    if api_rid:
        return str(api_rid)

    for _ in range(attempts):
        runs = core.gh_json([
            "run", "list", "--workflow", core.WORKFLOW_NAME, "--limit", "10",
            "--json", "databaseId,displayTitle,event",
        ], repo=repo)
        if isinstance(runs, list):
            for r in runs:
                if (str(r.get("displayTitle")) == task_id
                        and str(r.get("event")) == "workflow_dispatch"):
                    return str(r.get("databaseId"))
        time.sleep(delay)
    raise GhaError(
        f"已触发但没能解析出 run_id —— 用 `./gha list` 或网页查看：\n"
        f"    https://github.com/{repo}/actions"
    )


# ------------------------------------------------------------------ run 查询

def run_view(repo: str, run_id: str,
             fields: str = "databaseId,status,conclusion,displayTitle,url,createdAt,updatedAt") -> Optional[Dict[str, Any]]:
    return core.gh_json(["run", "view", run_id, "--json", fields], repo=repo)


def run_state(repo: str, run_id: str) -> Tuple[str, str]:
    """返回 (status, conclusion)。查不到返回 ("", "")。

    conclusion 在 run 进行中时是**空字符串**而不是 null —— bash 版用 jq 的 `//` 兜底
    只兜得住 null，兜不住空串，显示成 "conclusion="。这里显式判两种。
    """
    data = run_view(repo, run_id, "status,conclusion")
    if not data:
        return "", ""
    st = str(data.get("status") or "")
    cc = data.get("conclusion")
    cc = "" if cc in (None, "") else str(cc)
    return st, cc


def run_jobs(repo: str, run_id: str) -> List[Dict[str, Any]]:
    data = run_view(repo, run_id, "databaseId,status,conclusion,displayTitle,url,createdAt,updatedAt,jobs")
    if not data:
        return []
    out = []
    for j in data.get("jobs") or []:
        notable = []
        for s in j.get("steps") or []:
            cc = s.get("conclusion")
            if cc not in (None, "", "success", "skipped"):
                notable.append({"name": s.get("name"), "status": s.get("status"),
                                "conclusion": cc})
        out.append({
            "name": j.get("name"),
            "status": j.get("status"),
            "conclusion": j.get("conclusion") or "in_progress",
            "notable_steps": notable,
        })
    return out


def run_artifacts(repo: str, run_id: str) -> List[str]:
    data = run_view(repo, run_id, "artifacts")
    if not data:
        return []
    return [str(a.get("name")) for a in (data.get("artifacts") or []) if a.get("name")]


def list_runs(repo: str, limit: int = 20) -> List[Dict[str, Any]]:
    runs = core.gh_json([
        "run", "list", "--workflow", core.WORKFLOW_NAME, "--limit", str(limit),
        "--json", "databaseId,status,conclusion,displayTitle,url,createdAt",
    ], repo=repo)
    return runs if isinstance(runs, list) else []


def download_artifact(repo: str, run_id: str, name: str, dest: Path) -> None:
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    res = core.run_gh(["run", "download", run_id, "-n", name, "-D", str(dest)], repo=repo)
    if not res.ok:
        raise GhaError(
            f"下载 artifact 失败：{(res.stderr or res.stdout).strip()[:400]}\n"
            f"    常见原因：run 未结束、artifact 名不匹配（期望 {name}）、或已过保留期"
            f"（{core.DEFAULT_RETENTION_DAYS} 天）"
        )


def delete_branch(repo: str, branch: str) -> bool:
    res = core.run_gh(["api", "-X", "DELETE", f"repos/{repo}/git/refs/heads/{branch}"])
    return res.ok


# ------------------------------------------------------------------ 清理（run / artifact）

def list_run_artifacts(repo: str, run_id: str) -> List[Dict[str, Any]]:
    """列 run 的全部 artifact（每个含 id/name/size_in_bytes 等）。查不到返回 []。"""
    data = core.gh_json(["api", f"repos/{repo}/actions/runs/{run_id}/artifacts"])
    if not isinstance(data, dict):
        return []
    arts = data.get("artifacts")
    return arts if isinstance(arts, list) else []


def delete_run(repo: str, run_id: str) -> bool:
    """删 run（连带 run 日志）。删成功返回 True。"""
    res = core.run_gh(["api", "-X", "DELETE", f"repos/{repo}/actions/runs/{run_id}"])
    return res.ok


def delete_artifact(repo: str, artifact_id: int) -> bool:
    res = core.run_gh(["api", "-X", "DELETE",
                       f"repos/{repo}/actions/artifacts/{artifact_id}"])
    return res.ok


def workflow_present(repo: str) -> bool:
    return core.run_gh(["workflow", "view", core.WORKFLOW_NAME], repo=repo).ok


# ------------------------------------------------------------------ git（仅分支投递路径）

def git_identity() -> Tuple[str, str]:
    """取 commit 身份。

    优先用 git 全局/本地配置；缺失则从 gh 账号推导。
    **绝不写 git 配置** —— 用 `git -c user.name=… -c user.email=…` 做当次命令的局部覆盖。
    本机实测 git config --global user.name/user.email 常常是空的，空白环境里这几乎是必然。
    """
    name = _git_config("user.name")
    email = _git_config("user.email")
    if name and email:
        return name, email
    derived = derive_git_identity()
    if derived:
        return derived
    if name or email:
        return (name or "gha-runner"), (email or "gha-runner@users.noreply.github.com")
    raise GhaError(
        "git commit 身份未设置，且无法从 gh 账号推导 ——\n"
        "    请手工设置（只影响本仓库，不动全局）：\n"
        "      git config user.name <名字> && git config user.email <邮箱>"
    )


def _git_config(key: str) -> str:
    try:
        r = subprocess.run(["git", "config", "--get", key],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return ""
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def derive_git_identity() -> Optional[Tuple[str, str]]:
    """从 gh api user 推导 <login> / <id>+<login>@users.noreply.github.com。"""
    data = core.gh_json(["api", "user"])
    if not isinstance(data, dict):
        return None
    login = data.get("login")
    uid = data.get("id")
    if not login or not uid:
        return None
    return str(login), f"{uid}+{login}@users.noreply.github.com"


def _git(args: Sequence[str], cwd: Optional[Path] = None,
         identity: Optional[Tuple[str, str]] = None) -> Tuple[int, str]:
    cmd = ["git"]
    if identity:
        cmd += ["-c", f"user.name={identity[0]}", "-c", f"user.email={identity[1]}"]
    cmd += list(args)
    try:
        r = subprocess.run(cmd, cwd=str(cwd) if cwd else None,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return 127, str(e)
    return r.returncode, (r.stdout.decode("utf-8", "replace")
                          + r.stderr.decode("utf-8", "replace"))


def push_task_branch(repo: str, branch: str, remote_path: str, src: Path,
                     identity: Tuple[str, str],
                     declared_secrets: Optional[List[str]] = None,
                     interactive: bool = False) -> None:
    """把原始任务文件推到 <branch> 的 <remote_path>/，然后 dispatch --ref <branch>。

    用 git clone + push 而不是逐个文件调 contents API：一次推送搞定任意文件数，
    且保留原始文件（不是 base64 blob），可审计。

    declared_secrets 非 None 时把围栏支持文件（_gha/）写进投递副本 —— 分支路径不经
    bundle，不补这份云端就没有 credinject/secrets 可用。只含代码与键名，绝无凭证值。
    """
    if not shutil.which("git"):
        raise GhaError("分支投递需要 git，但本机没有 —— 安装 git 或缩小任务体积走内联路径")

    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="gha-branch-"))
    try:
        clone_dir = tmp / "repo"
        ui.info(f"克隆 {repo}（浅克隆）")
        # 用 gh repo clone 复用 gh 的认证，避免自己处理凭据
        res = core.run_gh(["repo", "clone", repo, str(clone_dir), "--",
                           "--depth", "1", "--quiet"])
        if not res.ok or not clone_dir.is_dir():
            raise GhaError(f"克隆失败：{repo}\n{(res.stderr or res.stdout).strip()[:400]}")

        rc, out = _git(["checkout", "-B", branch], cwd=clone_dir, identity=identity)
        if rc != 0:
            raise GhaError(f"创建分支 {branch} 失败：{out.strip()[:400]}")

        target = clone_dir / remote_path
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, target)
        if declared_secrets is not None:
            bundle.write_support_files(target, declared_secrets)
        if interactive:
            bundle.write_runtime_support_files(target)

        rc, out = _git(["add", "-A", remote_path], cwd=clone_dir, identity=identity)
        if rc != 0:
            raise GhaError(f"git add 失败：{out.strip()[:400]}")

        rc, out = _git(["diff", "--cached", "--quiet"], cwd=clone_dir, identity=identity)
        if rc == 0:
            ui.note("任务文件与远端一致，无需提交")
        else:
            rc, out = _git(["commit", "-q", "-m", f"task({branch}): {remote_path}"],
                           cwd=clone_dir, identity=identity)
            if rc != 0:
                raise GhaError(f"git commit 失败：{out.strip()[:400]}")

        rc, out = _git(["push", "-f", "-q", "origin", branch],
                       cwd=clone_dir, identity=identity)
        if rc != 0:
            raise GhaError(f"推送分支 {branch} 失败：{out.strip()[:400]}")

        ui.st_ok(f"已推送 {branch}（{remote_path}）")
        time.sleep(2)   # 等 GitHub 认下这个分支
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
