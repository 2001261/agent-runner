"""子命令实现：init / submit / status / wait / fetch / logs / list / clean / secret。

退出码是对外契约：0 成功 / 1 失败 / 2 wait 超时仍在跑 / 3 有 C 类待用户完成 /
4 凭据扫描命中已中止 / 125 缺 --yes。

secret 子命令与 submit --secret 构成"凭证传递围栏"的本地半边（机制说明见
SKILL.md「凭证传递围栏」与 credinject.py docstring）；铁律：绝不读取、回显、
记录凭证值到任何文件或日志 —— 只碰键名。
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import bundle, core, remote, secrets, setupenv, state, ui
from .ui import (EXIT_FAIL, EXIT_NOT_AUTHORIZED, EXIT_OK, EXIT_SECRET_FOUND,
                 EXIT_STILL_RUNNING, GhaError, NeedsUser, NotAuthorized)


# ------------------------------------------------------------------ 前置门禁

def require_auth() -> None:
    core.require_gh()
    logged_in, _, _ = setupenv.auth_status()
    if not logged_in:
        ui.log(setupenv.AUTH_INSTRUCTIONS)
        raise NeedsUser("gh 未认证（C 类：必须你亲手完成，完成后重跑 ./gha doctor）")


def require_dispatcher(repo: str) -> None:
    if not remote.workflow_present(repo):
        raise GhaError(
            f"仓库 {repo} 里没有 {core.WORKFLOW_NAME} —— "
            f"先跑：./gha init --repo {repo} --yes"
        )


# ------------------------------------------------------------------ init

def cmd_init(args) -> int:
    core.require_gh()
    require_auth()

    # 先跑一遍只读自检；有 C 类未就绪就停下等用户，不留半初始化状态
    ui.section("初始化前自检")
    gate = setupenv.cmd_setup(check_only=True)
    if gate == EXIT_FAIL:
        raise GhaError("环境自检有失败项，先修复再 init")
    if gate != EXIT_OK:
        # needs-user：gh 未装也算在这里，明确告诉用户下一步
        ui.warn("自检有 [install] / [needs-user] 项。init 需要 gh 已装好并已认证。")
        if not core.resolve_gh():
            raise GhaError("gh CLI 不可用 —— 先跑：./gha setup --yes（B 类安装，需用户同意）")

    repo = args.repo or core.cfg_repo()
    if not repo:
        data = core.gh_json(["api", "user"])
        login = (data or {}).get("login") if isinstance(data, dict) else None
        if not login:
            raise GhaError("无法获取 GitHub 账号名，请用 --repo OWNER/NAME 指定")
        repo = f"{login}/agent-runner"
        ui.note(f"未指定 --repo，默认使用：{repo}")
    if not core.valid_repo_slug(repo):
        raise GhaError(f"仓库名格式非法（应为 owner/name）：{repo}")

    vis = (args.visibility or core.cfg_visibility() or "public").lower()
    if vis == "public":
        ui.info("可见性 = public（默认策略）")
        ui.note("收益：ubuntu-latest 给到 4 vCPU / 16 GB；标准 runner 分钟数免费且不限量")
        ui.warn("代价：投递的任务脚本会进 git 历史并公开可见，artifact 任何人可下载")
        ui.note("因此 submit 带凭据/隐私前置扫描，命中即中止并向你求助")
    elif vis == "private":
        ui.info("可见性 = private（你显式指定的）")
        ui.warn("私有仓库 ubuntu-latest 只有 2 vCPU / 8 GB，且消耗分钟数配额（Free 2,000 分钟/月）")
    else:
        raise GhaError(f"--visibility 只能是 public 或 private，收到：{vis}")

    authorized = bool(args.yes)

    # --- 仓库是否存在
    actual = remote.repo_visibility(repo)
    if actual:
        ui.st_ok(f"仓库已存在：{repo}（可见性 {actual.upper()}）")
        if actual != vis:
            ui.warn(f"你要求 {vis}，但仓库实际是 {actual} —— 以实际为准，不擅自改可见性")
            vis = actual
    else:
        if not args.create:
            raise GhaError(f"仓库不存在：{repo} —— 要创建请加 --create（B 类操作，需用户同意）")
        core.confirm_b(
            f"创建 {vis} 仓库 {repo}",
            lambda: remote.create_repo(
                repo, vis,
                "gha-runner scratch repo: offloads high-intensity agent tasks to GitHub Actions"),
            authorized=authorized,
            show=f"gh repo create {repo} --{vis}",
        )
        ui.st_ok(f"仓库已创建：https://github.com/{repo}")

    # --- 推 dispatcher
    br = remote.default_branch(repo)
    if br:
        ui.st_ok(f"默认分支：{br}")
    else:
        ui.note("仓库为空，尚无默认分支")

    if remote.dispatcher_up_to_date(repo):
        ui.st_ok("dispatcher 已是最新（与本地模板 git blob sha 一致），跳过推送")
    else:
        if remote.workflow_present(repo):
            ui.st_install("dispatcher 已存在但与本地模板不一致 —— 需要更新")
        core.confirm_b(
            f"推送 templates/agent-dispatch.yml 到 {repo} 的 .github/workflows/",
            lambda: remote.push_dispatcher(repo, br),
            authorized=authorized,
            show=f"gh api -X PUT repos/{repo}/contents/.github/workflows/{core.WORKFLOW_NAME}",
        )
        for _ in range(6):
            if remote.workflow_present(repo):
                break
            time.sleep(3)
        if remote.workflow_present(repo):
            ui.st_ok(f"dispatcher 已就绪：{core.WORKFLOW_NAME}")
        else:
            ui.warn("dispatcher 已推送但 GitHub 还没注册出来，稍后用 ./gha doctor 复查")

    core.cfg_set("repo", repo)
    core.cfg_set("visibility", vis)
    ui.st_ok(f"配置已写入 config/repo={repo}, config/visibility={vis}")

    # --- 冒烟：同时满足"workflow 必须先在默认分支跑过一次"的前置条件
    if args.skip_smoke:
        ui.st_skip("按要求跳过冒烟（注意：首次 dispatch 到非默认分支前，"
                   "必须先在默认分支跑过一次）")
        return EXIT_OK

    ui.log("")
    ui.info("冒烟验证：投递 tasks/smoke 并等待结果")
    ui.note("这一步会真实触发一次 Actions run（公开仓库分钟数免费）")
    if not authorized:
        ui.st_install("冒烟未执行（缺 --yes）")
        ui.note("命令: ./gha submit tasks/smoke --task-id smoke --wait --yes")
        return EXIT_NOT_AUTHORIZED

    # 注意：--timeout 是【云端 job】的超时分钟数，等待时长是 wait_timeout（秒）。
    # bash 版这里把两者搞混过，冒烟的 job 超时被设成了 300 分钟。
    smoke = core.GHA_HOME / "tasks" / "smoke"
    if not smoke.is_dir():
        ui.st_skip(f"找不到示例任务 {smoke}，跳过冒烟")
        return EXIT_OK

    class _SmokeArgs:
        pass

    sa = _SmokeArgs()
    sa.task_dir = str(smoke)
    sa.task_id = "smoke"
    sa.runner = core.DEFAULT_RUNNER
    sa.shell = "auto"
    sa.timeout = str(core.DEFAULT_TIMEOUT_MINUTES)
    sa.out = None
    sa.wait = True
    sa.wait_timeout = 300
    sa.interval = core.DEFAULT_WAIT_INTERVAL
    sa.keep_ref = False
    sa.allow_public = False
    sa.secret = []
    sa.cache_key = ""
    sa.cache_paths = ""
    sa.cleanup = False
    sa.yes = True
    sa.force = False
    rc = cmd_submit(sa)
    return rc


# ------------------------------------------------------------------ submit

def _collect_declared_secrets(args, task_dir: Path) -> List[str]:
    """汇总凭证白名单：--secret KEY[,KEY...]（可重复）+ 任务目录里的 secrets.txt。

    secrets.txt 一行一个键名（# 开头是注释）。只收键名，绝不碰值。
    去重且保持顺序；键名必须是合法 env 变量名。
    """
    raw: List[str] = []
    for item in getattr(args, "secret", None) or []:
        # 只按逗号分隔（键名里不允许空白，"A B" 应报错而不是被拆成两个键）
        raw.extend(str(item).split(","))
    txt = task_dir / "secrets.txt"
    if txt.is_file():
        for line in core.read_text_file(txt).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    declared: List[str] = []
    for k in raw:
        k = k.strip()
        if not k:
            continue
        if not core.valid_env_name(k):
            raise GhaError(
                f"凭证键名非法（应为 env 变量名 [A-Za-z_][A-Za-z0-9_]*）：{k}")
        if k not in declared:
            declared.append(k)
    return declared


def cmd_submit(args) -> int:
    task_dir = Path(args.task_dir).expanduser()
    if not task_dir.is_dir():
        raise GhaError(f"任务目录不存在：{task_dir}")
    task_dir = task_dir.resolve()

    core.require_gh()
    require_auth()
    repo = core.need_repo()
    require_dispatcher(repo)

    # --- 参数校验
    task_id = args.task_id or core.derive_task_id(task_dir)
    if not core.valid_task_id(task_id):
        raise GhaError(f"task_id 非法（只允许 [A-Za-z0-9._-]，≤64 字符）：{task_id}")
    runner = args.runner or core.DEFAULT_RUNNER
    if not core.valid_runner(runner):
        raise GhaError(f"runner 非法：{runner}（可选 {'/'.join(core.VALID_RUNNERS)}）")
    shell_kind = args.shell or "auto"
    if not core.valid_shell(shell_kind):
        raise GhaError(f"shell 非法：{shell_kind}（可选 {'/'.join(core.VALID_SHELLS)}）")
    timeout_min = str(args.timeout or core.DEFAULT_TIMEOUT_MINUTES)
    if not core.valid_timeout_minutes(timeout_min):
        raise GhaError(
            f"timeout 必须是 1..{core.MAX_TIMEOUT_MINUTES} 的整数分钟"
            f"（GitHub 单 job 硬上限 6 小时）：{timeout_min}"
        )
    timeout_min_i = int(timeout_min)

    cache_key = (args.cache_key or "").strip()
    if cache_key and not state.validate_cache_key(cache_key):
        raise GhaError(f"cache-key 非法（只允许 [A-Za-z0-9._-]，≤100 字符）：{cache_key}")
    cache_paths = state.normalize_cache_paths(args.cache_paths or "")

    # --- 入口检查（显式指定 --shell 时不匹配就报错，绝不静默回落到别的入口）
    if shell_kind == "auto":
        entry = bundle.find_entry(task_dir)
        if not entry:
            raise GhaError(f"任务目录里没有 task.sh / task.py / task.js：{task_dir}")
    else:
        entry = bundle.find_entry(task_dir, shell_kind)
        if not entry:
            raise GhaError(
                f"指定了 --shell {shell_kind} 但找不到对应入口文件"
                f"（应为 {bundle.ENTRY_BY_SHELL[shell_kind]}）：{task_dir}"
            )
        shell_kind = bundle.shell_of_entry(entry)

    rdir = core.run_dir(task_id, args.out)

    # --- 凭证白名单（--secret 与任务目录的 secrets.txt 汇总；只收键名）
    declared = _collect_declared_secrets(args, task_dir)

    ui.section(f"提交任务 {task_id} → {repo}")
    ui.note(f"任务目录: {task_dir}")
    ui.note(f"入口:     {entry}（{shell_kind}）")
    ui.note(f"runner:   {runner}   超时: {timeout_min_i} 分钟")
    if cache_key:
        ui.note(f"状态复用: cache_key={cache_key}"
                + (f"，额外路径 {len(cache_paths.splitlines())} 个" if cache_paths else ""))
    if declared:
        ui.note(f"凭证白名单: {len(declared)} 个键 → {', '.join(declared)}")
        ui.note("            值经仓库 secret 传输，运行时由 _gha/credinject.py 注入并掩码")
    ui.note(f"结果目录: {rdir}")

    # --- 凭据/隐私扫描：必须在【打包之前】，更要在任何网络写操作之前。
    #     bash 版把它放在打包之后，结果拦截时磁盘上已经留下了一份含密钥的 bundle.tgz。
    vis = remote.repo_visibility(repo) or core.cfg_visibility()
    if vis == "public" and not args.allow_public:
        ui.info("凭据/隐私扫描（仓库是 public）")
        # secrets.txt 是围栏的键名声明（按约定只有名字没有值），放行不误杀
        content_hits, name_hits = secrets.scan_secrets(task_dir, exclude=["secrets.txt"])
        if content_hits or name_hits:
            ui.log(secrets.format_hits(content_hits, name_hits))
            ui.log("")
            ui.err(f"扫描命中。仓库 {repo} 是【公开】的 —— 任务脚本会进 git 历史并公开可见，")
            ui.err("run 日志与 artifact 任何人都能下载。已【中止提交】，没有任何内容被打包或推送。")
            ui.log(secrets.BLOCK_MESSAGE.format(repo=repo))
            raise ui.SecretFound("凭据/隐私扫描命中，已中止提交")
        ui.st_ok("未命中凭据特征")
    elif args.allow_public:
        ui.warn("已用 --allow-public 跳过凭据扫描 —— 责任自负")
    else:
        ui.note("仓库是 private，跳过公开暴露扫描")

    # --- 声明了凭证 + 仓库是 public：告知性警告，不门禁、不阻断（用户定的取舍）。
    #     值本身走仓库 secret，不进 git/payload；日志有掩码、artifact 上传前有扫描兜底。
    if declared and vis == "public":
        ui.warn(f"任务声明了 {len(declared)} 个凭证键，而仓库 {repo} 是【公开】的 —— "
                "任何人可下载该 run 的日志与 artifact（已知取舍，不阻断）")
        ui.note("凭证值不经 git 与 dispatch payload；步骤日志注册 ::add-mask:: 掩码，"
                "捕获日志上传前按全部凭证值脱敏 + 双通道扫描兜底（正则特征 + 已注册值"
                "字面比对）；但子串片段与主动外泄挡不住 —— 详见 SKILL.md「凭证传递围栏」")

    # --- 打包（扫描通过后才落盘）；_gha/ 支持目录随包注入（不落用户任务目录）
    rdir.mkdir(parents=True, exist_ok=True)
    bundle_path = rdir / "bundle.tgz"
    b64_path = rdir / "bundle.b64"
    bundle.pack_bundle(task_dir, bundle_path, declared=declared,
                       interactive=bool(getattr(args, "interactive", False)))
    b64_text, bsize = bundle.make_b64(bundle_path, b64_path)
    b64len = len(b64_text)
    ui.note(f"bundle: {core.human_bytes(bsize)} → base64 {b64len} 字符")
    if bsize > core.BUNDLE_WARN_BYTES:
        ui.warn(f"bundle 超过 {core.human_bytes(core.BUNDLE_WARN_BYTES)} —— "
                f"artifact 存储配额有限（Free 500 MB），上传可能失败")

    # --- 选投递路径
    transport = bundle.choose_transport(b64len)
    ref = ""
    task_path = ""
    if transport == "branch":
        ref = f"agent/{task_id}"
        task_path = f"tasks/{task_id}"
        ui.warn(f"base64 {b64len} 字符超过内联上限 {core.INLINE_B64_LIMIT}"
                f"（dispatch 总 payload 硬上限 65535）")
        ui.info(f"改走分支投递：把原始任务文件推到 {repo} 的 {ref}，再 dispatch --ref {ref}")
        ui.note("原始文件（不是 base64 blob）入库，保留可审计性")

    authorized = bool(args.yes)

    # --- 分支投递：先推文件（B 类）
    if transport == "branch":
        ident = remote.git_identity()
        ui.note("git commit 身份（仅本次命令局部使用，不改全局配置）：")
        ui.note(f"  user.name  = {ident[0]}")
        ui.note(f"  user.email = {ident[1]}")
        core.confirm_b(
            f"推送任务文件到分支 {ref}",
            lambda: remote.push_task_branch(repo, ref, task_path, task_dir, ident,
                                            declared_secrets=declared,
                                            interactive=bool(getattr(args, "interactive", False))),
            authorized=authorized,
            show=f"git push -f origin {ref}  # {task_path}/",
        )

    # --- dispatch（B 类）
    body = remote.build_dispatch_body(
        ref=ref or remote.default_branch(repo) or "main",
        task_id=task_id,
        payload_b64=b64_text if transport == "inline" else "",
        task_path=task_path,
        runner=runner,
        shell=shell_kind,
        timeout_minutes=timeout_min_i,
        cache_key=cache_key,
        cache_paths=cache_paths,
        interactive=bool(getattr(args, "interactive", False)),
        interactive_config=getattr(args, "interactive_config", "") or "",
    )
    if not authorized:
        ui.st_install("dispatch 未执行（缺 --yes）—— 这是 B 类写操作")
        ui.note(f"命令: ./gha submit \"{task_dir}\" --task-id {task_id} "
                f"--runner {runner} --timeout {timeout_min_i} --yes")
        raise NotAuthorized("需要 --yes 才能触发 workflow_dispatch")

    ui.info(f"触发 workflow_dispatch：{core.WORKFLOW_NAME}")
    _, api_rid = remote.dispatch(repo, body)

    rid = remote.resolve_dispatch_run_id(repo, task_id, api_rid)

    # --- 落 run 状态，agent 之后用 task_id 就能查
    core.run_set(task_id, "task_id", task_id, args.out)      # artifact 名以这个为准，不是目录名
    core.run_set(task_id, "run_id", rid, args.out)
    core.run_set(task_id, "repo", repo, args.out)
    core.run_set(task_id, "task_dir", str(task_dir), args.out)
    core.run_set(task_id, "timeout_minutes", str(timeout_min_i), args.out)
    if ref:
        core.run_set(task_id, "ref", ref, args.out)
    if args.keep_ref:
        core.run_set(task_id, "keep_ref", "1", args.out)
    if cache_key:
        core.run_set(task_id, "cache_key", cache_key, args.out)
    byrun = core.RUNS_DIR / "by-run" / rid
    byrun.mkdir(parents=True, exist_ok=True)
    core.write_text_file(byrun / "task_id", task_id)

    # --- --cleanup（B 类，需 --yes）：结果取回成功后自动清理该 run + artifact
    #     非 --wait 时把意图落进 .gha-runs/<task_id>/cleanup，之后 fetch 读到就生效；
    #     取回失败绝不清理 —— 要保留现场证据。
    if args.cleanup and not authorized:
        ui.st_install("自动清理未启用（--cleanup 是 B 类写操作，需要与 --yes 一起用）")
        ui.note(f"取回成功后可手动清理: ./gha clean --run-id {rid} --yes")
    elif args.cleanup and not args.wait:
        core.run_set(task_id, "cleanup", "1", args.out)
        ui.note("已登记 --cleanup：取回（fetch）成功后自动清理该 run 与 artifact")

    ui.st_ok(f"已提交：run_id={rid}")
    ui.log(f"    https://github.com/{repo}/actions/runs/{rid}")
    ui.note(f"查询: ./gha status {task_id}")
    ui.note(f"等待: ./gha wait {task_id} --timeout 600")
    ui.note(f"取回: ./gha fetch {task_id}")

    if args.wait:
        ui.log("")
        wrc = _wait(rid, repo, args.wait_timeout, args.interval)
        try:
            frc = _fetch(rid, repo, args.out, force=False, authorized=True,
                         cleanup=False)
        except GhaError as e:
            ui.warn(f"取回结果失败：{e.message}")
            return wrc
        if args.cleanup and frc == EXIT_OK:
            ui.info(f"取回成功，按 --cleanup 清理 run {rid} 与 artifact")
            _delete_run_contents(repo, rid)
        elif args.cleanup:
            ui.warn("取回未成功（退出码非 0），不做清理 —— 保留 run 与 artifact 供排查")
        return wrc
    return EXIT_OK


# ------------------------------------------------------------------ status / wait

def cmd_status(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    rid = core.resolve_run_id(args.target, args.out)

    data = remote.run_view(repo, rid,
                           "databaseId,status,conclusion,displayTitle,url,createdAt,updatedAt,jobs")
    if not data:
        raise GhaError(f"查询失败：run {rid} @ {repo}")

    out = {
        "run_id": data.get("databaseId"),
        "status": data.get("status"),
        "conclusion": data.get("conclusion") or "none",
        "title": data.get("displayTitle"),
        "url": data.get("url"),
        "started_at": data.get("createdAt"),
        "updated_at": data.get("updatedAt"),
        "jobs": remote.run_jobs(repo, rid),
    }
    ui.log(json.dumps(out, ensure_ascii=False, sort_keys=True))

    # 顺带给一句人话诊断，agent 不用自己解析
    task = core.resolve_task_id(args.target, args.out)
    rdir = core.run_dir(task, args.out)
    manifest = _read_manifest(rdir)
    v = state.diagnose(manifest, {"status": out["status"], "conclusion": out["conclusion"],
                                  "started_at": out["started_at"], "updated_at": out["updated_at"]},
                       _recorded_timeout(rdir))
    if v.kind not in ("success", "running"):
        ui.note(f"诊断: {v.kind} —— {v.summary.splitlines()[0]}")
    return EXIT_OK


def _recorded_timeout(rdir: Path) -> int:
    raw = core.read_text_file(rdir / "timeout_minutes").strip()
    try:
        return int(raw)
    except ValueError:
        return 0


def _read_manifest(rdir: Path) -> Optional[Dict[str, Any]]:
    p = rdir / "result" / "manifest.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _read_run_json(rdir: Path) -> Optional[Dict[str, Any]]:
    p = rdir / "run.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _wait(rid: str, repo: str, timeout: int, interval: int) -> int:
    interval = max(interval, core.MIN_WAIT_INTERVAL)
    deadline = core.now_epoch() + timeout
    started = core.now_epoch()

    ui.info(f"等待 run {rid} 完成（最多 {timeout}s，每 {interval}s 查一次）")
    ui.note(f"https://github.com/{repo}/actions/runs/{rid}")

    st = cc = ""
    polls = 0
    while True:
        polls += 1
        st, cc = remote.run_state(repo, rid)
        if not st:
            ui.warn(f"第 {polls} 次查询失败（网络或 run 尚未可见），继续重试")
        else:
            ui.log(f"  [{core.now_epoch() - started:>4}s] status={st} "
                   f"conclusion={cc or 'none'}")
            if st == "completed":
                ui.log("")
                if cc == "success":
                    ui.st_ok("run 成功")
                    return EXIT_OK
                ui.err(f"run 结束，conclusion={cc or 'none'}")
                return EXIT_FAIL

        if core.now_epoch() >= deadline:
            ui.log("")
            ui.warn(f"已等 {timeout}s，run 仍在进行（status={st or 'unknown'}）—— 这【不是失败】")
            ui.note(f"稍后继续查: ./gha status {rid}")
            ui.note(f"再等一轮:   ./gha wait {rid} --timeout {timeout}")
            ui.log(json.dumps({"still_running": True, "run_id": rid,
                               "status": st or "unknown"}, ensure_ascii=False))
            return EXIT_STILL_RUNNING
        time.sleep(interval)


def cmd_wait(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    rid = core.resolve_run_id(args.target, args.out)
    return _wait(rid, repo, args.timeout, args.interval)


# ------------------------------------------------------------------ fetch

def cmd_fetch(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    return _fetch(args.target, repo, args.out, bool(args.force), bool(args.yes),
                  bool(args.cleanup))


def _fetch(target: str, repo: str, out: Optional[str], force: bool, authorized: bool,
           cleanup: bool = False) -> int:
    task = core.resolve_task_id(target, out)
    rid = core.resolve_run_id(target, out)
    rdir = core.run_dir(task, out)
    rdir.mkdir(parents=True, exist_ok=True)

    # artifact 名要用【记录的 task_id】，不是本地目录名 ——
    # --out 可以让两者不同，bash 版在这里找过不存在的 result-<目录名>
    recorded = core.read_text_file(rdir / "task_id").strip()
    if recorded:
        task = recorded

    ui.info(f"取回 run {rid} 的结果 → {rdir}")

    st, cc = remote.run_state(repo, rid)
    if st and st != "completed":
        ui.warn(f"run 还没结束（status={st}）—— 现在下载可能拿不到 artifact。"
                f"先跑：./gha wait {target}")

    # 幂等判定必须按 run_id：只看 result/ 存不存在是不够的 ——
    # 同一个 task_id 重复提交时那会是【上一个 run】的旧结果，
    # 而 run.json 已指向新 run，两个文件来自不同 run，agent 会静默消费错数据。
    prev = core.read_text_file(rdir / "fetched_run").strip()
    result_dir = rdir / "result"
    if (result_dir / "manifest.json").is_file() and prev == rid and not force:
        ui.st_ok(f"result/ 已是 run {rid} 的结果，跳过重复下载（要重下加 --force）")
    else:
        if prev and prev != rid and result_dir.exists():
            ui.note(f"检测到 result/ 来自旧 run {prev}，当前是 {rid} —— 重新下载覆盖")
        for junk in (result_dir, rdir / "fetched_run"):
            if junk.is_dir():
                shutil.rmtree(junk, ignore_errors=True)
            elif junk.exists():
                try:
                    junk.unlink()
                except OSError:
                    pass
        remote.download_artifact(repo, rid, f"result-{task}", result_dir)
        core.write_text_file(rdir / "fetched_run", rid)
        ui.st_ok(f"artifact result-{task} 已下载（run {rid}）")

    # run.json：API 侧事实，与 runner 侧的 manifest.json 分开，不改动 artifact 内容
    data = remote.run_view(repo, rid,
                           "databaseId,status,conclusion,displayTitle,url,createdAt,updatedAt")
    if data:
        run_json = {
            "run_id": data.get("databaseId"),
            "status": data.get("status"),
            "conclusion": data.get("conclusion") or "none",
            "title": data.get("displayTitle"),
            "url": data.get("url"),
            "started_at": data.get("createdAt"),
            "updated_at": data.get("updatedAt"),
        }
        core.write_text_file(rdir / "run.json",
                             json.dumps(run_json, ensure_ascii=False, sort_keys=True))
    else:
        run_json = _read_run_json(rdir) or {}
        ui.warn("查询 run 状态失败，run.json 未更新")

    # 分支投递的清理（B 类）
    ref = core.read_text_file(rdir / "ref").strip()
    if ref:
        if core.read_text_file(rdir / "keep_ref").strip():
            ui.note(f"按要求保留远端分支 {ref}")
        elif authorized:
            if remote.delete_branch(repo, ref):
                ui.st_ok(f"已清理远端分支 {ref}")
            else:
                ui.warn(f"清理远端分支 {ref} 失败（可能已不存在）")
        else:
            ui.st_install(f"未清理远端分支 {ref}（缺 --yes）")

    ui.log("")
    manifest = _read_manifest(rdir)
    if manifest is None:
        ui.warn("下载完成但没找到 manifest.json —— result/ 内容：")
        for p in sorted(result_dir.rglob("*"))[:40]:
            ui.log(f"    {p.relative_to(rdir)}")
        return EXIT_FAIL

    ui.st_ok("结果就绪")
    ui.log(f"    manifest（runner 侧事实）: {result_dir / 'manifest.json'}")
    ui.log(f"    run.json（API 侧事实）:    {rdir / 'run.json'}")
    ui.log(f"    产物目录:                  {result_dir / 'output'}")
    ui.log(f"    完整日志:                  {result_dir / 'stdout.log'}, stderr.log")
    ui.log("")

    # 诊断：把"任务失败"和"撞了 6 小时墙"分开说
    v = state.diagnose(manifest, run_json, _recorded_timeout(rdir))
    if v.kind == "success":
        ui.st_ok(v.summary)
    elif v.kind == "timed_out":
        ui.warn("诊断：撞了时间上限（不是任务自己失败）")
        for line in v.summary.splitlines():
            ui.note(line)
    elif v.kind in ("task_failed", "cancelled"):
        ui.err(f"诊断：{v.summary}")
        tail = (manifest.get("stderr_tail") or "").strip()
        if tail:
            ui.note("stderr 末尾：")
            for line in tail.splitlines()[-8:]:
                ui.note(f"  {line}")
    else:
        ui.warn(f"诊断：{v.summary}")

    ui.log("")
    ui.note("状态复用: " + state.describe_state(manifest).split(": ", 1)[-1])
    ui.note("agent 后续用法：Read manifest.json 看 exit_code / outputs / runner_env / state，")
    ui.note("              再 Read output/ 下的具体产物。字段说明见 references/result-contract.md")
    _maybe_cleanup_after_fetch(repo, rid, rdir, cleanup, authorized)
    return EXIT_OK


# ------------------------------------------------------------------ logs / list

def cmd_logs(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    rid = core.resolve_run_id(args.target, args.out)
    if not args.failed:
        ui.note("完整日志可能很长；结果的干净副本在 .gha-runs/<task>/result/stdout.log")
    flag = "--log-failed" if args.failed else "--log"
    res = core.run_gh(["run", "view", rid, flag], repo=repo)
    if res.stdout:
        ui.log(res.stdout.rstrip("\n"))
    if not res.ok:
        raise GhaError(f"取日志失败（rc={res.rc}）：{res.stderr.strip()[:400]}")
    return EXIT_OK


def cmd_list(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    runs = remote.list_runs(repo, args.limit)
    ui.log(f"{'RUN_ID':<14}{'STATUS':<12}{'CONCLUSION':<12}{'TASK':<22}URL")
    if not runs:
        ui.note(f"（{repo} 里没有 {core.WORKFLOW_NAME} 的 run）")
        return EXIT_OK
    for r in runs:
        ui.log(f"{str(r.get('databaseId')):<14}"
               f"{str(r.get('status') or ''):<12}"
               f"{str(r.get('conclusion') or '-'):<12}"
               f"{str(r.get('displayTitle') or ''):<22}"
               f"{r.get('url') or ''}")
    return EXIT_OK


# ------------------------------------------------------------------ clean

# gh run list 的 --limit：gh 会在内部翻页一直取到这个数（默认 20，这里一次全清）
_CLEAN_ALL_RUN_LIMIT = 1000


def cmd_clean(args) -> int:
    core.require_gh()
    require_auth()
    repo = core.need_repo()

    if bool(getattr(args, "all", False)) == bool(getattr(args, "run_id", None)):
        raise GhaError("gha clean 必须二选一：--run-id <id>（task_id/run_id 均可）或 --all")

    if getattr(args, "all", False):
        runs = remote.list_runs(repo, _CLEAN_ALL_RUN_LIMIT)
        if not runs:
            ui.st_skip("仓库里没有可清理的 run")
            return EXIT_OK
        plan = _build_clean_plan(repo, runs)
        show_cmd = "./gha clean --all --yes"
    else:
        rid = core.resolve_run_id(args.run_id, args.out)
        data = remote.run_view(repo, rid)
        if not data:
            raise GhaError(f"run {rid} 不存在或无权访问：{repo}")
        plan = _build_clean_plan(repo, [data])
        show_cmd = f"./gha clean --run-id {rid} --yes"

    # B 类闸门：无 --yes 只打印将执行的删除清单，绝不删
    _print_clean_plan(repo, plan)
    if not bool(getattr(args, "yes", False)):
        ui.st_install("B 类操作未执行（缺 --yes）")
        ui.note(f"命令: {show_cmd}")
        raise NotAuthorized("需要 --yes 才能删除 run/artifact")

    total_runs = len(plan)
    total_arts = sum(len(p["artifacts"]) for p in plan)
    art_failed = run_failed = 0
    for p in plan:
        af, rf = _delete_run_contents(
            repo, p["run_id"], artifacts=p["artifacts"], title=p.get("title", ""))
        art_failed += af
        run_failed += rf

    if art_failed or run_failed:
        ui.err(f"清理完成但有失败：run {total_runs - run_failed}/{total_runs}、"
               f"artifact {total_arts - art_failed}/{total_arts} —— "
               f"失败项已逐一警告，未中断其余删除")
        return EXIT_FAIL
    ui.st_ok(f"清理完成：删了 {total_runs} 个 run、{total_arts} 个 artifact")
    return EXIT_OK


def _build_clean_plan(repo: str, runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把 run 列表扩成删除计划：每个 run 带它的全部 artifact（按 id 删）。"""
    plan = []
    for r in runs:
        rid = str(r.get("databaseId") or "")
        if not rid:
            continue
        artifacts = [a for a in remote.list_run_artifacts(repo, rid) if a.get("id") is not None]
        plan.append({
            "run_id": rid,
            "title": str(r.get("displayTitle") or ""),
            "url": str(r.get("url") or ""),
            "artifacts": artifacts,
        })
    return plan


def _print_clean_plan(repo: str, plan: List[Dict[str, Any]]) -> None:
    total_arts = sum(len(p["artifacts"]) for p in plan)
    ui.info(f"删除计划（{repo}）：{len(plan)} 个 run、{total_arts} 个 artifact")
    for p in plan:
        if p["artifacts"]:
            names = "、".join(
                f"{a.get('name') or a.get('id')}#{a.get('id')}" for a in p["artifacts"])
            ui.log(f"  run {p['run_id']}（{p['title']}）: artifact {names}")
        else:
            ui.log(f"  run {p['run_id']}（{p['title']}）: 无 artifact（删 run 即连带日志）")


def _delete_run_contents(repo: str, run_id: str, artifacts: Optional[List[Dict[str, Any]]] = None,
                         title: str = "") -> Tuple[int, int]:
    """删 run 的全部 artifact，再删 run 本身。返回 (artifact 失败数, run 失败数)。

    一个失败只警告、不中断其余删除；fetch 后的自动清理也走这里。
    artifacts 不传时现查（fetch 自动清理路径没有提前建计划）。
    """
    art_failed = 0
    if artifacts is None:
        artifacts = remote.list_run_artifacts(repo, run_id)
    for a in artifacts:
        if a.get("id") is None:
            continue
        aid = int(a.get("id"))
        name = str(a.get("name") or f"#{aid}")
        if remote.delete_artifact(repo, aid):
            ui.st_ok(f"已删 artifact {name}#{aid}")
        else:
            ui.warn(f"删除 artifact {name}#{aid} 失败")
            art_failed += 1
    suffix = f"（{title}）" if title else ""
    if remote.delete_run(repo, run_id):
        ui.st_ok(f"已删 run {run_id}{suffix}")
        return art_failed, 0
    ui.warn(f"删除 run {run_id}{suffix} 失败")
    return art_failed, 1


def _maybe_cleanup_after_fetch(repo: str, rid: str, rdir: Path,
                               cleanup: bool, authorized: bool) -> None:
    """fetch 成功后按请求清理 run + artifact（B 类）。

    调用方只在取回成功（manifest 就位、返回 EXIT_OK）时才会走到这里；
    取回失败直接提前返回，run 与 artifact 都保留供排查。

    cleanup 是本次命令带的 --cleanup；登记是 submit --cleanup --yes（非 --wait）
    落盘的 <rdir>/cleanup 标记 —— 那次提交已取得用户同意，fetch 时不必再要 --yes。
    """
    marked = core.read_text_file(rdir / "cleanup").strip() == "1"
    if not cleanup and not marked:
        return
    if cleanup and not marked and not authorized:
        ui.st_install("未清理 run/artifact（--cleanup 是 B 类写操作，需要与 --yes 一起用）")
        ui.note(f"命令: ./gha clean --run-id {rid} --yes（不删也行，run 记录会留下）")
        return
    if marked:
        ui.note("按提交时登记的 --cleanup，取回成功后清理该 run 与 artifact")
    _delete_run_contents(repo, rid)
    if marked:
        # 已执行完登记里的清理，摘掉标记，避免下次 fetch --force 再撞一遍
        try:
            (rdir / "cleanup").unlink()
        except OSError:
            pass


# ------------------------------------------------------------------ secret（凭证传递围栏）

# 只碰键名与 gh 的元数据。三条铁律：
#   * 绝不把凭证值回显到 stdout/stderr、写进任何文件
#   * set 的值只经 gh 子进程的 stdin 传输，绝不出现在 argv（命令行参数在同机可见）
#   * GitHub secrets 只写不可读 —— 无法增量合并，每次 set 都是全量覆盖，帮助文本
#     和本地提示都要把这一点说破

def cmd_secret(args) -> int:
    action = getattr(args, "secret_action", None)
    if action not in ("set", "list", "rm"):
        raise GhaError("用法：./gha secret set|list|rm …（详见 ./gha secret -h）")
    core.require_gh()
    require_auth()
    repo = core.need_repo()
    if action == "set":
        return _secret_set(args, repo)
    if action == "list":
        return _secret_list(repo)
    return _secret_rm(args, repo)


def _secret_read_input(args) -> str:
    """读全量 JSON 文本：默认 stdin；--from-file 时先给风险提示再读文件。"""
    from_file = getattr(args, "from_file", None)
    if from_file:
        p = Path(from_file).expanduser()
        if not p.is_file():
            raise GhaError(f"文件不存在：{from_file}")
        ui.warn(f"风险提示：--from-file 让含凭证的 JSON 明文存放在磁盘文件 {p} 上 —— "
                "用完请删除，别放进同步盘/备份目录")
        try:
            return p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            raise GhaError(f"读取失败（需要 UTF-8 文本）：{from_file}")
    try:
        interactive = sys.stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        ui.info("粘贴全量 JSON 对象（键=env 名，值=凭证字符串），"
                "输完按 Ctrl-D（Windows: Ctrl-Z 后回车）结束；值不会回显：")
    return sys.stdin.read()


def _secret_validate(text: str) -> Dict[str, str]:
    """校验是 JSON 对象且值均为字符串。错误消息只提键名，绝不带值。"""
    if not text.strip():
        raise GhaError("没有收到 JSON 输入（secrets 只写不可读，每次必须提供【全量】JSON）")
    try:
        obj = json.loads(text)
    except ValueError as e:
        # JSONDecodeError 的 msg/位置不含文档内容；其余异常类型兜底成类名
        raise GhaError("输入不是合法 JSON：%s（值不会被回显）" %
                       getattr(e, "msg", e.__class__.__name__))
    if not isinstance(obj, dict):
        raise GhaError('输入必须是 JSON 对象，形如 {"KEY": "值", ...}')
    bad = sorted(k for k, v in obj.items() if not isinstance(v, str))
    if bad:
        raise GhaError("以下键的值不是字符串（凭证必须是字符串）：" + ", ".join(bad))
    return obj


def _secret_set(args, repo: str) -> int:
    name = getattr(args, "secret_name", None) or core.SECRET_DEFAULT_NAME
    if not core.valid_secret_name(name):
        raise GhaError(f"secret 名字非法（只允许字母数字下划线，≤64 字符）：{name}")

    obj = _secret_validate(_secret_read_input(args))
    keys = sorted(obj)

    def do():
        # 值只走 stdin；不打印 gh 的输出，成功后由我们自己只报键名
        res = core.run_gh(["secret", "set", name], repo=repo, stdin_text=json.dumps(obj))
        if not res.ok:
            raise GhaError(f"写入 secret {name} 失败（rc={res.rc}）—— "
                           "检查 gh 认证与 repo scope；错误详情不回显，必要时手工跑 gh 查看")

    core.confirm_b(
        f"写入仓库 secret {name}（{len(keys)} 个键）@ {repo}",
        do,
        authorized=bool(args.yes),
        show=f"gh secret set {name} -R {repo}   # 全量 JSON 经 stdin 传入，不出现在命令行",
    )
    ui.st_ok(f"已写入 {name} @ {repo}")
    ui.log("    键名（只列名字，不含值）：")
    for k in keys:
        ui.note(f"  {k}")
    ui.note(f"共 {len(keys)} 个键")
    ui.warn("secrets 只写不可读，无法增量合并 —— 本次 set 已【整体覆盖】旧值，"
            "每次都必须提供全量 JSON；要保留原有键就必须带上"
            "（./gha secret list 只能看名字，看不到值）")
    return EXIT_OK


def _secret_list(repo: str) -> int:
    """A 类只读：只列名字与更新时间 —— API 本来就只写不可读，拿不到值。"""
    data = core.gh_json(["api", f"repos/{repo}/actions/secrets"])
    if not isinstance(data, dict) or "secrets" not in data:
        raise GhaError(f"查询 {repo} 的 secrets 列表失败 —— 检查仓库名与 gh 权限（repo scope）")
    items = data.get("secrets") or []
    if not items:
        ui.note(f"（{repo} 还没有任何仓库 secret）")
        return EXIT_OK
    ui.log(f"{'NAME':<32}UPDATED_AT")
    for s in items:
        ui.log(f"{str(s.get('name')):<32}{str(s.get('updated_at') or '')}")
    ui.note("secrets 只写不可读：这里只有名字与更新时间，值本来就取不到")
    return EXIT_OK


def _secret_rm(args, repo: str) -> int:
    name = getattr(args, "name", None) or core.SECRET_DEFAULT_NAME
    if not core.valid_secret_name(name):
        raise GhaError(f"secret 名字非法（只允许字母数字下划线，≤64 字符）：{name}")
    core.confirm_b(
        f"删除仓库 secret {name} @ {repo}",
        lambda: core.run_gh(
            ["api", "-X", "DELETE", f"repos/{repo}/actions/secrets/{name}"],
            allow_fail=False),
        authorized=bool(args.yes),
        show=f"gh api -X DELETE repos/{repo}/actions/secrets/{name}",
    )
    ui.st_ok(f"已删除 {name} @ {repo}")
    return EXIT_OK


# ------------------------------------------------------------------ 2.0 交互运行时客户端命令

def _resolve_interactive_client(target: Optional[str]) -> Tuple[Any, str]:
    """解析目标 task_id 或 URL 对应的 InteractiveClient"""
    from .interactive_client import InteractiveClient

    base_url = "http://127.0.0.1:8765"
    token = os.environ.get("GHA_INTERACTIVE_TOKEN", "")

    if target:
        if target.startswith("http://") or target.startswith("https://"):
            base_url = target
        else:
            # 尝试从本地任务输出目录中读取交互信息
            local_dir = core.RUNS_DIR / target
            run_file = local_dir / "run.json"
            inter_file = local_dir / "interactive.json"
            if inter_file.exists():
                try:
                    with open(inter_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        base_url = data.get("gateway_url") or data.get("tunnel_url") or base_url
                        token = data.get("agent_token") or token
                except Exception:
                    pass
            elif run_file.exists():
                try:
                    with open(run_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        base_url = data.get("tunnel_url") or base_url
                except Exception:
                    pass

            # 没有本地会话文件时，按 run_id 通过私有 Registry 发现当前 Runner。
            # Registry 同时返回 origin 与受限 Agent Token；只写权限 600 的本地文件，绝不打印。
            if not inter_file.exists():
                endpoint = os.environ.get("GHA_RENDEZVOUS_ENDPOINT", "")
                registry_token = os.environ.get("GHA_RENDEZVOUS_TOKEN", "")
                if not endpoint:
                    cfg_path = Path.home() / ".gha-runner" / "config" / "interactive.yaml"
                    if cfg_path.is_file():
                        from .interactive_config import InteractiveConfig
                        cfg = InteractiveConfig.load(str(cfg_path))
                        endpoint = cfg.rendezvous.endpoint or ""
                        registry_token = cfg.rendezvous.auth_token or registry_token
                run_id = ""
                run_id_file = local_dir / "run_id"
                if run_id_file.is_file():
                    run_id = run_id_file.read_text(encoding="utf-8").strip()
                elif run_file.is_file():
                    run_id = str(json.loads(run_file.read_text(encoding="utf-8")).get("id", ""))
                if endpoint and run_id:
                    import asyncio
                    from interactive_runtime.rendezvous import RendezvousClient
                    # Runner 的默认租户是 GITHUB_REPOSITORY；宿主也必须按该任务
                    # 实际提交的仓库查询，不能一边写仓库租户、一边用本地 default 查询。
                    repo = core.run_get(target, "repo") or core.need_repo()
                    record = asyncio.run(
                        RendezvousClient(endpoint, registry_token, user=repo).resolve_run(run_id)
                    )
                    if record and record.get("origin") and record.get("agent_token"):
                        base_url = record["origin"]
                        token = record["agent_token"]
                        payload = {
                            "gateway_url": base_url,
                            "agent_token": token,
                            "session_id": record.get("session_id", ""),
                            "run_id": run_id,
                            "expires_at": record.get("expires_at", 0),
                        }
                        with open(inter_file, "w", encoding="utf-8") as f:
                            json.dump(payload, f, ensure_ascii=False, indent=2)
                        try:
                            os.chmod(inter_file, 0o600)
                        except OSError:
                            pass
                        ui.note(f"已通过私有 Registry 发现 run {run_id} 的 Interactive Gateway（Token 未回显）")

    if not token:
        # 尝试从 runner temp 读取
        token_tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "gha-interactive-private" / ".agent_token"
        if token_tmp.exists():
            try:
                token = token_tmp.read_text(encoding="utf-8").strip()
            except Exception:
                pass

    return InteractiveClient(base_url=base_url, token=token), base_url


def cmd_interactive(args) -> int:
    """gha interactive doctor / status"""
    action = getattr(args, "interactive_action", None)
    if not action:
        ui.log("请指定子操作：doctor | status")
        return EXIT_FAIL

    if action == "doctor":
        host_only = bool(getattr(args, "host", False))
        ui.section("gha-runner 2.0 Interactive Runtime 自检（宿主机模式）" if host_only
                   else "gha-runner 2.0 Interactive Runtime 自检（Runner 完整模式）")
        items = [
            ("Python >= 3.9", f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", sys.version_info >= (3, 9)),
        ]
        if not host_only:
            items.extend([
                ("Linux Runner", sys.platform, sys.platform.startswith("linux")),
                ("Xvfb (虚拟屏幕)", shutil.which("Xvfb") or "未安装", bool(shutil.which("Xvfb"))),
                ("Openbox (窗口管理器)", shutil.which("openbox") or "未安装", bool(shutil.which("openbox"))),
                ("cloudflared (Tunnel)", shutil.which("cloudflared") or "未安装", bool(shutil.which("cloudflared"))),
                ("FFmpeg (录屏)", shutil.which("ffmpeg") or "未安装", bool(shutil.which("ffmpeg"))),
                ("xdotool (GUI 输入)", shutil.which("xdotool") or "未安装", bool(shutil.which("xdotool"))),
                ("wmctrl (窗口管理)", shutil.which("wmctrl") or "未安装", bool(shutil.which("wmctrl"))),
                ("agent-desktop", shutil.which("agent-desktop") or "未安装", bool(shutil.which("agent-desktop"))),
            ])
            try:
                import playwright
                items.append(("Playwright", playwright.__file__, True))
            except ImportError:
                items.append(("Playwright", "未安装 (pip install playwright)", False))

        from .vault import Vault
        v = Vault()
        items.append(("Host Vault 目录", str(v.root), v.root.exists()))

        failures = []
        for name, detail, ok in items:
            mark = "OK" if ok else "WARN"
            ui.log(f"  [{mark:4}] {name:<24} {detail}")
            if not ok:
                failures.append(name)

        if failures and not host_only:
            ui.err("Runner 环境预检失败：%s。Interactive Runtime 拒绝在缺组件时启动。" % ", ".join(failures))
            return EXIT_FAIL
        ui.st_ok("环境预检通过" if not failures else "宿主机检查完成（Runner 依赖未完整，仅宿主机模式可用）")
        return EXIT_OK

    elif action == "status":
        target = getattr(args, "target", "")
        client, base_url = _resolve_interactive_client(target)
        ui.log(f"正在连接 Interactive Gateway: {base_url} ...")
        try:
            status = client.session_status()
            ui.log(json.dumps(status, ensure_ascii=False, indent=2))
            return EXIT_OK
        except Exception as e:
            raise GhaError(f"获取状态失败: {e}")

    return EXIT_FAIL


def cmd_browser(args) -> int:
    """gha browser snapshot / navigate"""
    from .browser_client import BrowserClient

    action = getattr(args, "browser_action", None)
    target = getattr(args, "target", "")
    client, _ = _resolve_interactive_client(target)
    bc = BrowserClient(client)

    if action == "snapshot":
        res = bc.snapshot()
        ui.log(json.dumps(res, ensure_ascii=False, indent=2))
        return EXIT_OK
    elif action == "navigate":
        url = getattr(args, "url", "")
        res = bc.navigate(url)
        ui.log(json.dumps(res, ensure_ascii=False, indent=2))
        return EXIT_OK

    return EXIT_FAIL


def cmd_desktop(args) -> int:
    """gha desktop snapshot / screenshot"""
    from .desktop_client import DesktopClient

    action = getattr(args, "desktop_action", None)
    target = getattr(args, "target", "")
    client, _ = _resolve_interactive_client(target)
    dc = DesktopClient(client)

    if action == "snapshot":
        res = dc.snapshot()
        ui.log(json.dumps(res, ensure_ascii=False, indent=2))
        return EXIT_OK
    elif action == "screenshot":
        out_p = getattr(args, "out", None) or "desktop-screenshot.png"
        dc.screenshot(output_file=out_p)
        ui.st_ok(f"截屏已保存: {out_p}")
        return EXIT_OK

    return EXIT_FAIL


def cmd_handoff(args) -> int:
    """gha handoff request / open / complete / cancel"""
    from .handoff_client import HandoffClient

    action = getattr(args, "handoff_action", None)
    target = getattr(args, "target", "")
    client, base_url = _resolve_interactive_client(target)
    hc = HandoffClient(client)

    if action == "request":
        mode = getattr(args, "mode", "browser")
        res = hc.request_handoff(mode=mode)
        ticket = res.get("ticket", "")
        portal_path = res.get("handoff_url", "")
        full_portal = f"{base_url}{portal_path}"
        ui.section(f"人工接管请求已生成 (模式: {mode})")
        ui.log(f"  Ticket: {ticket}")
        ui.log(f"  入口链接: {full_portal}")
        ui.note("请在浏览器中打开链接完成操作，完成后调用 `gha handoff complete` 或在网页点击返还控制权。")
        return EXIT_OK
    elif action == "open":
        res = hc.request_handoff(mode="browser")
        portal = res.get("handoff_url", "/web/index.html")
        ui.log(f"正在本地浏览器打开: {base_url}{portal}")
        hc.open_portal(portal)
        return EXIT_OK
    elif action == "complete":
        res = hc.complete_handoff()
        ui.st_ok(f"控制权已返还: {res.get('message', 'ok')}")
        return EXIT_OK
    elif action == "cancel":
        res = hc.cancel_handoff()
        ui.st_ok("已取消接管请求")
        return EXIT_OK

    return EXIT_FAIL


def cmd_state(args) -> int:
    """gha state list / checkpoint / export / import / restore"""
    from .state_client import StateClient
    from .vault import Vault

    action = getattr(args, "state_action", None)
    target = getattr(args, "target", "")
    client, _ = _resolve_interactive_client(target)
    vault = Vault()
    sc = StateClient(client, vault=vault)

    if action == "list":
        manifest = sc.list_manifest()
        ui.log(json.dumps(manifest, ensure_ascii=False, indent=2))
        return EXIT_OK
    elif action == "checkpoint":
        cp_type = getattr(args, "type", "AUTH")
        res = sc.create_checkpoint(checkpoint_type=cp_type)
        ui.st_ok(f"已生成检查点 ({cp_type}): {res.get('checkpoint', {}).get('checkpoint_id')}")
        return EXIT_OK
    elif action == "export":
        proj = getattr(args, "project", "default") or "default"
        ui.log(f"正在从 Runner 回传状态对象并加密存储至 Vault (项目: {proj}) ...")
        res = sc.export_state_to_vault(project=proj)
        ui.st_ok(f"回传完成: 成功同步 {len(res.get('synced_objects', []))} 个对象")
        return EXIT_OK
    elif action == "import":
        proj = getattr(args, "project", "default") or "default"
        name = getattr(args, "name", "")
        cat = getattr(args, "category", "auth_state")
        res = sc.import_state_from_vault(project=proj, object_name=name, category=cat)
        ui.st_ok(f"已推送状态至 Runner: {res}")
        return EXIT_OK
    elif action == "restore":
        proj = getattr(args, "project", "default") or "default"
        name = getattr(args, "name", "")
        cat = getattr(args, "category", "auth_state")
        res = sc.import_state_from_vault(project=proj, object_name=name, category=cat)
        if res.get("status") != "completed" or not res.get("verified"):
            raise GhaError(f"状态恢复未确认成功：{res}")
        ui.st_ok(f"状态已推送并由 Runner 恢复：{name}")
        return EXIT_OK

    return EXIT_FAIL


def cmd_vault(args) -> int:
    """gha vault list / inspect / delete"""
    from .vault import Vault

    action = getattr(args, "vault_action", None)
    vault = Vault()

    if action == "list":
        cat = getattr(args, "category", None)
        proj = getattr(args, "project", None)
        objs = vault.list_objects(category=cat, project=proj)
        if not objs:
            ui.note("（Vault 中暂无存储对象）")
            return EXIT_OK
        ui.log(f"{'OBJECT_ID':<30}{'CATEGORY':<16}{'PROJECT':<12}{'BYTES':<10}{'ENCRYPTED'}")
        for o in objs:
            ui.log(f"{str(o.get('id')):<30}{str(o.get('category')):<16}{str(o.get('project')):<12}{str(o.get('size')):<10}{str(o.get('encrypted'))}")
        return EXIT_OK
    elif action == "inspect":
        obj_id = getattr(args, "object_id", "")
        item = vault.inspect_object(obj_id)
        if not item:
            raise GhaError(f"未找到 Vault 对象: {obj_id}")
        ui.log(json.dumps(item, ensure_ascii=False, indent=2))
        return EXIT_OK
    elif action == "delete":
        obj_id = getattr(args, "object_id", "")
        ok = vault.delete_object(obj_id)
        if ok:
            ui.st_ok(f"已删除 Vault 对象: {obj_id}")
        else:
            ui.warn(f"未找到对象或删除失败: {obj_id}")
        return EXIT_OK

    return EXIT_FAIL

