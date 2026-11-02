"""argparse 子命令树与统一错误处理。

子命令与 flag 与 bash 版逐字一致（对外契约）；新增 --cache-key / --cache-paths。
所有可预期失败都是 GhaError 子类，在这里统一转成退出码 —— 不打印 traceback。
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, commands, core, setupenv, ui
from .ui import EXIT_FAIL, EXIT_OK, GhaError

PROG = "gha"

EPILOG = """\
授权边界（重要）:
  A 只读检测      — gha 自主执行（doctor / status / list / logs / wait / fetch / secret list）
  B 写操作        — 装 gh、建仓、git push、dispatch、删分支/删 run/artifact（clean）、
                    写/删仓库 secret（secret set/rm）；需 --yes。
                    不带 --yes 时只打印将执行的命令并退出 125，绝不执行。
                    agent 每次都要先取得用户同意，一次同意只覆盖那一次那一个动作。
  C 必须真人操作  — gh auth login / auth refresh / SSO / 网页开关；
                    gha 只打印命令并停下等待，用户完成后必须重新跑 doctor 验证。

凭证传递围栏（详见 SKILL.md）:
  凭证经仓库 secret（默认名 GHA_TASK_SECRETS，值是 JSON 对象）传输，永不落仓库；
  任务用 submit --secret KEY[,KEY...]（或任务目录 secrets.txt）声明要注入的键名白名单；
  云端启动前对步骤日志注册 ::add-mask:: 掩码，任务跑完先对捕获日志按全部凭证值脱敏
  （***），artifact 上传前再双通道扫描整个待上传载荷（正则特征 + 已注册凭证值字面
  比对 —— 掩码管不到 artifact，实测）。
  secret 只写不可读：每次 gha secret set 必须给【全量】JSON，无法增量合并。

退出码:
  0 成功   1 失败   2 wait 超时但 run 仍在跑（不是失败）
  3 有 C 类待用户完成   4 凭据扫描命中已中止   125 缺 --yes，B 类动作未执行

详见 SKILL.md 与 references/setup.md。
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="gha — 把高强度任务卸载到 GitHub Actions 并取回结果",
        epilog=EPILOG,
    )
    p.add_argument("--version", action="version", version=f"gha-runner {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<子命令>")

    # --- setup / doctor
    s = sub.add_parser("setup", help="环境自举：检测并按需安装 gh、引导认证、补 git 身份",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("--check", action="store_true", help="只检测，不执行任何 B 类动作（= doctor）")
    s.add_argument("--yes", action="store_true", help="允许执行 B 类安装（下载 gh 到 <skill>/bin/）")
    s.set_defaults(func=_do_setup)

    d = sub.add_parser("doctor", help="= setup --check，只读检测")
    d.set_defaults(func=_do_doctor)

    # --- init
    i = sub.add_parser("init", help="建/接仓库，推 dispatcher 到默认分支并冒烟",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    i.add_argument("--create", action="store_true", help="仓库不存在时创建（B 类）")
    i.add_argument("--repo", help="OWNER/NAME；不给则用 config 里的，再不给用 <login>/agent-runner")
    i.add_argument("--visibility", choices=("public", "private"),
                   help="默认 public（4 vCPU/16GB、分钟数免费不限量）；private 仅在你显式指定时用")
    i.add_argument("--skip-smoke", action="store_true", help="跳过冒烟验证")
    i.add_argument("--yes", action="store_true", help="允许 B 类写操作（建仓、推 workflow、冒烟 dispatch）")
    i.set_defaults(func=commands.cmd_init)

    # --- submit
    sb = sub.add_parser("submit", help="打包任务并提交执行（默认立即返回，不阻塞）",
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    sb.add_argument("task_dir", help="任务目录，内含 task.sh / task.py / task.js")
    sb.add_argument("--task-id", help="默认从目录名派生；只允许 [A-Za-z0-9._-]")
    sb.add_argument("--runner", default=core.DEFAULT_RUNNER,
                    help=f"默认 {core.DEFAULT_RUNNER}；可选 {'/'.join(core.VALID_RUNNERS)}")
    sb.add_argument("--shell", default="auto",
                    help="auto(默认，按入口文件名推断) | bash | python3 | node")
    sb.add_argument("--timeout", default=str(core.DEFAULT_TIMEOUT_MINUTES),
                    help="【云端 job】超时分钟数，默认 360，硬上限 360（6 小时）")
    sb.add_argument("--out", help=f"结果目录，默认 <cwd>/.gha-runs/<task_id>")
    sb.add_argument("--wait", action="store_true", help="提交后阻塞等待（内部已含 fetch）")
    sb.add_argument("--wait-timeout", type=int, default=core.DEFAULT_WAIT_TIMEOUT,
                    help="配合 --wait，最长等待【秒】数，默认 600；超时返回 2，不算失败")
    sb.add_argument("--interval", type=int, default=core.DEFAULT_WAIT_INTERVAL,
                    help="配合 --wait，轮询间隔秒数，默认 15，最小 3")
    sb.add_argument("--keep-ref", action="store_true", help="分支投递时取回后保留远端分支")
    sb.add_argument("--allow-public", action="store_true",
                    help="跳过凭据/隐私扫描（责任自负，需用户明确要求）")
    sb.add_argument("--secret", action="append", default=[], metavar="KEY[,KEY...]",
                    help="凭证白名单：任务运行时要注入的 env 键名（逗号分隔，可重复给）。"
                         "值存在仓库 secret（默认名 GHA_TASK_SECRETS，./gha secret set 写入）里，"
                         "云端由 _gha/credinject.py 按名单 export + 步骤日志掩码 + 捕获日志脱敏。"
                         "也可在任务目录放 secrets.txt（一行一个键名）。见 SKILL.md「凭证传递围栏」")
    sb.add_argument("--cache-key", help="启用跨次环境复用；不给则完全关闭缓存")
    sb.add_argument("--cache-paths", help="额外要缓存的路径，逗号或换行分隔")
    sb.add_argument("--interactive", action="store_true",
                    help="启用 Interactive Runtime（提供图形桌面、浏览器自动化与 Handoff 通道）")
    sb.add_argument("--interactive-config", default="", help="交互运行时额外配置（JSON 字符串）")
    sb.add_argument("--cleanup", action="store_true",
                    help="取回成功后自动清理该 run + artifact（B 类，需与 --yes 一起用；"
                         "非 --wait 时登记到 fetch 时生效）")
    sb.add_argument("--yes", action="store_true", help="允许 B 类写操作（push、dispatch）")
    sb.set_defaults(func=commands.cmd_submit)

    # --- status
    st = sub.add_parser("status", help="一次性查询 run 状态，输出 JSON，不阻塞")
    st.add_argument("target", help="task_id 或 run_id")
    st.add_argument("--out")
    st.set_defaults(func=commands.cmd_status)

    # --- wait
    w = sub.add_parser("wait", help="阻塞等待到终态或超时（超时返回 2，不算失败）")
    w.add_argument("target", help="task_id 或 run_id")
    w.add_argument("--timeout", type=int, default=core.DEFAULT_WAIT_TIMEOUT,
                   help="最长等待【秒】数，默认 600")
    w.add_argument("--interval", type=int, default=core.DEFAULT_WAIT_INTERVAL,
                   help="轮询间隔秒数，默认 15，最小 3")
    w.add_argument("--out")
    w.set_defaults(func=commands.cmd_wait)

    # --- fetch
    f = sub.add_parser("fetch", help="下载 artifact 到本地，打印 manifest.json 路径")
    f.add_argument("target", help="task_id 或 run_id")
    f.add_argument("--out")
    f.add_argument("--force", action="store_true", help="忽略幂等缓存，强制重下")
    f.add_argument("--cleanup", action="store_true",
                   help="取回成功后自动清理该 run + artifact（B 类，需与 --yes 一起用）")
    f.add_argument("--yes", action="store_true", help="允许清理分支投递留下的远端分支（B 类）")
    f.set_defaults(func=commands.cmd_fetch)

    # --- clean
    c = sub.add_parser("clean", help="删 run 及其 artifact（B 类，需 --yes）",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    c.add_argument("--run-id", help="task_id 或 run_id：先删该 run 的全部 artifact，再删 run 本身")
    c.add_argument("--all", action="store_true",
                   help="删仓库里全部 workflow run 及其 artifact（逐条列出再删）")
    c.add_argument("--out")
    c.add_argument("--yes", action="store_true", help="允许删除（B 类）")
    c.set_defaults(func=commands.cmd_clean)

    # --- secret（凭证传递围栏：仓库 secret 管理。铁律：只碰键名，绝不回显值）
    sec = sub.add_parser("secret",
                         help="管理围栏用的仓库 secret：set / list / rm",
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    sec_sub = sec.add_subparsers(dest="secret_action", metavar="<set|list|rm>")

    ss = sec_sub.add_parser("set",
                            help="写入/整体覆盖仓库 secret（B 类，需 --yes）",
                            description="把【全量】JSON 对象写入仓库 secret（默认名 GHA_TASK_SECRETS）。\n"
                                        "键 = 任务里用的 env 名，值 = 凭证字符串。\n"
                                        "凭证值永不进 git 历史与 dispatch payload；run 步骤日志由\n"
                                        "GitHub 自动掩码，随 artifact 上传的捕获日志由围栏脱敏+扫描兜底。\n\n"
                                        "重要：GitHub secrets 只写不可读 —— 无法读取现值、无法增量合并，\n"
                                        "每次 set 都是整体覆盖，必须提供【全量】JSON（漏掉的键就没了）。\n\n"
                                        "默认只从 stdin 读（值不进命令行、不落磁盘）；--from-file 更危险，\n"
                                        "会先打印风险提示。任何情况下 gha 都不回显值，成功后只报键名。",
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    ss.add_argument("--secret-name", default=core.SECRET_DEFAULT_NAME,
                    help=f"secret 名，默认 {core.SECRET_DEFAULT_NAME}"
                         "（改了要同步改 dispatcher 的 env 映射，一般不要动）")
    ss.add_argument("--from-file", metavar="PATH",
                    help="从文件读全量 JSON（明文落盘，有风险提示；默认从 stdin 读）")
    ss.add_argument("--yes", action="store_true", help="允许 B 类写操作（gh secret set）")
    ss.set_defaults(func=commands.cmd_secret)

    sl = sec_sub.add_parser("list", help="列仓库 secret 的名字与更新时间（A 类只读；值本来就取不到）")
    sl.set_defaults(func=commands.cmd_secret)

    sr = sec_sub.add_parser("rm", help="删除仓库 secret（B 类，需 --yes）",
                            formatter_class=argparse.RawDescriptionHelpFormatter)
    sr.add_argument("name", nargs="?", default=None,
                    help=f"要删的 secret 名，默认 {core.SECRET_DEFAULT_NAME}")
    sr.add_argument("--yes", action="store_true", help="允许 B 类删除")
    sr.set_defaults(func=commands.cmd_secret)

    # --- logs
    lg = sub.add_parser("logs", help="取 run 日志")
    lg.add_argument("target", help="task_id 或 run_id")
    lg.add_argument("--failed", action="store_true", help="只看失败步骤的日志")
    lg.add_argument("--out")
    lg.set_defaults(func=commands.cmd_logs)

    # --- list
    ls = sub.add_parser("list", help="列本仓库的 run")
    ls.add_argument("--limit", type=int, default=20)
    ls.set_defaults(func=commands.cmd_list)

    # ---------------- 2.0 交互运行时子命令 ----------------
    # --- interactive
    inter = sub.add_parser("interactive", help="交互运行时诊断与会话状态")
    inter_sub = inter.add_subparsers(dest="interactive_action", metavar="<doctor|status>")
    idoc = inter_sub.add_parser("doctor", help="诊断宿主机与交互运行时依赖就绪状态")
    idoc.add_argument("--host", action="store_true", help="只检查宿主机，不检查 Runner GUI 依赖")
    idoc.set_defaults(func=commands.cmd_interactive)
    ist = inter_sub.add_parser("status", help="查询 Runner 当前交互状态机与网关信息")
    ist.add_argument("target", help="task_id 或 gateway URL")
    ist.set_defaults(func=commands.cmd_interactive)

    # --- browser
    br = sub.add_parser("browser", help="交互运行时浏览器自动化命令")
    br_sub = br.add_subparsers(dest="browser_action", metavar="<snapshot|navigate>")
    bsnap = br_sub.add_parser("snapshot", help="抓取浏览器 DOM 与无障碍树快照")
    bsnap.add_argument("target", help="task_id 或 gateway URL")
    bsnap.set_defaults(func=commands.cmd_browser)
    bnav = br_sub.add_parser("navigate", help="控制浏览器导航至指定 URL")
    bnav.add_argument("target", help="task_id 或 gateway URL")
    bnav.add_argument("url", help="目标网页地址")
    bnav.set_defaults(func=commands.cmd_browser)

    # --- desktop
    dk = sub.add_parser("desktop", help="交互运行时桌面 GUI 自动化命令")
    dk_sub = dk.add_subparsers(dest="desktop_action", metavar="<snapshot|screenshot>")
    dsnap = dk_sub.add_parser("snapshot", help="抓取桌面窗口列表与无障碍结构")
    dsnap.add_argument("target", help="task_id 或 gateway URL")
    dsnap.set_defaults(func=commands.cmd_desktop)
    dshot = dk_sub.add_parser("screenshot", help="捕获虚拟桌面屏幕截图")
    dshot.add_argument("target", help="task_id 或 gateway URL")
    dshot.add_argument("--out", help="本地截图输出文件路径")
    dshot.set_defaults(func=commands.cmd_desktop)

    # --- handoff
    hd = sub.add_parser("handoff", help="人工接管协调（Browser/Desktop Handoff）")
    hd_sub = hd.add_subparsers(dest="handoff_action", metavar="<request|open|complete|cancel>")
    hreq = hd_sub.add_parser("request", help="请求人工接管并获取单次 Ticket")
    hreq.add_argument("target", help="task_id 或 gateway URL")
    hreq.add_argument("--mode", choices=("browser", "desktop"), default="browser", help="接管模式")
    hreq.add_argument("--timeout", type=int, default=300, help="接管超时秒数")
    hreq.set_defaults(func=commands.cmd_handoff)
    hopen = hd_sub.add_parser("open", help="在宿主机浏览器中直接打开接管门户")
    hopen.add_argument("target", help="task_id 或 gateway URL")
    hopen.set_defaults(func=commands.cmd_handoff)
    hcomp = hd_sub.add_parser("complete", help="完成人工接管，交还控制权给 Agent")
    hcomp.add_argument("target", help="task_id 或 gateway URL")
    hcomp.set_defaults(func=commands.cmd_handoff)
    hcan = hd_sub.add_parser("cancel", help="取消人工接管请求")
    hcan.add_argument("target", help="task_id 或 gateway URL")
    hcan.set_defaults(func=commands.cmd_handoff)

    # --- state
    stt = sub.add_parser("state", help="状态持久化、Checkpoint 与文件回传")
    stt_sub = stt.add_subparsers(dest="state_action", metavar="<list|checkpoint|export|import|restore>")
    slist = stt_sub.add_parser("list", help="列出 Runner 当前可回传状态清单")
    slist.add_argument("target", help="task_id 或 gateway URL")
    slist.set_defaults(func=commands.cmd_state)
    scp = stt_sub.add_parser("checkpoint", help="触发生成检查点")
    scp.add_argument("target", help="task_id 或 gateway URL")
    scp.add_argument("--type", choices=("AUTH", "BROWSER", "DESKTOP", "TASK", "FINAL"), default="AUTH")
    scp.set_defaults(func=commands.cmd_state)
    sexp = stt_sub.add_parser("export", help="将 Runner 状态对象分块拉取并加密存入宿主机 Vault")
    sexp.add_argument("target", help="task_id 或 gateway URL")
    sexp.add_argument("--project", default="default", help="项目命名空间")
    sexp.set_defaults(func=commands.cmd_state)
    simp = stt_sub.add_parser("import", help="将宿主机 Vault 状态推送至 Runner")
    simp.add_argument("target", help="task_id 或 gateway URL")
    simp.add_argument("--project", default="default", help="项目命名空间")
    simp.add_argument("--name", required=True, help="状态对象名称")
    simp.add_argument("--category", default="auth_state", help="状态类别")
    simp.set_defaults(func=commands.cmd_state)
    sres = stt_sub.add_parser("restore", help="从宿主机 Vault 推送状态到 Runner 并立即恢复")
    sres.add_argument("target", help="task_id 或 gateway URL")
    sres.add_argument("--project", default="default", help="项目命名空间")
    sres.add_argument("--name", required=True, help="状态对象名称")
    sres.add_argument("--category", default="auth_state", choices=("auth_state", "browser_profile"), help="状态类别")
    sres.set_defaults(func=commands.cmd_state)

    # --- vault
    vt = sub.add_parser("vault", help="宿主机本地加密持久化凭证库管理")
    vt_sub = vt.add_subparsers(dest="vault_action", metavar="<list|inspect|delete>")
    vlist = vt_sub.add_parser("list", help="列出 Vault 中保存的对象元数据")
    vlist.add_argument("--category", help="按分类过滤")
    vlist.add_argument("--project", help="按项目过滤")
    vlist.set_defaults(func=commands.cmd_vault)
    vinsp = vt_sub.add_parser("inspect", help="查看指定对象的元数据与完整性")
    vinsp.add_argument("object_id", help="Vault 对象 ID")
    vinsp.set_defaults(func=commands.cmd_vault)
    vdel = vt_sub.add_parser("delete", help="安全删除指定 Vault 对象")
    vdel.add_argument("object_id", help="Vault 对象 ID")
    vdel.set_defaults(func=commands.cmd_vault)

    return p


def _do_setup(args) -> int:
    return setupenv.cmd_setup(check_only=bool(args.check), yes=bool(args.yes))


def _do_doctor(args) -> int:
    return setupenv.cmd_setup(check_only=True, yes=False)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK

    # argparse 把 --task-id 存成 task_id，commands 里按这个约定取
    try:
        return int(args.func(args) or EXIT_OK)
    except GhaError as e:
        ui.err(e.message)
        return e.code
    except KeyboardInterrupt:
        ui.warn("被用户中断")
        return 130
    except BrokenPipeError:
        # 被 head / grep 截断输出，不是错误
        return EXIT_OK


if __name__ == "__main__":      # pragma: no cover
    sys.exit(main())
