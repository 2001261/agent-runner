"""凭证传递围栏 —— runner 侧的包装启动器 + 捕获日志脱敏器。

本文件会被 bundle.py 原样复制进任务包的 _gha/ 目录，在云端 runner 上【独立】运行，
因此**不得有任何相对导入**，只依赖标准库（Python ≥ 3.9）。

调用方式（由 templates/agent-dispatch.yml 的 Run task / Redact captured logs 步骤发起）：

    python credinject.py [--blob-env NAME] [--declared PATH] [--mask-only] -- <解释器> <入口> [参数...]
    python credinject.py [--blob-env NAME] [--declared PATH] --emit-export
    python credinject.py [--blob-env NAME] --redact FILE [FILE...]

职责：
  1. 读环境变量 NAME（默认 GHA_TASK_SECRETS）里的 JSON 对象 —— 键 = 任务里用的 env 名，
     值 = 凭证。值经 GitHub repo secrets 传输，永不进 git 历史与 dispatch payload；
  2. 白名单：只 export <declared.json>（字符串数组）里声明过的键，未声明的一律不 export；
     声明了但 blob 里没有 → 明确报错（只列缺失的键名，**绝不打印 blob 内容**）；
  3. --mask-only：对 JSON 里所有字符串叶子（含嵌套）逐个输出 ::add-mask::<值>
     （长度 <4 的跳过，太短的值在正常日志里到处撞车，掩了只会制造噪音），
     再对整个 blob 原文 add-mask 一次。这一步的输出走【步骤日志】（不重定向），
     在同一 job 内注册一次即全程有效；
  4. 运行任务模式（`-- <解释器> <入口>`）：**不再输出任何 ::add-mask:: 行**。
     实测教训（run 36551046326 之后的 fence-a）：GitHub 的掩码只作用于平台发布的步骤日志，
     而我们重定向捕获进 stdout.log 的掩码声明自己就是泄露源 —— 任务输出连同掩码行会
     随 artifact 上传，公开仓库的 artifact 任何人可下载。掩码注册已由 --mask-only
     预跑完成，这里重复打印没有任何收益，只有泄露风险；
  5. --redact FILE...：把 blob 里全部字符串叶子（含嵌套、含 blob 原文）在给定文件里
     字面替换成 ***。这是对 stdout.log / stderr.log / manifest.json 这类【我们自己的
     产物】的脱敏 —— 掩码保护不了它们（见 4）。多行值按行拆开也进替换集；
     替换按长度降序（先整 blob、再整值、最后行片段），且绝不把值本身打印出来；
  6. --emit-export：按同一白名单把键=值逐行打印成 shell 的 export 语句，供 dispatcher
     在 Run task 之前把凭证交到预检（verify.sh）环境里；值只经 env 进子进程，绝不打印；
  7. 以子进程方式启动任务（环境已注入），**原样传播任务退出码**。

除三种命令行模式外，本模块还以文件路径被 dispatcher 的 Scan artifact payload 步骤
import：find_literal_leaks() 提供"已注册凭证值的精确字面比对"（与 --redact 同一套
替换集），补正则特征库看不见的泄露 —— 任务把自己拿到的凭证写进 output/ 产物。

blob 为空/未设置 → 透明直通：运行任务时行为与没有围栏时完全一致，不报错、不掩码；
--redact 时不改动任何文件。

Windows runner 的控制台默认 cp1252，打印中文会 UnicodeEncodeError —— 与 ui.py 同款处理。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

DEFAULT_BLOB_ENV = "GHA_TASK_SECRETS"
ERR = "::error::"
WARN = "::warning::"
# 长度 <4 的字符串跳过掩码与替换（见模块 docstring）
MIN_MASK_LEN = 4
REPLACEMENT = "***"

# 与 ui.py 一致：import 即把 stdout/stderr 重配成 utf-8 + replace。
# 宁可个别字符变 ?，也不能让一次打印带走整个任务。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ------------------------------------------------------------------ blob 字符串收集

def _string_leaves(node, out) -> None:
    """递归收集 JSON 里所有字符串叶子（dict 的值与 list 的元素，含任意层嵌套）。"""
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _string_leaves(v, out)
    elif isinstance(node, list):
        for v in node:
            _string_leaves(v, out)


def _lines_of(value):
    """多行值（如 PEM 私钥）拆成行 —— 日志里值经常是按行出现的。"""
    return value.replace("\r", "\n").split("\n")


# ------------------------------------------------------------------ 掩码（仅 --mask-only）

def _emit_mask(value: str) -> None:
    """输出一条 ::add-mask::。多行值按行拆开逐条注册。"""
    for part in _lines_of(value):
        if len(part) >= MIN_MASK_LEN:
            sys.stdout.write("::add-mask::%s\n" % part)


def mask_everything(blob_raw: str, obj) -> None:
    """--mask-only 模式的掩码声明。::add-mask:: 自身会被 runner 命令解析器吞掉，
    不会以明文进入步骤日志；重复注册是幂等的。"""
    leaves = []      # type: list
    _string_leaves(obj, leaves)
    seen = set()
    for v in leaves:
        if len(v) < MIN_MASK_LEN or v in seen:
            continue
        seen.add(v)
        _emit_mask(v)
    # blob 原文整体也注册一次：防止任务把 JSON 原样打印出来
    if len(blob_raw) >= MIN_MASK_LEN:
        _emit_mask(blob_raw)
    sys.stdout.flush()


# ------------------------------------------------------------------ 脱敏（--redact）

def redaction_patterns(blob_raw: str, obj) -> list:
    """替换集：全部字符串叶子 + 各自行片段 + blob 原文 + 原文行片段。

    按长度降序 —— 先替换长串（blob 原文、完整值），短串（行片段）兜底；
    否则先替换叶子会破坏 blob 原文的连续性，整行残留成 "*** 拼盘"虽不泄露，
    但长串优先能把"整段被凭证占据"的行干净折叠成一个 ***。
    """
    cands = []       # type: list
    leaves = []      # type: list
    if obj is not None:
        _string_leaves(obj, leaves)
    for v in leaves + [blob_raw]:
        cands.append(v)
        cands.extend(_lines_of(v))
    uniq = {}        # 用 dict 保序去重
    for p in cands:
        if len(p) >= MIN_MASK_LEN and p not in uniq:
            uniq[p] = True
    return sorted(uniq.keys(), key=len, reverse=True)


def _redact_one(path: str, patterns) -> int:
    """就地脱敏一个文件，返回替换次数（0 = 无命中或文件不存在，均不算错）。

    文件不存在通常是前置步骤没产出（如任务启动前就挂了）—— 静默跳过，
    后续 artifact 扫描会看到同样的现场。读写按字节往返：utf-8 失败退 latin-1
    （与 secrets.py 同款，宁可多掩不可漏），编码方式原样写回。
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return 0
    try:
        text = raw.decode("utf-8")
        enc = "utf-8"
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        enc = "latin-1"
    n = 0
    for p in patterns:
        c = text.count(p)
        if c:
            text = text.replace(p, REPLACEMENT)
            n += c
    if n:
        tmp = path + ".gha-redact.tmp"
        with open(tmp, "wb") as f:
            f.write(text.encode(enc))
        os.replace(tmp, path)
        sys.stdout.write("已脱敏 %d 处：%s\n" % (n, path))
    sys.stdout.flush()
    return n


def redact_files(paths, blob_raw: str) -> int:
    """--redact 主流程。blob 为空 → 不改动任何文件（透明）。绝不回显值。"""
    if not blob_raw.strip():
        return 0
    try:
        obj = json.loads(blob_raw)
        if not isinstance(obj, (dict, list)):
            obj = None
    except ValueError:
        obj = None    # blob 非法 JSON：原文本身也可能是敏感值，仍按原文与行片段脱敏
    patterns = redaction_patterns(blob_raw, obj)
    if not patterns:
        return 0
    total = 0
    for p in paths:
        try:
            total += _redact_one(p, patterns)
        except OSError as e:
            # 只报路径与失败原因，不含任何值
            sys.stderr.write("%s脱敏失败：%s（%s）\n" % (WARN, p, e.__class__.__name__))
    sys.stdout.write("redact 完成：共替换 %d 处，覆盖 %d 个文件\n" % (total, len(paths)))
    sys.stdout.flush()
    return 0


# ------------------------------------------------------------------ 字面比对（供 artifact 扫描调用）

def find_literal_leaks(root, blob_raw: str) -> list:
    """在 root 目录的全部文件里做【已注册凭证值】的精确字面比对。

    命中集与 --redact 的替换集完全同源（redaction_patterns：全部字符串叶子 +
    多行值的行片段 + blob 原文及其行片段，长度 <MIN_MASK_LEN 跳过）——不写第二份。
    分工：正则特征库（secrets.py）兜"运行期新产生的、不在 blob 里的敏感值"；
    这里兜"任务把自己拿到的凭证写进产物"（实测 fence-c：output/leaked.txt 放了
    明文凭证，正则对该值零感知，artifact 照常上传到公开仓库）。

    返回 ["<文件绝对路径>:<行号>", ...]（排序、去重），**不含任何命中内容**。
    逐行字节级比对：每个值预编成 utf-8 与 latin-1 两种字节形态，二进制与非
    UTF-8 文件不崩也不漏；流式读行，内存与大文件体量无关。
    """
    if not blob_raw.strip():
        return []
    try:
        obj = json.loads(blob_raw)
        if not isinstance(obj, (dict, list)):
            obj = None
    except ValueError:
        obj = None    # blob 非法 JSON：原文本身按整体与行片段比对（redaction_patterns 兜住）
    needles = set()
    for p in redaction_patterns(blob_raw, obj):
        needles.add(p.encode("utf-8"))
        try:
            needles.add(p.encode("latin-1"))
        except UnicodeEncodeError:
            pass      # 含非 latin-1 字符的值不可能以该编码形态出现在字节流里
    if not needles:
        return []
    files = []
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames.sort()
        for fn in filenames:
            files.append(os.path.join(dirpath, fn))
    hits = set()
    for path in sorted(files):
        try:
            with open(path, "rb") as fh:
                for lineno, line in enumerate(fh, 1):
                    for nd in needles:
                        if nd in line:
                            hits.add("%s:%d" % (path, lineno))
                            break   # 同一行报一次就够，绝不报命中的是哪个值
        except OSError:
            continue    # 读不了的文件（权限、坏符号链接）跳过 —— 正则通道仍会扫到它
    return sorted(hits)


# ------------------------------------------------------------------ 输入解析

def _parse_argv(argv):
    """解析 argv → (blob_env, declared_path, mask_only, redact_paths, cmd, emit_export)。

    选项一律带 -- 前缀，遇到孤立的 -- 其后全为任务命令；没有 -- 时，第一个不是
    已知选项的参数起即命令区（--mask-only / --redact 这类"只有选项"的调用不留 --）。
    --redact 之后到命令界（-- 或 argv 末尾）的全部参数都是文件路径。
    极简实现，不引 argparse：这是要独立跑在 runner 上的单文件。用法错误返回 None。
    """
    blob_env = DEFAULT_BLOB_ENV
    declared_path = None
    mask_only = False
    emit_export = False
    redact_paths = []
    cmd = []
    rest = list(argv)
    while rest:
        a = rest.pop(0)
        if a == "--":
            cmd = rest
            break
        if a == "--mask-only":
            mask_only = True
        elif a == "--emit-export":
            emit_export = True
        elif a == "--redact":
            redact_paths = rest
            rest = []
            break
        elif a in ("--blob-env", "--declared"):
            if not rest:
                return None
            v = rest.pop(0)
            if a == "--blob-env":
                blob_env = v
            else:
                declared_path = v
        else:
            # 第一个非选项起就是命令区（不解析任务自己的参数）
            cmd = [a] + rest
            break
    return blob_env, declared_path, mask_only, redact_paths, cmd, emit_export


# ------------------------------------------------------------------ 启动任务

def _exec_task(cmd, env=None) -> int:
    """子进程启动任务并原样传播退出码。env 为 None 时原样继承当前环境。"""
    if not cmd:
        sys.stderr.write("%s用法: credinject.py [选项] -- <解释器> <入口> [参数...]\n" % ERR)
        return 2
    try:
        proc = subprocess.run(cmd, env=env)
    except OSError as e:
        # 解释器/入口不存在之类：127 是 shell 的惯例
        sys.stderr.write("%s无法启动任务 %r：%s\n" % (ERR, cmd[0], e))
        return 127
    rc = proc.returncode
    if rc is None:
        return 1
    if rc < 0:
        # 被信号终止 → 按 shell 惯例折算成 128+signum
        return 128 - rc
    return rc


# ------------------------------------------------------------------ 白名单导出

def _shell_quote(value):
    """POSIX 单引号转义：凭证里出现引号/换行也不会截断 export 语句。"""
    return "'" + value.replace("'", "'\\''") + "'"


def emit_export_lines(blob_raw, declared_path=None) -> int:
    """按白名单打印 export 语句（stdout 只含键名与转义后的值，不经过任何日志转发）。

    dispatcher 用 `eval "$(credinject.py --emit-export)"` 在预检步骤里恢复凭证环境；
    输出的每一行仍会经过平台日志（命令回显时），所以调用方必须让 shell 不回显。
    """
    if not blob_raw.strip():
        return 0
    try:
        obj = json.loads(blob_raw)
    except ValueError as exc:
        sys.stderr.write("%s%s 不是合法 JSON：%s（blob 内容不回显）\n"
                         % (ERR, DEFAULT_BLOB_ENV, getattr(exc, "msg", "解析失败")))
        return 1
    if not isinstance(obj, dict):
        sys.stderr.write("%s%s 顶层必须是 JSON 对象（内容不回显）\n" % (ERR, DEFAULT_BLOB_ENV))
        return 1
    if declared_path is None:
        declared_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "declared.json")
    declared, err = _load_declared(declared_path)
    if declared is None:
        sys.stderr.write("%s%s\n" % (ERR, err))
        return 1
    for key in declared:
        value = obj.get(key)
        if isinstance(value, str):
            sys.stdout.write("export %s=%s\n" % (key, _shell_quote(value)))
    sys.stdout.flush()
    return 0


# ------------------------------------------------------------------ 主流程

def main(argv) -> int:
    parsed = _parse_argv(list(argv))
    if parsed is None:
        sys.stderr.write("%scredinject.py 选项解析失败（--blob-env/--declared 缺参数？）\n" % ERR)
        return 2
    blob_env, declared_path, mask_only, redact_paths, cmd, emit_export = parsed

    blob_raw = os.environ.get(blob_env) or ""

    # ---- --redact 模式：脱敏指定文件后退出，不启动任何任务
    if redact_paths:
        return redact_files(redact_paths, blob_raw)

    if emit_export:
        return emit_export_lines(blob_raw, declared_path)

    if not blob_raw.strip():
        # 透明直通：没有凭证要传，行为和没有围栏时完全一致
        if mask_only:
            return 0
        return _exec_task(cmd)

    # blob 存在但 JSON 非法：--mask-only 尽力掩原文后照常交棒，让正式包装启动去报清晰错误
    obj = None
    try:
        obj = json.loads(blob_raw)
    except ValueError as exc:
        if mask_only:
            _emit_mask(blob_raw)
            sys.stdout.flush()
            return 0
        # JSONDecodeError 的 msg/lineno/colno 只含位置信息，不含文档内容 ——
        # 错误消息绝不回显 blob
        sys.stderr.write("%s%s 不是合法 JSON：%s (line %s column %s)（blob 内容不回显）\n"
                         % (ERR, blob_env, getattr(exc, "msg", "解析失败"),
                            getattr(exc, "lineno", "?"), getattr(exc, "colno", "?")))
        # 非法 JSON 也可能是敏感文本，先掩原文再退出
        _emit_mask(blob_raw)
        sys.stdout.flush()
        return 1

    if mask_only:
        # 掩码声明走到底：对象/数组按叶子掩，标量掩原文
        if isinstance(obj, (dict, list)):
            mask_everything(blob_raw, obj)
        else:
            _emit_mask(blob_raw)
            sys.stdout.flush()
        return 0

    if not isinstance(obj, dict):
        sys.stderr.write("%s%s 顶层必须是 JSON 对象 {\"KEY\": \"值\"}（内容不回显）\n"
                         % (ERR, blob_env))
        _emit_mask(blob_raw)
        sys.stdout.flush()
        return 1

    # ---- 运行任务模式【不发任何 ::add-mask::】：
    #      掩码注册已由 --mask-only 预跑完成（同一 job 注册一次全程有效）；
    #      这里的 stdout 会被 dispatcher 重定向进 stdout.log 随 artifact 上传，
    #      掩码声明打进这条流 = 自己泄露（实测教训，见模块 docstring 第 4 条）。

    # ---- 白名单
    if declared_path is None:
        declared_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "declared.json")
    declared, err = _load_declared(declared_path)
    if declared is None:
        sys.stderr.write("%s%s\n" % (ERR, err))
        return 1

    env = os.environ.copy()
    missing = [k for k in declared if k not in obj]
    if missing:
        # 只列缺失的键名（键名来自任务自己的声明，不是凭证），绝不打印 blob
        sys.stderr.write("%s声明的凭证键在 %s 中缺失：%s —— 用 ./gha secret set 补全"
                         "（注意 secrets 只写不可读，必须提供全量 JSON）\n"
                         % (ERR, blob_env, ", ".join(missing)))
        return 1
    bad = [k for k in declared if not isinstance(obj[k], str)]
    if bad:
        sys.stderr.write("%s以下键的值不是字符串，无法 export：%s\n" % (ERR, ", ".join(bad)))
        return 1
    for k in declared:
        # 未声明的键一律不 export（上面只遍历 declared）
        env[k] = obj[k]

    return _exec_task(cmd, env=env)


def _load_declared(path):
    """读白名单文件：JSON 字符串数组。返回 (list, 错误消息)。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError:
        return None, "declared.json 不存在或不可读：%s" % path
    except ValueError:
        return None, "declared.json 不是合法 JSON（应为字符串数组）"
    if not isinstance(data, list) or any(not isinstance(k, str) for k in data):
        return None, "declared.json 必须是字符串数组"
    return data, ""


if __name__ == "__main__":      # pragma: no cover
    sys.exit(main(sys.argv[1:]))
