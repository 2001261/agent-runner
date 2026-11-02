"""输出与错误模型。

bash 版有两类结构性 bug 在这里被消灭：
  * `die` 在 `$( )` 子 shell 里 `exit` 传不出来 → 改用异常，由 cli.main() 统一捕获，
    异常不可能被"子 shell"吞掉。
  * `$VAR` 后紧跟全角字符被吃进变量名 → Python 没有这个问题。

退出码是对外契约，必须与 bash 版逐字一致：
  0 成功 / 1 失败 / 2 wait 超时仍在跑 / 3 有 C 类待用户完成 /
  4 凭据扫描命中已中止 / 125 缺 --yes，B 类动作未执行
"""

from __future__ import annotations

import os
import sys

# Windows 的 cp1252 控制台 encode 不了中文，print 直接 UnicodeEncodeError。
# import 本模块即把 stdout/stderr 重配成 utf-8 + replace：宁可个别字符变 ?，
# 也不能让一次打印带走整条命令。（macOS/Linux 的终端本来就是 UTF-8，无副作用）
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_STILL_RUNNING = 2
EXIT_NEEDS_USER = 3
EXIT_SECRET_FOUND = 4
EXIT_NOT_AUTHORIZED = 125


class GhaError(Exception):
    """可预期的失败：打印消息并以 code 退出，不打印 traceback。"""

    def __init__(self, message: str, code: int = EXIT_FAIL) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


class NotAuthorized(GhaError):
    """B 类写操作缺少 --yes。调用方应把"将执行的命令"打印出来后再抛。"""

    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_NOT_AUTHORIZED)


class NeedsUser(GhaError):
    """C 类：必须真人操作（认证 / 补 scope / SSO / 网页开关）。"""

    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_NEEDS_USER)


class SecretFound(GhaError):
    """凭据/隐私扫描命中，已中止提交。"""

    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_SECRET_FOUND)


# ------------------------------------------------------------------ 颜色

def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Win10 1511+ 支持 VT，但需要先"唤醒"控制台；这个空调用是通行做法。
        # 失败也无所谓 —— 最坏情况是用户看到转义序列，功能不受影响。
        os.system("")
        # 老版本 Windows 不支持 VT，用 ANSI 支持探测兜底
        if os.environ.get("TERM") in (None, "", "dumb"):
            return os.environ.get("WT_SESSION") is not None or os.environ.get("ANSICON") is not None
    return True


_C = _colors_enabled()


def _p(code: str) -> str:
    return f"\033[{code}m" if _C else ""


RESET = _p("0")
RED = _p("31")
GREEN = _p("32")
YELLOW = _p("33")
BLUE = _p("34")
DIM = _p("2")


# ------------------------------------------------------------------ 输出
# 全部走 sys.stdout / sys.stderr 的显式写入，不用 print 的默认 end，
# 保证 Windows 上也不会因为 CRLF 转换弄乱对齐。

def _write(stream, text: str) -> None:
    stream.write(text)
    stream.write("\n")
    stream.flush()


def log(msg: str = "") -> None:
    _write(sys.stdout, msg)


def info(msg: str) -> None:
    _write(sys.stdout, f"{BLUE}==>{RESET} {msg}")


def note(msg: str) -> None:
    _write(sys.stdout, f"{DIM}    {msg}{RESET}")


def warn(msg: str) -> None:
    _write(sys.stderr, f"{YELLOW}[warn]{RESET} {msg}")


def err(msg: str) -> None:
    _write(sys.stderr, f"{RED}[err]{RESET} {msg}")


def section(msg: str) -> None:
    _write(sys.stdout, f"\n{BLUE}{msg}{RESET}")


# setup / doctor 的四态标记。列宽与 bash 版一致，方便肉眼比对差分输出。
def st_ok(msg: str) -> None:
    _write(sys.stdout, f"  {GREEN}[ok]{RESET}         {msg}")


def st_install(msg: str) -> None:
    _write(sys.stdout, f"  {YELLOW}[install]{RESET}     {msg}")


def st_user(msg: str) -> None:
    _write(sys.stdout, f"  {YELLOW}[needs-user]{RESET} {msg}")


def st_fail(msg: str) -> None:
    _write(sys.stdout, f"  {RED}[fail]{RESET}       {msg}")


def st_skip(msg: str) -> None:
    _write(sys.stdout, f"  {DIM}[skip]{RESET}       {msg}")
