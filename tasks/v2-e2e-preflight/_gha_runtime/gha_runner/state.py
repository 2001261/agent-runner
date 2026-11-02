"""跨次环境复用（cache）与超时判定。

两件事：
  1. cache key / paths 的计算与归一
  2. 把"撞了 6 小时墙"和"任务自己失败"区分开 —— 超时的 conclusion 是
     `cancelled` 而不是 `timed_out`，GitHub 没有提供任何字段能直接区分，
     只能用三个已有信号组合判断。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from . import core

# 判定"撞了时间上限"时允许的误差（秒）：run 的 started_at 含排队，
# manifest 的 job_started_at 才是任务真正开始的时刻，两者会差几十秒。
TIMEOUT_EPSILON_SECONDS = 90


def normalize_cache_paths(raw: str) -> str:
    """把用户给的 --cache-paths 归一成换行分隔。

    接受逗号或换行分隔；去空白；丢掉空项。用换行而不是逗号做最终分隔符，
    因为路径本身可能含逗号（罕见但合法）。
    """
    if not raw:
        return ""
    items = [p.strip() for p in re.split(r"[,\n]+", raw) if p.strip()]
    # 去重但保持顺序
    seen = set()
    out = []
    for p in items:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return "\n".join(out)


def validate_cache_key(key: str) -> bool:
    """cache key 会拼进 `${{ inputs.cache_key }}-<run_id>`，
    限制字符集避免把奇怪的东西送进 workflow 表达式。"""
    return bool(re.match(r"^[A-Za-z0-9._-]{1,100}$", key or ""))


def cache_save_key(cache_key: str, run_id: str) -> str:
    """存唯一键：`<key>-<run_id>`。

    actions/cache/save 遇到已存在的 key 会报错（"Cache already exists"）。
    标准解法就是存唯一键、按前缀恢复 —— 永不冲突，旧条目靠 7 天 + LRU 自动回收。
    """
    return f"{cache_key}-{run_id}"


def cache_restore_prefix(cache_key: str) -> str:
    """按前缀恢复最近一次的缓存。"""
    return f"{cache_key}-"


def cache_churn_warning(cache_key: str, state_bytes: int) -> Optional[str]:
    """缓存体积接近仓库 10 GB 上限时给出预警。

    每次 run 都会写一个新 entry，状态大 + 跑得频繁时会挤爆上限。
    """
    if state_bytes <= 0:
        return None
    limit = 10 * 1024 * 1024 * 1024
    if state_bytes > limit // 4:
        return (
            f"缓存体积 {core.human_bytes(state_bytes)} 已超仓库 10 GB 上限的 1/4，"
            f"而每次 run 都会写一个新 entry（key={cache_key}-<run_id>）。"
            f"频繁运行会触发 LRU 淘汰churn —— 考虑缩小缓存范围。"
        )
    return None


# ------------------------------------------------------------------ 超时判定

class Verdict:
    """一次 run 的诊断结论。"""

    def __init__(self, kind: str, summary: str, exit_code: Optional[int] = None) -> None:
        self.kind = kind          # success / task_failed / timed_out / cancelled / unknown / running
        self.summary = summary
        self.exit_code = exit_code

    def __repr__(self) -> str:
        return f"Verdict({self.kind!r}, exit_code={self.exit_code!r})"


def diagnose(manifest: Optional[Dict[str, Any]], run: Optional[Dict[str, Any]],
             timeout_minutes: int = 0) -> Verdict:
    """综合 manifest（runner 侧）与 run.json（API 侧）给出诊断。

    超时识别靠三个信号组合 —— GitHub 不提供任何直接字段：
      * conclusion == "cancelled"（超时走的就是取消机制，实测不产生 "timed_out"）
      * manifest.exit_code_recorded == False（说明 Run task 步骤没能写下退出码，
        即被强制终止；这个字段本来就是为此加的）
      * job 时长 >= timeout_minutes*60 - 误差
    """
    run = run or {}
    status = str(run.get("status") or "")
    conclusion = str(run.get("conclusion") or "")

    if status and status != "completed":
        return Verdict("running", f"run 仍在进行（status={status}）")

    recorded = bool((manifest or {}).get("exit_code_recorded", True))
    exit_code = (manifest or {}).get("exit_code")
    duration = _run_duration_seconds(manifest, run)

    if conclusion in ("cancelled", "timed_out"):
        if _looks_like_timeout(recorded, duration, timeout_minutes):
            mins = timeout_minutes or 0
            return Verdict(
                "timed_out",
                f"撞了时间上限：job 跑了 {duration}s，而 --timeout 设的是 {mins} 分钟"
                f"（{mins * 60}s）。GitHub 对超时的 conclusion 是 'cancelled' 而不是"
                f" 'timed_out'，所以这里是用「退出码没记录下来 + 时长达到上限」推出来的。"
                f"\n    单 job 硬上限 360 分钟，不可延长。解法：拆成 needs: 串联的多个 job"
                f"（每个 job 各有独立的 6 小时预算），或用 matrix 分片并行。",
                exit_code if isinstance(exit_code, int) else None,
            )
        return Verdict("cancelled", f"run 被取消（conclusion={conclusion}）",
                       exit_code if isinstance(exit_code, int) else None)

    if conclusion == "success":
        # run 成功但任务退出码非 0 的情况不该出现（Run task 步骤会如实 exit $code），
        # 真出现了就说明模板被改坏了，明确报出来。
        if isinstance(exit_code, int) and exit_code != 0:
            return Verdict("task_failed",
                           f"run conclusion=success 但任务 exit_code={exit_code} —— "
                           f"模板的 Run task 步骤没有如实传播退出码，检查 templates/agent-dispatch.yml",
                           exit_code)
        return Verdict("success", f"任务成功（exit_code={exit_code}）",
                       exit_code if isinstance(exit_code, int) else 0)

    if conclusion == "failure":
        if isinstance(exit_code, int) and exit_code >= 0:
            return Verdict("task_failed", f"任务失败，exit_code={exit_code}", exit_code)
        return Verdict("task_failed",
                       f"run 失败但没能取到任务退出码（exit_code={exit_code}）—— "
                       f"看 result/stderr.log 或 `./gha logs --failed`",
                       exit_code if isinstance(exit_code, int) else None)

    return Verdict("unknown", f"无法判定（status={status!r} conclusion={conclusion!r}）")


def _looks_like_timeout(exit_code_recorded: bool, duration: int,
                        timeout_minutes: int) -> bool:
    if exit_code_recorded:
        # Run task 步骤正常写下了退出码 → 不是被强杀
        return False
    if timeout_minutes <= 0:
        # 不知道上限就只凭"退出码没记录"判断，给个保守结论
        return duration > 0
    return duration >= timeout_minutes * 60 - TIMEOUT_EPSILON_SECONDS


def _run_duration_seconds(manifest: Optional[Dict[str, Any]],
                          run: Dict[str, Any]) -> int:
    """优先用 manifest 的 job 起止（不含排队），否则退回 run 的时间戳。"""
    m = manifest or {}
    start = m.get("job_started_at")
    end = m.get("job_finished_at")
    if isinstance(start, int) and isinstance(end, int) and end >= start > 0:
        return end - start

    from datetime import datetime
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        a = datetime.strptime(str(run.get("started_at")), fmt)
        b = datetime.strptime(str(run.get("updated_at")), fmt)
        return max(0, int((b - a).total_seconds()))
    except (ValueError, TypeError):
        return 0


def describe_state(manifest: Optional[Dict[str, Any]]) -> str:
    """把 manifest 的 state 小节渲染成一行，让 agent 一眼看到复用有没有生效。"""
    st = (manifest or {}).get("state") or {}
    if not st or not st.get("cache_key"):
        return "状态复用: 未启用（submit 时没给 --cache-key）"
    hit = st.get("cache_hit")
    size = st.get("state_dir_bytes") or 0
    parts = [
        f"cache_key={st.get('cache_key')}",
        f"命中={'是' if hit else '否（首次）'}",
    ]
    if st.get("restored_key"):
        parts.append(f"恢复到自 {st['restored_key']}")
    if size:
        parts.append(f"$GHA_STATE_DIR={core.human_bytes(int(size))}")
    paths = st.get("cached_paths") or []
    if paths:
        parts.append(f"缓存了 {len(paths)} 个路径")
    return "状态复用: " + "，".join(parts)
