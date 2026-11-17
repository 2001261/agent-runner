"""Interactive Runtime 命令行主入口。

在 GitHub Actions Runner 上以守护模式启动 Runtime Supervisor，
或包装执行任务命令并在结束时自动触发最终 Checkpoint 归档。
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import os
import signal
import sys
import sysconfig
from typing import Dict, List, Optional

from gha_runner.interactive_config import (
    InteractiveConfig,
    TunnelProtocolError,
    parse_tunnel_protocol,
)
from .preflight import TUNNEL_PROTOCOL_ENV
from .supervisor import RuntimeSupervisor


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="gha-runner Interactive Runtime Supervisor")
    parser.add_argument("--config", help="交互配置文件 (YAML)")
    parser.add_argument("--run-id", help="GitHub Run ID")
    parser.add_argument("--port", type=int, default=8765, help="网关绑定端口")
    parser.add_argument("--command", help="待执行的任务启动脚本或命令")
    return parser.parse_args(argv)


def _runtime_site_packages() -> List[str]:
    """Runtime 依赖所在的 site-packages（隔离 venv 优先，其次自身 venv）。"""
    found: List[str] = []
    venv = os.environ.get("GHA_INTERACTIVE_VENV", "")
    if venv:
        found.extend(sorted(glob.glob(os.path.join(venv, "lib", "python*", "site-packages"))))
        found.extend(sorted(glob.glob(os.path.join(venv, "Lib", "site-packages"))))
    if sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        try:
            found.append(sysconfig.get_paths()["purelib"])
        except KeyError:
            pass
    return [p for p in dict.fromkeys(found) if os.path.isdir(p)]


def task_env(supervisor: RuntimeSupervisor) -> Dict[str, str]:
    """托管任务的环境：GUI 共享环境 + Runtime venv 的依赖路径。

    workflow 用系统解释器启动任务（`python3 ./task.py`），而 aiohttp/playwright 等
    依赖只装在 Runtime 的隔离 venv 里。不把这条路径前置进 PYTHONPATH，任务会在
    import 阶段直接失败（run 41611428434：ModuleNotFoundError: aiohttp）。
    """
    env = supervisor.shared_gui_env()
    extra = _runtime_site_packages()
    if extra:
        parts = [p for p in (env.get("PYTHONPATH") or "").split(os.pathsep) if p]
        env["PYTHONPATH"] = os.pathsep.join(extra + [p for p in parts if p not in extra])
    return env


async def async_main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.config and os.path.isfile(args.config):
        cfg = InteractiveConfig.load(args.config)
    else:
        cfg = InteractiveConfig()

    if args.port:
        cfg.gateway.port = args.port

    # Registry 凭证只经 Secret/env 注入（模板从 GHA_TASK_SECRETS 取出后 export），
    # 绝不写入配置文件或日志；缺失时由 Supervisor 在 GHA 上 fail-closed。
    if os.environ.get("GHA_RENDEZVOUS_ENDPOINT"):
        cfg.rendezvous.endpoint = os.environ["GHA_RENDEZVOUS_ENDPOINT"]
    if os.environ.get("GHA_RENDEZVOUS_TOKEN"):
        cfg.rendezvous.auth_token = os.environ["GHA_RENDEZVOUS_TOKEN"]

    # 非敏感传输偏好：GHA_TUNNEL_PROTOCOL 显式设置时覆盖配置；非法值在启动 Supervisor 前退出。
    try:
        protocol = parse_tunnel_protocol(os.environ.get(TUNNEL_PROTOCOL_ENV))
    except TunnelProtocolError as exc:
        print(f"GHA_TUNNEL_PROTOCOL 非法：{exc}", file=sys.stderr)
        return 1
    if protocol:
        cfg.tunnel.protocol = protocol

    supervisor = RuntimeSupervisor(config=cfg, run_id=args.run_id)

    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _sig_handler():
        stop_event.set()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _sig_handler)
        except NotImplementedError:
            pass

    try:
        token = await supervisor.start()
        # 写入受限 Token 文件供任务脚本消费
        token_file = os.path.join(supervisor.storage_dir, ".agent_token")
        with open(token_file, "w", encoding="utf-8") as f:
            f.write(token)
        os.chmod(token_file, 0o600)

        # 挂入环境变量
        os.environ["GHA_INTERACTIVE_TOKEN"] = token
        os.environ["GHA_INTERACTIVE_GATEWAY"] = f"http://127.0.0.1:{cfg.gateway.port}"
        # 任务据此定位 Runtime 私有目录（transfers/ 等）；已由 workflow 给出时不覆盖
        os.environ.setdefault("GHA_INTERACTIVE_CONFIG_FILE",
                              os.path.join(supervisor.storage_dir, "interactive.yaml"))
        # 在同一 DISPLAY 上跑 noVNC 接管自查时，人工端要用真实门户页面连这个 Gateway。
        os.environ.setdefault("GHA_SELFTEST_PORTAL_BASE",
                              f"http://127.0.0.1:{cfg.gateway.port}")

        if args.command:
            # 任务子进程沿用 supervisor 的 GUI 环境（DISPLAY / 会话总线）：Supervisor 在
            # start() 里才把 DISPLAY 写进自身环境，而 env=None 会继承父进程启动时的原始
            # 环境，任务里的 Playwright/xdotool/agent-desktop 就找不到那台 X。
            proc = await asyncio.create_subprocess_shell(args.command,
                                                         env=task_env(supervisor))
            rc = await proc.wait()
            # 正常执行终态快照
            await supervisor.exporter.create_final_checkpoint("auto-final")
            return rc
        else:
            # 常驻直到信号
            await stop_event.wait()
            return 0
    finally:
        await supervisor.stop()


def main() -> None:
    code = asyncio.run(async_main(sys.argv[1:]))
    sys.exit(code)


if __name__ == "__main__":
    main()
