"""Interactive Runtime 命令行主入口。

在 GitHub Actions Runner 上以守护模式启动 Runtime Supervisor，
或包装执行任务命令并在结束时自动触发最终 Checkpoint 归档。
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from typing import List, Optional

from gha_runner.interactive_config import InteractiveConfig
from .supervisor import RuntimeSupervisor


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="gha-runner Interactive Runtime Supervisor")
    parser.add_argument("--config", help="交互配置文件 (YAML)")
    parser.add_argument("--run-id", help="GitHub Run ID")
    parser.add_argument("--port", type=int, default=8765, help="网关绑定端口")
    parser.add_argument("--command", help="待执行的任务启动脚本或命令")
    return parser.parse_args(argv)


async def async_main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.config and os.path.isfile(args.config):
        cfg = InteractiveConfig.load(args.config)
    else:
        cfg = InteractiveConfig()

    if args.port:
        cfg.gateway.port = args.port

    # Registry 地址可以经 dispatch input 传递；认证信息只允许经 Secret/env 注入。
    if os.environ.get("GHA_RENDEZVOUS_ENDPOINT"):
        cfg.rendezvous.endpoint = os.environ["GHA_RENDEZVOUS_ENDPOINT"]
    if os.environ.get("GHA_RENDEZVOUS_TOKEN"):
        cfg.rendezvous.auth_token = os.environ["GHA_RENDEZVOUS_TOKEN"]
    if os.environ.get("GHA_TUNNEL_HOSTNAME"):
        cfg.tunnel.provider = "named"
        cfg.tunnel.hostname = os.environ["GHA_TUNNEL_HOSTNAME"]
        cfg.tunnel.token_secret = "GHA_TUNNEL_TOKEN"

    supervisor = RuntimeSupervisor(config=cfg, run_id=args.run_id)
    print("[runtime] tunnel=%s registry_configured=%s" % (
        cfg.tunnel.provider, bool(cfg.rendezvous.endpoint and cfg.rendezvous.auth_token), flush=True)

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

        if args.command:
            # 运行任务子进程
            proc = await asyncio.create_subprocess_shell(args.command)
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
