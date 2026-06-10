#!/usr/bin/env python3
"""
WAF Honeypot Collector — CLI 入口。

用法:
    python main.py init-db         初始化数据库
    python main.py recv-safeline   启动 SafeLine Syslog 接收（Phase 1）
    python main.py show-latest     查看最近事件（Phase 1）
    python main.py stats           查看统计信息（Phase 1）
    ...
"""

import argparse
import sys
from pathlib import Path

from app.config import get_config
from app.db import init_db, close_connection
from app.logger import setup_logging, get_logger


def cmd_init_db(args):
    """初始化数据库。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    result = init_db(db_path)
    logger.info("数据库初始化完成: %s", result)
    print(f"[OK] 数据库初始化完成: {result}")


def cmd_recv_safeline(args):
    """启动 SafeLine Syslog 接收服务（Phase 1 实现）。"""
    print("[INFO] recv-safeline 命令将在 Phase 1 中实现。")
    print("请参考 docs/development_plan.md 进入 Phase 1 开发。")


def cmd_show_latest(args):
    """查看最近事件（Phase 1 实现）。"""
    print("[INFO] show-latest 命令将在 Phase 1 中实现。")
    print("请参考 docs/development_plan.md 进入 Phase 1 开发。")


def cmd_stats(args):
    """查看统计信息（Phase 1 实现）。"""
    print("[INFO] stats 命令将在 Phase 1 中实现。")
    print("请参考 docs/development_plan.md 进入 Phase 1 开发。")


def main():
    parser = argparse.ArgumentParser(
        description="基于 WAF 与蜜罐的安全事件采集与关联分析平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python main.py init-db              # 初始化数据库
    python main.py recv-safeline        # 启动 Syslog 接收
    python main.py show-latest          # 查看最近事件
    python main.py stats                # 查看统计

更多命令将在后续 Phase 中添加。
        """,
    )

    # 全局参数
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="配置文件路径（默认: config.yaml）",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="启用 DEBUG 日志级别",
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # init-db
    subparsers.add_parser("init-db", help="初始化数据库")

    # recv-safeline（Phase 1 骨架）
    subparsers.add_parser("recv-safeline", help="启动 SafeLine Syslog 接收服务")

    # show-latest（Phase 1 骨架）
    p_show = subparsers.add_parser("show-latest", help="显示最近事件")
    p_show.add_argument("--limit", type=int, default=20, help="显示条数（默认: 20）")

    # stats（Phase 1 骨架）
    subparsers.add_parser("stats", help="显示基本统计信息")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # 初始化日志
    log_level = "DEBUG" if args.debug else "INFO"
    setup_logging(level=log_level)

    global logger
    logger = get_logger("main")

    # 分发子命令
    commands = {
        "init-db": cmd_init_db,
        "recv-safeline": cmd_recv_safeline,
        "show-latest": cmd_show_latest,
        "stats": cmd_stats,
    }

    try:
        cmd_func = commands.get(args.command)
        if cmd_func:
            cmd_func(args)
        else:
            parser.print_help()
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] 用户中断")
        sys.exit(0)
    except Exception as e:
        logger.error("命令执行失败: %s", e, exc_info=True)
        print(f"[ERROR] {e}")
        sys.exit(1)
    finally:
        close_connection()


if __name__ == "__main__":
    main()
