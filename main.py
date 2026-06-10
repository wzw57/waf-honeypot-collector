#!/usr/bin/env python3
"""
WAF Honeypot Collector — CLI 入口。

用法:
    python main.py init-db         初始化数据库
    python main.py recv-safeline   启动 SafeLine Syslog 接收
    python main.py show-latest     查看最近事件
    python main.py stats           查看统计信息
    ...
"""

import argparse
import sys
from pathlib import Path

from app.config import get_config
from app.db import (
    close_connection,
    get_basic_stats,
    get_latest_safeline_logs,
    init_db,
    insert_raw_safeline_log,
)
from app.logger import get_logger, setup_logging
from collectors.safeline_syslog import SafeLineSyslogReceiver


def cmd_init_db(args):
    """初始化数据库。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    result = init_db(db_path)
    logger.info("数据库初始化完成: %s", result)
    print(f"[OK] 数据库初始化完成: {result}")


def cmd_recv_safeline(args):
    """启动 SafeLine Syslog 接收服务。"""
    config = get_config(args.config)

    # 从配置读取参数，允许命令行覆盖
    host = args.host or config["safeline"]["host"]
    port = args.port or config["safeline"]["port"]
    buffer_size = config["safeline"]["buffer_size"]
    db_path = config["database"]["path"]

    # 确保数据库已初始化
    init_db(db_path)

    # 定义日志入库回调
    def on_log_received(raw_message, sender_ip, parse_result):
        insert_raw_safeline_log(db_path, raw_message, sender_ip, parse_result)

    receiver = SafeLineSyslogReceiver(
        host=host,
        port=port,
        buffer_size=buffer_size,
        on_log_received=on_log_received,
    )

    receiver.start()


def cmd_show_latest(args):
    """查看最近事件。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    limit = args.limit

    logs = get_latest_safeline_logs(db_path, limit=limit)

    if not logs:
        print("[INFO] 暂无日志记录")
        return

    print(f"\n{'='*80}")
    print(f"  最近 {len(logs)} 条 SafeLine 原始日志")
    print(f"{'='*80}")
    print(f"{'ID':>6} | {'接收时间':<22} | {'发送IP':<15} | {'状态':<10} | {'报文预览'}")
    print("-" * 80)

    for log in logs:
        preview = log["raw_message_preview"].replace("\n", " ")[:60]
        print(f"{log['id']:>6} | {log['received_at']:<22} | "
              f"{log['sender_ip'] or 'N/A':<15} | {log['parse_status']:<10} | {preview}")

    print("=" * 80)
    print(f"  提示: 使用 --limit N 控制显示条数")
    print()


def cmd_stats(args):
    """查看统计信息。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]

    stats = get_basic_stats(db_path)

    print(f"\n{'='*50}")
    print(f"  统计信息")
    print(f"{'='*50}")
    print(f"  总日志条数:        {stats['total']}")
    print(f"  ├─ 解析成功:       {stats['parsed']}")
    print(f"  ├─ 解析失败:       {stats['failed']}")
    print(f"  └─ 待解析:         {stats['pending']}")
    print()

    if stats["top_senders"]:
        print(f"  Top 发送源 IP:")
        for s in stats["top_senders"]:
            print(f"    {s['ip']:<20s} {s['count']} 条")
    print("=" * 50)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="基于 WAF 与蜜罐的安全事件采集与关联分析平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    python main.py init-db                    # 初始化数据库
    python main.py recv-safeline              # 启动 Syslog 接收
    python main.py recv-safeline --port 1514  # 指定端口接收
    python main.py show-latest                # 查看最近 20 条
    python main.py show-latest --limit 50     # 查看最近 50 条
    python main.py stats                      # 查看统计

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

    # recv-safeline
    p_recv = subparsers.add_parser(
        "recv-safeline",
        help="启动 SafeLine Syslog 接收服务（前台阻塞）",
    )
    p_recv.add_argument(
        "--host", type=str, default=None,
        help="监听地址（覆盖 config.yaml 配置）",
    )
    p_recv.add_argument(
        "--port", type=int, default=None,
        help="监听端口（覆盖 config.yaml 配置）",
    )

    # show-latest
    p_show = subparsers.add_parser("show-latest", help="显示最近事件")
    p_show.add_argument("--limit", type=int, default=20, help="显示条数（默认: 20）")

    # stats
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
