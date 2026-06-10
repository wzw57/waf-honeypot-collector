#!/usr/bin/env python3
"""
WAF Honeypot Collector — CLI 入口。

用法:
    python main.py init-db                 初始化数据库
    python main.py recv-safeline           启动 SafeLine Syslog 接收
    python main.py show-latest             查看最近事件
    python main.py stats                   查看统计信息
    python main.py collect-hfish           单次拉取 HFish 日志
    python main.py collect-hfish-loop      循环拉取 HFish 日志
    python main.py normalize               标准化事件
    python main.py show-ip --ip 1.2.3.4    按 IP 查询事件
    ...
"""

import argparse
import sys
from pathlib import Path

from app.config import get_config
from app.db import (
    close_connection,
    get_basic_stats,
    get_events_by_ip,
    get_extended_stats,
    get_latest_normalized_events,
    get_latest_safeline_logs,
    get_latest_hfish_events,
    init_db,
    insert_normalized_event,
    insert_raw_hfish_event,
    insert_raw_safeline_log,
)
from app.logger import get_logger, setup_logging
from analyzers.normalize_runner import run_normalize
from app.utils import now_iso
from collectors.hfish_api import HFishCollector
from collectors.safeline_syslog import SafeLineSyslogReceiver
from parsers.hfish_parser import (
    compute_event_id,
    extract_fields as extract_hfish_fields,
    extract_hfish_event,
)
from parsers.safeline_parser import parse_safeline_syslog


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
    host = args.host or config["safeline"]["host"]
    port = args.port or config["safeline"]["port"]
    buffer_size = config["safeline"]["buffer_size"]
    db_path = config["database"]["path"]

    init_db(db_path)

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
    """查看最近事件（支持原始日志和标准化事件）。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    limit = args.limit
    source = args.source
    mode = args.mode or "normalized"

    if mode == "raw_safeline":
        logs = get_latest_safeline_logs(db_path, limit=limit)
        if not logs:
            print("[INFO] 暂无 SafeLine 原始日志")
            return
        print(f"\n{'='*90}")
        print(f"  最近 {len(logs)} 条 SafeLine 原始日志")
        print(f"{'='*90}")
        print(f"{'ID':>6} | {'接收时间':<22} | {'发送IP':<15} | {'状态':<10} | {'报文预览'}")
        print("-" * 90)
        for log in logs:
            preview = log["raw_message_preview"].replace("\n", " ")[:60]
            print(f"{log['id']:>6} | {log['received_at']:<22} | "
                  f"{log['sender_ip'] or 'N/A':<15} | {log['parse_status']:<10} | {preview}")
        print("=" * 90)
        print()

    elif mode == "raw_hfish":
        logs = get_latest_hfish_events(db_path, limit=limit)
        if not logs:
            print("[INFO] 暂无 HFish 原始日志")
            return
        print(f"\n{'='*90}")
        print(f"  最近 {len(logs)} 条 HFish 原始日志")
        print(f"{'='*90}")
        print(f"{'ID':>6} | {'接收时间':<22} | {'事件ID':<20} | {'状态':<10} | {'数据预览'}")
        print("-" * 90)
        for log in logs:
            preview = log["raw_data_preview"].replace("\n", " ")[:50]
            print(f"{log['id']:>6} | {log['received_at']:<22} | "
                  f"{(log['event_id'] or 'N/A'):<20} | {log['parse_status']:<10} | {preview}")
        print("=" * 90)
        print()

    else:
        # 默认：显示标准化事件
        logs = get_latest_normalized_events(db_path, limit=limit, source=source)
        if not logs:
            print("[INFO] 暂无标准化事件")
            return
        print(f"\n{'='*100}")
        print(f"  最近 {len(logs)} 条标准化事件" + (f" ({source})" if source else ""))
        print(f"{'='*100}")
        print(f"{'ID':>5} | {'来源':<10} | {'时间':<22} | {'源IP':<15} | {'攻击类型':<20} | {'严重级别'}")
        print("-" * 100)
        for log in logs:
            print(f"{log['id']:>5} | {log['source']:<10} | {log['event_time']:<22} | "
                  f"{log['src_ip']:<15} | {log['attack_type'] or 'N/A':<20} | {log['severity'] or 'N/A'}")
        print("=" * 100)
        print()


def cmd_stats(args):
    """查看扩展统计信息。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]

    stats = get_extended_stats(db_path)

    s = stats["safeline"]
    h = stats["hfish"]
    n = stats["normalized"]

    print(f"\n{'='*50}")
    print(f"  数据统计概览")
    print(f"{'='*50}")

    print(f"\n  [SafeLine WAF]")
    print(f"    总日志: {s['total']} 条")
    if s["total"] > 0:
        print(f"    ├─ 解析成功: {s['parsed']}")
        print(f"    ├─ 解析失败: {s['failed']}")
        print(f"    └─ 待解析:   {s['pending']}")

    print(f"\n  [HFish 蜜罐]")
    print(f"    总日志: {h['total']} 条")
    if h["total"] > 0:
        print(f"    ├─ 解析成功: {h['parsed']}")
        print(f"    ├─ 解析失败: {h['failed']}")
        print(f"    └─ 待解析:   {h['pending']}")

    print(f"\n  [标准化事件]")
    print(f"    总事件: {n['total']} 条")
    if n["source_distribution"]:
        print(f"    来源分布:")
        for src, cnt in n["source_distribution"].items():
            print(f"      {src}: {cnt} 条")

    print(f"\n  总采集: {s['total'] + h['total']} 条 | "
          f"标准化: {n['total']} 条")
    print("=" * 50)
    print()


def cmd_collect_hfish(args):
    """单次拉取 HFish 攻击日志。"""
    config = get_config(args.config)
    hf_config = config["hfish"]
    db_path = config["database"]["path"]

    if not hf_config.get("api_url"):
        print("[ERROR] HFish API URL 未配置，请在 config.yaml 中设置 hfish.api_url")
        return

    init_db(db_path)

    def _ingest(raw_jsons, label="HFish"):
        """将 HFish 原始 JSON 列表入库，使用 compute_event_id 做 fallback 去重。"""
        count = 0
        skipped = 0
        for raw_json in raw_jsons:
            parse_result = extract_hfish_event(raw_json)
            parsed_dict = parse_result.get("parsed_dict")
            raw_fields = extract_hfish_fields(parsed_dict) if parsed_dict else {}
            event_id = raw_fields.get("event_id")

            # 如果事件没有 event_id，用 raw_json 的 sha256 作为稳定 ID
            if not event_id:
                event_id = compute_event_id(raw_json)

            row_id = insert_raw_hfish_event(db_path, raw_json, event_id, parse_result)
            if row_id is not None:
                count += 1
            else:
                skipped += 1

        logger.info("%s 入库: 新增 %d 条, 去重跳过 %d 条", label, count, skipped)
        print(f"[INFO] {label} 入库完成: 新增 {count} 条, 去重跳过 {skipped} 条")

    collector = HFishCollector(
        api_url=hf_config["api_url"],
        auth_type=hf_config.get("auth_type", "token"),
        api_token=hf_config.get("api_token"),
        username=hf_config.get("username"),
        password=hf_config.get("password"),
        api_path=hf_config.get("api_path", "/api/v1/attack"),
        page_size=hf_config.get("page_size", 100),
        on_events_received=lambda jsons: _ingest(jsons, "HFish"),
    )

    print(f"[INFO] 开始拉取 HFish 日志: {hf_config['api_url']}")
    events = collector.fetch_once()
    print(f"[INFO] 共拉取 {len(events)} 条事件")


def cmd_collect_hfish_loop(args):
    """循环拉取 HFish 攻击日志。"""
    config = get_config(args.config)
    hf_config = config["hfish"]
    db_path = config["database"]["path"]
    interval = args.interval or hf_config.get("interval", 60)

    if not hf_config.get("api_url"):
        print("[ERROR] HFish API URL 未配置")
        return

    init_db(db_path)

    def on_events_received(raw_jsons):
        count = 0
        skipped = 0
        for raw_json in raw_jsons:
            parse_result = extract_hfish_event(raw_json)
            parsed_dict = parse_result.get("parsed_dict")
            raw_fields = extract_hfish_fields(parsed_dict) if parsed_dict else {}
            event_id = raw_fields.get("event_id")
            if not event_id:
                event_id = compute_event_id(raw_json)
            row_id = insert_raw_hfish_event(db_path, raw_json, event_id, parse_result)
            if row_id is not None:
                count += 1
            else:
                skipped += 1
        logger.info("HFish 循环入库: 新增 %d, 跳过 %d", count, skipped)

    collector = HFishCollector(
        api_url=hf_config["api_url"],
        auth_type=hf_config.get("auth_type", "token"),
        api_token=hf_config.get("api_token"),
        username=hf_config.get("username"),
        password=hf_config.get("password"),
        api_path=hf_config.get("api_path", "/api/v1/attack"),
        page_size=hf_config.get("page_size", 100),
        on_events_received=on_events_received,
    )

    collector.fetch_loop(interval=interval)


def cmd_normalize(args):
    """标准化待处理的原始日志。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    source_filter = args.source  # None 表示全部

    result = run_normalize(db_path, source_filter=source_filter)
    print(f"[INFO] 标准化完成: 新增 {result['normalized']} 条, 跳过 {result['skipped']} 条")


def cmd_show_ip(args):
    """按 IP 查询事件。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    ip = args.ip
    limit = args.limit

    if not ip:
        print("[ERROR] 请指定 IP 地址: --ip 1.2.3.4")
        return

    events = get_events_by_ip(db_path, ip, limit=limit)

    if not events:
        print(f"[INFO] IP {ip} 暂无标准化事件")
        return

    print(f"\n{'='*100}")
    print(f"  IP: {ip}  — 最近 {len(events)} 条事件")
    print(f"{'='*100}")
    print(f"{'ID':>5} | {'来源':<10} | {'时间':<22} | {'攻击类型':<22} | {'协议':<10} | {'严重级别'}")
    print("-" * 100)
    for e in events:
        print(f"{e['id']:>5} | {e['source']:<10} | {e['event_time']:<22} | "
              f"{(e['attack_type'] or 'N/A'):<22} | {(e['protocol'] or 'N/A'):<10} | {e['severity'] or 'N/A'}")
    print("=" * 100)
    print()


def cmd_extract_ioc(args):
    """提取 IOC。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]

    from analyzers.ioc_extractor import extract_all_pending
    total = extract_all_pending(db_path)
    print(f"[INFO] IOC 提取完成: 共新增 {total} 个 IOC")


def cmd_build_profiles(args):
    """构建攻击源画像。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    rebuild = args.rebuild

    from analyzers.profiler import build_all_profiles
    count = build_all_profiles(db_path, rebuild=rebuild)
    print(f"[INFO] 攻击源画像构建完成: {count} 个 IP")


def cmd_correlate(args):
    """执行关联分析。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]

    from analyzers.correlator import correlate_all
    results = correlate_all(db_path)

    rules = results.get("rules", {})
    if not rules:
        return  # 前置条件提示已在 correlate_all 中输出

    print(f"[INFO] 关联分析完成:")
    for rule, count in rules.items():
        print(f"  {rule}: 触发 {count} 次")
    if results.get("profiles_recalculated", 0) > 0:
        print(f"[INFO] 已重新计算 {results['profiles_recalculated']} 个 IP 的风险评分")


def cmd_show_profile(args):
    """显示攻击源画像。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    ip = args.ip

    from app.db import get_profile_by_ip, get_events_by_ip
    profile = get_profile_by_ip(db_path, ip)

    if not profile:
        print(f"[INFO] IP {ip} 暂无画像数据")
        return

    print(f"\n{'='*60}")
    print(f"  攻击源画像: {ip}")
    print(f"{'='*60}")
    print(f"  首次出现:      {profile['first_seen']}")
    print(f"  最近活跃:      {profile['last_seen']}")
    print(f"  事件总数:      {profile['total_count']}")
    print(f"  ├─ SafeLine:   {profile['safeline_count']}")
    print(f"  └─ HFish:     {profile['hfish_count']}")
    print(f"  多源命中:      {'是' if profile['is_multi_source'] else '否'}")
    print(f"  风险评分:      {profile['risk_score']}/100")
    print(f"  风险等级:      {profile['risk_level']}")

    tags = profile.get('tags')
    if tags:
        import json
        try:
            tag_list = json.loads(tags)
            if tag_list:
                print(f"  风险标签:      {', '.join(tag_list)}")
        except (json.JSONDecodeError, TypeError):
            pass

    attack_types = profile.get('attack_types')
    if attack_types:
        try:
            at = json.loads(attack_types)
            if at:
                print(f"\n  攻击类型分布:")
                for t, c in sorted(at.items(), key=lambda x: -x[1])[:5]:
                    print(f"    {t}: {c} 次")
        except (json.JSONDecodeError, TypeError):
            pass
    print("=" * 60)
    print()


def cmd_top_ip(args):
    """显示 Top 攻击源 IP。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    sort_by = args.sort
    limit = args.limit

    from app.db import get_top_ips
    ips = get_top_ips(db_path, sort_by=sort_by, limit=limit)

    if not ips:
        print("[INFO] 暂无画像数据")
        return

    print(f"\n{'='*90}")
    print(f"  Top {len(ips)} 攻击源 IP（按 {sort_by} 排序）")
    print(f"{'='*90}")
    print(f"{'#':>3} | {'IP':<18} | {'事件数':>8} | {'多源':>4} | {'评分':>4} | {'等级':<10} | {'标签'}")
    print("-" * 90)
    for i, p in enumerate(ips, 1):
        import json
        tags = ""
        try:
            tag_list = json.loads(p['tags']) if p.get('tags') else []
            tags = ", ".join(tag_list[:3])
        except (json.JSONDecodeError, TypeError):
            pass
        multi = "✓" if p['is_multi_source'] else ""
        print(f"{i:>3} | {p['src_ip']:<18} | {p['total_count']:>8} | {multi:>4} | "
              f"{p['risk_score']:>4} | {p['risk_level']:<10} | {tags[:30]:<30}")
    print("=" * 90)
    print()


def cmd_map_attack(args):
    """执行 ATT&CK 映射。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    rebuild = args.rebuild

    from analyzers.attack_mapper import map_all_pending
    count = map_all_pending(db_path, rebuild=rebuild)
    print(f"[INFO] ATT&CK 映射完成: 新增 {count} 条")


def cmd_ai_summary(args):
    """使用 AI 生成攻击摘要。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    ip = args.ip

    from app.db import get_profile_by_ip
    from ai.deepseek_client import DeepSeekClient
    from app.db import get_connection, get_iocs

    profile = get_profile_by_ip(db_path, ip)
    if not profile:
        print(f"[INFO] IP {ip} 暂无画像数据")
        return

    # 构建结构化输入
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT payload FROM normalized_events WHERE src_ip = ? AND payload IS NOT NULL",
        (ip,),
    )
    payloads = [r["payload"] for r in cursor.fetchall() if r["payload"]]

    iocs = get_iocs(db_path, limit=100)
    ip_iocs = [i for i in iocs if i.get("src_ip") == ip]

    from app.utils import safe_json_loads
    import json
    try:
        attack_types = json.loads(profile["attack_types"]) if profile.get("attack_types") else {}
    except (json.JSONDecodeError, TypeError):
        attack_types = {}

    # 安全解析 tags（非法 JSON 降级为空列表）
    raw_tags = profile.get("tags")
    if isinstance(raw_tags, str):
        parsed_tags = safe_json_loads(raw_tags, default=[])
        tags_list = parsed_tags if isinstance(parsed_tags, list) else []
    else:
        tags_list = raw_tags or []

    ip_data = {
        "ip": ip,
        "risk_score": profile.get("risk_score", 0),
        "risk_level": profile.get("risk_level", "low"),
        "tags": tags_list,
        "total_events": profile.get("total_count", 0),
        "safeline_events": profile.get("safeline_count", 0),
        "hfish_events": profile.get("hfish_count", 0),
        "attack_types": attack_types,
        "first_seen": profile.get("first_seen", ""),
        "last_seen": profile.get("last_seen", ""),
        "is_multi_source": bool(profile.get("is_multi_source")),
        "sample_payloads": payloads[:5],
        "ioc_count": len(ip_iocs),
    }

    client = DeepSeekClient(config.get("deepseek", {}))
    if not client.is_available():
        print("[INFO] DeepSeek API 未启用或未配置 API Key")
        print("[INFO] 请设置环境变量 DEEPSEEK_API_KEY，并将 deepseek.enabled 设为 true")
        return

    print(f"[INFO] 正在请求 AI 研判... (IP: {ip})")
    summary = client.generate_summary(ip_data, cache_db_path=db_path)
    if summary:
        print(f"\n{'='*60}")
        print(f"  AI 攻击行为摘要 — {ip}")
        print(f"{'='*60}")
        print(summary)
        print("=" * 60)
    else:
        print("[WARN] AI 研判失败，请检查 API 配置和网络连接")


def cmd_report(args):
    """生成攻击源 Markdown 报告。"""
    config = get_config(args.config)
    db_path = config["database"]["path"]
    ip = args.ip
    output = args.output
    all_ips = args.all
    with_ai = args.with_ai
    deepseek_config = config.get("deepseek", {})

    from reports.markdown_report import generate_report, generate_all_reports

    if all_ips:
        if with_ai and deepseek_config.get("enabled"):
            print("[INFO] ⚠️  --all --with-ai 将对多个 IP 触发 AI 分析请求")
            print("[INFO]    请确认 API Key 有效且已了解 Token 消耗和费用情况")
        out_dir = output or "reports/output"
        count = generate_all_reports(db_path, output_dir=out_dir, with_ai=with_ai,
                                     deepseek_config=deepseek_config)
        print(f"[INFO] 已为 {count} 个 IP 生成报告，输出目录: {out_dir}")
        return

    if not ip:
        print("[ERROR] 请指定 --ip 或使用 --all")
        return

    report = generate_report(db_path, ip, with_ai=with_ai,
                             deepseek_config=deepseek_config)

    if not report:
        print(f"[INFO] IP {ip} 暂无数据，无法生成报告")
        return

    if output:
        out_path = Path(output)
        # 以 .md 结尾 → 当作具体文件路径
        if out_path.suffix == ".md":
            out_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            # 不以 .md 结尾 → 当作目录，自动创建并生成 <ip>.md
            out_path.mkdir(parents=True, exist_ok=True)
            safe_name = ip.replace(".", "_").replace(":", "_")
            out_path = out_path / f"{safe_name}.md"
        out_path.write_text(report, encoding="utf-8")
        print(f"[INFO] 报告已保存: {out_path}")
    else:
        print(report)


def main():
    parser = argparse.ArgumentParser(
        description="基于 WAF 与蜜罐的安全事件采集与关联分析平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 初始化
    python main.py init-db

    # 采集
    python main.py recv-safeline
    python main.py collect-hfish
    python main.py collect-hfish-loop --interval 60

    # 查看
    python main.py show-latest
    python main.py show-latest --source safeline
    python main.py show-latest --mode raw_safeline
    python main.py show-ip --ip 10.0.0.1
    python main.py stats

    # 分析
    python main.py normalize
    python main.py extract-ioc
    python main.py build-profiles
    python main.py correlate

    # 画像
    python main.py show-profile --ip 10.0.0.1
    python main.py top-ip

    # 威胁映射与报告
    python main.py map-attack
    python main.py report --ip 10.0.0.1
    python main.py report --ip 10.0.0.1 --output report.md
    python main.py report --all

    # AI 辅助研判
    python main.py ai-summary --ip 10.0.0.1
    python main.py report --ip 10.0.0.1 --with-ai
        """,
    )

    # 全局参数
    parser.add_argument(
        "--config", type=str, default=None,
        help="配置文件路径（默认: config.yaml）",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="启用 DEBUG 日志级别",
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # --- Phase 0 ---
    subparsers.add_parser("init-db", help="初始化数据库")

    # --- Phase 1 ---
    p_recv = subparsers.add_parser(
        "recv-safeline",
        help="启动 SafeLine Syslog 接收服务（前台阻塞）",
    )
    p_recv.add_argument("--host", type=str, default=None, help="监听地址（覆盖配置）")
    p_recv.add_argument("--port", type=int, default=None, help="监听端口（覆盖配置）")

    # --- Phase 2 ---
    subparsers.add_parser("collect-hfish", help="单次拉取 HFish 攻击日志")

    p_hfish_loop = subparsers.add_parser(
        "collect-hfish-loop",
        help="循环拉取 HFish 攻击日志（前台阻塞）",
    )
    p_hfish_loop.add_argument(
        "--interval", type=int, default=None,
        help="拉取间隔秒数（覆盖 config.yaml 配置）",
    )

    p_normalize = subparsers.add_parser("normalize", help="标准化待处理的原始日志")
    p_normalize.add_argument(
        "--source", type=str, default=None,
        choices=["safeline", "hfish"],
        help="仅标准化指定数据源（默认全部）",
    )

    p_show_ip = subparsers.add_parser("show-ip", help="按 IP 查询标准化事件")
    p_show_ip.add_argument("--ip", type=str, required=True, help="源 IP 地址")
    p_show_ip.add_argument("--limit", type=int, default=50, help="返回条数（默认: 50）")

    # --- 通用查看命令（Phase 1 增强） ---
    p_latest = subparsers.add_parser("show-latest", help="显示最近事件")
    p_latest.add_argument("--limit", type=int, default=20, help="显示条数（默认: 20）")
    p_latest.add_argument(
        "--source", type=str, default=None,
        choices=["safeline", "hfish"],
        help="按数据源过滤（仅标准化事件模式）",
    )
    p_latest.add_argument(
        "--mode", type=str, default="normalized",
        choices=["normalized", "raw_safeline", "raw_hfish"],
        help="显示模式（默认: normalized 标准化事件）",
    )

    subparsers.add_parser("stats", help="显示扩展统计信息（含所有数据源）")

    # --- Phase 3 ---
    subparsers.add_parser("extract-ioc", help="从标准化事件中提取 IOC")

    p_profiles = subparsers.add_parser("build-profiles", help="构建攻击源画像")
    p_profiles.add_argument(
        "--rebuild", action="store_true",
        help="重建全部画像（清空已有数据）",
    )

    subparsers.add_parser("correlate", help="执行关联分析")

    p_show_profile = subparsers.add_parser("show-profile", help="显示攻击源画像详情")
    p_show_profile.add_argument("--ip", type=str, required=True, help="攻击源 IP")

    p_top = subparsers.add_parser("top-ip", help="显示 Top 攻击源 IP")
    p_top.add_argument(
        "--sort", type=str, default="total_count",
        choices=["total_count", "risk_score"],
        help="排序字段（默认: total_count）",
    )
    p_top.add_argument(
        "--limit", type=int, default=10,
        help="返回条数（默认: 10）",
    )

    # --- Phase 4 ---
    p_map = subparsers.add_parser("map-attack", help="执行 ATT&CK 映射")
    p_map.add_argument(
        "--rebuild", action="store_true",
        help="重建全部映射",
    )

    p_report = subparsers.add_parser("report", help="生成攻击源 Markdown 报告")
    p_report.add_argument("--ip", type=str, default=None, help="攻击源 IP")
    p_report.add_argument(
        "--output", type=str, default=None,
        help="输出路径（文件或目录，默认输出到终端）",
    )
    p_report.add_argument(
        "--all", action="store_true",
        help="为所有已画像的 IP 生成报告",
    )
    p_report.add_argument(
        "--with-ai", action="store_true",
        help="启用 AI 辅助研判（需配置 DeepSeek API）",
    )

    # --- Phase 5 ---
    p_ai = subparsers.add_parser("ai-summary", help="使用 AI 生成攻击摘要")
    p_ai.add_argument("--ip", type=str, required=True, help="攻击源 IP")

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
        "collect-hfish": cmd_collect_hfish,
        "collect-hfish-loop": cmd_collect_hfish_loop,
        "normalize": cmd_normalize,
        "show-ip": cmd_show_ip,
        "extract-ioc": cmd_extract_ioc,
        "build-profiles": cmd_build_profiles,
        "correlate": cmd_correlate,
        "show-profile": cmd_show_profile,
        "top-ip": cmd_top_ip,
        "map-attack": cmd_map_attack,
        "report": cmd_report,
        "ai-summary": cmd_ai_summary,
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
