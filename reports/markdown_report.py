"""
Markdown 报告生成器。

从数据库中读取攻击源画像、事件、IOC、ATT&CK 映射等数据，
使用 Jinja2 模板生成结构化的 Markdown 安全分析报告。
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from app.db import get_connection
from app.logger import get_logger

logger = get_logger("report")

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _load_template():
    """加载 Jinja2 报告模板。"""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    return env.get_template("ip_report.md.j2")


def generate_report(db_path, src_ip: str, with_ai: bool = False,
                    deepseek_config: Optional[dict] = None) -> Optional[str]:
    """
    为指定 IP 生成完整 Markdown 报告。

    Args:
        db_path: 数据库文件路径。
        src_ip: 攻击源 IP。
        with_ai: 是否使用 AI 辅助内容（Phase 5 启用）。
        deepseek_config: DeepSeek 配置字典（传此参数可避免重新读取 config.yaml）。

    Returns:
        str|None: Markdown 报告字符串，IP 无数据时返回 None。
    """
    from app.db import get_profile_by_ip, get_events_by_ip, get_iocs
    from analyzers.attack_mapper import get_mappings_by_ip

    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 1. 画像
    profile = get_profile_by_ip(db_path, src_ip)
    if not profile:
        logger.info("IP %s 无画像数据，跳过报告生成", src_ip)
        return None

    # 2. 攻击类型分布
    import json
    attack_types_raw = profile.get("attack_types", "{}")
    try:
        attack_types_list = sorted(
            json.loads(attack_types_raw).items(),
            key=lambda x: -x[1],
        )
    except (json.JSONDecodeError, TypeError):
        attack_types_list = []

    # 3. 攻击时间线
    events = get_events_by_ip(db_path, src_ip, limit=200)

    # 4. IOC 列表
    iocs = get_iocs(db_path, limit=100)
    iocs_filtered = [i for i in iocs if i.get("src_ip") == src_ip]

    # 5. ATT&CK 映射
    mappings = get_mappings_by_ip(db_path, src_ip)

    # 6. 原始事件索引
    safeline_raw_ids = []
    hfish_raw_ids = []
    for ev in events:
        if ev.get("source") == "safeline":
            safeline_raw_ids.append(str(ev.get("raw_id", "?")))
        elif ev.get("source") == "hfish":
            hfish_raw_ids.append(str(ev.get("raw_id", "?")))

    safeline_ids_str = ", ".join(safeline_raw_ids) if safeline_raw_ids else "无"
    hfish_ids_str = ", ".join(hfish_raw_ids) if hfish_raw_ids else "无"

    # 7. 处置建议（基于规则，可选 AI 增强）
    remediation = _generate_remediation(profile)

    # AI 辅助内容（if enabled）
    ai_summary_text = ""
    ai_remediation_text = ""
    if with_ai:
        try:
            from ai.deepseek_client import DeepSeekClient
            import json as _json

            # 如果外部传入了 deepseek_config，优先使用（尊重 --config）
            if deepseek_config is None:
                from app.config import get_config as get_app_config
                deepseek_config = get_app_config().get("deepseek", {})

            client = DeepSeekClient(deepseek_config)

            if client.is_available():
                # 构建 AI 输入
                tags_raw = profile.get("tags", "[]")
                try:
                    tags_list = _json.loads(tags_raw) if isinstance(tags_raw, str) else (tags_raw or [])
                except Exception:
                    tags_list = []

                try:
                    at = _json.loads(profile["attack_types"]) if profile.get("attack_types") else {}
                except Exception:
                    at = {}

                ip_data = {
                    "ip": src_ip,
                    "risk_score": profile.get("risk_score", 0),
                    "risk_level": profile.get("risk_level", "low"),
                    "tags": tags_list,
                    "total_events": profile.get("total_count", 0),
                    "safeline_events": profile.get("safeline_count", 0),
                    "hfish_events": profile.get("hfish_count", 0),
                    "attack_types": at,
                    "first_seen": profile.get("first_seen", ""),
                    "last_seen": profile.get("last_seen", ""),
                    "is_multi_source": bool(profile.get("is_multi_source")),
                    "sample_payloads": [ev.get("payload", "") for ev in events if ev.get("payload")][:5],
                    "ioc_count": len(iocs_filtered),
                }

                ai_summary_text = client.generate_summary(ip_data, cache_db_path=db_path)
                ai_remediation_text = client.generate_remediation(profile, cache_db_path=db_path)

        except Exception as e:
            logger.warning("AI 辅助研判失败（已降级）: %s", e)

    # 8. 时间信息
    duration = _compute_duration(
        profile.get("first_seen"), profile.get("last_seen")
    )

    # 9. 标签显示
    tags_raw = profile.get("tags", "[]")
    try:
        tags_list = json.loads(tags_raw) if isinstance(tags_raw, str) else (tags_raw or [])
    except (json.JSONDecodeError, TypeError):
        tags_list = []
    tags_display = ", ".join(tags_list) if tags_list else "无"

    # 10. 多源显示
    source_display = "多源命中（WAF + 蜜罐）" if profile.get("is_multi_source") else "单源"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 构建 AI 章节（截断防溢出）
    MAX_AI_LENGTH = 2000
    ai_section = ""
    if ai_summary_text:
        truncated = ai_summary_text[:MAX_AI_LENGTH]
        if len(ai_summary_text) > MAX_AI_LENGTH:
            truncated += "\n\n*（内容已截断）*"
        ai_section += f"\n## AI 辅助分析\n\n*以下内容由 AI 生成，仅供参考*\n\n{truncated}\n"
    if ai_remediation_text:
        truncated = ai_remediation_text[:MAX_AI_LENGTH]
        if len(ai_remediation_text) > MAX_AI_LENGTH:
            truncated += "\n\n*（内容已截断）*"
        ai_section += f"\n### AI 处置建议\n\n{truncated}\n"

    # 渲染模板
    template = _load_template()
    report = template.render(
        ip=src_ip,
        profile=profile,
        tags_display=tags_display,
        source_display=source_display,
        duration=duration,
        attack_types=attack_types_list,
        timeline=events,
        iocs=iocs_filtered,
        attack_mappings=mappings,
        remediation=remediation,
        safeline_raw_ids=safeline_ids_str,
        hfish_raw_ids=hfish_ids_str,
        generated_at=now,
        ai_section=ai_section,
    )

    return report


def generate_all_reports(db_path, output_dir: str = "reports/output",
                         with_ai: bool = False,
                         deepseek_config: Optional[dict] = None) -> int:
    """
    为所有有画像的 IP 生成报告。

    Args:
        db_path: 数据库文件路径。
        output_dir: 输出目录。
        with_ai: 是否启用 AI 辅助。

    Returns:
        int: 生成的报告数量。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT src_ip FROM attacker_profiles")
    ips = [row["src_ip"] for row in cursor.fetchall()]

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    count = 0
    for ip in ips:
        report = generate_report(db_path, ip, with_ai=with_ai,
                                  deepseek_config=deepseek_config)
        if report:
            safe_name = ip.replace(".", "_").replace(":", "_")
            file_path = out_path / f"{safe_name}.md"
            file_path.write_text(report, encoding="utf-8")
            count += 1
            logger.info("报告已生成: %s", file_path)

    logger.info("全部报告生成完成: %d 个", count)
    return count


def _generate_remediation(profile: Dict[str, Any]) -> str:
    """基于画像数据生成处置建议。"""
    risk_level = profile.get("risk_level", "low")
    tags_raw = profile.get("tags", "[]")
    import json
    try:
        tags = json.loads(tags_raw) if isinstance(tags_raw, str) else (tags_raw or [])
    except (json.JSONDecodeError, TypeError):
        tags = []

    suggestions = []

    if risk_level in ("high", "critical"):
        suggestions.append("该攻击源风险等级为 **高风险**，建议立即将 IP 加入WAF黑名单进行封禁。")

    if "多源命中" in tags:
        suggestions.append("该 IP 同时命中 WAF 和蜜罐，表明攻击者正在对 Web 应用和基础服务进行交叉探测，建议重点监控。")

    if "SQL 注入尝试" in tags:
        suggestions.append("检测到 SQL 注入尝试，请检查 WAF 规则是否覆盖该攻击向量，并确认相关接口是否存在注入漏洞。")

    if "XSS 尝试" in tags:
        suggestions.append("检测到 XSS 尝试，请检查输入过滤和输出编码是否完善。")

    if "Web 扫描" in tags:
        suggestions.append("检测到 Web 扫描行为，建议确认是否为授权测试，若非授权测试应采取 IP 临时封禁策略。")

    if "敏感文件探测" in tags:
        suggestions.append("检测到敏感文件/路径探测行为，请确认 `.git`、`.env`、备份文件等是否已在 Web 访问中排除。")

    if "弱口令爆破" in tags:
        suggestions.append("检测到弱口令爆破行为，建议检查相关服务密码强度，并启用登录频率限制。")

    if "多阶段攻击" in tags:
        suggestions.append("该 IP 表现出多阶段攻击特征（先扫描 Web 再爆破服务），建议联动 WAF 与 HIDS 进行纵深防御。")

    if "高危 Payload" in tags:
        suggestions.append("检测到高危攻击 Payload，建议原始日志留存备查，并确认业务系统是否存在对应漏洞。")

    if "多协议探测" in tags:
        suggestions.append("该 IP 使用多种协议进行探测，建议限制非必要端口的公网访问。")

    # 兜底建议
    if not suggestions:
        if risk_level == "low":
            suggestions.append("该攻击源风险较低，建议保持监控，观察后续行为。")
        elif risk_level == "medium":
            suggestions.append("该攻击源存在一定风险，建议持续关注其活跃情况。")
        else:
            suggestions.append("建议关注该攻击源的行为变化。")

    return "\n".join(f"- {s}" for s in suggestions)


def _compute_duration(first: Optional[str], last: Optional[str]) -> str:
    """计算活跃时长。"""
    if not first or not last:
        return "未知"

    try:
        import dateutil.parser as parser
        from dateutil.parser import ParserError

        try:
            dt_first = parser.parse(first)
            dt_last = parser.parse(last)
        except (ParserError, ValueError, TypeError):
            dt_first = None

        if dt_first:
            delta = dt_last.replace(tzinfo=None) - dt_first.replace(tzinfo=None)
            hours = int(delta.total_seconds() // 3600)
            minutes = int((delta.total_seconds() % 3600) // 60)
            if hours > 0:
                return f"{hours} 小时 {minutes} 分钟"
            return f"{minutes} 分钟"
    except ImportError:
        # 无 python-dateutil，简单处理
        pass

    return f"{first} → {last}"
