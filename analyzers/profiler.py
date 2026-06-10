"""
攻击源画像构建引擎。

按 src_ip 聚合标准化事件，构建攻击源画像。
"""

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.logger import get_logger
from app.db import get_connection

logger = get_logger("profiler")


def build_profile(db_path, src_ip: str) -> Optional[Dict[str, Any]]:
    """
    为单个 IP 构建/更新攻击源画像。

    Args:
        db_path: 数据库文件路径。
        src_ip: 攻击源 IP。

    Returns:
        dict|None: 画像字典，无事件时返回 None。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 查询该 IP 的所有标准化事件
    cursor.execute(
        "SELECT * FROM normalized_events WHERE src_ip = ? ORDER BY event_time ASC",
        (src_ip,),
    )
    rows = cursor.fetchall()
    if not rows:
        return None

    events = [dict(r) for r in rows]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 基础统计
    safeline_count = sum(1 for e in events if e["source"] == "safeline")
    hfish_count = sum(1 for e in events if e["source"] == "hfish")
    total_count = len(events)

    first_seen = events[0]["event_time"]
    last_seen = events[-1]["event_time"]

    # 攻击类型分布
    type_counter: Counter = Counter()
    for e in events:
        at = e.get("attack_type") or "Unknown"
        type_counter[at] += 1

    # 协议分布
    proto_counter: Counter = Counter()
    for e in events:
        p = e.get("protocol") or "unknown"
        proto_counter[p] += 1

    # 多源命中判断
    is_multi_source = safeline_count > 0 and hfish_count > 0

    from analyzers.risk_scorer import calculate_score

    # 准备 profile_data
    profile_data = {
        "src_ip": src_ip,
        "safeline_count": safeline_count,
        "hfish_count": hfish_count,
        "total_count": total_count,
        "is_multi_source": is_multi_source,
        "attack_types": json.dumps(dict(type_counter), ensure_ascii=False),
        "protocols": json.dumps(dict(proto_counter), ensure_ascii=False),
        "tags": [],
    }

    # 计算风险
    risk_result = calculate_score(profile_data, events=events)
    profile_data["risk_score"] = risk_result["score"]
    profile_data["risk_level"] = risk_result["level"]

    # 标签
    tags = _compute_tags(profile_data, events)
    profile_data["tags"] = json.dumps(tags, ensure_ascii=False)

    # 时间字段
    profile_data["first_seen"] = first_seen
    profile_data["last_seen"] = last_seen
    profile_data["last_event_time"] = last_seen
    profile_data["updated_at"] = now

    # 写入数据库
    _upsert_profile(db_path, profile_data)

    return profile_data


def build_all_profiles(db_path, rebuild: bool = False) -> int:
    """
    为所有 IP 构建画像。

    Args:
        db_path: 数据库文件路径。
        rebuild: 是否重建全部（清空已有画像）。

    Returns:
        int: 构建的画像数量。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    if rebuild:
        cursor.execute("DELETE FROM attacker_profiles")
        logger.info("已清空所有画像")

    # 获取所有有事件的 IP
    cursor.execute(
        "SELECT DISTINCT src_ip FROM normalized_events ORDER BY src_ip"
    )
    ips = [row["src_ip"] for row in cursor.fetchall()]

    count = 0
    for ip in ips:
        try:
            result = build_profile(db_path, ip)
            if result:
                count += 1
        except Exception as e:
            logger.error("构建画像失败 %s: %s", ip, e)

    logger.info("攻击源画像构建完成: %d/%d 个 IP", count, len(ips))
    return count


def _compute_tags(profile_data: Dict[str, Any],
                  events: List[Dict[str, Any]]) -> List[str]:
    """根据画像数据和事件计算风险标签。"""
    tags = []

    attack_types = profile_data.get("attack_types", "{}")
    if isinstance(attack_types, str):
        try:
            attack_types = json.loads(attack_types)
        except (json.JSONDecodeError, TypeError):
            attack_types = {}
    if not isinstance(attack_types, dict):
        attack_types = {}

    protocols = profile_data.get("protocols", "{}")
    if isinstance(protocols, str):
        try:
            protocols = json.loads(protocols)
        except (json.JSONDecodeError, TypeError):
            protocols = {}
    if not isinstance(protocols, dict):
        protocols = {}

    # Web 扫描
    scan_keywords = ["scan", "dirbust", "directory", "probe"]
    if any(any(kw in at.lower() for kw in scan_keywords) for at in attack_types):
        tags.append("Web 扫描")

    # SQL 注入
    sql_keywords = ["sql injection", "sqli"]
    if any(any(kw in at.lower() for kw in sql_keywords) for at in attack_types):
        tags.append("SQL 注入尝试")

    # XSS
    if any("xss" in at.lower() for at in attack_types):
        tags.append("XSS 尝试")

    # 敏感文件探测
    sensitive_keywords = ["sensitive file", "path traversal"]
    sensitive_paths = [".git", ".env", "/web-inf/", "/admin/"]
    has_sensitive = any(
        any(kw in at.lower() for kw in sensitive_keywords)
        for at in attack_types
    )
    for ev in events:
        uri = ev.get("uri") or ""
        if any(sp in uri.lower() for sp in sensitive_paths):
            has_sensitive = True
            break
    if has_sensitive:
        tags.append("敏感文件探测")

    # 多协议探测
    if len(protocols) >= 3:
        tags.append("多协议探测")

    # 弱口令爆破
    bf_keywords = ["brute force", "ssh", "redis", "mysql", "weak password"]
    if any(any(kw in at.lower() for kw in bf_keywords) for at in attack_types):
        tags.append("弱口令爆破")

    # 多源命中
    if profile_data.get("is_multi_source"):
        tags.append("多源命中")

    # 高频攻击源
    if profile_data.get("total_count", 0) > 50:
        tags.append("高频攻击源")

    # 高风险攻击源
    if profile_data.get("risk_score", 0) >= 50:
        tags.append("高风险攻击源")

    return tags


def _upsert_profile(db_path, profile_data: Dict[str, Any]):
    """插入或更新攻击源画像。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO attacker_profiles
            (src_ip, first_seen, last_seen, safeline_count, hfish_count,
             total_count, attack_types, protocols, is_multi_source,
             risk_score, risk_level, tags, last_event_time, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(src_ip) DO UPDATE SET
            first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,
            safeline_count=excluded.safeline_count,
            hfish_count=excluded.hfish_count,
            total_count=excluded.total_count,
            attack_types=excluded.attack_types,
            protocols=excluded.protocols,
            is_multi_source=excluded.is_multi_source,
            risk_score=excluded.risk_score,
            risk_level=excluded.risk_level,
            tags=excluded.tags,
            last_event_time=excluded.last_event_time,
            updated_at=excluded.updated_at
        """,
        (
            profile_data["src_ip"],
            profile_data["first_seen"],
            profile_data["last_seen"],
            profile_data["safeline_count"],
            profile_data["hfish_count"],
            profile_data["total_count"],
            profile_data["attack_types"],
            profile_data["protocols"],
            1 if profile_data["is_multi_source"] else 0,
            profile_data["risk_score"],
            profile_data["risk_level"],
            profile_data["tags"],
            profile_data["last_event_time"],
            profile_data["updated_at"],
        ),
    )
    conn.commit()
