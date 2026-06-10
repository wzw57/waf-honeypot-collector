"""
关联分析引擎。

基于规则引擎对事件、画像进行交叉关联分析，
识别多源命中、多阶段攻击、扫描行为等安全模式。
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db import get_connection
from app.logger import get_logger

logger = get_logger("correlator")

# 高危 Payload 正则（简单关键词匹配）
HIGH_RISK_PAYLOAD_KEYWORDS = [
    "union select", "1=1", "1=2", "' or '", "\" or \"",
    "<script>", "alert(", "onerror=",
    "eval(", "exec(", "system(", "passthru(",
    "../../", "..\\\\",
]


def correlate_all(db_path) -> Dict[str, int]:
    """
    执行所有关联分析规则。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: 各规则触发的统计 {"CORR-001": int, ...}
    """
    results = {}

    # CORR-001: 多源命中
    results["CORR-001"] = _corr_multi_source(db_path)

    # CORR-002: 多类型攻击
    results["CORR-002"] = _corr_multi_attack_type(db_path)

    # CORR-003: 多阶段攻击（Web → 服务爆破）
    results["CORR-003"] = _corr_multi_stage(db_path)

    # CORR-004: 扫描行为
    results["CORR-004"] = _corr_scan_behavior(db_path)

    # CORR-005: Payload 特征检测
    results["CORR-005"] = _corr_payload_detection(db_path)

    logger.info("关联分析完成: %s", results)
    return results


def _ensure_tags_json(tags_val: Any) -> list:
    """确保 tags 字段为列表。"""
    if not tags_val:
        return []
    if isinstance(tags_val, list):
        return tags_val
    if isinstance(tags_val, str):
        try:
            return json.loads(tags_val)
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def _add_tag_to_profile(db_path, src_ip: str, new_tag: str):
    """向攻击源画像添加标签（幂等）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT tags FROM attacker_profiles WHERE src_ip = ?", (src_ip,)
    )
    row = cursor.fetchone()
    if not row:
        return

    tags = _ensure_tags_json(row["tags"])
    if new_tag not in tags:
        tags.append(new_tag)
        cursor.execute(
            "UPDATE attacker_profiles SET tags = ?, updated_at = ? WHERE src_ip = ?",
            (json.dumps(tags, ensure_ascii=False),
             datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             src_ip),
        )
        conn.commit()


def _corr_multi_source(db_path) -> int:
    """CORR-001: 识别多源命中 IP。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT src_ip FROM normalized_events
        WHERE source = 'safeline'
        INTERSECT
        SELECT src_ip FROM normalized_events
        WHERE source = 'hfish'
    """)
    multi_source_ips = [row["src_ip"] for row in cursor.fetchall()]

    count = 0
    for ip in multi_source_ips:
        cursor.execute(
            "UPDATE attacker_profiles SET is_multi_source = 1, updated_at = ? WHERE src_ip = ?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), ip),
        )
        _add_tag_to_profile(db_path, ip, "多源命中")
        count += 1

    if count:
        logger.info("CORR-001 多源命中: %d 个 IP", count)
    return count


def _corr_multi_attack_type(db_path) -> int:
    """CORR-002: 识别多类型攻击 IP（≥3 种不同 attack_type）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT src_ip, COUNT(DISTINCT attack_type) as type_count
        FROM normalized_events
        WHERE attack_type IS NOT NULL AND attack_type != ''
        GROUP BY src_ip
        HAVING type_count >= 3
    """)
    ips = [row["src_ip"] for row in cursor.fetchall()]

    for ip in ips:
        _add_tag_to_profile(db_path, ip, "多类型攻击")

    return len(ips)


def _corr_multi_stage(db_path) -> int:
    """CORR-003: 识别多阶段攻击（Web 探测 → SSH/Redis/MySQL 爆破）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 查找同时有 SafeLine 事件和 HFish 非 HTTP 事件的 IP
    cursor.execute("""
        SELECT DISTINCT n.src_ip
        FROM normalized_events n
        WHERE n.source = 'safeline'
          AND n.src_ip IN (
              SELECT src_ip FROM normalized_events
              WHERE source = 'hfish'
                AND protocol NOT IN ('HTTP', 'HTTPS', 'UNKNOWN')
          )
    """)
    ips = [row["src_ip"] for row in cursor.fetchall()]

    for ip in ips:
        _add_tag_to_profile(db_path, ip, "多阶段攻击")

    return len(ips)


def _corr_scan_behavior(db_path) -> int:
    """CORR-004: 识别扫描行为（高频 + 敏感路径）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    suspicious_keywords = [
        ".git", ".env", "/admin/", "/backup/", "/wp-admin/",
        "/phpmyadmin/", "/web-inf/", "/actuator/", "/swagger",
    ]

    count = 0
    cursor.execute("""
        SELECT src_ip, COUNT(*) as cnt,
               COUNT(DISTINCT uri) as uri_count
        FROM normalized_events
        WHERE source = 'safeline'
        GROUP BY src_ip
    """)
    for row in cursor.fetchall():
        ip = row["src_ip"]
        uri_count = row["uri_count"]
        total = row["cnt"]

        # 高频 + 多个不同 URI
        if total >= 5 and uri_count >= 3:
            _add_tag_to_profile(db_path, ip, "Web 扫描")
            count += 1
            continue

        # 敏感路径
        cursor.execute(
            "SELECT uri FROM normalized_events WHERE src_ip = ? AND uri IS NOT NULL",
            (ip,),
        )
        uris = [r["uri"] for r in cursor.fetchall()]
        if any(any(kw in (u or "").lower() for kw in suspicious_keywords) for u in uris):
            _add_tag_to_profile(db_path, ip, "Web 扫描")
            count += 1

    return count


def _corr_payload_detection(db_path) -> int:
    """CORR-005: 检测高危 Payload 特征。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT DISTINCT src_ip FROM normalized_events WHERE payload IS NOT NULL"
    )
    ips = [row["src_ip"] for row in cursor.fetchall()]

    count = 0
    for ip in ips:
        cursor.execute(
            "SELECT payload FROM normalized_events WHERE src_ip = ? AND payload IS NOT NULL",
            (ip,),
        )
        payloads = [str(r["payload"]) for r in cursor.fetchall()]
        combined = " ".join(payloads).lower()

        if any(kw in combined for kw in HIGH_RISK_PAYLOAD_KEYWORDS):
            _add_tag_to_profile(db_path, ip, "高危 Payload")
            count += 1

    return count
