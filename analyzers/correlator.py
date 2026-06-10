"""
关联分析引擎。

基于规则引擎对事件、画像进行交叉关联分析，
识别多源命中、多阶段攻击、扫描行为等安全模式。
关联分析后自动重新计算受影响 IP 的风险评分。
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db import get_connection
from app.logger import get_logger

logger = get_logger("correlator")

# 高危 Payload 关键词
HIGH_RISK_PAYLOAD_KEYWORDS = [
    "union select", "1=1", "1=2", "' or '", "\" or \"",
    "<script>", "alert(", "onerror=",
    "eval(", "exec(", "system(", "passthru(",
    "../../", "..\\\\",
]


def correlate_all(db_path) -> Dict[str, Any]:
    """
    执行所有关联分析规则。

    如果 attacker_profiles 为空，友好提示并返回空结果。
    执行完成后，对受影响的 IP 重新计算风险评分。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: {
            "rules": {"CORR-001": int, ...},
            "profiles_recalculated": int
        }
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 前置条件检查：画像是否存在
    cursor.execute("SELECT COUNT(*) as cnt FROM attacker_profiles")
    if cursor.fetchone()["cnt"] == 0:
        logger.info("attacker_profiles 为空，跳过关联分析")
        print("[INFO] attacker_profiles 为空，请先运行 python main.py build-profiles")
        return {"rules": {}, "profiles_recalculated": 0}

    # 收集受影响的 IP（在各项规则中追加标签的 IP）
    affected_ips: set = set()

    # 执行各规则，同时收集 affected_ips
    def _tag(ip, tag):
        _add_tag_to_profile(db_path, ip, tag)
        affected_ips.add(ip)

    results = {}

    # CORR-001: 多源命中
    count, ips = _corr_multi_source(db_path)
    for ip in ips:
        affected_ips.add(ip)
    results["CORR-001"] = count

    # CORR-002: 多类型攻击
    count, ips = _corr_multi_attack_type(db_path)
    for ip in ips:
        affected_ips.add(ip)
    results["CORR-002"] = count

    # CORR-003: 多阶段攻击
    count, ips = _corr_multi_stage(db_path)
    for ip in ips:
        affected_ips.add(ip)
    results["CORR-003"] = count

    # CORR-004: 扫描行为
    count, ips = _corr_scan_behavior(db_path)
    for ip in ips:
        affected_ips.add(ip)
    results["CORR-004"] = count

    # CORR-005: Payload 检测
    count, ips = _corr_payload_detection(db_path)
    for ip in ips:
        affected_ips.add(ip)
    results["CORR-005"] = count

    # 对受影响的 IP 重新计算风险评分
    recalculated = _recalculate_risk_scores(db_path, affected_ips)

    logger.info("关联分析完成: rules=%s, profiles_recalculated=%d",
                results, recalculated)
    return {"rules": results, "profiles_recalculated": recalculated}


def _recalculate_risk_scores(db_path, ips: set) -> int:
    """对指定 IP 重新运行风险评分并更新画像。"""
    if not ips:
        return 0

    from analyzers.risk_scorer import calculate_score
    from app.db import get_connection

    conn = get_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    count = 0

    for ip in ips:
        # 读取当前画像
        cursor.execute("SELECT * FROM attacker_profiles WHERE src_ip = ?", (ip,))
        row = cursor.fetchone()
        if not row:
            continue

        profile = dict(row)

        # 准备评分输入
        score_input = {
            "safeline_count": profile.get("safeline_count", 0),
            "hfish_count": profile.get("hfish_count", 0),
            "total_count": profile.get("total_count", 0),
            "is_multi_source": profile.get("is_multi_source", 0),
            "attack_types": profile.get("attack_types"),
            "protocols": profile.get("protocols"),
            "tags": profile.get("tags"),
        }

        # 查询该 IP 的标准化事件
        cursor.execute(
            "SELECT * FROM normalized_events WHERE src_ip = ? ORDER BY event_time ASC",
            (ip,),
        )
        events = [dict(r) for r in cursor.fetchall()]

        risk = calculate_score(score_input, events=events)

        cursor.execute(
            """UPDATE attacker_profiles
               SET risk_score = ?, risk_level = ?, updated_at = ?
               WHERE src_ip = ?""",
            (risk["score"], risk["level"], now, ip),
        )
        count += 1

    conn.commit()
    logger.info("已重新计算 %d 个 IP 的风险评分", count)
    return count


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


def _corr_multi_source(db_path):
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
    ips = [row["src_ip"] for row in cursor.fetchall()]

    for ip in ips:
        cursor.execute(
            "UPDATE attacker_profiles SET is_multi_source = 1, updated_at = ? WHERE src_ip = ?",
            (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), ip),
        )
        _add_tag_to_profile(db_path, ip, "多源命中")

    if ips:
        logger.info("CORR-001 多源命中: %d 个 IP", len(ips))
    return len(ips), ips


def _corr_multi_attack_type(db_path):
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

    return len(ips), ips


def _corr_multi_stage(db_path):
    """CORR-003: 识别多阶段攻击（Web 探测 → SSH/Redis/MySQL 爆破）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

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

    return len(ips), ips


def _corr_scan_behavior(db_path):
    """CORR-004: 识别扫描行为（高频 + 敏感路径）。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    suspicious_keywords = [
        ".git", ".env", "/admin/", "/backup/", "/wp-admin/",
        "/phpmyadmin/", "/web-inf/", "/actuator/", "/swagger",
    ]

    affected = []
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

        if total >= 5 and uri_count >= 3:
            _add_tag_to_profile(db_path, ip, "Web 扫描")
            affected.append(ip)
            continue

        cursor.execute(
            "SELECT uri FROM normalized_events WHERE src_ip = ? AND uri IS NOT NULL",
            (ip,),
        )
        uris = [r["uri"] for r in cursor.fetchall()]
        if any(any(kw in (u or "").lower() for kw in suspicious_keywords) for u in uris):
            _add_tag_to_profile(db_path, ip, "Web 扫描")
            affected.append(ip)

    return len(affected), affected


def _corr_payload_detection(db_path):
    """CORR-005: 检测高危 Payload 特征。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT DISTINCT src_ip FROM normalized_events WHERE payload IS NOT NULL"
    )
    ips = [row["src_ip"] for row in cursor.fetchall()]

    affected = []
    for ip in ips:
        cursor.execute(
            "SELECT payload FROM normalized_events WHERE src_ip = ? AND payload IS NOT NULL",
            (ip,),
        )
        payloads = [str(r["payload"]) for r in cursor.fetchall()]
        combined = " ".join(payloads).lower()

        if any(kw in combined for kw in HIGH_RISK_PAYLOAD_KEYWORDS):
            _add_tag_to_profile(db_path, ip, "高危 Payload")
            affected.append(ip)

    return len(affected), affected
