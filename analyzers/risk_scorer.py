"""
风险评分引擎。

基于规则引擎（非 AI）计算攻击源的风险评分和风险等级。
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.logger import get_logger

logger = get_logger("risk_scorer")

# 敏感路径关键词（用于评分规则）
SENSITIVE_PATH_KEYWORDS = [
    ".git", ".env", ".svn", "/web-inf/", "/admin/",
    "/backup/", "/wp-admin/", "/phpmyadmin/", "/actuator/",
]


def calculate_score(profile_data: Dict[str, Any],
                    events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    基于规则计算攻击源风险评分和风险等级。

    Args:
        profile_data: attacker_profile 的部分数据，至少包含：
            safeline_count, hfish_count, is_multi_source, total_count,
            attack_types, protocols, tags
        events: 该 IP 的标准化事件列表（用于详细规则判断）。

    Returns:
        dict: {"score": int, "level": str}
            score: 0-100 的风险评分
            level: low / medium / high / critical
    """
    score = 0

    # 1. 事件数量加分
    safeline_count = profile_data.get("safeline_count", 0) or 0
    hfish_count = profile_data.get("hfish_count", 0) or 0
    total_count = profile_data.get("total_count", 0) or 0

    if safeline_count > 0:
        score += min(safeline_count * 10, 30)  # +10/条，上限 30
    if hfish_count > 0:
        score += min(hfish_count * 15, 45)  # +15/条，上限 45

    # 2. 多源命中
    if profile_data.get("is_multi_source"):
        score += 30

    # 3. 高频事件（>50 条）
    if total_count > 50:
        score += 15

    # 4. 攻击类型专项加分
    attack_types = profile_data.get("attack_types")
    if isinstance(attack_types, str):
        try:
            import json
            attack_types = json.loads(attack_types)
        except (json.JSONDecodeError, TypeError):
            attack_types = {}

    if isinstance(attack_types, dict):
        for atype in attack_types:
            atype_lower = atype.lower()
            if "sql injection" in atype_lower or "sqli" in atype_lower:
                score += 20
            if "xss" in atype_lower:
                score += 15
            if "sensitive file" in atype_lower or "path traversal" in atype_lower:
                score += 15

    # 5. 协议专项加分
    protocols = profile_data.get("protocols")
    if isinstance(protocols, str):
        try:
            import json
            protocols = json.loads(protocols)
        except (json.JSONDecodeError, TypeError):
            protocols = {}

    if isinstance(protocols, dict):
        unique_protocols = list(protocols.keys())
        ssh_bf = any("SSH" in p.upper() for p in unique_protocols)
        redis_bf = any("REDIS" in p.upper() for p in unique_protocols)
        mysql_bf = any("MYSQL" in p.upper() for p in unique_protocols)

        if ssh_bf:
            score += 20
        if redis_bf:
            score += 20
        if mysql_bf:
            score += 20

        # 多协议探测（≥3 种）
        if len(unique_protocols) >= 3:
            score += 15

    # 6. 基于事件的详细分析（events 参数）
    if events:
        # 检查敏感路径
        for ev in events:
            uri = ev.get("uri") or ""
            if any(kw in uri.lower() for kw in SENSITIVE_PATH_KEYWORDS):
                score += 15
                break  # 只加一次

        # 检查有效载荷中的高危特征
        for ev in events:
            payload = ev.get("payload") or ""
            if payload and isinstance(payload, str):
                payload_lower = payload.lower()
                if "union select" in payload_lower or "1=1" in payload_lower:
                    score += 20
                    break

    # 7. 多阶段攻击（通过 tags 判断）
    tags = profile_data.get("tags")
    if isinstance(tags, str):
        try:
            import json
            tags = json.loads(tags)
        except (json.JSONDecodeError, TypeError):
            tags = []
    if isinstance(tags, list) and "多阶段攻击" in tags:
        score += 25

    # 上限 100
    score = min(score, 100)

    # 确定等级
    level = _score_to_level(score)

    return {"score": score, "level": level}


def _score_to_level(score: int) -> str:
    """
    将分数映射为风险等级。

    Args:
        score: 风险评分（0-100）。

    Returns:
        str: low / medium / high / critical
    """
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"
