"""
ATT&CK 映射引擎。

基于规则将攻击行为映射到 MITRE ATT&CK 技术。
第一版使用规则映射，不做复杂推理。
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.logger import get_logger

logger = get_logger("attack_mapper")

# 单词边界正则缓存
_WORD_BOUNDARY_CACHE: dict = {}


def _word_match(val: str, text: str) -> bool:
    """
    单词级别匹配（非子串匹配）。
    例如 "rce" 不匹配 "force"，但匹配 "rce" 或 "rce_attack"。
    """
    pattern = _WORD_BOUNDARY_CACHE.get(val)
    if pattern is None:
        # 使用 \b 单词边界，使 "exec" 在 "exec('id')" 中可匹配
        pattern = re.compile(
            r"\b" + re.escape(val) + r"\b",
            re.IGNORECASE,
        )
        _WORD_BOUNDARY_CACHE[val] = pattern
    return bool(pattern.search(text))

# 映射规则: (条件, technique_id, technique_name, attack_behavior)
# 条件按优先级从高到低排列，第一个匹配的生效
MAPPING_RULES: List[Tuple[str, str, str, str]] = [
    # --- 扫描探测 / 敏感文件探测（T1595） ---
    ("attack_type:scan", "T1595", "Active Scanning", "扫描探测"),
    ("attack_type:dirbust", "T1595", "Active Scanning", "目录扫描"),
    ("attack_type:directory scan", "T1595", "Active Scanning", "目录扫描"),
    ("attack_type:directory", "T1595", "Active Scanning", "目录扫描"),
    ("attack_type:sensitive file probe", "T1595", "Active Scanning", "敏感文件探测"),
    ("attack_type:sensitive file", "T1595", "Active Scanning", "敏感文件探测"),
    ("attack_type:probe", "T1595", "Active Scanning", "服务探测"),
    ("attack_type:探测", "T1595", "Active Scanning", "服务探测"),

    # --- Web 漏洞利用（T1190） ---
    ("attack_type:path traversal", "T1190", "Exploit Public-Facing Application", "路径遍历"),
    ("attack_type:sql injection", "T1190", "Exploit Public-Facing Application", "SQL 注入攻击"),
    ("attack_type:sqli", "T1190", "Exploit Public-Facing Application", "SQL 注入攻击"),
    ("attack_type:xss", "T1190", "Exploit Public-Facing Application", "XSS 攻击"),
    ("attack_type:rce", "T1190", "Exploit Public-Facing Application", "远程命令执行"),
    ("attack_type:command execution", "T1190", "Exploit Public-Facing Application", "命令执行"),
    ("attack_type:command", "T1190", "Exploit Public-Facing Application", "命令注入"),
    ("attack_type:file inclusion", "T1190", "Exploit Public-Facing Application", "文件包含"),
    ("attack_type:注入", "T1190", "Exploit Public-Facing Application", "注入攻击"),
    ("attack_type:ssrf", "T1190", "Exploit Public-Facing Application", "SSRF 攻击"),
    ("attack_type:xxe", "T1190", "Exploit Public-Facing Application", "XXE 攻击"),
    ("attack_type:webshell", "T1190", "Exploit Public-Facing Application", "Webshell 上传"),

    # --- 暴力破解（T1110 / T1110.001） ---
    ("attack_type:brute force", "T1110", "Brute Force", "暴力破解"),
    ("attack_type:bruteforce", "T1110", "Brute Force", "暴力破解"),
    ("protocol:SSH and attack_type:ssh", "T1110", "Brute Force", "SSH 暴力破解"),
    ("protocol:REDIS and attack_type:redis", "T1110", "Brute Force", "Redis 暴力破解"),
    ("protocol:MYSQL and attack_type:mysql", "T1110", "Brute Force", "MySQL 暴力破解"),
    ("protocol:TELNET and attack_type:telnet", "T1110", "Brute Force", "Telnet 暴力破解"),
    ("protocol:FTP and attack_type:ftp", "T1110", "Brute Force", "FTP 暴力破解"),
    ("attack_type:爆破", "T1110", "Brute Force", "暴力破解"),
    ("attack_type:weak password", "T1110", "Brute Force", "弱口令尝试"),

    # HFish 凭据尝试优先映射到 Password Guessing
    ("source:hfish and has_username", "T1110.001", "Password Guessing", "凭据猜测"),
    ("source:hfish and has_password", "T1110.001", "Password Guessing", "凭据猜测"),

    # --- 命令执行（T1059, Payload 级别） ---
    ("payload:exec", "T1059", "Command and Scripting Interpreter", "命令执行"),
    ("payload:system", "T1059", "Command and Scripting Interpreter", "系统命令执行"),
    ("payload:passthru", "T1059", "Command and Scripting Interpreter", "命令执行"),
]


def map_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    对单条标准化事件进行 ATT&CK 映射。

    Args:
        event: normalized_events 的一行（字典格式）。

    Returns:
        dict|None: {
            "normalized_event_id": int,
            "src_ip": str,
            "attack_behavior": str,
            "technique_id": str,
            "technique_name": str,
            "mapping_type": "rule"
        }
        无法映射时返回 None。
    """
    attack_type = (event.get("attack_type") or "").lower()
    protocol = (event.get("protocol") or "").upper()
    source = (event.get("source") or "").lower()
    payload = (event.get("payload") or "").lower()

    has_username = "username" in payload
    has_password = "password" in payload

    # 按规则匹配
    for rule, tid, tname, behavior in MAPPING_RULES:
        parts = rule.split(" and ")
        match = True
        for part in parts:
            if part.startswith("attack_type:"):
                val = part.split(":", 1)[1].lower()
                if not _word_match(val, attack_type):
                    match = False
                    break
            elif part.startswith("protocol:"):
                val = part.split(":", 1)[1].upper()
                if val not in protocol:  # protocol 用精确匹配
                    match = False
                    break
            elif part.startswith("source:"):
                val = part.split(":", 1)[1].lower()
                if val not in source:  # source 用精确匹配
                    match = False
                    break
            elif part.startswith("payload:"):
                val = part.split(":", 1)[1].lower()
                if not _word_match(val, payload):
                    match = False
                    break
            elif part == "has_username":
                if not has_username:
                    match = False
                    break
            elif part == "has_password":
                if not has_password:
                    match = False
                    break
            elif part.startswith("username:"):
                val = part.split(":", 1)[1]
                if val not in payload:
                    match = False
                    break
            else:
                match = False
                break

        if match:
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return {
                "normalized_event_id": event.get("id"),
                "src_ip": event.get("src_ip") or "",
                "attack_behavior": behavior,
                "technique_id": tid,
                "technique_name": tname,
                "mapping_type": "rule",
                "created_at": now,
            }

    return None


def map_all_pending(db_path, rebuild: bool = False) -> int:
    """
    对所有尚未映射的标准化事件执行 ATT&CK 映射。

    Args:
        db_path: 数据库文件路径。
        rebuild: 是否重建全部映射。

    Returns:
        int: 新增映射数量。
    """
    from app.db import get_connection, insert_attack_mapping

    conn = get_connection(db_path)
    cursor = conn.cursor()

    if rebuild:
        cursor.execute("DELETE FROM attack_mappings")
        logger.info("已清空所有 ATT&CK 映射")

    # 查找尚未映射的事件
    cursor.execute("""
        SELECT n.* FROM normalized_events n
        WHERE n.id NOT IN (
            SELECT DISTINCT normalized_event_id FROM attack_mappings
        )
        ORDER BY n.id ASC
    """)
    rows = cursor.fetchall()

    count = 0
    for row in rows:
        event = dict(row)
        mapping = map_event(event)
        if mapping:
            insert_attack_mapping(db_path, mapping)
            count += 1

    logger.info("ATT&CK 映射完成: %d 个事件 -> %d 条映射", len(rows), count)
    return count


def get_mappings_by_ip(db_path, src_ip: str) -> List[Dict[str, Any]]:
    """查询指定 IP 的 ATT&CK 映射。"""
    from app.db import get_connection

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM attack_mappings WHERE src_ip = ? ORDER BY id ASC",
        (src_ip,),
    )
    return [dict(r) for r in cursor.fetchall()]
