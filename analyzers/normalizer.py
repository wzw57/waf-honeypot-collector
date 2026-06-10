"""
事件标准化引擎。

将 SafeLine 和 HFish 的解析结果统一为 normalized_events 标准格式。
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.logger import get_logger

logger = get_logger("normalizer")

# 攻击类型映射（原始 -> 标准）
ATTACK_TYPE_MAP = {
    # SafeLine 常见类型
    "sql injection": "SQL Injection",
    "sql_injection": "SQL Injection",
    "sqli": "SQL Injection",
    "xss": "XSS",
    "cross site scripting": "XSS",
    "rce": "Command Execution",
    "command injection": "Command Execution",
    "cmd injection": "Command Execution",
    "lfi": "File Inclusion",
    "local file inclusion": "File Inclusion",
    "rfi": "File Inclusion",
    "path traversal": "Path Traversal",
    "directory traversal": "Path Traversal",
    "sensitive file probe": "Sensitive File Probe",
    "sensitive file": "Sensitive File Probe",
    "brute force": "Brute Force",
    "bruteforce": "Brute Force",
    "scan": "Port Scan",
    "port scan": "Port Scan",
    "dirbust": "Directory Scan",
    "directory scan": "Directory Scan",
    "webshell": "Webshell Upload",
    "file upload": "Webshell Upload",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "csrf": "CSRF",
    # HFish 常见类型
    "ssh": "SSH Brute Force",
    "ssh brute force": "SSH Brute Force",
    "ssh爆破": "SSH Brute Force",
    "redis": "Redis Brute Force",
    "redis brute force": "Redis Brute Force",
    "mysql": "MySQL Brute Force",
    "mysql brute force": "MySQL Brute Force",
    "weak password": "Weak Password Attempt",
    "弱口令": "Weak Password Attempt",
    "telnet": "Telnet Brute Force",
    "ftp": "FTP Brute Force",
    "mssql": "MSSQL Brute Force",
    "postgresql": "PostgreSQL Brute Force",
    "http": "HTTP Probe",
    "http probe": "HTTP Probe",
    "https": "HTTPS Probe",
}

# 严重级别映射
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "informational": "low",
    "严重": "critical",
    "高危": "high",
    "中危": "medium",
    "低危": "low",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
    "5": "critical",
}


def normalize_severity(raw_severity: Any) -> str:
    """
    将原始严重级别映射为标准值。

    Args:
        raw_severity: 原始严重级别。

    Returns:
        str: 标准严重级别：low / medium / high / critical。
    """
    if raw_severity is None:
        return "low"

    raw = str(raw_severity).strip().lower()
    return SEVERITY_MAP.get(raw, "low")


def normalize_attack_type(raw_type: Any) -> str:
    """
    将原始攻击类型映射为标准名称。

    Args:
        raw_type: 原始攻击类型。

    Returns:
        str: 标准化攻击类型。无法映射时返回原始值。
    """
    if raw_type is None:
        return "Unknown"

    raw = str(raw_type).strip().lower()
    return ATTACK_TYPE_MAP.get(raw, str(raw_type).strip())


def normalize_event_time(raw_time: Any) -> Optional[str]:
    """
    标准化事件时间。

    尝试多种常见时间格式。

    Args:
        raw_time: 原始时间值。

    Returns:
        str|None: ISO 8601 格式的时间字符串，解析失败返回 None。
    """
    if raw_time is None:
        return None

    if isinstance(raw_time, (int, float)):
        # Unix 时间戳
        try:
            return datetime.fromtimestamp(raw_time, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (OSError, ValueError):
            return None

    raw = str(raw_time).strip()
    if not raw:
        return None

    # 已经是 ISO 格式
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
    ]:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            return dt.strftime("%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            continue

    return raw


def normalize_from_safeline(parsed_dict: Optional[Dict]) -> Optional[Dict[str, Any]]:
    """
    将 SafeLine 解析结果标准化为统一事件格式。

    Args:
        parsed_dict: SafeLine parser 返回的 parsed_dict。

    Returns:
        dict|None: 标准化事件字典，解析失败返回 None。
    """
    if not parsed_dict or not isinstance(parsed_dict, dict):
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "source": "safeline",
        "source_event_id": parsed_dict.get("event_id") or "",
        "event_time": normalize_event_time(parsed_dict.get("event_time")) or now,
        "src_ip": parsed_dict.get("src_ip") or "",
        "src_port": parsed_dict.get("src_port"),
        "dst_ip": parsed_dict.get("dst_ip"),
        "dst_port": parsed_dict.get("dst_port"),
        "protocol": "HTTP",
        "http_method": parsed_dict.get("method"),
        "host": parsed_dict.get("host"),
        "uri": parsed_dict.get("uri"),
        "user_agent": parsed_dict.get("user_agent"),
        "attack_type": normalize_attack_type(parsed_dict.get("attack_type")),
        "severity": normalize_severity(parsed_dict.get("severity")),
        "payload": parsed_dict.get("payload"),
    }


def normalize_from_hfish(parsed_fields: Optional[Dict]) -> Optional[Dict[str, Any]]:
    """
    将 HFish 解析结果标准化为统一事件格式。

    Args:
        parsed_fields: HFish parser 的 extract_fields() 返回的字段字典。

    Returns:
        dict|None: 标准化事件字典，解析失败返回 None。
    """
    if not parsed_fields or not isinstance(parsed_fields, dict):
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 确定协议
    protocol = parsed_fields.get("protocol") or "unknown"
    http_method = None
    uri = None
    host = None

    # 如果是 HTTP 协议，从 request_content 提取信息
    if protocol.lower() in ("http", "https"):
        http_method = "GET"  # 默认
        uri = "/"

    # 攻击类型优先使用 event_type，其次用 protocol
    attack_type = parsed_fields.get("event_type") or protocol

    # 构建 payload：优先 command，其次 request_content
    payload = parsed_fields.get("command") or parsed_fields.get("request_content")

    return {
        "source": "hfish",
        "source_event_id": parsed_fields.get("event_id") or "",
        "event_time": normalize_event_time(parsed_fields.get("event_time")) or now,
        "src_ip": parsed_fields.get("src_ip") or "",
        "src_port": parsed_fields.get("src_port"),
        "dst_ip": None,
        "dst_port": parsed_fields.get("target_port"),
        "protocol": protocol.upper() if protocol else "UNKNOWN",
        "http_method": http_method,
        "host": host,
        "uri": uri,
        "user_agent": parsed_fields.get("user_agent"),
        "attack_type": normalize_attack_type(attack_type),
        "severity": normalize_severity(parsed_fields.get("severity")),
        "payload": payload,
    }
