"""
事件标准化引擎。

将 SafeLine 和 HFish 的解析结果统一为 normalized_events 标准格式。
"""

import re
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

# HTTP 请求行正则: GET /path HTTP/1.1
HTTP_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)

# Host 头正则
HTTP_HOST_RE = re.compile(r"^Host:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
# User-Agent 头正则
HTTP_UA_RE = re.compile(r"^User-Agent:\s*(.+)", re.IGNORECASE | re.MULTILINE)


# =============================================================================
# HTTP 请求解析
# =============================================================================


def parse_http_request(request_content: Optional[str]) -> Dict[str, Optional[str]]:
    """
    从 HTTP 请求内容中解析 HTTP method / URI / Host / User-Agent。

    适用于 HFish HTTP 蜜罐捕获到的原始请求。

    Args:
        request_content: 原始 HTTP 请求字符串（可能包含请求行和头）。

    Returns:
        dict: {
            "http_method": str|None,
            "uri": str|None,
            "host": str|None,
            "user_agent": str|None,
        }
    """
    result = {
        "http_method": None,
        "uri": None,
        "host": None,
        "user_agent": None,
    }

    if not request_content or not isinstance(request_content, str):
        return result

    # 提取请求行: GET /path HTTP/1.1
    match = HTTP_REQUEST_LINE_RE.search(request_content)
    if match:
        result["http_method"] = match.group(1).upper()
        result["uri"] = match.group(2)

    # 提取 Host 头
    host_match = HTTP_HOST_RE.search(request_content)
    if host_match:
        result["host"] = host_match.group(1)

    # 提取 User-Agent 头
    ua_match = HTTP_UA_RE.search(request_content)
    if ua_match:
        result["user_agent"] = ua_match.group(1).strip()

    return result


# =============================================================================
# 标准化核心函数
# =============================================================================


def normalize_severity(raw_severity: Any) -> str:
    """将原始严重级别映射为标准值。"""
    if raw_severity is None:
        return "low"

    raw = str(raw_severity).strip().lower()
    return SEVERITY_MAP.get(raw, "low")


def normalize_attack_type(raw_type: Any) -> str:
    """将原始攻击类型映射为标准名称。"""
    if raw_type is None:
        return "Unknown"

    raw = str(raw_type).strip().lower()
    return ATTACK_TYPE_MAP.get(raw, str(raw_type).strip())


def normalize_event_time(raw_time: Any) -> Optional[str]:
    """标准化事件时间，支持多种格式。"""
    if raw_time is None:
        return None

    if isinstance(raw_time, (int, float)):
        try:
            return datetime.fromtimestamp(raw_time, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (OSError, ValueError):
            return None

    raw = str(raw_time).strip()
    if not raw:
        return None

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
    """将 SafeLine 解析结果标准化为统一事件格式。"""
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

    对 HTTP 协议的蜜罐事件，从 request_content 中尝试解析
    http_method / uri / host / user_agent。
    """
    if not parsed_fields or not isinstance(parsed_fields, dict):
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    protocol = parsed_fields.get("protocol") or "unknown"
    protocol_upper = protocol.upper() if protocol else "UNKNOWN"

    http_method = None
    uri = None
    host = None

    # 对 HTTP 协议，从 request_content 做轻量解析
    request_content = parsed_fields.get("request_content")
    if protocol_upper in ("HTTP", "HTTPS"):
        http_info = parse_http_request(request_content)
        http_method = http_info.get("http_method") or "GET"
        uri = http_info.get("uri") or "/"
        host = http_info.get("host")
        # 如果 parser 层没提取到 user_agent，尝试从 HTTP 头中提取
        if not parsed_fields.get("user_agent") and http_info.get("user_agent"):
            parsed_fields["user_agent"] = http_info["user_agent"]

    # 攻击类型优先使用 event_type，其次用 protocol
    attack_type = parsed_fields.get("event_type") or protocol

    # 构建 payload：优先 command，其次 request_content
    payload = parsed_fields.get("command") or request_content

    return {
        "source": "hfish",
        "source_event_id": parsed_fields.get("event_id") or "",
        "event_time": normalize_event_time(parsed_fields.get("event_time")) or now,
        "src_ip": parsed_fields.get("src_ip") or "",
        "src_port": parsed_fields.get("src_port"),
        "dst_ip": None,
        "dst_port": parsed_fields.get("target_port"),
        "protocol": protocol_upper,
        "http_method": http_method,
        "host": host,
        "uri": uri,
        "user_agent": parsed_fields.get("user_agent"),
        "attack_type": normalize_attack_type(attack_type),
        "severity": normalize_severity(parsed_fields.get("severity")),
        "payload": payload,
    }


# =============================================================================
# ModSecurity 标准化
# =============================================================================

# CRS rule_id -> attack_type 推断
CRS_ATTACK_TYPE_RANGES = [
    (920000, 929999, "scanner"),
    (930000, 931999, "path_traversal"),
    (932000, 932999, "command_injection"),
    (933000, 933999, "path_traversal"),
    (934000, 934999, "command_injection"),
    (941000, 941999, "xss"),
    (942000, 943999, "sql_injection"),
    (944000, 944999, "command_injection"),
    (950000, 959999, "scanner"),
]

CRS_MESSAGE_KEYWORDS = [
    ("sql injection", "sql_injection"),
    ("sqli", "sql_injection"),
    ("xss", "xss"),
    ("cross site", "xss"),
    ("rfi", "path_traversal"),
    ("lfi", "path_traversal"),
    ("path traversal", "path_traversal"),
    ("rce", "command_injection"),
    ("command injection", "command_injection"),
    ("remote file", "path_traversal"),
    ("local file", "path_traversal"),
    ("scanner", "scanner"),
    ("protocol violation", "scanner"),
    ("php injection", "command_injection"),
]


def infer_attack_type(rule_id: Optional[str], message: Optional[str]) -> str:
    """
    根据 rule_id 和 message 推断攻击类型。

    Args:
        rule_id: CRS 规则 ID（字符串）。
        message: 规则消息。

    Returns:
        str: 标准攻击类型。
    """
    # 优先按 rule_id 范围推断
    if rule_id:
        try:
            rid = int(rule_id)
            for start, end, atype in CRS_ATTACK_TYPE_RANGES:
                if start <= rid <= end:
                    return atype
        except ValueError:
            pass

    # 其次按 message 关键词推断
    if message:
        msg_lower = message.lower()
        for keyword, atype in CRS_MESSAGE_KEYWORDS:
            if keyword in msg_lower:
                return atype

    return "web_attack"


def normalize_from_modsecurity(parsed: Optional[Dict]) -> Optional[Dict[str, Any]]:
    """
    将 ModSecurity 解析结果标准化为统一事件格式。

    Args:
        parsed: ModSecurity parser 的 parse_transaction() 返回结果。

    Returns:
        dict|None: 标准化事件字典。
    """
    if not parsed or not isinstance(parsed, dict):
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attack_type = infer_attack_type(
        parsed.get("rule_id"), parsed.get("message")
    )

    return {
        "source": "modsecurity",
        "source_event_id": parsed.get("transaction_id") or "",
        "event_time": normalize_event_time(parsed.get("timestamp")) or now,
        "src_ip": parsed.get("client_ip") or "",
        "src_port": parsed.get("client_port"),
        "dst_ip": parsed.get("server_ip"),
        "dst_port": parsed.get("server_port"),
        "protocol": "HTTP",
        "http_method": parsed.get("method"),
        "host": parsed.get("host"),
        "uri": parsed.get("uri"),
        "user_agent": parsed.get("user_agent"),
        "attack_type": attack_type,
        "severity": normalize_severity(parsed.get("severity")),
        "payload": parsed.get("matched_data") or parsed.get("message"),
        # 额外字段放入 payload 末尾
        "_rule_id": parsed.get("rule_id"),
        "_rule_name": parsed.get("message"),
        "_action": parsed.get("action"),
        "_blocked": parsed.get("blocked", False),
    }
