"""
通用工具函数模块。
"""

import re
from datetime import datetime, timezone, timedelta


# IPv4 正则
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def now_iso(tz=None):
    """
    返回当前时间的 ISO 8601 格式字符串。

    Args:
        tz: 时区信息。为 None 时使用 UTC。

    Returns:
        str: ISO 8601 格式的时间字符串，如 "2026-06-10T10:30:00Z"。
    """
    if tz is None:
        tz = timezone.utc
    return datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_valid_ipv4(ip):
    """
    验证是否为合法的 IPv4 地址。

    Args:
        ip: 待验证的 IP 字符串。

    Returns:
        bool: 是否合法。
    """
    if not ip or not isinstance(ip, str):
        return False
    return bool(IPV4_RE.match(ip.strip()))


def safe_json_loads(text, default=None):
    """
    安全地解析 JSON 字符串，解析失败返回默认值。

    Args:
        text: JSON 字符串。
        default: 解析失败时的返回值。

    Returns:
        dict/list/object: 解析结果或默认值。
    """
    import json

    if not text:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def truncate(text, max_length=4096, suffix="..."):
    """
    截断文本到指定长度。

    Args:
        text: 原始文本。
        max_length: 最大长度。
        suffix: 截断后的后缀。

    Returns:
        str: 截断后的文本。
    """
    if not text:
        return text
    if isinstance(text, str) and len(text) > max_length:
        return text[:max_length] + suffix
    return text
