"""
HFish 蜜罐日志解析器。

将 HFish API 返回的 JSON 事件解析为结构化字段。
"""

import json
from typing import Any, Dict, Optional


def extract_hfish_event(raw_data: str) -> Dict[str, Any]:
    """
    解析 HFish API 返回的单条事件 JSON。

    HFish API 返回数据格式可能嵌套（如 data.items[]），
    此函数支持传入单条事件对象或包含嵌套的原始 JSON。

    Args:
        raw_data: HFish API 返回的 JSON 字符串（单条事件）。

    Returns:
        dict: {
            "success": bool,
            "parsed_dict": dict|None,
            "error_message": str|None
        }
    """
    result = {
        "success": False,
        "parsed_dict": None,
        "error_message": None,
    }

    if not raw_data or not isinstance(raw_data, str):
        result["error_message"] = "raw_data is empty or not a string"
        return result

    try:
        parsed = json.loads(raw_data)
    except json.JSONDecodeError as e:
        result["error_message"] = f"JSON decode error: {e}"
        return result

    if not isinstance(parsed, dict):
        result["error_message"] = "parsed JSON is not a dict"
        return result

    result["success"] = True
    result["parsed_dict"] = parsed
    return result


def extract_fields(parsed_dict: Optional[Dict]) -> Dict[str, Any]:
    """
    从解析后的 HFish 事件字典中提取标准字段。

    HFish API 字段名称可能因版本而异，此函数做兼容处理。

    Args:
        parsed_dict: HFish 事件字典。

    Returns:
        dict: 提取的字段字典，包含以下可选字段：
            event_id, event_time, src_ip, src_port, protocol,
            target_port, username, password, command, request_content,
            user_agent, node_name, location, event_type, severity
    """
    fields = {
        "event_id": None,
        "event_time": None,
        "src_ip": None,
        "src_port": None,
        "protocol": None,
        "target_port": None,
        "username": None,
        "password": None,
        "command": None,
        "request_content": None,
        "user_agent": None,
        "node_name": None,
        "location": None,
        "event_type": None,
        "severity": None,
    }

    if not parsed_dict or not isinstance(parsed_dict, dict):
        return fields

    # 尝试多种可能的字段名（不同 HFish 版本可能有差异）
    fields["event_id"] = (
        parsed_dict.get("id")
        or parsed_dict.get("event_id")
        or parsed_dict.get("_id")
    )

    fields["event_time"] = (
        parsed_dict.get("time")
        or parsed_dict.get("event_time")
        or parsed_dict.get("create_time")
        or parsed_dict.get("timestamp")
    )

    fields["src_ip"] = (
        parsed_dict.get("src_ip")
        or parsed_dict.get("source_ip")
        or parsed_dict.get("attacker_ip")
        or parsed_dict.get("ip")
    )

    fields["src_port"] = (
        parsed_dict.get("src_port")
        or parsed_dict.get("source_port")
        or parsed_dict.get("port")
    )

    fields["protocol"] = (
        parsed_dict.get("type")
        or parsed_dict.get("proto")
        or parsed_dict.get("protocol")
        or parsed_dict.get("service")
    )

    fields["target_port"] = (
        parsed_dict.get("dst_port")
        or parsed_dict.get("target_port")
        or parsed_dict.get("local_port")
    )

    fields["username"] = (
        parsed_dict.get("username")
        or parsed_dict.get("user")
        or parsed_dict.get("user_name")
    )

    fields["password"] = (
        parsed_dict.get("password")
        or parsed_dict.get("pass")
        or parsed_dict.get("passwd")
    )

    fields["command"] = (
        parsed_dict.get("cmd")
        or parsed_dict.get("command")
        or parsed_dict.get("input")
    )

    fields["request_content"] = (
        parsed_dict.get("request")
        or parsed_dict.get("request_content")
        or parsed_dict.get("raw_request")
        or parsed_dict.get("data")
        or parsed_dict.get("content")
    )

    fields["user_agent"] = (
        parsed_dict.get("user_agent")
        or parsed_dict.get("ua")
        or parsed_dict.get("user-agent")
    )

    fields["node_name"] = (
        parsed_dict.get("node")
        or parsed_dict.get("node_name")
        or parsed_dict.get("honeypot")
    )

    fields["location"] = (
        parsed_dict.get("location")
        or parsed_dict.get("geo")
        or parsed_dict.get("country")
    )

    fields["event_type"] = (
        parsed_dict.get("event_type")
        or parsed_dict.get("attack_type")
        or parsed_dict.get("action")
    )

    fields["severity"] = (
        parsed_dict.get("severity")
        or parsed_dict.get("level")
        or parsed_dict.get("risk_level")
    )

    return fields
