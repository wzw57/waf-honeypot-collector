"""
SafeLine Syslog 解析器。

从 Syslog 原始报文中提取 JSON 部分并进行解析。

TODO: 当前 JSON 提取策略（查找首尾 {}）适合 Phase 1 MVP。
      后续需要根据真实 SafeLine Syslog 样本增强：
      - 确认 Syslog 报文中 JSON 的确切位置（可能有固定前缀）
      - 处理转义字符和多行 JSON
      - 增加字段类型校验和归一化
      - 对接后续 Normalizer 模块
"""

import json
from typing import Tuple


def extract_json_from_syslog(raw_message: str) -> Tuple[str, str]:
    """
    从 Syslog 报文提取 JSON 部分。

    查找第一个 '{' 到最后一个 '}' 之间的内容。

    Args:
        raw_message: Syslog 原始报文。

    Returns:
        Tuple[str, str]: (提取的 JSON 字符串, 错误信息)
        - 提取成功: json_str 为 JSON 字符串，error 为空
        - 提取失败: json_str 为空，error 为错误描述
    """
    if not raw_message or not isinstance(raw_message, str):
        return "", "raw_message is empty or not a string"

    start = raw_message.find("{")
    end = raw_message.rfind("}")

    if start == -1 or end == -1 or start >= end:
        return "", "no JSON object found in syslog message"

    json_str = raw_message[start : end + 1]
    return json_str, ""


def parse_safeline_syslog(raw_message: str) -> dict:
    """
    解析 SafeLine Syslog 报文。

    Args:
        raw_message: Syslog 原始报文。

    Returns:
        dict: {
            "success": bool,        # 是否成功解析
            "parsed_json": str|None,  # 提取并解析成功的 JSON 字符串
            "parsed_dict": dict|None, # 解析后的字典（成功时）
            "error_message": str|None # 错误信息（失败时）
        }
    """
    result = {
        "success": False,
        "parsed_json": None,
        "parsed_dict": None,
        "error_message": None,
    }

    try:
        # 提取 JSON 部分
        json_str, extract_error = extract_json_from_syslog(raw_message)

        if not json_str:
            result["error_message"] = extract_error
            return result

        # 尝试解析 JSON
        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as e:
            result["parsed_json"] = json_str  # 保留原始 JSON 字符串
            result["error_message"] = f"JSON decode error: {e}"
            return result

        result["success"] = True
        result["parsed_json"] = json_str
        result["parsed_dict"] = parsed
        result["error_message"] = None

    except Exception as e:
        # 兜底：确保任何异常都不会向上传播
        result["error_message"] = f"unexpected parser error: {e}"

    return result
