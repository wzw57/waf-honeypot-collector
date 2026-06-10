"""
ModSecurity Audit Log 解析器。

解析 ModSecurity 原生审计日志格式（--transaction_id-SECTION--），
提取 HTTP 请求字段、规则命中信息、拦截状态等。
"""

import re
from typing import Any, Dict, List, Optional

# Section 行正则: --<transaction_id>-<section>--
SECTION_HEADER_RE = re.compile(r"^--([a-fA-F0-9]+)-([A-Z])--$")

# A 段：时间戳和连接信息
# 格式: [10/Jun/2026:13:50:01 +0800] <unique_id> <client_ip> <client_port> <server_ip> <server_port>
A_LINE_RE = re.compile(
    r"\[([^\]]+)\]\s+\S+\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)"
)

# B 段请求行: METHOD /path HTTP/1.x
REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+(HTTP/\d+\.\d+)", re.IGNORECASE)

# B 段响应状态: HTTP/1.x 403
STATUS_LINE_RE = re.compile(r"^HTTP/\d+\.\d+\s+(\d+)", re.IGNORECASE)

# F 段响应行: HTTP/1.1 403 Forbidden
RESPONSE_LINE_RE = re.compile(r"^HTTP/\d+\.\d+\s+(\d+)")

# H 段规则字段
# [id "942100"] [msg "..."] [severity "CRITICAL"] [data "..."] [tag "..."]
ID_RE = re.compile(r'\[id\s+"(\d+)"\]')
MSG_RE = re.compile(r'\[msg\s+"([^"]*)"\]')
SEVERITY_RE = re.compile(r'\[severity\s+"([^"]*)"\]')
DATA_RE = re.compile(r'\[data\s+"([^"]*)"\]')
TAG_RE = re.compile(r'\[tag\s+"([^"]*)"\]')

# Action 行
ACTION_RE = re.compile(r"^Action:\s*(.+)", re.IGNORECASE)

# Apache-Error 行
APACHE_ERROR_RE = re.compile(r"^Apache-Error:", re.IGNORECASE)

# Host 头
HOST_RE = re.compile(r"^Host:\s*(\S+)", re.IGNORECASE)
UA_RE = re.compile(r"^User-Agent:\s*(.*)", re.IGNORECASE)


def split_transactions(raw_log: str) -> List[str]:
    """
    将 ModSecurity audit log 文本分割为独立的 transaction 块。

    Args:
        raw_log: 原始日志文本（可能包含多个 transaction）。

    Returns:
        list[str]: transaction 文本列表（含 section 头）。
    """
    transactions: List[str] = []
    current: List[str] = []
    in_transaction = False

    for line in raw_log.splitlines(keepends=True):
        stripped = line.strip()
        match = SECTION_HEADER_RE.match(stripped)
        if match:
            tid, section = match.group(1), match.group(2)
            if section == "A":
                if current:
                    transactions.append("".join(current))
                current = [line]
                in_transaction = True
            else:
                if in_transaction:
                    current.append(line)
                # Z 段后即使没有下一个 A 段也会提交
            if section == "Z" and in_transaction:
                transactions.append("".join(current))
                current = []
                in_transaction = False
        elif in_transaction:
            current.append(line)

    # 末尾未关闭的 transaction
    if current:
        transactions.append("".join(current))

    return transactions


def parse_transaction(text: str) -> Dict[str, Any]:
    """
    解析单条 ModSecurity transaction。

    Args:
        text: 完整的 transaction 文本。

    Returns:
        dict: 解析后的字段，包含 transaction_id, timestamp, client_ip,
              method, uri, host, rule_id, severity, action, blocked 等。
              字段允许缺失。
    """
    result: Dict[str, Any] = {
        "transaction_id": None,
        "timestamp": None,
        "client_ip": None,
        "client_port": None,
        "server_ip": None,
        "server_port": None,
        "method": None,
        "uri": None,
        "http_version": None,
        "host": None,
        "user_agent": None,
        "status_code": None,
        "rule_id": None,
        "message": None,
        "severity": None,
        "matched_data": None,
        "rule_tags": [],
        "action": None,
        "blocked": False,
        "raw_message": text,
    }

    current_section = None
    transaction_id = None
    in_request_headers = False
    in_response_headers = False
    in_h_section = False

    for line in text.splitlines():
        stripped = line.strip()

        # Section 头
        section_match = SECTION_HEADER_RE.match(stripped)
        if section_match:
            transaction_id = section_match.group(1)
            current_section = section_match.group(2)
            result["transaction_id"] = transaction_id
            in_request_headers = (current_section == "B")
            in_response_headers = (current_section == "F")
            in_h_section = (current_section == "H")
            continue

        if current_section == "A" and not result["timestamp"]:
            a_match = A_LINE_RE.match(stripped)
            if a_match:
                result["timestamp"] = a_match.group(1)
                result["client_ip"] = a_match.group(2)
                result["client_port"] = int(a_match.group(3)) if a_match.group(3).isdigit() else None
                result["server_ip"] = a_match.group(4)
                result["server_port"] = int(a_match.group(5)) if a_match.group(5).isdigit() else None

        elif current_section == "B" and in_request_headers:
            # 请求行
            req_match = REQUEST_LINE_RE.match(stripped)
            if req_match and not result["method"]:
                result["method"] = req_match.group(1)
                result["uri"] = req_match.group(2)
                result["http_version"] = req_match.group(3)
                continue

            # Host 头
            host_match = HOST_RE.match(stripped)
            if host_match and not result["host"]:
                result["host"] = host_match.group(1)
                continue

            # User-Agent
            ua_match = UA_RE.match(stripped)
            if ua_match and not result["user_agent"]:
                result["user_agent"] = ua_match.group(1).strip()

        elif current_section == "F" and in_response_headers:
            resp_match = RESPONSE_LINE_RE.match(stripped)
            if resp_match and not result["status_code"]:
                result["status_code"] = int(resp_match.group(1))
                # 403 被视为 blocked
                if result["status_code"] == 403:
                    result["blocked"] = True
                    if not result["action"]:
                        result["action"] = "blocked"

        elif current_section == "H" and in_h_section:
            # 规则 ID
            id_match = ID_RE.search(stripped)
            if id_match and not result["rule_id"]:
                result["rule_id"] = id_match.group(1)

            # 消息
            msg_match = MSG_RE.search(stripped)
            if msg_match and not result["message"]:
                result["message"] = msg_match.group(1)

            # 严重级别
            sev_match = SEVERITY_RE.search(stripped)
            if sev_match and not result["severity"]:
                result["severity"] = sev_match.group(1)

            # 匹配数据
            data_match = DATA_RE.search(stripped)
            if data_match and not result["matched_data"]:
                result["matched_data"] = data_match.group(1)

            # 标签（一行可能多个 [tag "..."]）
            for tag_match in TAG_RE.finditer(stripped):
                result["rule_tags"].append(tag_match.group(1))

            # Action
            act_match = ACTION_RE.match(stripped)
            if act_match:
                action_val = act_match.group(1).strip().lower()
                result["action"] = action_val
                if action_val == "intercepted":
                    result["blocked"] = True

    # 如果 status_code 为 403 但 action 未设置
    if result.get("status_code") == 403 and not result.get("action"):
        result["action"] = "blocked"
        result["blocked"] = True

    return result
