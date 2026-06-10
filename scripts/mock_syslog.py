#!/usr/bin/env python3
"""
SafeLine Syslog 模拟发送工具。

向指定的 UDP 地址和端口发送模拟的 SafeLine Syslog 报文，
用于测试 recv-safeline 接收功能。

用法:
    python scripts/mock_syslog.py
    python scripts/mock_syslog.py --host 127.0.0.1 --port 1514 --count 10
    python scripts/mock_syslog.py --host 127.0.0.1 --port 1514 --interval 0.5
"""

import argparse
import json
import random
import socket
import sys
import time
from datetime import datetime

# 模拟 SafeLine Syslog 样本
SAMPLE_EVENTS = [
    {
        "event_time": None,  # 动态填充
        "src_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/admin/login.php",
        "query_string": "user=admin&pass=123456",
        "user_agent": "Mozilla/5.0 (compatible; sqlmap/1.7)",
        "attack_type": "SQL Injection",
        "severity": "high",
        "rule_id": "1001",
        "payload": "1' OR '1'='1",
        "status_code": 200,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.2",
        "src_port": 43210,
        "dst_ip": "192.168.1.100",
        "dst_port": 443,
        "host": "www.target.com",
        "method": "POST",
        "uri": "/search",
        "query_string": "",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "attack_type": "XSS",
        "severity": "high",
        "rule_id": "1002",
        "payload": "<script>alert(1)</script>",
        "status_code": 403,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.3",
        "src_port": 39871,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/.git/config",
        "query_string": "",
        "user_agent": "curl/7.88.1",
        "attack_type": "Sensitive File Probe",
        "severity": "medium",
        "rule_id": "2001",
        "payload": "/.git/config",
        "status_code": 404,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.4",
        "src_port": 51234,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/web-inf/web.xml",
        "query_string": "",
        "user_agent": "nikto/2.5.0",
        "attack_type": "Path Traversal",
        "severity": "high",
        "rule_id": "3001",
        "payload": "/web-inf/web.xml",
        "status_code": 200,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.5",
        "src_port": 39812,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "POST",
        "uri": "/api/login",
        "query_string": "",
        "user_agent": "python-requests/2.31.0",
        "attack_type": "Brute Force",
        "severity": "medium",
        "rule_id": "4001",
        "payload": '{"username":"admin","password":"admin123"}',
        "status_code": 401,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.1",
        "src_port": 54322,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/wp-admin/admin-ajax.php",
        "query_string": "action=malicious",
        "user_agent": "Mozilla/5.0 (compatible; sqlmap/1.7)",
        "attack_type": "SQL Injection",
        "severity": "critical",
        "rule_id": "1003",
        "payload": "1' UNION SELECT * FROM users--",
        "status_code": 200,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.6",
        "src_port": 38721,
        "dst_ip": "192.168.1.100",
        "dst_port": 443,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/.env",
        "query_string": "",
        "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "attack_type": "Sensitive File Probe",
        "severity": "high",
        "rule_id": "2002",
        "payload": "/.env",
        "status_code": 200,
        "event_id": None,
    },
    {
        "event_time": None,
        "src_ip": "10.0.0.7",
        "src_port": 45231,
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "host": "www.target.com",
        "method": "GET",
        "uri": "/index.php",
        "query_string": "id=1 UNION SELECT 1,2,3",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) sqlmap/1.8",
        "attack_type": "SQL Injection",
        "severity": "critical",
        "rule_id": "1004",
        "payload": "1 UNION SELECT 1,2,3",
        "status_code": 200,
        "event_id": None,
    },
]


def build_syslog_message(event: dict) -> str:
    """
    构建模拟的 SafeLine Syslog 报文。

    格式: <PRI>Timestamp hostname SafeLine[PID]: {"json": "payload"}

    Args:
        event: 事件字典。

    Returns:
        str: Syslog 格式的报文。
    """
    import uuid

    now = time.strftime("%b %d %H:%M:%S", time.localtime())
    event_id = str(uuid.uuid4())[:8]

    # 填充动态字段
    event["event_time"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
    event["event_id"] = f"SL-{event_id}"

    json_payload = json.dumps(event, ensure_ascii=False)

    # Syslog RFC 3164 格式
    syslog_msg = (
        f"<134>{now} safeline-server SafeLine[{random.randint(1000, 9999)}]: "
        f"{json_payload}"
    )
    return syslog_msg


def build_invalid_syslog() -> str:
    """生成一条不含 JSON 的无效 Syslog 报文，用于测试解析失败容错。"""
    now = time.strftime("%b %d %H:%M:%S", time.localtime())
    messages = [
        f"<134>{now} safeline-server SafeLine[{random.randint(1000, 9999)}]: "
        f"this is a plain text log message without JSON content",
        f"<134>{now} safeline-server SafeLine[{random.randint(1000, 9999)}]: "
        f"connection closed by remote host",
        f"<134>{now} safeline-server SafeLine[{random.randint(1000, 9999)}]: "
        f"error processing request: invalid method",
    ]
    return random.choice(messages)


def send_mock_log(host: str, port: int, count: int, interval: float,
                  invalid: bool = False):
    """
    发送模拟 Syslog 报文。

    Args:
        host: 目标地址。
        port: 目标端口。
        count: 发送条数。
        interval: 发送间隔（秒）。
        invalid: 是否发送无 JSON 的无效报文（用于测试容错）。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    mode = "无效(无JSON)" if invalid else "正常"
    print(f"[INFO] 开始发送 {count} 条{mode}模拟 SafeLine Syslog")
    print(f"[INFO] 目标: {host}:{port}/udp")
    print(f"[INFO] 间隔: {interval} 秒")
    print("-" * 50)

    for i in range(count):
        if invalid:
            message = build_invalid_syslog()
            label = "(no-json)"
        else:
            event = random.choice(SAMPLE_EVENTS)
            message = build_syslog_message(event)
            label = f"{event['attack_type']:>25s} | {event['src_ip']:>15s} | {event['uri']}"

        try:
            sock.sendto(message.encode("utf-8"), (host, port))
            print(f"[SENT] #{i + 1}/{count} | {label}")
        except Exception as e:
            print(f"[ERROR] #{i + 1}/{count} 发送失败: {e}")

        if interval > 0 and i < count - 1:
            time.sleep(interval)

    sock.close()
    print("-" * 50)
    print(f"[INFO] 已发送 {count} 条日志")


def main():
    parser = argparse.ArgumentParser(
        description="模拟 SafeLine Syslog 发送工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="目标地址（默认: 127.0.0.1）"
    )
    parser.add_argument(
        "--port", type=int, default=1514,
        help="目标端口（默认: 1514）"
    )
    parser.add_argument(
        "--count", type=int, default=5,
        help="发送条数（默认: 5）"
    )
    parser.add_argument(
        "--interval", type=float, default=0.2,
        help="发送间隔秒数（默认: 0.2）"
    )
    parser.add_argument(
        "--invalid", action="store_true",
        help="发送无 JSON 的无效 Syslog 报文（测试解析容错）"
    )

    args = parser.parse_args()
    send_mock_log(args.host, args.port, args.count, args.interval, invalid=args.invalid)


if __name__ == "__main__":
    main()
