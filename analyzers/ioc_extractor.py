"""
IOC 提取引擎。

从标准化事件（normalized_events）中自动化提取威胁情报指标，
存入 iocs 表。
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.logger import get_logger

logger = get_logger("ioc_extractor")

# 敏感路径正则
SUSPICIOUS_PATH_RE = re.compile(
    r"(\.git|\.env|\.svn|\.DS_Store|/web-inf/|/WEB-INF/|"
    r"/admin/|/backup/|/wp-admin/|/wp-content/|"
    r"/phpmyadmin/|/manager/html|/actuator/|/swagger)",
    re.IGNORECASE,
)

# 静态资源后缀（排除）
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico",
    ".css", ".js", ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz",
}

# IPv4 正则
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# User-Agent 工具指纹
UA_TOOL_PATTERNS = {
    "sqlmap": "sqlmap",
    "nmap": "Nmap",
    "gobuster": "GoBuster",
    "dirbuster": "DirBuster",
    "nikto": "Nikto",
    "curl": "curl",
    "python-requests": "Python Requests",
    "python3": "Python HTTP",
    "masscan": "Masscan",
    "zap": "ZAP",
    "nessus": "Nessus",
    "acunetix": "Acunetix",
    "openvas": "OpenVAS",
    "burp": "Burp Suite",
    "postman": "Postman",
    "wpscan": "WPScan",
}

# 敏感文件名正则（从 uri 提取文件名后匹配）
SENSITIVE_FILENAMES_RE = re.compile(
    r"(config\.php|config\.bak|\.env|\.git|wp-config|"
    r"web\.config|\.htaccess|\.bash_history|id_rsa|"
    r"dump\.sql|backup\.sql|admin\.php)",
    re.IGNORECASE,
)


def extract_iocs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    从单条标准化事件中提取所有 IOC。

    Args:
        event: normalized_events 表的一行（字典格式）。

    Returns:
        list[dict]: IOC 字典列表，每个字典包含：
            ioc_type, ioc_value, source, src_ip, normalized_event_id,
            first_seen, last_seen, context
    """
    iocs: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    event_id = event.get("id")
    src_ip = event.get("src_ip") or ""
    source = event.get("source") or "unknown"

    def add_ioc(ioc_type: str, ioc_value: str, ctx: Optional[dict] = None):
        if not ioc_value or not isinstance(ioc_value, str):
            return
        iocs.append({
            "ioc_type": ioc_type,
            "ioc_value": ioc_value.strip(),
            "source": source,
            "src_ip": src_ip,
            "normalized_event_id": event_id,
            "first_seen": now,
            "last_seen": now,
            "context": json.dumps(ctx, ensure_ascii=False) if ctx else None,
        })

    # 1. IP
    if IPV4_RE.match(src_ip):
        add_ioc("ip", src_ip)

    # 2. Host
    host = event.get("host")
    if host and isinstance(host, str) and host.strip():
        add_ioc("host", host.strip())

    # 3. URI（排除静态资源）
    uri = event.get("uri")
    if uri and isinstance(uri, str):
        uri_stripped = uri.strip()
        if uri_stripped and uri_stripped != "/":
            ext = _get_extension(uri_stripped)
            if ext not in STATIC_EXTENSIONS:
                add_ioc("uri", uri_stripped)

    # 4. URL（host + uri）
    if host and uri:
        full_url = f"http://{host}{uri}"
        add_ioc("url", full_url)

    # 5. User-Agent
    ua = event.get("user_agent")
    if ua and isinstance(ua, str) and ua.strip():
        ua_stripped = ua.strip()
        add_ioc("user_agent", ua_stripped)
        # 工具指纹识别
        tool = _detect_ua_tool(ua_stripped)
        if tool:
            add_ioc("user_agent", f"[tool] {tool}", {"matched_tool": tool})

    # 6. Payload
    payload = event.get("payload")
    if payload and isinstance(payload, str) and payload.strip():
        add_ioc("payload", payload.strip()[:4096])

    # 7. Filename（从 uri 提取）
    if uri and isinstance(uri, str):
        filename = _extract_filename(uri)
        if filename and SENSITIVE_FILENAMES_RE.search(filename):
            add_ioc("filename", filename)

    # 8. Suspicious path
    if uri and isinstance(uri, str):
        if SUSPICIOUS_PATH_RE.search(uri):
            add_ioc("suspicious_path", uri.strip())

    # 9. HFish username / password（从 payload 中提取——实际数据在 raw 层）
    #  此处从事件 payload 中尝试提取，多数情况下 HFish parser
    #  已将 username/password 丢弃（只在 raw 层保留）。
    #  后续可在 profiler/correlator 中从 raw 表补充。
    if source == "hfish":
        payload_text = event.get("payload") or ""
        if "username" in payload_text.lower() or "user" in payload_text.lower():
            # 简单标记，精确提取留给后期增强
            pass

    return iocs


def extract_all_pending(db_path) -> int:
    """
    遍历所有尚未提取 IOC 的标准化事件，提取并入库。

    Args:
        db_path: 数据库文件路径。

    Returns:
        int: 新增 IOC 数量。
    """
    from app.db import get_connection, insert_ioc

    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 查找尚未提取 IOC 的事件
    cursor.execute("""
        SELECT n.* FROM normalized_events n
        WHERE n.id NOT IN (
            SELECT DISTINCT normalized_event_id FROM iocs
            WHERE normalized_event_id IS NOT NULL
        )
        ORDER BY n.id ASC
    """)
    rows = cursor.fetchall()

    total_iocs = 0
    for row in rows:
        event = dict(row)
        iocs = extract_iocs(event)
        for ioc in iocs:
            insert_ioc(db_path, ioc)
            total_iocs += 1

    logger.info("IOC 提取完成: %d 条事件 -> %d 个 IOC", len(rows), total_iocs)
    return total_iocs


def _get_extension(path: str) -> str:
    """获取文件扩展名（小写）。"""
    if "." not in path:
        return ""
    ext = path.rsplit(".", 1)[-1].lower()
    return f".{ext}"


def _extract_filename(uri: str) -> Optional[str]:
    """从 URI 中提取文件名。"""
    # 去掉查询参数
    path = uri.split("?")[0].split("#")[0]
    # 取最后一段
    filename = path.rstrip("/").rsplit("/", 1)[-1]
    if not filename or "." not in filename:
        return None
    return filename


def _detect_ua_tool(ua: str) -> Optional[str]:
    """识别 User-Agent 中的工具指纹。"""
    ua_lower = ua.lower()
    for pattern, tool_name in UA_TOOL_PATTERNS.items():
        if pattern in ua_lower:
            return tool_name
    return None
