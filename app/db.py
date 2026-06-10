"""
数据库操作模块。

集中管理 SQLite 数据库的初始化和连接。
所有业务代码通过此模块访问数据库，不直接执行原始 SQL（除非必要）。
"""

import sqlite3
import threading
from pathlib import Path
from typing import Optional

from app.utils import now_iso

_local = threading.local()


def get_connection(db_path):
    """
    获取数据库连接（线程本地单例，按路径缓存）。

    Args:
        db_path: SQLite 数据库文件路径。

    Returns:
        sqlite3.Connection: 数据库连接对象。
    """
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(db_path)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn_db_path = db_path
    elif _local.conn_db_path != db_path:
        # 路径变化时重新连接
        _local.conn.close()
        _local.conn = sqlite3.connect(db_path)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn_db_path = db_path
    return _local.conn


def close_connection():
    """关闭当前线程的数据库连接。"""
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


def init_db(db_path):
    """
    初始化数据库，创建所有必要的表结构。

    Args:
        db_path: SQLite 数据库文件路径。

    Returns:
        str: 数据库文件路径。
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(str(db_path))
    cursor = conn.cursor()

    # ========== raw_safeline_logs — SafeLine 原始 Syslog ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_safeline_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            sender_ip TEXT,
            raw_message TEXT NOT NULL,
            parsed_json TEXT,
            parse_status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_safeline_parse_status
        ON raw_safeline_logs(parse_status)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_safeline_received_at
        ON raw_safeline_logs(received_at)
    """)

    # ========== raw_hfish_events — HFish 原始日志 ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_hfish_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_data TEXT NOT NULL,
            event_id TEXT UNIQUE,
            parse_status TEXT NOT NULL DEFAULT 'pending',
            error_message TEXT,
            received_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hfish_parse_status
        ON raw_hfish_events(parse_status)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hfish_received_at
        ON raw_hfish_events(received_at)
    """)

    # ========== normalized_events — 标准化事件 ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            source_event_id TEXT,
            event_time TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            http_method TEXT,
            host TEXT,
            uri TEXT,
            user_agent TEXT,
            attack_type TEXT,
            severity TEXT,
            payload TEXT,
            raw_table TEXT NOT NULL,
            raw_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_src_ip
        ON normalized_events(src_ip)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_event_time
        ON normalized_events(event_time)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_source
        ON normalized_events(source)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_attack_type
        ON normalized_events(attack_type)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_normalized_ip_time
        ON normalized_events(src_ip, event_time)
    """)

    # ========== iocs — 威胁情报指标 ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,
            ioc_value TEXT NOT NULL,
            source TEXT NOT NULL,
            src_ip TEXT,
            normalized_event_id INTEGER,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            context TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(ioc_type, ioc_value)
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_iocs_src_ip
        ON iocs(src_ip)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_iocs_event_id
        ON iocs(normalized_event_id)
    """)

    # ========== attacker_profiles — 攻击源画像 ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacker_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT UNIQUE NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            safeline_count INTEGER NOT NULL DEFAULT 0,
            hfish_count INTEGER NOT NULL DEFAULT 0,
            total_count INTEGER NOT NULL DEFAULT 0,
            attack_types TEXT,
            protocols TEXT,
            is_multi_source INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'low',
            tags TEXT,
            last_event_time TEXT,
            updated_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_profiles_risk
        ON attacker_profiles(risk_score)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_profiles_count
        ON attacker_profiles(total_count)
    """)

    # ========== attack_mappings — ATT&CK 映射（可选） ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            normalized_event_id INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            attack_behavior TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique_name TEXT NOT NULL,
            mapping_type TEXT NOT NULL DEFAULT 'rule',
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_mappings_event_id
        ON attack_mappings(normalized_event_id)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_mappings_src_ip
        ON attack_mappings(src_ip)
    """)

    # ========== raw_waf_logs — 通用 WAF 原始日志（ModSecurity 等） ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_waf_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL DEFAULT 'modsecurity',
            raw_message TEXT NOT NULL,
            raw_hash TEXT UNIQUE,
            event_time TEXT,
            received_at TEXT NOT NULL,
            parsed_json TEXT,
            processed INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_raw_waf_source
        ON raw_waf_logs(source)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_raw_waf_processed
        ON raw_waf_logs(processed)
    """)

    # ========== ioc_extraction_status — IOC 提取状态 ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ioc_extraction_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            normalized_event_id INTEGER UNIQUE NOT NULL,
            extracted_at TEXT NOT NULL,
            ioc_count INTEGER NOT NULL DEFAULT 0
        )
    """)

    # ========== ai_analysis_cache — AI 分析缓存（可选） ==========
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_analysis_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cache_key TEXT UNIQUE NOT NULL,
            input_hash TEXT NOT NULL,
            model TEXT NOT NULL,
            result TEXT NOT NULL,
            usage TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT
        )
    """)

    conn.commit()
    return str(db_path)


# =============================================================================
# SafeLine 原始日志操作
# =============================================================================


def insert_raw_safeline_log(db_path, raw_message, sender_ip, parse_result):
    """
    插入一条 SafeLine 原始日志。

    Args:
        db_path: 数据库文件路径。
        raw_message: Syslog 原始报文。
        sender_ip: 发送方 IP。
        parse_result: Parser 返回的解析结果字典。

    Returns:
        int: 插入记录的自增 ID。
    """
    now = now_iso()

    parse_status = "pending"
    if parse_result.get("success"):
        parse_status = "parsed"
    else:
        parse_status = "failed"

    parsed_json = parse_result.get("parsed_json")
    error_message = parse_result.get("error_message")

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO raw_safeline_logs
            (received_at, sender_ip, raw_message, parsed_json,
             parse_status, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (now, sender_ip, raw_message, parsed_json,
         parse_status, error_message, now),
    )
    conn.commit()
    return cursor.lastrowid


def get_latest_safeline_logs(db_path, limit=20):
    """
    获取最近的 SafeLine 日志。

    Args:
        db_path: 数据库文件路径。
        limit: 返回条数。

    Returns:
        list[dict]: 日志记录列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, received_at, sender_ip, parse_status, error_message,
               substr(raw_message, 1, 200) as raw_message_preview,
               length(raw_message) as raw_length,
               substr(parsed_json, 1, 200) as parsed_json_preview
        FROM raw_safeline_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_basic_stats(db_path):
    """
    获取基本统计信息。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: 统计信息。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 总条数
    cursor.execute("SELECT COUNT(*) as cnt FROM raw_safeline_logs")
    total = cursor.fetchone()["cnt"]

    # 按解析状态统计
    cursor.execute(
        "SELECT parse_status, COUNT(*) as cnt FROM raw_safeline_logs GROUP BY parse_status"
    )
    status_rows = cursor.fetchall()
    status_stats = {row["parse_status"]: row["cnt"] for row in status_rows}

    # 按发送方 IP 统计
    cursor.execute(
        "SELECT sender_ip, COUNT(*) as cnt FROM raw_safeline_logs GROUP BY sender_ip ORDER BY cnt DESC LIMIT 10"
    )
    ip_rows = cursor.fetchall()
    top_senders = [{"ip": row["sender_ip"], "count": row["cnt"]} for row in ip_rows]

    return {
        "total": total,
        "status": status_stats,
        "parsed": status_stats.get("parsed", 0),
        "failed": status_stats.get("failed", 0),
        "pending": status_stats.get("pending", 0),
        "top_senders": top_senders,
    }


# =============================================================================
# HFish 原始日志操作
# =============================================================================


def insert_raw_hfish_event(db_path, raw_data, event_id, parse_result):
    """
    插入一条 HFish 原始日志（使用 INSERT OR IGNORE 去重）。

    Args:
        db_path: 数据库文件路径。
        raw_data: API 返回的完整 JSON 字符串。
        event_id: HFish 事件唯一 ID（用于去重）。
        parse_result: Parser 返回的解析结果字典。

    Returns:
        int|None: 插入记录的自增 ID，去重跳过时返回 None。
    """
    now = now_iso()

    parse_status = "pending"
    if parse_result.get("success"):
        parse_status = "parsed"
    else:
        parse_status = "failed"

    error_message = parse_result.get("error_message")

    conn = get_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO raw_hfish_events
                (raw_data, event_id, parse_status, error_message,
                 received_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (raw_data, event_id, parse_status, error_message, now, now),
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        # event_id 重复，去重跳过
        logger.debug("HFish 事件去重跳过: %s", event_id)
        return None


def get_latest_hfish_events(db_path, limit=20):
    """
    获取最近的 HFish 日志。

    Args:
        db_path: 数据库文件路径。
        limit: 返回条数。

    Returns:
        list[dict]: 日志记录列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, received_at, event_id, parse_status, error_message,
               substr(raw_data, 1, 200) as raw_data_preview,
               length(raw_data) as raw_length
        FROM raw_hfish_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


# =============================================================================
# 通用 WAF 日志操作（ModSecurity 等）
# =============================================================================


def insert_raw_waf_log(db_path, source, raw_message, raw_hash,
                       event_time=None, parsed_json=None):
    """
    插入一条通用 WAF 原始日志。

    Args:
        db_path: 数据库文件路径。
        source: 数据源标识（如 modsecurity）。
        raw_message: 原始日志全文。
        raw_hash: SHA256 哈希（用于去重）。
        event_time: 事件时间。
        parsed_json: 解析后的 JSON 字符串。

    Returns:
        int|None: 插入记录 ID，重复时返回 None。
    """
    from app.utils import now_iso
    from app.db import get_connection

    now = now_iso()
    conn = get_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO raw_waf_logs
                (source, raw_message, raw_hash, event_time,
                 received_at, parsed_json, processed, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (source, raw_message, raw_hash, event_time, now, parsed_json, now),
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        logger.debug("raw_waf_logs 去重跳过 (hash=%s)", raw_hash[:16])
        return None


def get_latest_raw_waf_logs(db_path, limit=20, source=None):
    """获取最近的通用 WAF 日志。"""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    if source:
        cursor.execute(
            "SELECT id, source, event_time, received_at, processed, "
            "substr(raw_message, 1, 200) as raw_preview, "
            "length(raw_message) as raw_length "
            "FROM raw_waf_logs WHERE source = ? ORDER BY id DESC LIMIT ?",
            (source, limit),
        )
    else:
        cursor.execute(
            "SELECT id, source, event_time, received_at, processed, "
            "substr(raw_message, 1, 200) as raw_preview, "
            "length(raw_message) as raw_length "
            "FROM raw_waf_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    return [dict(r) for r in cursor.fetchall()]


# =============================================================================
# 标准化事件操作
# =============================================================================


def insert_normalized_event(db_path, event_dict, raw_table, raw_id):
    """
    插入一条标准化事件。

    Args:
        db_path: 数据库文件路径。
        event_dict: 标准化事件字典（由 normalizer 生成）。
        raw_table: 来源原始表名。
        raw_id: 来源原始表记录 ID。

    Returns:
        int: 插入记录的自增 ID。
    """
    now = now_iso()

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO normalized_events
            (source, source_event_id, event_time, src_ip, src_port,
             dst_ip, dst_port, protocol, http_method, host, uri,
             user_agent, attack_type, severity, payload,
             raw_table, raw_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_dict.get("source", "unknown"),
            event_dict.get("source_event_id", ""),
            event_dict.get("event_time", now),
            event_dict.get("src_ip", ""),
            event_dict.get("src_port"),
            event_dict.get("dst_ip"),
            event_dict.get("dst_port"),
            event_dict.get("protocol"),
            event_dict.get("http_method"),
            event_dict.get("host"),
            event_dict.get("uri"),
            event_dict.get("user_agent"),
            event_dict.get("attack_type"),
            event_dict.get("severity"),
            event_dict.get("payload"),
            raw_table,
            raw_id,
            now,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_latest_normalized_events(db_path, limit=20, source=None):
    """
    获取最近的标准化事件。

    Args:
        db_path: 数据库文件路径。
        limit: 返回条数。
        source: 数据源过滤（"safeline"/"hfish"/None 表示全部）。

    Returns:
        list[dict]: 标准化事件列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    if source:
        cursor.execute(
            """
            SELECT id, source, source_event_id, event_time, src_ip, src_port,
                   protocol, http_method, host, uri, attack_type, severity,
                   raw_table, raw_id, created_at
            FROM normalized_events
            WHERE source = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (source, limit),
        )
    else:
        cursor.execute(
            """
            SELECT id, source, source_event_id, event_time, src_ip, src_port,
                   protocol, http_method, host, uri, attack_type, severity,
                   raw_table, raw_id, created_at
            FROM normalized_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_events_by_ip(db_path, src_ip, limit=100):
    """
    按 IP 查询标准化事件。

    Args:
        db_path: 数据库文件路径。
        src_ip: 源 IP 地址。
        limit: 返回条数。

    Returns:
        list[dict]: 标准化事件列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, source, source_event_id, event_time, src_ip, src_port,
               protocol, http_method, host, uri, attack_type, severity, payload,
               raw_table, raw_id, created_at
        FROM normalized_events
        WHERE src_ip = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (src_ip, limit),
    )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


# =============================================================================
# 增强统计（含 HFish 和标准化事件）
# =============================================================================


def get_extended_stats(db_path):
    """
    获取扩展统计信息（含所有数据源）。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: 包含 safeline / hfish / normalized 的统计信息。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # 白名单：只允许查询预期的表名，防止 SQL 注入
    _ALLOWED_TABLES = {"raw_safeline_logs", "raw_hfish_events", "raw_waf_logs", "normalized_events"}
    _ALLOWED_STATUS_TABLES = {"raw_safeline_logs", "raw_hfish_events", "raw_waf_logs"}

    def _validate_table(table, allowed_set):
        if table not in allowed_set:
            raise ValueError(f"不允许查询的表: {table}")

    def count_table(table):
        _validate_table(table, _ALLOWED_TABLES)
        cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
        return cursor.fetchone()["cnt"]

    def count_by_status(table):
        _validate_table(table, _ALLOWED_STATUS_TABLES)
        cursor.execute(
            f"SELECT parse_status, COUNT(*) as cnt FROM {table} GROUP BY parse_status"
        )
        return {row["parse_status"]: row["cnt"] for row in cursor.fetchall()}

    def count_by_source():
        cursor.execute(
            "SELECT source, COUNT(*) as cnt FROM normalized_events GROUP BY source"
        )
        return {row["source"]: row["cnt"] for row in cursor.fetchall()}

    # raw_waf_logs 的 processed 字段类似 parse_status
    def count_waf_by_processed():
        cursor.execute(
            "SELECT processed, COUNT(*) as cnt FROM raw_waf_logs GROUP BY processed"
        )
        return {("processed" if r["processed"] else "pending"): r["cnt"] for r in cursor.fetchall()}

    def count_waf_total():
        _validate_table("raw_waf_logs", _ALLOWED_TABLES)
        cursor.execute("SELECT COUNT(*) as cnt FROM raw_waf_logs")
        return cursor.fetchone()["cnt"]

    safeline_total = count_table("raw_safeline_logs")
    hfish_total = count_table("raw_hfish_events")
    waf_total = count_waf_total()
    normalized_total = count_table("normalized_events")

    safeline_status = count_by_status("raw_safeline_logs")
    hfish_status = count_by_status("raw_hfish_events")
    waf_status = count_waf_by_processed()

    source_dist = count_by_source()

    return {
        "safeline": {
            "total": safeline_total,
            "parsed": safeline_status.get("parsed", 0),
            "failed": safeline_status.get("failed", 0),
            "pending": safeline_status.get("pending", 0),
        },
        "hfish": {
            "total": hfish_total,
            "parsed": hfish_status.get("parsed", 0),
            "failed": hfish_status.get("failed", 0),
            "pending": hfish_status.get("pending", 0),
        },
        "waf": {
            "total": waf_total,
            "processed": waf_status.get("processed", 0),
            "pending": waf_status.get("pending", 0),
        },
        "normalized": {
            "total": normalized_total,
            "source_distribution": source_dist,
        },
    }


# =============================================================================
# IOC 操作
# =============================================================================


def insert_ioc(db_path, ioc_dict):
    """
    插入一条 IOC（同 type+value 合并计数）。

    Args:
        db_path: 数据库文件路径。
        ioc_dict: IOC 字典，包含 ioc_type, ioc_value, source, src_ip,
                  normalized_event_id, first_seen, last_seen, context。

    Returns:
        int: 记录 ID（新插入或已有记录）。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO iocs
            (ioc_type, ioc_value, source, src_ip, normalized_event_id,
             first_seen, last_seen, count, context, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
            count = count + 1,
            last_seen = excluded.last_seen
        """,
        (
            ioc_dict["ioc_type"],
            ioc_dict["ioc_value"],
            ioc_dict.get("source", ""),
            ioc_dict.get("src_ip"),
            ioc_dict.get("normalized_event_id"),
            ioc_dict.get("first_seen"),
            ioc_dict.get("last_seen"),
            ioc_dict.get("context"),
            ioc_dict.get("first_seen"),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_iocs(db_path, ioc_type=None, limit=100):
    """
    查询 IOC 列表。

    Args:
        db_path: 数据库文件路径。
        ioc_type: IOC 类型过滤（None 表示全部）。
        limit: 返回条数。

    Returns:
        list[dict]: IOC 列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    if ioc_type:
        cursor.execute(
            "SELECT * FROM iocs WHERE ioc_type = ? ORDER BY count DESC, last_seen DESC LIMIT ?",
            (ioc_type, limit),
        )
    else:
        cursor.execute(
            "SELECT * FROM iocs ORDER BY count DESC, last_seen DESC LIMIT ?",
            (limit,),
        )

    return [dict(r) for r in cursor.fetchall()]


# =============================================================================
# ATT&CK 映射操作
# =============================================================================


def insert_attack_mapping(db_path, mapping_dict):
    """
    插入一条 ATT&CK 映射。

    Args:
        db_path: 数据库文件路径。
        mapping_dict: 映射字典，包含 normalized_event_id, src_ip,
                     attack_behavior, technique_id, technique_name,
                     mapping_type, created_at。

    Returns:
        int: 记录 ID。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO attack_mappings
            (normalized_event_id, src_ip, attack_behavior,
             technique_id, technique_name, mapping_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            mapping_dict["normalized_event_id"],
            mapping_dict["src_ip"],
            mapping_dict["attack_behavior"],
            mapping_dict["technique_id"],
            mapping_dict["technique_name"],
            mapping_dict.get("mapping_type", "rule"),
            mapping_dict.get("created_at"),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_attack_mappings(db_path, limit=100):
    """
    查询 ATT&CK 映射列表。

    Args:
        db_path: 数据库文件路径。
        limit: 返回条数。

    Returns:
        list[dict]: 映射列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM attack_mappings ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in cursor.fetchall()]


# =============================================================================
# 攻击源画像操作
# =============================================================================


def get_profile_by_ip(db_path, src_ip):
    """
    查询单个攻击源画像。

    Args:
        db_path: 数据库文件路径。
        src_ip: 攻击源 IP。

    Returns:
        dict|None: 画像字典。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM attacker_profiles WHERE src_ip = ?", (src_ip,)
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def get_top_ips(db_path, sort_by="total_count", limit=10):
    """
    获取 Top 攻击源 IP。

    Args:
        db_path: 数据库文件路径。
        sort_by: 排序字段（total_count / risk_score）。
        limit: 返回条数。

    Returns:
        list[dict]: 画像列表。
    """
    allowed_sorts = {"total_count", "risk_score"}
    if sort_by not in allowed_sorts:
        sort_by = "total_count"

    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT * FROM attacker_profiles ORDER BY {sort_by} DESC LIMIT ?",
        (limit,),
    )
    return [dict(r) for r in cursor.fetchall()]


def get_profile_stats(db_path):
    """
    获取画像统计信息。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: 画像统计。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as cnt FROM attacker_profiles")
    total_profiles = cursor.fetchone()["cnt"]

    cursor.execute(
        "SELECT risk_level, COUNT(*) as cnt FROM attacker_profiles GROUP BY risk_level"
    )
    level_dist = {r["risk_level"]: r["cnt"] for r in cursor.fetchall()}

    cursor.execute(
        "SELECT COUNT(*) as cnt FROM attacker_profiles WHERE is_multi_source = 1"
    )
    multi_source = cursor.fetchone()["cnt"]

    return {
        "total_profiles": total_profiles,
        "level_distribution": level_dist,
        "multi_source_count": multi_source,
    }


# =============================================================================
# IOC 提取状态
# =============================================================================


def mark_ioc_extracted(db_path, normalized_event_id, ioc_count):
    """
    标记一条标准化事件的 IOC 已完成提取。

    Args:
        db_path: 数据库文件路径。
        normalized_event_id: 标准化事件 ID。
        ioc_count: 提取出的 IOC 数量。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    now = now_iso()
    cursor.execute(
        """
        INSERT INTO ioc_extraction_status
            (normalized_event_id, extracted_at, ioc_count)
        VALUES (?, ?, ?)
        ON CONFLICT(normalized_event_id) DO UPDATE SET
            extracted_at = excluded.extracted_at,
            ioc_count = excluded.ioc_count
        """,
        (normalized_event_id, now, ioc_count),
    )
    conn.commit()


def get_unprocessed_event_ids(db_path):
    """
    获取尚未提取 IOC 的 normalizd_event_id 列表。

    Args:
        db_path: 数据库文件路径。

    Returns:
        list[int]: 未处理的标准化事件 ID 列表。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT n.id FROM normalized_events n
        WHERE n.id NOT IN (
            SELECT normalized_event_id FROM ioc_extraction_status
        )
        ORDER BY n.id ASC
    """)
    return [r["id"] for r in cursor.fetchall()]


def count_ioc_extraction_status(db_path):
    """
    统计 IOC 提取状态。

    Args:
        db_path: 数据库文件路径。

    Returns:
        dict: 已处理事件数和 IOC 总数。
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) as events, COALESCE(SUM(ioc_count), 0) as iocs
        FROM ioc_extraction_status
    """)
    row = cursor.fetchone()
    return {"events": row["events"], "iocs": row["iocs"]}
