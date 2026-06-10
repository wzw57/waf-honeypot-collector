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
    获取数据库连接（线程本地单例）。

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
