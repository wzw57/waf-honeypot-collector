"""
标准化执行器。

将 main.py 中 cmd_normalize 的业务逻辑抽取至此，
main.py 只负责读取参数、调用函数、打印结果。
"""

import json

from app.db import get_connection, insert_normalized_event
from app.logger import get_logger
from parsers.hfish_parser import extract_fields as extract_hfish_fields
from parsers.hfish_parser import extract_hfish_event
from .normalizer import normalize_from_hfish, normalize_from_safeline

logger = get_logger("normalize_runner")


def run_normalize(db_path, source_filter=None):
    """
    执行标准化流程，处理所有待处理的原始日志。

    Args:
        db_path: 数据库文件路径。
        source_filter: 数据源过滤，"safeline"/"hfish"/None 表示全部。

    Returns:
        dict: {"normalized": int, "skipped": int}
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()
    normalized_count = 0
    skipped_count = 0

    # 标准化 SafeLine
    if source_filter is None or source_filter == "safeline":
        cursor.execute(
            "SELECT id, parsed_json FROM raw_safeline_logs "
            "WHERE parse_status IN ('parsed', 'pending') "
            "AND id NOT IN ("
            "  SELECT raw_id FROM normalized_events"
            "  WHERE raw_table = 'raw_safeline_logs'"
            ")"
        )
        rows = cursor.fetchall()
        for row in rows:
            raw_id = row["id"]
            parsed_json = row["parsed_json"]
            if parsed_json:
                try:
                    parsed_dict = json.loads(parsed_json)
                    event = normalize_from_safeline(parsed_dict)
                    if event:
                        insert_normalized_event(
                            db_path, event, "raw_safeline_logs", raw_id
                        )
                        normalized_count += 1
                    else:
                        skipped_count += 1
                except (json.JSONDecodeError, Exception) as e:
                    logger.debug("SafeLine 标准化跳过 #%d: %s", raw_id, e)
                    skipped_count += 1
            else:
                skipped_count += 1

    # 标准化 HFish
    if source_filter is None or source_filter == "hfish":
        cursor.execute(
            "SELECT id, raw_data FROM raw_hfish_events "
            "WHERE parse_status IN ('parsed', 'pending') "
            "AND id NOT IN ("
            "  SELECT raw_id FROM normalized_events"
            "  WHERE raw_table = 'raw_hfish_events'"
            ")"
        )
        rows = cursor.fetchall()
        for row in rows:
            raw_id = row["id"]
            raw_data = row["raw_data"]
            parse_result = extract_hfish_event(raw_data)
            if parse_result["success"]:
                fields = extract_hfish_fields(parse_result["parsed_dict"])
                event = normalize_from_hfish(fields)
                if event and event.get("src_ip"):
                    insert_normalized_event(
                        db_path, event, "raw_hfish_events", raw_id
                    )
                    normalized_count += 1
                else:
                    skipped_count += 1
            else:
                skipped_count += 1

    logger.info("标准化完成: 新增 %d 条, 跳过 %d 条", normalized_count, skipped_count)
    return {"normalized": normalized_count, "skipped": skipped_count}
