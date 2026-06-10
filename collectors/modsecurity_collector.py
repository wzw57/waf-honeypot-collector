"""
ModSecurity Audit Log Collector。

读取 ModSecurity 审计日志文件，增量解析 transaction，
支持 state 文件持久化（inode/offset/mtime）实现断点续采。
"""

import hashlib
import json
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from app.logger import get_logger

logger = get_logger("modsecurity_collector")


class ModSecurityFileState:
    """
    ModSecurity 审计日志文件状态管理。

    记录 inode / offset / mtime，支持 logrotate 检测和断点续采。
    """

    def __init__(self, state_path: str):
        self.state_path = state_path
        self._state: Dict[str, Any] = {}

    def load(self) -> Dict[str, Any]:
        """从文件加载 state。"""
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("state 文件损坏，重置: %s", e)
                self._state = {}
        else:
            self._state = {}
        return dict(self._state)

    def save(self, path: str, inode: int, offset: int, mtime: float):
        """保存 state 到文件。"""
        self._state = {
            "path": path,
            "inode": inode,
            "offset": offset,
            "mtime": mtime,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        Path(self.state_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, ensure_ascii=False)

    def get(self) -> Dict[str, Any]:
        return dict(self._state)


def get_file_info(path: str) -> Optional[Dict[str, Any]]:
    """获取文件的 inode / size / mtime。"""
    try:
        stat = os.stat(path)
        return {
            "inode": stat.st_ino,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
        }
    except OSError as e:
        logger.error("无法访问文件 %s: %s", path, e)
        return None


class ModSecurityCollector:
    """
    ModSecurity 审计日志采集器。

    支持增量读取、state 持久化、logrotate 检测、SHA256 去重。
    on_transaction 回调应返回 bool：True 表示真实插入，False 表示跳过/重复。
    """

    def __init__(self, audit_log_path: str, state_file: str,
                 read_from_end: bool = True,
                 on_transaction: Optional[Callable] = None):
        """
        Args:
            audit_log_path: ModSecurity audit log 文件路径。
            state_file: state 文件路径。
            read_from_end: 仅在 state 不存在或无效时，首次读取是否从文件末尾开始。
            on_transaction: 每条 transaction 解析后的回调。
                           回调签名: callback(parsed) -> bool
        """
        self.audit_log_path = audit_log_path
        self.state_file = state_file
        self.read_from_end = read_from_end
        self.on_transaction = on_transaction
        self.state_mgr = ModSecurityFileState(state_file)

    def _resolve_start_offset(self, state: dict,
                               finfo: dict) -> int:
        """
        确定本次读取的起始 offset。

        规则：
        1. 如果 state 存在且有效（inode 匹配、offset ≤ 文件大小、未 logrotate），
           从 prev_offset 继续读取；
        2. 如果 logrotate，按 read_from_end 策略处理；
        3. 如果 state 不存在或无效（首次运行），按 read_from_end 策略处理。
        """
        prev_inode = state.get("inode")
        prev_offset = state.get("offset", 0)

        # 检测 logrotate
        if prev_inode is not None and prev_inode != finfo["inode"]:
            logger.info("检测到 logrotate: inode %s → %s", prev_inode, finfo["inode"])
            return finfo["size"] if self.read_from_end else 0
        if prev_offset and finfo["size"] < prev_offset:
            logger.info("文件变小，疑似 logrotate: offset %s → size %s",
                        prev_offset, finfo["size"])
            return finfo["size"] if self.read_from_end else 0

        # state 有效且无 logrotate → 从 prev_offset 继续
        if state and prev_offset is not None and prev_offset >= 0:
            logger.debug("从 state offset 继续读取: %d", prev_offset)
            return prev_offset

        # state 不存在或无效 → 按 read_from_end 策略
        if self.read_from_end:
            logger.info("首次运行（无有效 state），从文件末尾开始")
            return finfo["size"]
        else:
            logger.info("首次运行（无有效 state），从文件开头开始")
            return 0

    def collect_once(self) -> Dict[str, Any]:
        """
        单次增量采集。

        Returns:
            dict: {"parsed": int, "inserted": int, "skipped": int, "error": str|None}
        """
        result = {"parsed": 0, "inserted": 0, "skipped": 0, "error": None}

        finfo = get_file_info(self.audit_log_path)
        if finfo is None:
            result["error"] = f"无法访问日志文件: {self.audit_log_path}"
            return result

        state = self.state_mgr.load()
        offset = self._resolve_start_offset(state, finfo)

        # 如果 offset >= 文件大小，没有新数据
        if offset >= finfo["size"]:
            logger.debug("无新日志 (offset=%d size=%d)", offset, finfo["size"])
            return result

        # 读取增量内容
        try:
            with open(self.audit_log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                new_content = f.read()
                new_offset = f.tell()
        except OSError as e:
            result["error"] = str(e)
            logger.error("读取文件失败: %s", e)
            return result

        if not new_content:
            return result

        # 解析 transaction
        from parsers.modsecurity_parser import split_transactions, parse_transaction

        transactions = split_transactions(new_content)
        result["parsed"] = len(transactions)

        for trans_text in transactions:
            parsed = parse_transaction(trans_text)
            raw_hash = hashlib.sha256(trans_text.encode("utf-8")).hexdigest()
            parsed["_raw_hash"] = raw_hash
            parsed["_raw_text"] = trans_text

            if self.on_transaction:
                try:
                    inserted = self.on_transaction(parsed)
                    if inserted:
                        result["inserted"] += 1
                    else:
                        result["skipped"] += 1
                except Exception as e:
                    logger.error("transaction 回调失败: %s", e)
                    result["skipped"] += 1

        # 保存 state
        self.state_mgr.save(
            path=self.audit_log_path,
            inode=finfo["inode"],
            offset=new_offset,
            mtime=finfo["mtime"],
        )

        logger.info("ModSecurity 采集完成: parsed=%d inserted=%d skipped=%d",
                    result["parsed"], result["inserted"], result["skipped"])
        return result

    def collect_loop(self, interval: int = 30):
        """循环采集。"""
        running = True

        def handler(signum, frame):
            nonlocal running
            if running:
                logger.info("收到信号，停止 ModSecurity 循环采集")
                running = False

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        logger.info("ModSecurity 循环采集已启动，间隔 %d 秒", interval)
        print(f"[INFO] ModSecurity 循环采集已启动，间隔 {interval} 秒")
        print("[INFO] 按 Ctrl+C 停止")

        while running:
            try:
                self.collect_once()
            except Exception as e:
                logger.error("ModSecurity 采集异常: %s", e)

            for _ in range(interval):
                if not running:
                    break
                time.sleep(1)

        logger.info("ModSecurity 循环采集已停止")
        print("[INFO] ModSecurity 循环采集已停止")
