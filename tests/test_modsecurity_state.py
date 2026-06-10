"""
ModSecurity File State 单元测试。
"""

import hashlib
import json
import os
import os
import tempfile

import pytest

from collectors.modsecurity_collector import ModSecurityFileState, get_file_info


class TestModSecurityFileState:
    """测试 state 文件管理。"""

    def test_save_and_load(self, tmp_path):
        """保存后加载应返回相同数据。"""
        state_path = str(tmp_path / "state.json")
        state = ModSecurityFileState(state_path)

        state.save("/tmp/test.log", inode=12345, offset=98765, mtime=1000.0)
        loaded = state.load()
        assert loaded["path"] == "/tmp/test.log"
        assert loaded["inode"] == 12345
        assert loaded["offset"] == 98765

    def test_load_nonexistent(self, tmp_path):
        """不存在的 state 文件应返回空字典。"""
        state_path = str(tmp_path / "nonexistent.json")
        state = ModSecurityFileState(state_path)
        loaded = state.load()
        assert loaded == {}

    def test_load_corrupted(self, tmp_path):
        """损坏的 state 文件应返回空字典。"""
        state_path = str(tmp_path / "corrupted.json")
        with open(state_path, "w") as f:
            f.write("not valid json")
        state = ModSecurityFileState(state_path)
        loaded = state.load()
        assert loaded == {}

    def test_get_after_save(self, tmp_path):
        """保存后 get 应返回最新数据。"""
        state_path = str(tmp_path / "state.json")
        state = ModSecurityFileState(state_path)
        state.save("/tmp/t.log", inode=1, offset=100, mtime=200.0)
        data = state.get()
        assert data["inode"] == 1
        assert data["offset"] == 100


class TestGetFileInfo:
    """测试文件信息获取。"""

    def test_existing_file(self, tmp_path):
        """存在的文件应返回正确信息。"""
        f = tmp_path / "test.log"
        f.write_text("hello\nworld\n")
        info = get_file_info(str(f))
        assert info is not None
        assert info["size"] == 12
        assert info["inode"] > 0

    def test_nonexistent_file(self):
        """不存在的文件应返回 None。"""
        info = get_file_info("/tmp/nonexistent_file_xxx.log")
        assert info is None


class TestModSecurityCollectorBehavior:
    """测试 ModSecurityCollector 的 offset 决策逻辑。"""

    def test_existing_state_uses_prev_offset(self, tmp_path):
        """已有有效 state 时，应从 prev_offset 继续读取。"""
        from collectors.modsecurity_collector import ModSecurityCollector

        log_file = tmp_path / "audit.log"
        log_file.write_text("line1\nline2\nline3\n")

        state_file = str(tmp_path / "state.json")
        with open(state_file, "w") as f:
            json.dump({"path": str(log_file), "inode": os.stat(str(log_file)).st_ino,
                       "offset": 12, "mtime": os.stat(str(log_file)).st_mtime}, f)

        collector = ModSecurityCollector(
            audit_log_path=str(log_file),
            state_file=state_file,
            read_from_end=False,
        )
        finfo = {"inode": os.stat(str(log_file)).st_ino, "size": 18, "mtime": 0}
        state = {"inode": finfo["inode"], "offset": 12}
        offset = collector._resolve_start_offset(state, finfo)
        assert offset == 12, f"应为 12，实际 {offset}"

    def test_no_state_read_from_end(self, tmp_path):
        """无 state 且 read_from_end=True 时，应从文件末尾开始。"""
        from collectors.modsecurity_collector import ModSecurityCollector

        log_file = tmp_path / "audit.log"
        log_file.write_text("data\n" * 10)

        collector = ModSecurityCollector(
            audit_log_path=str(log_file),
            state_file=str(tmp_path / "nonexistent.json"),
            read_from_end=True,
        )
        state = {}
        finfo = {"inode": 999, "size": 50, "mtime": 0}
        offset = collector._resolve_start_offset(state, finfo)
        assert offset == 50, f"应为 50，实际 {offset}"

    def test_no_state_read_from_start(self, tmp_path):
        """无 state 且 read_from_end=False 时，应从文件开头开始。"""
        from collectors.modsecurity_collector import ModSecurityCollector

        log_file = tmp_path / "audit.log"
        log_file.write_text("data\n" * 10)

        collector = ModSecurityCollector(
            audit_log_path=str(log_file),
            state_file=str(tmp_path / "nonexistent.json"),
            read_from_end=False,
        )
        state = {}
        finfo = {"inode": 999, "size": 50, "mtime": 0}
        offset = collector._resolve_start_offset(state, finfo)
        assert offset == 0, f"应为 0，实际 {offset}"

    def test_logrotate_read_from_end(self, tmp_path):
        """logrotate 后按 read_from_end 策略读取。"""
        from collectors.modsecurity_collector import ModSecurityCollector

        collector = ModSecurityCollector(
            audit_log_path="/nonexistent",
            state_file=str(tmp_path / "state.json"),
            read_from_end=True,
        )
        state = {"inode": 111, "offset": 999999}
        finfo = {"inode": 222, "size": 100, "mtime": 0}
        offset = collector._resolve_start_offset(state, finfo)
        assert offset == 100, f"logrotate 后应到文件末尾，实际 {offset}"

    def test_on_transaction_skipped_counts(self, tmp_path):
        """on_transaction 返回 False 时应增加 skipped 而非 inserted。"""
        from collectors.modsecurity_collector import ModSecurityCollector

        log_file = tmp_path / "audit.log"
        # 写入一个有效 transaction 和 一个无效的（解析失败但不会崩溃）
        log_file.write_text("--a1-A--\n--a1-Z--\n")

        call_count = [0]

        def on_tx(parsed) -> bool:
            call_count[0] += 1
            return False  # 模拟重复

        collector = ModSecurityCollector(
            audit_log_path=str(log_file),
            state_file=str(tmp_path / "state.json"),
            read_from_end=False,
            on_transaction=on_tx,
        )
        result = collector.collect_once()
        assert result["parsed"] >= 1
        assert result["inserted"] == 0
        assert result["skipped"] >= 1
        assert call_count[0] >= 1


class TestNormalizeSourceModsecurity:
    """测试 argparse 接受 normalize --source modsecurity。"""

    def test_argparse_accepts_modsecurity_source(self):
        """normalize --source modsecurity 应通过参数验证。"""
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        p = sub.add_parser("normalize")
        p.add_argument("--source", type=str, default=None,
                       choices=["safeline", "hfish", "modsecurity"])
        args = parser.parse_args(["normalize", "--source", "modsecurity"])
        assert args.source == "modsecurity"
