"""
ModSecurity File State 单元测试。
"""

import json
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
