"""
pytest 共享 fixture。
"""

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def db_path():
    """提供临时数据库路径。"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def sample_raw_safeline_logs():
    """加载 SafeLine 样本日志。"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    file_path = fixtures_dir / "safeline_samples.json"
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)
