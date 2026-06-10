"""
HFish Parser 单元测试。
"""

import json
from pathlib import Path

import pytest

from parsers.hfish_parser import (
    compute_event_id,
    extract_hfish_event,
    extract_fields,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_samples():
    with open(FIXTURES_DIR / "hfish_samples.json", "r", encoding="utf-8") as f:
        return json.load(f)


class TestExtractHfishEvent:
    """测试 HFish JSON 解析。"""

    def test_parse_valid_json(self):
        """有效 JSON 应解析成功。"""
        samples = load_samples()
        for sample in samples:
            if sample.get("expect_parse_fail"):
                continue
            result = extract_hfish_event(sample["raw_data"])
            assert result["success"] is True, (
                f"应成功: {sample['description']}"
            )
            assert result["parsed_dict"] is not None

            # 验证字段
            if "expected_fields" in sample:
                for key, value in sample["expected_fields"].items():
                    assert result["parsed_dict"].get(key) == value, (
                        f"字段 {key} 应为 {value}: {sample['description']}"
                    )

    def test_parse_invalid_json(self):
        """无效 JSON 应解析失败。"""
        result = extract_hfish_event("this is not json")
        assert result["success"] is False
        assert result["parsed_dict"] is None
        assert result["error_message"] is not None

    def test_parse_empty_string(self):
        """空字符串应解析失败。"""
        result = extract_hfish_event("")
        assert result["success"] is False
        assert result["error_message"] is not None

    def test_parse_json_array(self):
        """JSON 数组应解析失败（预期是对象）。"""
        result = extract_hfish_event("[1, 2, 3]")
        assert result["success"] is False
        assert "not a dict" in result["error_message"]

    def test_parse_none(self):
        """None 输入应解析失败。"""
        result = extract_hfish_event(None)
        assert result["success"] is False


class TestComputeEventId:
    """测试 fallback event_id 生成。"""

    def test_compute_event_id_consistent(self):
        """相同 raw_json 应生成相同 event_id。"""
        raw = '{"src_ip":"1.2.3.4","type":"SSH"}'
        id1 = compute_event_id(raw)
        id2 = compute_event_id(raw)
        assert id1 == id2
        assert id1.startswith("sha256:")

    def test_compute_event_id_different(self):
        """不同 raw_json 应生成不同 event_id。"""
        id1 = compute_event_id('{"a":1}')
        id2 = compute_event_id('{"a":2}')
        assert id1 != id2

    def test_compute_event_id_format(self):
        """event_id 应为 sha256: + 16 位 hex。"""
        event_id = compute_event_id('{"test":"data"}')
        assert event_id.startswith("sha256:")
        hex_part = event_id.split(":")[1]
        assert len(hex_part) == 16
        int(hex_part, 16)  # 验证是合法 hex

    def test_compute_event_id_empty_string(self):
        """空字符串也应生成有效 ID。"""
        event_id = compute_event_id("")
        assert event_id.startswith("sha256:")


class TestExtractFields:
    """测试字段提取。"""

    def test_extract_ssh_event(self):
        """SSH 事件字段提取。"""
        raw = json.dumps({
            "id": "evt_001",
            "time": "2026-06-10T10:30:00+0800",
            "src_ip": "10.0.0.100",
            "src_port": 38888,
            "type": "SSH",
            "dst_port": 22,
            "username": "root",
            "password": "admin123",
            "node": "node-1",
            "location": "CN",
            "severity": "high",
        })
        result = extract_hfish_event(raw)
        fields = extract_fields(result["parsed_dict"])

        assert fields["event_id"] == "evt_001"
        assert fields["src_ip"] == "10.0.0.100"
        assert fields["protocol"] == "SSH"
        assert fields["username"] == "root"
        assert fields["password"] == "admin123"
        assert fields["src_port"] == 38888
        assert fields["target_port"] == 22

    def test_extract_redis_event(self):
        """Redis 事件字段提取（不同字段名）。"""
        raw = json.dumps({
            "_id": "evt_002",
            "create_time": "2026-06-10T10:31:00",
            "attacker_ip": "10.0.0.101",
            "source_port": 40000,
            "proto": "Redis",
            "target_port": 6379,
            "cmd": "INFO",
            "honeypot": "redis-honeypot",
            "geo": "US",
            "level": "medium",
        })
        result = extract_hfish_event(raw)
        fields = extract_fields(result["parsed_dict"])

        assert fields["event_id"] == "evt_002"
        assert fields["src_ip"] == "10.0.0.101"
        assert fields["protocol"] == "Redis"
        assert fields["command"] == "INFO"
        assert fields["node_name"] == "redis-honeypot"

    def test_extract_empty_dict(self):
        """空字典应返回空字段。"""
        fields = extract_fields({})
        for key, value in fields.items():
            assert value is None, f"字段 {key} 应为 None"

    def test_extract_none(self):
        """None 输入应返回空字段。"""
        fields = extract_fields(None)
        for key, value in fields.items():
            assert value is None, f"字段 {key} 应为 None"

    def test_extract_all_field_variants(self):
        """测试所有字段的多种命名变体。"""
        raw = json.dumps({
            "id": "evt_003",
            "time": "2026-06-10T10:32:00",
            "ip": "10.0.0.102",
            "port": 50000,
            "service": "HTTP",
            "local_port": 8080,
            "user": "admin",
            "pass": "pass123",
            "input": "GET /",
            "request": "GET /index.html",
            "ua": "curl/7.88",
            "node": "web-honeypot",
            "country": "JP",
            "attack_type": "Web Probe",
            "risk_level": "medium",
        })
        result = extract_hfish_event(raw)
        fields = extract_fields(result["parsed_dict"])

        assert fields["event_id"] == "evt_003"
        assert fields["src_ip"] == "10.0.0.102"
        assert fields["protocol"] == "HTTP"
        assert fields["username"] == "admin"
        assert fields["password"] == "pass123"
        assert fields["command"] == "GET /"
        assert fields["user_agent"] == "curl/7.88"
        assert fields["severity"] == "medium"
