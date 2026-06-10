"""
SafeLine Parser 单元测试。
"""

import json
from pathlib import Path

import pytest

from parsers.safeline_parser import parse_safeline_syslog, extract_json_from_syslog


# 加载测试样本
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_samples():
    with open(FIXTURES_DIR / "safeline_samples.json", "r", encoding="utf-8") as f:
        return json.load(f)


class TestExtractJsonFromSyslog:
    """测试 JSON 提取功能。"""

    def test_extract_valid_json(self):
        """有效 JSON 应被正确提取。"""
        msg = 'prefix text {"key": "value"} suffix text'
        json_str, error = extract_json_from_syslog(msg)
        assert json_str == '{"key": "value"}'
        assert error == ""

    def test_extract_no_json(self):
        """无 JSON 时返回错误。"""
        json_str, error = extract_json_from_syslog("this is plain text")
        assert json_str == ""
        assert "no JSON object found" in error

    def test_extract_empty_string(self):
        """空字符串输入应返回错误。"""
        json_str, error = extract_json_from_syslog("")
        assert json_str == ""
        assert "empty" in error

    def test_extract_nested_json(self):
        """嵌套 JSON 应被完整提取（从第一个 { 到最后一个 }）。"""
        msg = 'data: {"outer": {"inner": "value"}, "list": [1,2,3]} end'
        json_str, error = extract_json_from_syslog(msg)
        parsed = json.loads(json_str)
        assert parsed["outer"]["inner"] == "value"
        assert parsed["list"] == [1, 2, 3]

    def test_extract_non_string_input(self):
        """非字符串输入应返回错误。"""
        json_str, error = extract_json_from_syslog(None)
        assert json_str == ""
        assert "empty" in error or "not a string" in error


class TestParseSafelineSyslog:
    """测试 SafeLine Syslog 解析。"""

    def test_parse_valid_syslog(self):
        """有效 Syslog 应解析成功。"""
        samples = load_samples()
        for sample in samples:
            if sample["expected_parse_status"] != "parsed":
                continue
            result = parse_safeline_syslog(sample["syslog"])
            assert result["success"] is True, (
                f"应为 success=True: {sample['description']}"
            )
            assert result["parsed_json"] is not None
            assert result["parsed_dict"] is not None

            # 验证关键字段
            for key, value in sample["expected_fields"].items():
                assert result["parsed_dict"].get(key) == value, (
                    f"字段 {key} 应为 {value}: {sample['description']}"
                )

    def test_parse_invalid_syslog_no_json(self):
        """无 JSON 的 Syslog 应解析失败但不可怕。"""
        result = parse_safeline_syslog(
            "<134>Jun 10 10:35:00 safeline SafeLine[1239]: plain text log"
        )
        assert result["success"] is False
        assert result["parsed_json"] is None
        assert result["parsed_dict"] is None
        assert result["error_message"] is not None

    def test_parse_empty_string(self):
        """空字符串应解析失败。"""
        result = parse_safeline_syslog("")
        assert result["success"] is False
        assert result["error_message"] is not None

    def test_parse_malformed_json(self):
        """格式错误的 JSON 应解析失败，但保留原始 JSON 字符串。"""
        msg = '<134>prefix {"key": "value", broken} suffix'
        result = parse_safeline_syslog(msg)
        assert result["success"] is False
        # parsed_json 应保留原始提取的 JSON 字符串
        assert result["parsed_json"] is not None
        assert result["error_message"] is not None

    def test_parse_all_samples(self):
        """所有样本均不应导致异常。"""
        samples = load_samples()
        for sample in samples:
            try:
                parse_safeline_syslog(sample["syslog"])
            except Exception as e:
                pytest.fail(
                    f"解析样本时抛出异常: {sample['description']}: {e}"
                )

    def test_parse_result_structure(self):
        """解析结果应包含所有预期字段。"""
        result = parse_safeline_syslog(
            "<134>Jun 10 10:30:00 safeline SafeLine[1234]: "
            '{"attack_type":"SQL Injection","src_ip":"10.0.0.1"}'
        )
        expected_keys = {"success", "parsed_json", "parsed_dict", "error_message"}
        assert set(result.keys()) == expected_keys, (
            f"返回键不匹配: {set(result.keys())}"
        )

    def test_success_parsed_json_not_none(self):
        """解析成功时 parsed_json 不应为 None。"""
        result = parse_safeline_syslog(
            "<134>Jun 10 10:30:00 safeline SafeLine[1234]: "
            '{"attack_type":"SQL Injection"}'
        )
        assert result["success"] is True
        assert result["parsed_json"] is not None
        assert result["parsed_dict"] is not None
        assert result["error_message"] is None

    def test_failed_parsed_dict_is_none(self):
        """解析失败时 parsed_dict 应为 None。"""
        result = parse_safeline_syslog("no json here")
        assert result["success"] is False
        assert result["parsed_dict"] is None
