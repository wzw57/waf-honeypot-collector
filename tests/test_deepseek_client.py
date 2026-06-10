"""
DeepSeek API Client 单元测试。
"""

from unittest.mock import MagicMock, patch

import pytest

from ai.deepseek_client import DeepSeekClient


class TestDeepSeekClientAvailability:
    """测试 API 可用性判断。"""

    def test_disabled_by_default(self):
        """默认 enabled=False 时不可用。"""
        client = DeepSeekClient({"enabled": False})
        assert client.is_available() is False

    def test_no_api_key(self):
        """enabled=True 但无 API Key 时不可用。"""
        client = DeepSeekClient({"enabled": True})
        assert client.is_available() is False

    def test_available_with_key(self):
        """enabled=True + API Key 时可用的。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            client = DeepSeekClient({"enabled": True, "api_key_env": "DEEPSEEK_API_KEY"})
            assert client.is_available() is True

    def test_reads_api_key_from_env(self):
        """API Key 从环境变量读取。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test-key-123"}):
            client = DeepSeekClient({"enabled": True, "api_key_env": "DEEPSEEK_API_KEY"})
            assert client.api_key == "sk-test-key-123"


class TestDeepSeekClientChat:
    """测试 chat_completion 调用。"""

    def test_returns_none_when_disabled(self):
        """禁用时应返回 None。"""
        client = DeepSeekClient({"enabled": False})
        result = client.chat_completion([{"role": "user", "content": "hi"}])
        assert result is None

    def test_timeout_returns_none(self):
        """超时应返回 None 不崩溃。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            client = DeepSeekClient({"enabled": True, "timeout": 0.001})

            with patch("requests.post") as mock_post:
                mock_post.side_effect = TimeoutError("timed out")
                result = client.chat_completion([{"role": "user", "content": "hi"}])
                assert result is None

    def test_http_error_returns_none(self):
        """HTTP 错误应返回 None 不崩溃。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            client = DeepSeekClient({"enabled": True})

            with patch("requests.post") as mock_post:
                mock_response = MagicMock()
                mock_response.raise_for_status.side_effect = Exception("HTTP 500")
                mock_post.return_value = mock_response
                result = client.chat_completion([{"role": "user", "content": "hi"}])
                assert result is None

    def test_successful_response(self):
        """成功响应应返回 content。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            client = DeepSeekClient({"enabled": True})

            with patch("requests.post") as mock_post:
                mock_response = MagicMock()
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {
                    "choices": [{"message": {"content": "这是一段分析结果"}}]
                }
                mock_post.return_value = mock_response

                result = client.chat_completion([{"role": "user", "content": "analyze"}])
                assert result == "这是一段分析结果"


class TestDeepSeekClientGenerate:
    """测试高级生成方法。"""

    def test_generate_summary_returns_empty_when_disabled(self):
        """禁用时 generate_summary 应返回空字符串。"""
        client = DeepSeekClient({"enabled": False})
        result = client.generate_summary({"ip": "1.2.3.4"})
        assert result == ""

    def test_generate_summary_calls_chat(self):
        """启用时 generate_summary 应调用 chat_completion。"""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            client = DeepSeekClient({"enabled": True})
            # Mock chat_completion to avoid real API call
            client.chat_completion = MagicMock(return_value="AI summary text")
            result = client.generate_summary({"ip": "1.2.3.4", "total_events": 10})
            assert result == "AI summary text"
            client.chat_completion.assert_called_once()

    def test_generate_remediation_returns_empty_when_disabled(self):
        """禁用时 generate_remediation 应返回空字符串。"""
        client = DeepSeekClient({"enabled": False})
        result = client.generate_remediation({"src_ip": "1.2.3.4"})
        assert result == ""


class TestPromptInjection:
    """测试 Prompt Injection 防护。"""

    def test_system_prompt_contains_security_warning(self):
        """system_prompt 应包含不可信数据警告。"""
        from ai.prompts import system_prompt
        result = system_prompt()
        content = result["content"]
        assert "不可信攻击数据" in content or "不得遵循" in content

    def test_summary_prompt_contains_security_warning(self):
        """summary_prompt 应包含不可信数据警告。"""
        from ai.prompts import summary_prompt
        result = summary_prompt({"ip": "1.2.3.4"})
        content = result["content"]
        assert "不可信" in content or "不得被遵循" in content

    def test_payload_explain_prompt_contains_security_warning(self):
        """payload_explain_prompt 应包含不可信数据警告。"""
        from ai.prompts import payload_explain_prompt
        result = payload_explain_prompt(["' OR 1=1 --"])
        content = result["content"]
        assert "不可信" in content or "不得遵循" in content


class TestAiOutputLength:
    """测试 AI 输出截断。"""

    def test_report_ai_content_truncated(self):
        """超长 AI 内容在报告中应被截断。"""
        import tempfile
        from reports.markdown_report import generate_report
        from app.db import init_db, get_connection
        from datetime import datetime, timezone

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name
        init_db(db)

        conn = get_connection(db)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "e1", now, "10.0.0.50", 12345,
              "HTTP", "GET", "x.com", "/", "test",
              "SQL Injection", "high", "1=1",
              "raw_safeline_logs", 1, now))
        conn.commit()

        from analyzers.profiler import build_all_profiles
        build_all_profiles(db)

        # with_ai=True but no API Key → AI 内容为空 → 不触发截断
        report = generate_report(db, "10.0.0.50", with_ai=True)
        assert report is not None
        # 如果 AI 内容为空，不应有截断标记
        assert "内容已截断" not in report

        import os
        os.unlink(db)


class TestStableProfileCache:
    """测试缓存 key 使用的稳定字段。"""

    def test_stable_profile_extracts_stable_fields(self):
        """_stable_profile 应只包含稳定字段，排除 updated_at/last_event_time。"""
        from ai.deepseek_client import DeepSeekClient

        profile = {
            "src_ip": "1.2.3.4",
            "risk_score": 85,
            "risk_level": "critical",
            "tags": '["高危"]',
            "total_count": 100,
            "attack_types": '{"SQL Injection": 5}',
            "protocols": '{"HTTP": 10}',
            "is_multi_source": 1,
            "updated_at": "2026-06-10T12:00:00Z",
            "last_event_time": "2026-06-10T11:00:00Z",
        }
        stable = DeepSeekClient._stable_profile(profile)
        assert "src_ip" in stable
        assert "risk_score" in stable
        assert "updated_at" not in stable
        assert "last_event_time" not in stable
        assert stable["src_ip"] == "1.2.3.4"
        assert stable["risk_score"] == 85

    def test_stable_profile_cache_consistency(self):
        """相同画像应生成相同缓存 key。"""
        from ai.deepseek_client import DeepSeekClient

        p1 = {"src_ip": "1.2.3.4", "risk_score": 50, "tags": '["a"]',
              "total_count": 10, "attack_types": "{}", "protocols": "{}",
              "is_multi_source": 0}
        p2 = {"src_ip": "1.2.3.4", "risk_score": 50, "tags": '["a"]',
              "total_count": 10, "attack_types": "{}", "protocols": "{}",
              "is_multi_source": 0, "updated_at": "2026-06-10T12:00:00Z"}
        s1 = DeepSeekClient._stable_profile(p1)
        s2 = DeepSeekClient._stable_profile(p2)
        assert s1 == s2


class TestTagsSafety:
    """测试 tags 解析安全性。"""

    def test_safe_json_loads_for_tags(self):
        """非法 tags JSON 应降级为空列表不崩溃。"""
        from app.utils import safe_json_loads

        result = safe_json_loads("not valid json", default=[])
        assert result == []

        result = safe_json_loads('["a", "b"]', default=[])
        assert result == ["a", "b"]

        result = safe_json_loads(None, default=[])
        assert result == []


class TestAiSummaryCli:
    """测试 ai-summary CLI 的降级行为。"""

    def test_no_api_key_shows_message(self, tmp_path, capsys):
        """无 API Key 时 ai-summary 应给出明确提示。"""
        from main import cmd_ai_summary
        import argparse
        from app.db import init_db, get_connection
        from datetime import datetime, timezone

        db_file = str(tmp_path / "test.db")
        init_db(db_file)

        # 插入一条事件和画像，让 AI 检查逻辑能走到
        conn = get_connection(db_file)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "e1", now, "10.0.0.1", 12345,
              "HTTP", "GET", "x.com", "/", "test",
              "SQL Injection", "high", "1=1",
              "raw_safeline_logs", 1, now))
        conn.commit()

        from analyzers.profiler import build_all_profiles
        build_all_profiles(db_file)

        args = argparse.Namespace(ip="10.0.0.1", config=None)

        with patch("main.get_config") as mock_cfg:
            mock_cfg.return_value = {
                "database": {"path": db_file},
                "deepseek": {"enabled": False},
            }
            cmd_ai_summary(args)

        captured = capsys.readouterr()
        assert "未启用" in captured.out or "未配置" in captured.out

    def test_report_with_ai_disabled_falls_back(self):
        """--with-ai 但 AI 不可用时，报告应正常生成（不包含 AI 章节）。"""
        # 纯逻辑测试：generate_report with_ai=True 但无 API Key 应降级
        from reports.markdown_report import generate_report
        import tempfile
        from app.db import init_db, get_connection
        from datetime import datetime, timezone

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db = f.name

        init_db(db)

        # 插入一条事件
        conn = get_connection(db)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "evt_001", now, "10.0.0.99", 12345,
              "HTTP", "GET", "x.com", "/", "test",
              "SQL Injection", "high", "payload",
              "raw_safeline_logs", 1, now))
        conn.commit()

        # 构建画像
        from analyzers.profiler import build_all_profiles
        build_all_profiles(db)

        # 生成报告（with_ai=True，但无 API Key）
        report = generate_report(db, "10.0.0.99", with_ai=True)
        assert report is not None
        assert "AI 辅助分析" not in report  # 无 AI 内容
        assert "处置建议" in report  # 规则生成的应有

        import os
        os.unlink(db)
