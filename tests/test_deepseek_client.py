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
