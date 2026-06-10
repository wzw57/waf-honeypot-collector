"""
ModSecurity Parser 单元测试。
"""

from parsers.modsecurity_parser import (
    split_transactions,
    parse_transaction,
)


SAMPLE_TRANSACTION = """--abc123-A--
[10/Jun/2026:13:50:01 +0800] Axyz123 1.2.3.4 12345 10.0.0.1 80
--abc123-B--
GET /index.php?id=1%27 HTTP/1.1
Host: example.com
User-Agent: curl/8.0
Accept: */*
--abc123-F--
HTTP/1.1 403 Forbidden
Connection: close
--abc123-H--
Message: Warning. detected SQLi using libinjection. [file "/etc/modsecurity/rules.conf"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"] [data "Matched Data: 1' found at ARGS:id"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "capec/1000/152/248/66"]
Apache-Error: ...
Action: Intercepted
--abc123-Z--
"""


class TestSplitTransactions:
    """测试 transaction 分割。"""

    def test_split_single(self):
        """单个完整 transaction 应分割为一条。"""
        result = split_transactions(SAMPLE_TRANSACTION)
        assert len(result) == 1

    def test_split_multiple(self):
        """多个 transaction 应正确分割。"""
        text = SAMPLE_TRANSACTION + "\n" + SAMPLE_TRANSACTION
        result = split_transactions(text)
        assert len(result) == 2

    def test_split_empty(self):
        """空文本应为空列表。"""
        result = split_transactions("")
        assert result == []

    def test_split_no_transaction(self):
        """无 transaction 标记的文本应为空。"""
        result = split_transactions("just some random text\nwith no markers\n")
        assert result == []

    def test_split_incomplete(self):
        """末尾未关闭的 transaction 也应被收集。"""
        text = SAMPLE_TRANSACTION.split("--abc123-Z--")[0]
        result = split_transactions(text)
        # 至少包含 --abc123-A-- 开头的部分
        assert len(result) >= 1


class TestParseTransaction:
    """测试 transaction 解析。"""

    def test_parse_client_ip(self):
        """应解析 client_ip。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["client_ip"] == "1.2.3.4"

    def test_parse_timestamp(self):
        """应解析时间戳。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert "10/Jun/2026" in result["timestamp"]

    def test_parse_method_uri(self):
        """应解析 method 和 uri。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["method"] == "GET"
        assert "/index.php" in result["uri"]

    def test_parse_host(self):
        """应解析 Host。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["host"] == "example.com"

    def test_parse_user_agent(self):
        """应解析 User-Agent。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["user_agent"] == "curl/8.0"

    def test_parse_rule_id(self):
        """应解析 rule_id。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["rule_id"] == "942100"

    def test_parse_message(self):
        """应解析消息。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert "SQL Injection" in result["message"]

    def test_parse_severity(self):
        """应解析严重级别。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["severity"] == "CRITICAL"

    def test_parse_status_code(self):
        """应解析 status_code。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["status_code"] == 403

    def test_parse_action_intercepted(self):
        """Action: Intercepted 应标记为 blocked。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert result["blocked"] is True
        assert result["action"] == "intercepted"

    def test_parse_rule_tags(self):
        """应解析规则标签。"""
        result = parse_transaction(SAMPLE_TRANSACTION)
        assert len(result["rule_tags"]) > 0
        assert "attack-sqli" in result["rule_tags"]

    def test_parse_non_blocked(self):
        """没有 Action: Intercepted 且非 403 应标记为未拦截。"""
        text = SAMPLE_TRANSACTION.replace(
            'HTTP/1.1 403 Forbidden', 'HTTP/1.1 200 OK'
        ).replace(
            'Action: Intercepted', 'Action: Passed'
        )
        result = parse_transaction(text)
        assert result["blocked"] is False
        assert result["action"] == "passed"

    def test_missing_fields_not_crash(self):
        """字段缺失不应崩溃。"""
        minimal = "--a1-A--\n--a1-Z--\n"
        result = parse_transaction(minimal)
        assert result["client_ip"] is None
        assert result["blocked"] is False

    def test_non_hex_transaction_id(self):
        """非 hex transaction id 应正确分割和解析。"""
        text = """--abcXYZ_123-A--
[10/Jun/2026:13:50:01 +0800] xyz 1.2.3.4 12345 10.0.0.1 80
--abcXYZ_123-B--
GET /?id=1 HTTP/1.1
Host: example.com
--abcXYZ_123-F--
HTTP/1.1 403 Forbidden
--abcXYZ_123-H--
[id "942100"] [msg "test"]
Action: Intercepted
--abcXYZ_123-Z--
"""
        result = parse_transaction(text)
        assert result["transaction_id"] == "abcXYZ_123"
        assert result["client_ip"] == "1.2.3.4"
        assert result["method"] == "GET"
        assert result["rule_id"] == "942100"
        assert result["blocked"] is True


class TestInferAttackType:
    """测试攻击类型推断。"""

    def test_infer_sqli(self):
        """942100 → sql_injection。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type("942100", "") == "sql_injection"

    def test_infer_xss(self):
        """941100 → xss。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type("941100", "") == "xss"

    def test_infer_path_traversal(self):
        """930100 → path_traversal。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type("930100", "") == "path_traversal"

    def test_infer_command_injection(self):
        """932100 → command_injection。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type("932100", "") == "command_injection"

    def test_infer_from_message(self):
        """无 rule_id 时从 message 推断。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type(None, "SQL Injection detected") == "sql_injection"

    def test_infer_unknown(self):
        """无法推断时返回 web_attack。"""
        from analyzers.normalizer import infer_attack_type
        assert infer_attack_type("999999", "Some unknown rule") == "web_attack"
