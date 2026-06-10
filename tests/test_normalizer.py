"""
Normalizer 单元测试。
"""

from analyzers.normalizer import (
    normalize_attack_type,
    normalize_event_time,
    normalize_from_hfish,
    normalize_from_safeline,
    normalize_severity,
    parse_http_request,
)


class TestNormalizeSeverity:
    """测试严重级别标准化。"""

    def test_standard_values(self):
        """标准值应原样保留。"""
        assert normalize_severity("low") == "low"
        assert normalize_severity("medium") == "medium"
        assert normalize_severity("high") == "high"
        assert normalize_severity("critical") == "critical"

    def test_chinese_values(self):
        """中文值应映射。"""
        assert normalize_severity("低危") == "low"
        assert normalize_severity("中危") == "medium"
        assert normalize_severity("高危") == "high"
        assert normalize_severity("严重") == "critical"

    def test_numeric_values(self):
        """数字值应映射。"""
        assert normalize_severity("1") == "low"
        assert normalize_severity("2") == "medium"
        assert normalize_severity("3") == "high"
        assert normalize_severity("4") == "critical"
        assert normalize_severity("5") == "critical"

    def test_none_value(self):
        """None 应返回 low。"""
        assert normalize_severity(None) == "low"

    def test_unknown_value(self):
        """未知值应返回 low。"""
        assert normalize_severity("unknown") == "low"
        assert normalize_severity("") == "low"


class TestNormalizeAttackType:
    """测试攻击类型标准化。"""

    def test_safeline_types(self):
        """SafeLine 攻击类型映射。"""
        assert normalize_attack_type("SQL Injection") == "SQL Injection"
        assert normalize_attack_type("sql_injection") == "SQL Injection"
        assert normalize_attack_type("XSS") == "XSS"
        assert normalize_attack_type("rce") == "Command Execution"
        assert normalize_attack_type("Path Traversal") == "Path Traversal"
        assert normalize_attack_type("dirbust") == "Directory Scan"

    def test_hfish_types(self):
        """HFish 攻击类型映射。"""
        assert normalize_attack_type("SSH") == "SSH Brute Force"
        assert normalize_attack_type("ssh brute force") == "SSH Brute Force"
        assert normalize_attack_type("Redis") == "Redis Brute Force"
        assert normalize_attack_type("MySQL") == "MySQL Brute Force"
        assert normalize_attack_type("弱口令") == "Weak Password Attempt"

    def test_unknown_type(self):
        """未知类型应原样返回。"""
        assert normalize_attack_type("CustomAttack") == "CustomAttack"

    def test_none_type(self):
        """None 应返回 Unknown。"""
        assert normalize_attack_type(None) == "Unknown"


class TestNormalizeEventTime:
    """测试时间标准化。"""

    def test_iso_format(self):
        """ISO 格式应保留。"""
        result = normalize_event_time("2026-06-10T10:30:00")
        assert result is not None
        assert "2026-06-10" in result

    def test_unix_timestamp(self):
        """Unix 时间戳应转换。"""
        result = normalize_event_time(1718000000)
        assert result is not None
        # 验证格式
        assert result.endswith("Z")

    def test_none_time(self):
        """None 应返回 None。"""
        assert normalize_event_time(None) is None

    def test_empty_string(self):
        """空字符串应返回 None。"""
        assert normalize_event_time("") is None


class TestNormalizeFromSafeline:
    """测试 SafeLine 标准化。"""

    def test_normalize_valid_event(self):
        """有效 SafeLine 事件应标准化。"""
        parsed = {
            "event_id": "SL-abc123",
            "event_time": "2026-06-10T10:30:00",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "method": "GET",
            "host": "www.target.com",
            "uri": "/admin/login.php",
            "user_agent": "sqlmap/1.7",
            "attack_type": "SQL Injection",
            "severity": "high",
            "payload": "1' OR '1'='1",
        }
        result = normalize_from_safeline(parsed)
        assert result is not None
        assert result["source"] == "safeline"
        assert result["src_ip"] == "10.0.0.1"
        assert result["attack_type"] == "SQL Injection"
        assert result["severity"] == "high"
        assert result["http_method"] == "GET"

    def test_normalize_none(self):
        """None 或空输入应返回 None。"""
        assert normalize_from_safeline(None) is None
        assert normalize_from_safeline({}) is None  # 空字典无有效字段

    def test_normalize_minimal_event(self):
        """最小有效事件应标准化成功。"""
        result = normalize_from_safeline({"src_ip": "10.0.0.1"})
        assert result is not None
        assert result["source"] == "safeline"
        assert result["src_ip"] == "10.0.0.1"
        assert result["attack_type"] != ""  # 应该有默认值


class TestParseHttpRequest:
    """测试 HTTP 请求解析。"""

    def test_parse_get_request(self):
        """完整 GET 请求应解析出 method / uri / host / ua。"""
        raw = (
            "GET /admin/login.php HTTP/1.1\r\n"
            "Host: target.com\r\n"
            "User-Agent: sqlmap/1.7\r\n"
            "Accept: */*\r\n"
        )
        result = parse_http_request(raw)
        assert result["http_method"] == "GET"
        assert result["uri"] == "/admin/login.php"
        assert result["host"] == "target.com"
        assert result["user_agent"] == "sqlmap/1.7"

    def test_parse_post_request(self):
        """POST 请求应解析正确。"""
        raw = (
            "POST /api/login HTTP/1.1\r\n"
            "Host: app.example.com\r\n"
            "Content-Type: application/json\r\n"
        )
        result = parse_http_request(raw)
        assert result["http_method"] == "POST"
        assert result["uri"] == "/api/login"
        assert result["host"] == "app.example.com"
        assert result["user_agent"] is None  # 没有 User-Agent 头

    def test_parse_no_content(self):
        """空内容应返回全 None。"""
        result = parse_http_request(None)
        assert result["http_method"] is None
        assert result["uri"] is None

    def test_parse_empty_string(self):
        """空字符串应返回全 None。"""
        result = parse_http_request("")
        for v in result.values():
            assert v is None

    def test_parse_non_http_content(self):
        """非 HTTP 内容不应误解析。"""
        result = parse_http_request("SSH-2.0-OpenSSH_8.9")
        assert result["http_method"] is None
        assert result["uri"] is None

    def test_hfish_normalize_with_http_parse(self):
        """HFish HTTP 蜜罐事件应通过 parse_http_request 增强字段。"""
        fields = {
            "event_id": "h_http_001",
            "event_time": "2026-06-10T10:30:00",
            "src_ip": "10.0.0.200",
            "protocol": "HTTP",
            "request_content": (
                "GET /manager/html HTTP/1.1\r\n"
                "Host: web-vuln-lab.local\r\n"
                "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n"
            ),
            "event_type": "Web Probe",
        }
        result = normalize_from_hfish(fields)
        assert result is not None
        assert result["http_method"] == "GET"
        assert result["uri"] == "/manager/html"
        assert result["host"] == "web-vuln-lab.local"
        assert result["user_agent"] == "Mozilla/5.0 (compatible; Nmap Scripting Engine)"


class TestNormalizeFromHfish:
    """测试 HFish 标准化。"""

    def test_normalize_ssh_event(self):
        """SSH 事件应标准化。"""
        fields = {
            "event_id": "h_001",
            "event_time": "2026-06-10T10:30:00",
            "src_ip": "10.0.0.100",
            "src_port": 38888,
            "protocol": "SSH",
            "target_port": 22,
            "username": "root",
            "password": "admin123",
            "event_type": "SSH Brute Force",
            "severity": "high",
        }
        result = normalize_from_hfish(fields)
        assert result is not None
        assert result["source"] == "hfish"
        assert result["src_ip"] == "10.0.0.100"
        assert result["protocol"] == "SSH"
        assert result["attack_type"] == "SSH Brute Force"

    def test_normalize_http_event(self):
        """HTTP 事件应标准化。"""
        fields = {
            "event_id": "h_002",
            "event_time": "2026-06-10T10:31:00",
            "src_ip": "10.0.0.101",
            "protocol": "HTTP",
            "request_content": "GET /manager/html",
            "user_agent": "nmap",
        }
        result = normalize_from_hfish(fields)
        assert result is not None
        assert result["protocol"] == "HTTP"
        assert result["http_method"] is not None

    def test_normalize_none(self):
        """None 输入应返回 None。"""
        assert normalize_from_hfish(None) is None
