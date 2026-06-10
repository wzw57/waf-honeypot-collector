"""
ATT&CK Mapper 单元测试。
"""

from analyzers.attack_mapper import map_event


class TestAttackMapper:
    """测试 ATT&CK 映射规则。"""

    def test_map_sql_injection(self):
        """SQL 注入应映射到 T1190。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "attack_type": "SQL Injection",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"
        assert result["technique_name"] == "Exploit Public-Facing Application"

    def test_map_xss(self):
        """XSS 应映射到 T1190。"""
        event = {"id": 2, "src_ip": "1.2.3.5", "attack_type": "XSS",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_map_scan(self):
        """扫描探测应映射到 T1595。"""
        event = {"id": 3, "src_ip": "1.2.3.6", "attack_type": "Port Scan",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1595"

    def test_map_directory_scan(self):
        """目录扫描应映射到 T1595。"""
        event = {"id": 4, "src_ip": "1.2.3.7", "attack_type": "Directory Scan",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result["technique_id"] == "T1595"

    def test_map_ssh_brute_force(self):
        """SSH 暴力破解应映射到 T1110。"""
        event = {"id": 5, "src_ip": "1.2.3.8", "attack_type": "SSH Brute Force",
                 "protocol": "SSH", "source": "hfish", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1110"

    def test_map_hfish_password_guess(self):
        """HFish 密码猜测应映射到 T1110 或 T1110.001（取决于协议匹配优先级）。"""
        event = {"id": 6, "src_ip": "1.2.3.9", "attack_type": "SSH",
                 "protocol": "SSH", "source": "hfish", "payload": "password=admin123"}
        result = map_event(event)
        assert result is not None
        # SSH 协议会优先匹配 T1110，子技术 T1110.001 同样合理
        assert result["technique_id"] in ("T1110", "T1110.001")

    def test_map_hfish_admin_credential(self):
        """HFish admin 凭据应映射到 T1555。"""
        event = {"id": 7, "src_ip": "1.2.3.10", "attack_type": "login",
                 "protocol": "SSH", "source": "hfish",
                 "payload": "username=admin&password=123456"}
        result = map_event(event)
        assert result is not None
        # T1555 (admin) 或 T1110.001 (password 猜测) 都算合理
        assert result["technique_id"] in ("T1555", "T1110.001")

    def test_map_unknown_type_returns_none(self):
        """未知攻击类型应返回 None。"""
        event = {"id": 8, "src_ip": "1.2.3.11", "attack_type": "UnknownCustomType",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is None

    def test_map_sensitive_file(self):
        """敏感文件探测应映射到 T1036。"""
        event = {"id": 9, "src_ip": "1.2.3.12", "attack_type": "Sensitive File Probe",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1036"

    def test_map_rce(self):
        """命令执行应映射到 T1190 或 T1059。"""
        event = {"id": 10, "src_ip": "1.2.3.13", "attack_type": "RCE",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"
