"""
ATT&CK Mapper 单元测试。
"""

from analyzers.attack_mapper import map_event


class TestAttackMapper:
    """测试 ATT&CK 映射规则优先级。"""

    def test_map_sql_injection(self):
        """SQL 注入 → T1190。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "attack_type": "SQL Injection",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_map_xss(self):
        """XSS → T1190。"""
        event = {"id": 2, "src_ip": "1.2.3.5", "attack_type": "XSS",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_map_scan(self):
        """端口扫描 → T1595。"""
        event = {"id": 3, "src_ip": "1.2.3.6", "attack_type": "Port Scan",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1595"

    def test_map_directory_scan(self):
        """目录扫描 → T1595。"""
        event = {"id": 4, "src_ip": "1.2.3.7", "attack_type": "Directory Scan",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result["technique_id"] == "T1595"

    def test_map_ssh_brute_force(self):
        """SSH 爆破 → T1110。"""
        event = {"id": 5, "src_ip": "1.2.3.8", "attack_type": "SSH Brute Force",
                 "protocol": "SSH", "source": "hfish", "payload": ""}
        result = map_event(event)
        assert result["technique_id"] == "T1110"

    def test_map_sensitive_file_probe(self):
        """敏感文件探测 → T1595（而非 T1036）。"""
        event = {"id": 6, "src_ip": "1.2.3.9", "attack_type": "Sensitive File Probe",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1595"

    def test_map_path_traversal(self):
        """路径遍历 → T1190。"""
        event = {"id": 7, "src_ip": "1.2.3.10", "attack_type": "Path Traversal",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_map_unknown_type_returns_none(self):
        """未知攻击类型 → None。"""
        event = {"id": 8, "src_ip": "1.2.3.11", "attack_type": "UnknownCustomType",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is None

    def test_map_rce(self):
        """RCE → T1190。"""
        event = {"id": 9, "src_ip": "1.2.3.12", "attack_type": "RCE",
                 "protocol": "HTTP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1190"

    def test_map_hfish_password_guess(self):
        """HFish 密码猜测 → T1110.001。"""
        event = {"id": 10, "src_ip": "1.2.3.13", "attack_type": "SSH",
                 "protocol": "SSH", "source": "hfish", "payload": "password=admin123"}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] in ("T1110", "T1110.001")

    def test_map_hfish_username_guess(self):
        """HFish 用户名猜测 → T1110.001。"""
        event = {"id": 11, "src_ip": "1.2.3.14", "attack_type": "login",
                 "protocol": "SSH", "source": "hfish",
                 "payload": "username=admin&password=123456"}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] in ("T1110", "T1110.001")

    def test_map_payload_exec(self):
        """Payload exec → T1059。"""
        event = {"id": 12, "src_ip": "1.2.3.15", "attack_type": "whatever",
                 "protocol": "HTTP", "source": "safeline", "payload": "exec('id')"}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1059"

    def test_map_payload_system(self):
        """Payload system → T1059。"""
        event = {"id": 13, "src_ip": "1.2.3.16", "attack_type": "whatever",
                 "protocol": "HTTP", "source": "safeline", "payload": "system('ls')"}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1059"

    def test_map_payload_passthru(self):
        """Payload passthru → T1059。"""
        event = {"id": 14, "src_ip": "1.2.3.17", "attack_type": "whatever",
                 "protocol": "HTTP", "source": "safeline", "payload": "passthru('id')"}
        result = map_event(event)
        assert result is not None
        assert result["technique_id"] == "T1059"

    def test_map_scan_trumps_brute_force(self):
        """扫描规则应优先于爆破规则 — Port Scan → T1595 而非 T1110。"""
        event = {"id": 15, "src_ip": "1.2.3.18", "attack_type": "Port Scan",
                 "protocol": "TCP", "source": "safeline", "payload": ""}
        result = map_event(event)
        assert result["technique_id"] == "T1595"
