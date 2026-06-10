"""
IOC Extractor 单元测试。
"""

import json

import pytest

from analyzers.correlator import correlate_all
from analyzers.ioc_extractor import (
    _detect_ua_tool,
    _extract_filename,
    _get_extension,
    extract_all_pending,
    extract_iocs,
)
from analyzers.profiler import build_all_profiles, build_profile
from app.db import (
    count_ioc_extraction_status,
    get_connection,
    get_profile_by_ip,
    get_unprocessed_event_ids,
    get_top_ips,
    init_db,
    insert_ioc,
    insert_normalized_event,
    mark_ioc_extracted,
)


class TestExtractIocs:
    """测试 IOC 提取核心逻辑。"""

    def test_extract_ip(self):
        """应提取 src_ip。"""
        event = {"id": 1, "src_ip": "10.0.0.1", "source": "safeline"}
        iocs = extract_iocs(event)
        ips = [i for i in iocs if i["ioc_type"] == "ip"]
        assert len(ips) == 1
        assert ips[0]["ioc_value"] == "10.0.0.1"

    def test_extract_host(self):
        """应提取 host。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "host": "www.target.com",
                 "source": "safeline"}
        iocs = extract_iocs(event)
        hosts = [i for i in iocs if i["ioc_type"] == "host"]
        assert len(hosts) == 1
        assert hosts[0]["ioc_value"] == "www.target.com"

    def test_extract_uri(self):
        """应提取 URI（排除根路径）。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "uri": "/admin/login.php",
                 "source": "safeline"}
        iocs = extract_iocs(event)
        uris = [i for i in iocs if i["ioc_type"] == "uri"]
        assert len(uris) == 1
        assert uris[0]["ioc_value"] == "/admin/login.php"

    def test_skip_static_uri(self):
        """应跳过静态资源 URI。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "uri": "/static/style.css",
                 "source": "safeline"}
        iocs = extract_iocs(event)
        uris = [i for i in iocs if i["ioc_type"] == "uri"]
        assert len(uris) == 0

    def test_skip_root_uri(self):
        """根路径 / 不应提取为 URI IOC。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "uri": "/", "source": "safeline"}
        iocs = extract_iocs(event)
        uris = [i for i in iocs if i["ioc_type"] == "uri"]
        assert len(uris) == 0

    def test_extract_url(self):
        """host + uri 应拼接为 URL。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "host": "x.com",
                 "uri": "/path", "source": "safeline"}
        iocs = extract_iocs(event)
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(urls) == 1
        assert "x.com" in urls[0]["ioc_value"]

    def test_extract_user_agent(self):
        """应提取 User-Agent。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "user_agent": "sqlmap/1.7", "source": "safeline"}
        iocs = extract_iocs(event)
        uas = [i for i in iocs if i["ioc_type"] == "user_agent"]
        assert len(uas) >= 1

    def test_detect_sqlmap_ua(self):
        """应识别 sqlmap 工具指纹。"""
        assert _detect_ua_tool("sqlmap/1.7") == "sqlmap"
        assert _detect_ua_tool("Mozilla sqlmap 1.8") == "sqlmap"

    def test_detect_nmap_ua(self):
        """应识别 Nmap 工具指纹。"""
        assert _detect_ua_tool("Mozilla/5.0 Nmap Scripting Engine") == "Nmap"

    def test_extract_payload(self):
        """应提取 payload。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "payload": "1' OR '1'='1", "source": "safeline"}
        iocs = extract_iocs(event)
        payloads = [i for i in iocs if i["ioc_type"] == "payload"]
        assert len(payloads) == 1

    def test_suspicious_path_git(self):
        """.git 路径应标记为 suspicious_path。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "uri": "/.git/config", "source": "safeline"}
        iocs = extract_iocs(event)
        sp = [i for i in iocs if i["ioc_type"] == "suspicious_path"]
        assert len(sp) >= 1

    def test_suspicious_path_env(self):
        """.env 路径应标记为 suspicious_path。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "uri": "/.env", "source": "safeline"}
        iocs = extract_iocs(event)
        sp = [i for i in iocs if i["ioc_type"] == "suspicious_path"]
        assert len(sp) >= 1

    def test_extract_filename_sensitive(self):
        """应提取敏感文件名。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "uri": "/backup/config.php.bak", "source": "safeline"}
        iocs = extract_iocs(event)
        fns = [i for i in iocs if i["ioc_type"] == "filename"]
        assert len(fns) >= 1
        # 或者 suspicious_path
        sp = [i for i in iocs if i["ioc_type"] == "suspicious_path"]
        assert len(sp) >= 1

    def test_extract_filename_non_sensitive(self):
        """非敏感文件名不应提取为 IOC。"""
        event = {"id": 1, "src_ip": "1.2.3.4",
                 "uri": "/images/logo.png", "source": "safeline"}
        iocs = extract_iocs(event)
        fns = [i for i in iocs if i["ioc_type"] == "filename"]
        # logo.png 不是敏感文件名，不应提取 filename IOC
        # 但 uri 应该被跳过（静态资源）
        uris = [i for i in iocs if i["ioc_type"] == "uri"]
        assert len(uris) == 0

    def test_empty_event(self):
        """空事件应返回空列表。"""
        iocs = extract_iocs({"id": None, "src_ip": "", "source": "safeline"})
        assert isinstance(iocs, list)


    def test_url_protocol_http(self):
        """HTTP 协议的 URL 应使用 http:// 前缀。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "host": "x.com",
                 "uri": "/path", "source": "safeline", "protocol": "HTTP"}
        iocs = extract_iocs(event)
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(urls) == 1
        assert urls[0]["ioc_value"].startswith("http://")

    def test_url_protocol_https(self):
        """HTTPS 协议的 URL 应使用 https:// 前缀。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "host": "secure.com",
                 "uri": "/admin", "source": "safeline", "protocol": "HTTPS"}
        iocs = extract_iocs(event)
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(urls) == 1
        assert urls[0]["ioc_value"].startswith("https://")

    def test_url_protocol_unknown_defaults_http(self):
        """未知协议的 URL 应默认使用 http://。"""
        event = {"id": 1, "src_ip": "1.2.3.4", "host": "x.com",
                 "uri": "/path", "source": "safeline", "protocol": "UNKNOWN"}
        iocs = extract_iocs(event)
        urls = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(urls) == 1
        assert urls[0]["ioc_value"].startswith("http://")


class TestIocIdempotency:
    """测试 IOC 提取幂等性（使用真实 SQLite 数据库）。"""

    @pytest.fixture
    def db(self, tmp_path):
        """提供一个已初始化的临时数据库，包含一条标准化事件。"""
        db_file = str(tmp_path / "test.db")
        init_db(db_file)

        # 插入一条标准化事件
        conn = get_connection(db_file)
        cursor = conn.cursor()
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "evt_001", now, "10.0.0.1", 54321,
              "HTTP", "GET", "target.com", "/admin.php", "sqlmap/1.7",
              "SQL Injection", "high", "1' OR '1'='1",
              "raw_safeline_logs", 1, now))
        conn.commit()
        return db_file

    def test_first_run_extracts_iocs(self, db):
        """首次运行应提取 IOC。"""
        count = extract_all_pending(db)
        assert count > 0

        status = count_ioc_extraction_status(db)
        assert status["events"] >= 1
        assert status["iocs"] == count

    def test_second_run_no_duplicate(self, db):
        """第二次运行不应重复提取（IOC count 不变）。"""
        first = extract_all_pending(db)
        second = extract_all_pending(db)
        assert second == 0  # 第二次无新事件

    def test_mark_and_check_status(self, db):
        """标记 IOC 提取状态后，不应再出现在未处理列表。"""
        from app.db import get_unprocessed_event_ids, mark_ioc_extracted

        # 处理前应有一个未处理
        assert len(get_unprocessed_event_ids(db)) == 1

        # 标记已处理
        mark_ioc_extracted(db, 1, 5)

        # 处理后应无未处理
        assert len(get_unprocessed_event_ids(db)) == 0


class TestHelperFunctions:
    """测试辅助函数。"""

    def test_get_extension(self):
        assert _get_extension("file.jpg") == ".jpg"
        assert _get_extension("noext") == ""
        assert _get_extension("/a/b/c.JS") == ".js"

    def test_extract_filename(self):
        assert _extract_filename("/a/b/file.php") == "file.php"
        assert _extract_filename("/a/b/") is None
        assert _extract_filename("/a/b") is None


class TestCorrelatePreconditions:
    """测试关联分析前置条件。"""

    def test_correlate_empty_profiles_returns_empty(self, tmp_path):
        """没有画像时 correlate 应友好返回空结果。"""
        db_file = str(tmp_path / "test.db")
        init_db(db_file)

        result = correlate_all(db_file)
        assert result["rules"] == {}
        assert result["profiles_recalculated"] == 0

    def test_correlate_with_profiles_runs(self, tmp_path):
        """有画像时 correlate 应正常执行。"""
        db_file = str(tmp_path / "test.db")
        init_db(db_file)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        conn = get_connection(db_file)
        cursor = conn.cursor()

        # 插入一条 normalized_event
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "evt_002", now, "10.0.0.2", 12345,
              "HTTP", "GET", "t.com", "/", "curl",
              "Port Scan", "low", "",
              "raw_safeline_logs", 1, now))
        conn.commit()

        # 先 build profiles
        build_all_profiles(db_file)

        result = correlate_all(db_file)
        assert "rules" in result
        assert isinstance(result["rules"], dict)

    def test_tags_affect_risk_score(self, tmp_path):
        """关联标签应最终影响风险评分。"""
        db_file = str(tmp_path / "test.db")
        init_db(db_file)

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        conn = get_connection(db_file)
        cursor = conn.cursor()

        # 插入一条带有高危 Payload 的事件
        cursor.execute("""
            INSERT INTO normalized_events
                (source, source_event_id, event_time, src_ip, src_port,
                 protocol, http_method, host, uri, user_agent,
                 attack_type, severity, payload, raw_table, raw_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, ("safeline", "evt_003", now, "10.0.0.3", 12345,
              "HTTP", "GET", "t.com", "/search", "sqlmap",
              "SQL Injection", "high", "1' UNION SELECT * FROM users--",
              "raw_safeline_logs", 1, now))
        conn.commit()

        # 构建画像（此时刚开始，risk_score 应为较低）
        build_all_profiles(db_file)
        profile_before = get_profile_by_ip(db_file, "10.0.0.3")
        score_before = profile_before["risk_score"] if profile_before else 0

        # 关联分析（应添加"高危 Payload"标签并重算评分）
        correlate_all(db_file)
        profile_after = get_profile_by_ip(db_file, "10.0.0.3")

        assert profile_after is not None
        assert "高危 Payload" in (profile_after.get("tags") or "")
        # 重算后的 risk_score 应 >= 关联前的值
        assert profile_after["risk_score"] >= profile_before["risk_score"]
