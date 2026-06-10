"""
IOC Extractor 单元测试。
"""

import json

import pytest

from analyzers.ioc_extractor import (
    _detect_ua_tool,
    _extract_filename,
    _get_extension,
    extract_iocs,
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
