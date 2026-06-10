"""
HFish API 客户端。

支持 Token 认证和账号密码认证，提供单次拉取和循环定时拉取。
"""

import json
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

import requests

from app.logger import get_logger

logger = get_logger("hfish_api")


class HFishCollector:
    """
    HFish API 客户端。

    从 HFish 蜜罐的 REST API 拉取攻击日志，
    支持单次拉取和循环定时拉取。
    """

    def __init__(self, api_url: str, auth_type: str = "token",
                 api_token: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 api_path: str = "/api/v1/attack",
                 page_size: int = 100,
                 timeout: int = 15,
                 on_events_received: Optional[Callable] = None):
        """
        初始化 HFish 客户端。

        Args:
            api_url: HFish API 基础 URL，如 "http://192.168.1.100:5000"。
            auth_type: 认证方式，"token" 或 "password"。
            api_token: API Token（auth_type=token 时使用）。
            username: 登录用户名（auth_type=password 时使用）。
            password: 登录密码（auth_type=password 时使用）。
            api_path: 攻击日志 API 路径。
            page_size: 每页条数。
            timeout: HTTP 请求超时秒数。
            on_events_received: 拉取到事件后的回调函数。
                              回调签名: callback(raw_json_list)
        """
        self.api_url = api_url.rstrip("/")
        self.auth_type = auth_type
        self.api_token = api_token
        self.username = username
        self.password = password
        self.api_path = api_path
        self.page_size = page_size
        self.timeout = timeout
        self.on_events_received = on_events_received
        self.session_token = None
        self._stats = {"fetched": 0, "pages": 0, "errors": 0}

    def _get_headers(self) -> dict:
        """获取 HTTP 请求头。"""
        headers = {"Content-Type": "application/json"}
        if self.auth_type == "token" and self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
            headers["X-API-Key"] = self.api_token
        return headers

    def _authenticate(self) -> bool:
        """
        使用账号密码认证，获取会话 Token。

        Returns:
            bool: 是否认证成功。
        """
        if self.auth_type != "password" or not self.username or not self.password:
            return False

        login_path = "/api/v1/auth/login"
        url = f"{self.api_url}{login_path}"

        try:
            resp = requests.post(
                url,
                json={"username": self.username, "password": self.password},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                self.session_token = data.get("token", data.get("data", {}).get("token"))
                if self.session_token:
                    logger.info("HFish 账号密码认证成功")
                    return True
            logger.warning("HFish 认证失败: HTTP %d", resp.status_code)
        except requests.RequestException as e:
            logger.error("HFish 认证请求异常: %s", e)

        return False

    def fetch_once(self) -> List[str]:
        """
        单次拉取 HFish 攻击日志。

        遍历所有页面，返回原始 JSON 字符串列表。

        Returns:
            list[str]: 原始 JSON 字符串列表（每条事件一条）。
        """
        if not self.api_url:
            logger.warning("HFish API URL 未配置，跳过拉取")
            return []

        if self.auth_type == "password" and not self.session_token:
            if not self._authenticate():
                logger.error("HFish 认证失败，无法拉取日志")
                return []

        all_events = []
        page = 1
        total_pages = 1

        while page <= total_pages:
            try:
                events, total_pages = self._fetch_page(page)
                if events:
                    all_events.extend(events)
                    self._stats["fetched"] += len(events)
                self._stats["pages"] += 1
                logger.debug("HFish 拉取第 %d/%d 页: %d 条", page, total_pages, len(events))
            except Exception as e:
                self._stats["errors"] += 1
                logger.error("HFish 第 %d 页拉取失败: %s", page, e)
                # 失败后继续下一页，不阻塞

            page += 1

        logger.info("HFish 单次拉取完成: 共 %d 条, %d 页, %d 次错误",
                     len(all_events), self._stats["pages"], self._stats["errors"])

        if all_events and self.on_events_received:
            try:
                self.on_events_received(all_events)
            except Exception as e:
                logger.error("HFish 事件回调执行失败: %s", e)

        return all_events

    def _fetch_page(self, page: int) -> tuple:
        """
        拉取指定页的 HFish 事件。

        Args:
            page: 页码（从 1 开始）。

        Returns:
            tuple: (events_list, total_pages)
            - events_list: 当前页的原始 JSON 字符串列表
            - total_pages: 总页数（从第一页响应中获取）
        """
        headers = self._get_headers()
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"

        url = f"{self.api_url}{self.api_path}"
        params = {
            "page": page,
            "page_size": self.page_size,
            "order": "desc",
        }

        resp = requests.get(url, headers=headers, params=params, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()

        # 尝试多种可能的响应结构
        items = None
        total_pages = 1

        if isinstance(data, list):
            # 直接返回数组
            items = data
        elif isinstance(data, dict):
            # 尝试嵌套结构
            items = (
                data.get("data", {}).get("items")
                or data.get("data", {}).get("list")
                or data.get("data", {}).get("rows")
                or data.get("items")
                or data.get("list")
                or data.get("rows")
                or data.get("result", [])
            )
            total_pages = (
                data.get("data", {}).get("total_page")
                or data.get("data", {}).get("pages")
                or data.get("total_page")
                or data.get("pages")
                or 1
            )

        if items is None:
            logger.warning("HFish API 返回格式无法识别: %s", str(data)[:200])
            return [], 1

        # 将每个事件转为 JSON 字符串（保留原始数据）
        raw_jsons = []
        for item in items:
            if isinstance(item, dict):
                raw_jsons.append(json.dumps(item, ensure_ascii=False))
            elif isinstance(item, str):
                raw_jsons.append(item)

        return raw_jsons, total_pages

    def fetch_loop(self, interval: int = 60):
        """
        循环定时拉取 HFish 日志。

        Args:
            interval: 拉取间隔（秒）。
        """
        import signal

        running = True

        def handler(signum, frame):
            nonlocal running
            if running:
                logger.info("收到信号，停止 HFish 循环拉取")
                running = False

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        logger.info("HFish 循环拉取已启动，间隔 %d 秒", interval)
        print(f"[INFO] HFish 循环拉取已启动，间隔 {interval} 秒")
        print("[INFO] 按 Ctrl+C 停止")

        while running:
            try:
                self.fetch_once()
            except Exception as e:
                logger.error("HFish 循环拉取出错: %s", e)
                self._stats["errors"] += 1

            # 等待，每秒检查一次 running 标志
            for _ in range(interval):
                if not running:
                    break
                time.sleep(1)

        logger.info("HFish 循环拉取已停止")
        print(f"[INFO] HFish 循环拉取已停止")
        print(f"[INFO] 本次运行: 拉取 {self._stats['fetched']} 条, "
              f"{self._stats['pages']} 页, {self._stats['errors']} 次错误")

    def get_stats(self) -> dict:
        """获取运行统计。"""
        return dict(self._stats)
