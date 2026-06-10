"""
DeepSeek API 客户端。

对 DeepSeek 兼容 API（OpenAI 格式）进行 HTTP 调用封装。
支持超时保护、异常降级、结果缓存。
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from app.logger import get_logger
from app.utils import now_iso

logger = get_logger("deepseek_client")


class DeepSeekClient:
    """
    DeepSeek API 客户端。

    从配置和环境变量读取 API 参数，提供结构化的对话式 API 调用。
    所有请求设置 timeout，异常时降级返回 None。
    """

    def __init__(self, config: dict):
        """
        初始化 DeepSeek 客户端。

        Args:
            config: deepseek 配置字典，包含 base_url, model,
                    api_key_env, timeout, max_tokens。
        """
        self.base_url = config.get("base_url", "https://api.deepseek.com").rstrip("/")
        self.model = config.get("model", "deepseek-chat")
        self.api_key_env = config.get("api_key_env", "DEEPSEEK_API_KEY")
        self.timeout = config.get("timeout", 30)
        self.max_tokens = config.get("max_tokens", 1200)
        self.enabled = config.get("enabled", False)

        # 从环境变量读取 API Key
        self.api_key = os.environ.get(self.api_key_env, "")
        if not self.api_key:
            logger.warning("环境变量 %s 未设置，DeepSeek API 不可用", self.api_key_env)

    def is_available(self) -> bool:
        """检查 API 是否可用（已启用 + 有 API Key）。"""
        return bool(self.enabled and self.api_key)

    def chat_completion(self, messages: List[Dict[str, str]],
                        **kwargs) -> Optional[str]:
        """
        发送对话补全请求。

        Args:
            messages: 消息列表 [{"role": "system", "content": "..."},
                                 {"role": "user", "content": "..."}]
            **kwargs: 覆盖默认参数（如 temperature, max_tokens）。

        Returns:
            str|None: AI 响应文本，失败时返回 None。
        """
        if not self.is_available():
            logger.debug("DeepSeek API 不可用（enabled=%s, api_key=%s）",
                         self.enabled, bool(self.api_key))
            return None

        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", 0.7),
        }

        try:
            logger.debug("发送 DeepSeek API 请求: %s tokens=%d",
                         self.model, payload["max_tokens"])
            resp = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()

            content = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content")
            )
            if content:
                logger.debug("DeepSeek API 响应成功: %d chars", len(content))
                return content.strip()

            logger.warning("DeepSeek API 返回空内容: %s", str(data)[:200])

        except requests.Timeout:
            logger.error("DeepSeek API 请求超时（%ds）", self.timeout)
        except requests.ConnectionError as e:
            logger.error("DeepSeek API 连接失败: %s", e)
        except requests.HTTPError as e:
            logger.error("DeepSeek API HTTP 错误: %s", e)
        except Exception as e:
            logger.error("DeepSeek API 请求异常: %s", e, exc_info=True)

        return None

    def generate_summary(self, ip_data: Dict[str, Any],
                         cache_db_path: Optional[str] = None) -> str:
        """
        生成攻击行为摘要（带缓存）。

        Args:
            ip_data: 结构化攻击源数据。
            cache_db_path: 数据库路径（启用缓存时传入）。

        Returns:
            str: 攻击摘要文本。API 不可用或失败时返回空字符串。
        """
        if not self.is_available():
            return ""

        # 检查缓存
        if cache_db_path:
            cached = self._get_cached(cache_db_path, "summary", ip_data)
            if cached is not None:
                return cached

        from ai.prompts import summary_prompt, system_prompt

        messages = [system_prompt(), summary_prompt(ip_data)]
        result = self.chat_completion(messages)

        if result and cache_db_path:
            self._set_cached(cache_db_path, "summary", ip_data, result)

        return result or ""

    def generate_remediation(self, profile: Dict[str, Any],
                             cache_db_path: Optional[str] = None) -> str:
        """
        生成 AI 处置建议（带缓存）。

        Args:
            profile: 攻击源画像数据。
            cache_db_path: 数据库路径（启用缓存时传入）。

        Returns:
            str: 处置建议文本。
        """
        if not self.is_available():
            return ""

        # 提取稳定字段作为缓存 key，避免 updated_at 等变化字段导致缓存失效
        cache_input = self._stable_profile(profile)

        if cache_db_path:
            cached = self._get_cached(cache_db_path, "remediation", cache_input)
            if cached is not None:
                return cached

        from ai.prompts import remediation_prompt, system_prompt

        messages = [system_prompt(), remediation_prompt(profile)]
        result = self.chat_completion(messages)

        if result and cache_db_path:
            self._set_cached(cache_db_path, "remediation", cache_input, result)

        return result or ""

    @staticmethod
    def _stable_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
        """从画像中提取稳定字段，用于缓存 key。"""
        return {
            "src_ip": profile.get("src_ip", ""),
            "risk_score": profile.get("risk_score", 0),
            "risk_level": profile.get("risk_level", "low"),
            "tags": profile.get("tags", "[]"),
            "total_count": profile.get("total_count", 0),
            "attack_types": profile.get("attack_types", "{}"),
            "protocols": profile.get("protocols", "{}"),
            "is_multi_source": profile.get("is_multi_source", 0),
        }

    def generate_payload_explain(self, payloads: List[str],
                                 cache_db_path: Optional[str] = None) -> str:
        """解释 Payload。"""
        if not self.is_available():
            return ""

        key_data = {"payloads": payloads[:5]}
        if cache_db_path:
            cached = self._get_cached(cache_db_path, "payload", key_data)
            if cached is not None:
                return cached

        from ai.prompts import payload_explain_prompt, system_prompt

        messages = [system_prompt(), payload_explain_prompt(payloads)]
        result = self.chat_completion(messages)

        if result and cache_db_path:
            self._set_cached(cache_db_path, "payload", key_data, result)

        return result or ""

    def _cache_key(self, prefix: str, data: Any) -> str:
        """生成缓存键。"""
        raw = f"{prefix}:{json.dumps(data, sort_keys=True, ensure_ascii=False)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def _get_cached(self, db_path: str, prefix: str, data: Any) -> Optional[str]:
        """从 ai_analysis_cache 表读取缓存。"""
        from app.db import get_connection

        cache_key = self._cache_key(prefix, data)
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT result FROM ai_analysis_cache WHERE cache_key = ? "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (cache_key, now_iso()),
        )
        row = cursor.fetchone()
        if row:
            logger.debug("AI 缓存命中: %s", cache_key[:16])
            return row["result"]
        return None

    def _set_cached(self, db_path: str, prefix: str, data: Any, result: str):
        """写入 ai_analysis_cache 表缓存（1 小时过期）。"""
        from app.db import get_connection

        cache_key = self._cache_key(prefix, data)
        input_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        conn = get_connection(db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc)
        expires = datetime.fromtimestamp(
            now.timestamp() + 3600, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor.execute(
            """
            INSERT INTO ai_analysis_cache
                (cache_key, input_hash, model, result, usage, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                result = excluded.result,
                expires_at = excluded.expires_at
            """,
            (cache_key, input_hash, self.model, result,
             json.dumps({"tokens": len(result)}),
             now.strftime("%Y-%m-%dT%H:%M:%SZ"), expires),
        )
        conn.commit()
        logger.debug("AI 缓存已写入: %s", cache_key[:16])
