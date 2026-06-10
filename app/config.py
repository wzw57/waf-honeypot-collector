"""
配置加载模块。

优先从 config.yaml 加载配置，支持通过 --config 参数指定路径。
配置项缺失时使用合理的默认值。
"""

import os
from pathlib import Path

import yaml

# 默认配置文件路径（项目根目录下的 config.yaml）
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"

# 默认配置值
DEFAULT_CONFIG = {
    "app": {
        "name": "waf-honeypot-collector",
        "version": "1.0.0",
        "log_level": "INFO",
        "log_dir": "logs",
        "timezone": "Asia/Shanghai",
    },
    "database": {
        "path": "data/collector.db",
        "backup_dir": "data/backups",
    },
    "safeline": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 1514,
        "buffer_size": 65536,
        "enable_normalization": True,
    },
    "hfish": {
        "enabled": True,
        "api_url": "",
        "auth_type": "token",
        "api_token": "",
        "username": "",
        "password": "",
        "api_path": "/api/v1/attack",
        "interval": 60,
        "page_size": 100,
        "enable_normalization": True,
    },
    "ioc": {
        "enabled": True,
    },
    "profile": {
        "enabled": True,
    },
    "correlation": {
        "enabled": True,
    },
    "deepseek": {
        "enabled": False,
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "timeout": 30,
        "max_tokens": 1200,
    },
    "web": {
        "enabled": False,
        "host": "127.0.0.1",
        "port": 8000,
    },
}


def load_config(config_path=None):
    """
    从 YAML 文件加载配置。

    Args:
        config_path: 配置文件路径。为 None 时尝试默认路径。

    Returns:
        dict: 完整的配置字典。缺失的配置项使用默认值填充。

    Raises:
        FileNotFoundError: 指定的 config_path 不存在。
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(
            f"配置文件不存在: {config_path}\n"
            f"请复制示例文件后修改: cp config.yaml.example config.yaml"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        user_config = yaml.safe_load(f) or {}

    # 合并用户配置与默认配置（用户配置覆盖默认值）
    merged = _deep_merge(DEFAULT_CONFIG, user_config)

    return merged


def _deep_merge(base, override):
    """
    深度合并两个字典。override 中的值优先于 base。

    Args:
        base: 基础字典（默认配置）。
        override: 覆盖字典（用户配置）。

    Returns:
        dict: 合并后的字典。
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def resolve_env_vars(config):
    """
    将配置中的环境变量占位符替换为真实值。
    目前处理 hfish.api_token, hfish.password, deepseek.api_key_env。

    Args:
        config: 配置字典（已由 load_config 返回）。

    Returns:
        dict: 环境变量已解析的配置字典。
    """
    # DeepSeek API Key
    api_key_env = config.get("deepseek", {}).get("api_key_env", "DEEPSEEK_API_KEY")
    api_key = os.environ.get(api_key_env, "")
    config["deepseek"]["api_key"] = api_key

    # HFish API Token
    hfish_token = os.environ.get("HFISH_API_TOKEN", "")
    if hfish_token:
        config["hfish"]["api_token"] = hfish_token

    # HFish Password
    hfish_password = os.environ.get("HFISH_PASSWORD", "")
    if hfish_password:
        config["hfish"]["password"] = hfish_password

    return config


def get_config(config_path=None):
    """
    一次性获取完整配置（加载 + 环境变量解析）。

    Args:
        config_path: 配置文件路径。

    Returns:
        dict: 完整的配置字典。
    """
    cfg = load_config(config_path)
    cfg = resolve_env_vars(cfg)
    return cfg
