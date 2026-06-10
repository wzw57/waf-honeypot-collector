"""
日志配置模块。

统一日志格式和输出方式。所有模块通过此配置获取 logger。
"""

import logging
import sys
from pathlib import Path

# 日志格式
DEFAULT_FORMAT = "%(asctime)s [%(levelname)-7s] %(name)s - %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level="INFO", log_dir=None, logger_name=None):
    """
    配置统一的日志系统。

    Args:
        level: 日志级别（DEBUG / INFO / WARNING / ERROR）。
        log_dir: 日志文件目录。为 None 时仅输出到控制台。
        logger_name: 要配置的 logger 名称。为 None 时配置 root logger。

    Returns:
        logging.Logger: 配置好的 logger 对象。
    """
    level = getattr(logging, level.upper(), logging.INFO)

    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    # 清除已有 handler，避免重复添加
    logger.handlers.clear()

    # 控制台 Handler（始终启用）
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(DEFAULT_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 文件 Handler（可选）
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            log_path / "collector.log", encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(DEFAULT_FORMAT, datefmt=DEFAULT_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name=None):
    """
    获取指定名称的 logger。如果尚未配置，会设置合理的默认值。

    Args:
        name: logger 名称，通常传入 __name__。

    Returns:
        logging.Logger: logger 对象。
    """
    logger = logging.getLogger(name)

    # 如果没有任何 handler，设置默认配置
    if not logger.handlers:
        setup_logging(logger_name=name)

    return logger
