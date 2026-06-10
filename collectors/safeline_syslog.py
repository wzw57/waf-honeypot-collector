"""
SafeLine Syslog UDP 接收器。

监听 UDP 端口接收 SafeLine WAF 发送的 Syslog 日志，
保存原始报文并尝试解析 JSON。
"""

import signal
import socket
import sys
from datetime import datetime, timezone
from typing import Callable, Optional

from app.logger import get_logger
from parsers.safeline_parser import parse_safeline_syslog

logger = get_logger("safeline_syslog")

# 全局运行标志
_running = True


def _signal_handler(signum, frame):
    """信号处理函数，实现优雅退出。"""
    global _running
    if _running:
        logger.info("收到信号 %s，正在优雅退出...", signum)
        _running = False


class SafeLineSyslogReceiver:
    """
    SafeLine Syslog UDP 接收器。

    创建 UDP Socket 监听指定地址和端口，接收 Syslog 报文，
    解析后写入数据库。
    """

    def __init__(self, host: str, port: int, buffer_size: int = 65536,
                 on_log_received: Optional[Callable] = None):
        """
        初始化接收器。

        Args:
            host: 监听地址（如 "0.0.0.0"）。
            port: 监听端口（如 1514）。
            buffer_size: UDP 接收缓冲区大小。
            on_log_received: 每条日志接收后的回调函数。
                            回调签名: callback(raw_message, sender_ip, parse_result)
        """
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.on_log_received = on_log_received
        self.sock = None
        self._stats = {"received": 0, "parsed": 0, "failed": 0}

    def start(self):
        """
        启动 UDP 接收服务（前台阻塞）。

        监听 Ctrl+C (SIGINT) 和 SIGTERM 实现优雅退出。
        """
        global _running
        _running = True

        # 注册信号处理
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # 创建 UDP Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.buffer_size)
        self.sock.settimeout(1.0)  # 1 秒超时，以便检查 _running 标志

        try:
            self.sock.bind((self.host, self.port))
        except OSError as e:
            logger.error("无法绑定 %s:%d — %s", self.host, self.port, e)
            raise

        logger.info("SafeLine Syslog 接收器已启动: %s:%d/udp", self.host, self.port)
        logger.info("按 Ctrl+C 停止接收")
        print(f"[INFO] SafeLine Syslog 接收器已启动: {self.host}:{self.port}/udp")
        print("[INFO] 按 Ctrl+C 停止接收")

        while _running:
            try:
                data, addr = self.sock.recvfrom(self.buffer_size)
                sender_ip = addr[0]
                raw_message = data.decode("utf-8", errors="replace")

                self._stats["received"] += 1

                # 解析日志
                parse_result = parse_safeline_syslog(raw_message)
                if parse_result["success"]:
                    self._stats["parsed"] += 1
                else:
                    self._stats["failed"] += 1

                logger.debug("收到来自 %s 的 Syslog (%d 字节, 解析: %s)",
                             sender_ip, len(raw_message), "成功" if parse_result["success"] else "失败")

                # 调用回调（写入数据库）
                if self.on_log_received:
                    try:
                        self.on_log_received(raw_message, sender_ip, parse_result)
                    except Exception as e:
                        logger.error("日志回调执行失败: %s", e)

            except socket.timeout:
                continue
            except Exception as e:
                logger.error("接收日志异常: %s", e, exc_info=True)
                continue

        self._shutdown()

    def _shutdown(self):
        """关闭 Socket 并输出统计信息。"""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        logger.info("SafeLine Syslog 接收器已停止")
        logger.info("本次运行统计: 接收 %d 条, 解析成功 %d 条, 解析失败 %d 条",
                     self._stats["received"], self._stats["parsed"], self._stats["failed"])
        print(f"\n[INFO] 接收器已停止")
        print(f"[INFO] 本次运行统计: 接收 {self._stats['received']} 条"
              f" | 解析成功 {self._stats['parsed']} 条"
              f" | 解析失败 {self._stats['failed']} 条")

    def get_stats(self) -> dict:
        """获取当前运行统计。"""
        return dict(self._stats)
