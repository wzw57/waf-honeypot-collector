"""
Web Dashboard — FastAPI 应用入口。
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.logger import get_logger

logger = get_logger("web")

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="WAF Honeypot Collector", version="1.0.0")

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def create_app(db_path: str, config: dict) -> FastAPI:
    """创建 FastAPI 应用，注入数据库路径和配置，注册路由。"""
    app.state.db_path = db_path
    app.state.config = config

    from web.routes import router as web_router
    app.include_router(web_router)
    return app
