"""
Web Dashboard — 路由定义。
"""

import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from app.db import (
    get_connection,
    get_extended_stats,
    get_events_by_ip,
    get_iocs,
    get_latest_hfish_events,
    get_latest_normalized_events,
    get_latest_safeline_logs,
    get_profile_by_ip,
    get_profile_stats,
    get_top_ips,
)
from app.logger import get_logger

logger = get_logger("web_router")

from pathlib import Path

from fastapi.templating import Jinja2Templates

router = APIRouter()

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


def _tpl():
    """获取 Jinja2Templates 实例。"""
    return _templates


def _get_db(request: Request) -> str:
    """从 request state 获取数据库路径。"""
    return request.app.state.db_path


# ========== 页面路由 ==========


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """首页概览。"""
    db = _get_db(request)
    ext = get_extended_stats(db)
    prof = get_profile_stats(db)

    total_events = ext["safeline"]["total"] + ext["hfish"]["total"]
    normalized = ext["normalized"]["total"]

    ctx = {
        "request": request,
        "total_events": total_events,
        "normalized": normalized,
        "total_profiles": prof["total_profiles"],
        "multi_source": prof["multi_source_count"],
        "high_risk": prof["level_distribution"].get("high", 0),
        "critical_risk": prof["level_distribution"].get("critical", 0),
        "safeline_total": ext["safeline"]["total"],
        "hfish_total": ext["hfish"]["total"],
    }
    return _tpl().TemplateResponse(request, "index.html", ctx)


@router.get("/events", response_class=HTMLResponse)
async def events_page(
    request: Request,
    source: Optional[str] = None,
    attack_type: Optional[str] = None,
    ip: Optional[str] = None,
    page: int = Query(1, ge=1),
):
    """事件列表页。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()
    limit = 50
    offset = (page - 1) * limit

    where = []
    params = []
    if source:
        where.append("source = ?")
        params.append(source)
    if attack_type:
        where.append("attack_type = ?")
        params.append(attack_type)
    if ip:
        where.append("src_ip = ?")
        params.append(ip)

    where_clause = (" WHERE " + " AND ".join(where)) if where else ""

    cursor.execute(
        f"SELECT COUNT(*) as cnt FROM normalized_events{where_clause}", params
    )
    total = cursor.fetchone()["cnt"]

    cursor.execute(
        f"SELECT * FROM normalized_events{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    )
    events = [dict(r) for r in cursor.fetchall()]

    total_pages = max(1, (total + limit - 1) // limit)

    # 获取筛选选项
    cursor.execute(
        "SELECT DISTINCT attack_type FROM normalized_events WHERE attack_type IS NOT NULL AND attack_type != '' ORDER BY attack_type"
    )
    attack_types = [r["attack_type"] for r in cursor.fetchall()]

    ctx = {
        "request": request,
        "events": events,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "source_filter": source or "",
        "attack_type_filter": attack_type or "",
        "ip_filter": ip or "",
        "attack_types": attack_types,
    }
    return _tpl().TemplateResponse(request, "events.html", ctx)


@router.get("/top-ip", response_class=HTMLResponse)
async def top_ip_page(request: Request, sort: str = "total_count"):
    """Top 攻击源。"""
    db = _get_db(request)
    ips = get_top_ips(db, sort_by=sort, limit=50)

    for p in ips:
        try:
            tags = json.loads(p["tags"]) if p.get("tags") else []
            p["tags_list"] = tags[:4]
        except (json.JSONDecodeError, TypeError):
            p["tags_list"] = []

    ctx = {"request": request, "ips": ips, "sort": sort}
    return _tpl().TemplateResponse(request, "top_ip.html", ctx)


@router.get("/profile/{ip}", response_class=HTMLResponse)
async def ip_detail_page(request: Request, ip: str):
    """IP 详情。"""
    db = _get_db(request)
    profile = get_profile_by_ip(db, ip)
    events = get_events_by_ip(db, ip, limit=200)
    iocs_all = get_iocs(db, limit=200)
    ip_iocs = [i for i in iocs_all if i.get("src_ip") == ip]

    if not profile:
        ctx = {"request": request, "ip": ip, "not_found": True}
        return _tpl().TemplateResponse(request, "ip_detail.html", ctx)

    # 解析 JSON 字段
    for field in ("attack_types", "protocols", "tags"):
        val = profile.get(field)
        if val and isinstance(val, str):
            try:
                profile[field] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                profile[field] = {}

    ctx = {
        "request": request,
        "ip": ip,
        "profile": profile,
        "events": events,
        "iocs": ip_iocs,
        "not_found": False,
    }
    return _tpl().TemplateResponse(request, "ip_detail.html", ctx)


@router.get("/iocs", response_class=HTMLResponse)
async def iocs_page(request: Request, ioc_type: Optional[str] = None):
    """IOC 列表。"""
    db = _get_db(request)
    items = get_iocs(db, ioc_type=ioc_type, limit=200)

    conn = get_connection(db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT DISTINCT ioc_type FROM iocs ORDER BY ioc_type"
    )
    types = [r["ioc_type"] for r in cursor.fetchall()]

    ctx = {
        "request": request,
        "iocs": items,
        "types": types,
        "current_type": ioc_type or "",
    }
    return _tpl().TemplateResponse(request, "iocs.html", ctx)


@router.get("/attack-types", response_class=HTMLResponse)
async def attack_types_page(request: Request):
    """攻击类型分布。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM normalized_events "
        "WHERE attack_type IS NOT NULL AND attack_type != '' "
        "GROUP BY attack_type ORDER BY cnt DESC"
    )
    data = [dict(r) for r in cursor.fetchall()]

    ctx = {"request": request, "data": data}
    return _tpl().TemplateResponse(request, "attack_types.html", ctx)


@router.get("/trends", response_class=HTMLResponse)
async def trends_page(request: Request):
    """趋势视图。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()

    # 按日期统计
    cursor.execute("""
        SELECT substr(event_time, 1, 10) as day, source, COUNT(*) as cnt
        FROM normalized_events
        GROUP BY day, source ORDER BY day
    """)
    rows = cursor.fetchall()

    days = {}
    for r in rows:
        day = r["day"]
        if day not in days:
            days[day] = {"safeline": 0, "hfish": 0}
        if r["source"] in days[day]:
            days[day][r["source"]] = r["cnt"]

    trend_data = [{"day": d, **v} for d, v in sorted(days.items())]

    ctx = {"request": request, "trend_data": trend_data}
    return _tpl().TemplateResponse(request, "trends.html", ctx)


@router.get("/high-risk", response_class=HTMLResponse)
async def high_risk_page(request: Request):
    """高风险 IP。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM attacker_profiles WHERE risk_level IN ('high', 'critical') "
        "ORDER BY risk_score DESC LIMIT 100"
    )
    ips = [dict(r) for r in cursor.fetchall()]

    for p in ips:
        try:
            tags = json.loads(p["tags"]) if p.get("tags") else []
            p["tags_list"] = tags[:5]
        except (json.JSONDecodeError, TypeError):
            p["tags_list"] = []

    ctx = {"request": request, "ips": ips}
    return _tpl().TemplateResponse(request, "high_risk.html", ctx)


@router.get("/report/{ip}", response_class=HTMLResponse)
async def report_view_page(request: Request, ip: str):
    """报告在线查看。"""
    db = _get_db(request)
    from reports.markdown_report import generate_report

    report = generate_report(db, ip)
    if not report:
        ctx = {"request": request, "ip": ip, "not_found": True}
        return _tpl().TemplateResponse(request, "report_view.html", ctx)

    ctx = {"request": request, "ip": ip, "report_content": report, "not_found": False}
    return _tpl().TemplateResponse(request, "report_view.html", ctx)


# ========== API 路由（图表数据） ==========


@router.get("/api/stats")
async def api_stats(request: Request):
    """首页统计数据。"""
    db = _get_db(request)
    ext = get_extended_stats(db)
    prof = get_profile_stats(db)
    return {
        "total_events": ext["safeline"]["total"] + ext["hfish"]["total"],
        "normalized": ext["normalized"]["total"],
        "safeline": ext["safeline"]["total"],
        "hfish": ext["hfish"]["total"],
        "profiles": prof["total_profiles"],
        "multi_source": prof["multi_source_count"],
        "high_risk": prof["level_distribution"].get("high", 0),
        "critical_risk": prof["level_distribution"].get("critical", 0),
    }


@router.get("/api/events")
async def api_events(
    request: Request,
    source: Optional[str] = None,
    limit: int = 50,
):
    """事件 JSON 数据。"""
    db = _get_db(request)
    events = get_latest_normalized_events(db, limit=limit, source=source)
    return {"events": events}


@router.get("/api/attack-types-distribution")
async def api_attack_types(request: Request):
    """攻击类型分布数据。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM normalized_events "
        "WHERE attack_type IS NOT NULL AND attack_type != '' "
        "GROUP BY attack_type ORDER BY cnt DESC LIMIT 20"
    )
    return [dict(r) for r in cursor.fetchall()]


@router.get("/api/trends")
async def api_trends(request: Request):
    """趋势数据。"""
    db = _get_db(request)
    conn = get_connection(db)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT substr(event_time, 1, 10) as day, source, COUNT(*) as cnt
        FROM normalized_events
        GROUP BY day, source ORDER BY day
    """)
    return [dict(r) for r in cursor.fetchall()]


# templates is imported from server at registration time

