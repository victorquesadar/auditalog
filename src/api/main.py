"""API FastAPI + Dashboard de AuditaLog.

Levantar en desarrollo:
    uvicorn src.api.main:app --reload

Endpoints:
    GET  /                   → Dashboard HTML
    GET  /eventos            → Página con tabla de últimos 50 eventos
    GET  /alertas            → Página con tabla de alertas abiertas
    GET  /api/events         → JSON de eventos (con filtros + paginación)
    GET  /api/alerts         → JSON de alertas
    GET  /api/dashboard      → JSON con KPIs del dashboard (usa caché Redis TTL 30s)
    POST /api/ingest         → Recibe un evento JSON y lo mete al stream
    GET  /api/health         → Ping de los 3 motores
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import redis
from bson import ObjectId
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from pymongo import DESCENDING, MongoClient

from src.common.config import key, settings

BASE = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE / "templates"))

APP_VERSION = "1.0.0"

app = FastAPI(
    title="AuditaLog",
    description="Bitácora de auditoría de accesos y cambios de configuración.",
    version=APP_VERSION,
)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

# ----------------------------------------------------------------------------
# Autenticación (opcional, se activa definiendo AUTH_USER y AUTH_PASS en .env)
# ----------------------------------------------------------------------------
from src.api.auth import (  # noqa: E402
    AuthMiddleware, SESSION_COOKIE, SESSION_MAX_AGE,
    auth_enabled, check_credentials, make_session_value, render_login_page,
)
from fastapi import Form  # noqa: E402
from fastapi.responses import PlainTextResponse  # noqa: E402

app.add_middleware(AuthMiddleware)


@app.get("/login", response_class=HTMLResponse)
def view_login(request: Request, next: str = "/", error: Optional[str] = None):
    """Página de login. Si la auth está desactivada, redirige al dashboard."""
    if not auth_enabled():
        return RedirectResponse("/", status_code=303)
    from fastapi.responses import HTMLResponse as _HTML
    return _HTML(render_login_page(error=error, next_url=next))


@app.post("/login")
def do_login(
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
):
    """Procesa el formulario de login."""
    if not auth_enabled():
        return RedirectResponse("/", status_code=303)
    if not check_credentials(username, password):
        from fastapi.responses import HTMLResponse as _HTML
        return _HTML(
            render_login_page(error="Usuario o contraseña incorrectos", next_url=next),
            status_code=401,
        )
    value = make_session_value(username)
    resp = RedirectResponse(next or "/", status_code=303)
    resp.set_cookie(
        key=SESSION_COOKIE, value=value, max_age=SESSION_MAX_AGE,
        httponly=True, samesite="lax",
    )
    return resp


@app.get("/logout")
def do_logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# Necesarios arriba
from fastapi.responses import RedirectResponse  # noqa: E402


# ----------------------------------------------------------------------------
# Conexiones (singletons simples)
# ----------------------------------------------------------------------------

_mongo: Optional[MongoClient] = None
_redis: Optional[redis.Redis] = None


def get_mongo() -> MongoClient:
    global _mongo
    if _mongo is None:
        _mongo = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    return _mongo


def get_db():
    return get_mongo()[settings.mongo_db]


def get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db,
            decode_responses=True,
        )
    return _redis


# ----------------------------------------------------------------------------
# Serialización
# ----------------------------------------------------------------------------

def _serialize(doc: dict) -> dict:
    """Convierte un documento Mongo a dict JSON-friendly."""
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime):
            out[k] = v.isoformat()
        elif isinstance(v, dict):
            out[k] = _serialize(v)
        elif isinstance(v, list):
            out[k] = [_serialize(x) if isinstance(x, dict) else
                      (str(x) if isinstance(x, ObjectId) else x) for x in v]
        else:
            out[k] = v
    # Enriquecer con GeoIP si tiene IP
    ip = out.get("ip")
    if not ip and isinstance(out.get("evidence"), dict):
        ip = out["evidence"].get("ip")
    if ip and isinstance(ip, str):
        try:
            from src.common.geoip import lookup_ip
            out["geo"] = lookup_ip(ip)
        except Exception:
            pass
    return out


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------

@app.get("/api/health")
def health():
    from src.common.geoip import status as geoip_status
    status: dict[str, Any] = {"app": "ok", "version": app.version}
    try:
        get_mongo().admin.command("ping")
        status["mongo"] = "ok"
    except Exception as e:
        status["mongo"] = f"error: {e}"
    try:
        get_redis().ping()
        status["redis"] = "ok"
    except Exception as e:
        status["redis"] = f"error: {e}"
    status["geoip"] = geoip_status()
    return status


# ----------------------------------------------------------------------------
# GET /api/geoip/{ip} — resolver una IP a país + ASN (sin llamar a internet)
# ----------------------------------------------------------------------------

@app.get("/api/geoip/{ip}")
def api_geoip(ip: str):
    from src.common.geoip import lookup_ip
    return lookup_ip(ip)


# ----------------------------------------------------------------------------
# POST /api/geoip/refresh — descarga DB-IP Lite desde el servidor y recarga
# ----------------------------------------------------------------------------

@app.post("/api/geoip/refresh")
def api_geoip_refresh():
    """Descarga DB-IP Lite MMDB (country + ASN) en el servidor y limpia el caché
    del módulo geoip para que empiece a usar la base completa en el próximo request.

    No requiere license key — DB-IP Lite es gratis sin registro.
    Esta operación puede tardar 30-90 segundos (son unos ~20 MB).
    """
    import os as _os
    import subprocess
    import sys as _sys
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[2]
    script = root / "scripts" / "download_geoip.py"
    if not script.exists():
        raise HTTPException(status_code=500, detail="scripts/download_geoip.py no existe")

    # Cerrar los readers antes de descargar — en Windows maxminddb
    # mapea el archivo con mmap y lo bloquea para escritura.
    try:
        from src.common import geoip as _geoip
        _geoip.close_readers()
    except Exception:
        pass

    try:
        env = dict(_os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [_sys.executable, str(script)],
            capture_output=True, text=True, timeout=180, cwd=str(root),
            env=env, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="timeout descargando DB-IP Lite")

    # Asegurar reset total después de la descarga
    try:
        from src.common import geoip as _geoip
        _geoip.close_readers()
    except Exception:
        pass

    return {
        "ok": proc.returncode == 0,
        "stdout": proc.stdout.strip().split("\n")[-20:],
        "stderr": proc.stderr.strip().split("\n")[-5:] if proc.stderr else [],
    }


# ----------------------------------------------------------------------------
# GET /api/geo-summary — alertas agrupadas por país y por ASN
# ----------------------------------------------------------------------------

@app.get("/api/geo-summary")
def api_geo_summary(limit: int = Query(20, ge=1, le=100)):
    """Agrupa las alertas por país y por ASN para el dashboard GeoIP.

    Resuelve las IPs localmente (sin APIs HTTP) y devuelve los TOP N por volumen.
    """
    from src.common.geoip import lookup_ip
    from collections import Counter

    db = get_db()

    by_country: Counter = Counter()
    by_country_iso: dict[str, str] = {}
    by_asn: Counter = Counter()
    asn_org: dict = {}
    ip_count: Counter = Counter()
    ip_geo: dict = {}

    total = 0
    for alert in db.alerts.find({"evidence.ip": {"$exists": True, "$ne": None}}, {"evidence.ip": 1}):
        ip = (alert.get("evidence") or {}).get("ip")
        if not ip:
            continue
        info = lookup_ip(ip)
        total += 1
        by_country[info["country"]] += 1
        by_country_iso[info["country"]] = info["country_iso"]
        asn = info["asn"]
        key_asn = f"AS{asn}" if asn else "AS?"
        by_asn[key_asn] += 1
        asn_org[key_asn] = info["organization"]
        ip_count[ip] += 1
        ip_geo[ip] = info

    def _pct(n: int) -> float:
        return round(n * 100 / total, 1) if total else 0.0

    return {
        "total_alerts_with_ip": total,
        "by_country": [
            {"country": c, "iso": by_country_iso[c], "count": n, "pct": _pct(n)}
            for c, n in by_country.most_common(limit)
        ],
        "by_asn": [
            {"asn": a, "organization": asn_org[a], "count": n, "pct": _pct(n)}
            for a, n in by_asn.most_common(limit)
        ],
        "top_ips": [
            {
                "ip": ip,
                "count": n,
                "country_iso": ip_geo[ip]["country_iso"],
                "country": ip_geo[ip]["country"],
                "asn": ip_geo[ip]["asn"],
                "organization": ip_geo[ip]["organization"],
            }
            for ip, n in ip_count.most_common(limit)
        ],
    }


# ----------------------------------------------------------------------------
# JSON API — Events
# ----------------------------------------------------------------------------

@app.get("/api/events")
def api_events(
    source: Optional[str] = Query(None, description="auth.log | access.log | app"),
    severity: Optional[str] = Query(None, description="info | warn | critical"),
    ip: Optional[str] = None,
    user: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
):
    db = get_db()
    q: dict[str, Any] = {}
    if source: q["source"] = source
    if severity: q["severity"] = severity
    if ip: q["ip"] = ip
    if user: q["user"] = user

    total = db.events.count_documents(q)
    cursor = db.events.find(q).sort("ts", DESCENDING).skip(skip).limit(limit)
    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "items": [_serialize(e) for e in cursor],
    }


# ----------------------------------------------------------------------------
# JSON API — Alerts
# ----------------------------------------------------------------------------

@app.get("/api/alerts")
def api_alerts(
    status_filter: Optional[str] = Query(None, alias="status",
                                         description="open | acknowledged | closed"),
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
):
    db = get_db()
    q: dict[str, Any] = {}
    if status_filter: q["status"] = status_filter
    if severity: q["severity"] = severity

    total = db.alerts.count_documents(q)
    cursor = db.alerts.find(q).sort("fired_at", DESCENDING).skip(skip).limit(limit)
    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "items": [_serialize(a) for a in cursor],
    }


# ----------------------------------------------------------------------------
# JSON API — Dashboard (con caché Redis)
# ----------------------------------------------------------------------------

@app.get("/api/dashboard")
def api_dashboard():
    r = get_redis()
    cache_key = key("cache:dashboard:v1")

    cached = r.get(cache_key)
    if cached:
        return JSONResponse(json.loads(cached), headers={"X-Cache": "HIT"})

    db = get_db()
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    data = {
        "events_last_hour": db.events.count_documents({"ts": {"$gte": hour_ago}}),
        "events_last_day": db.events.count_documents({"ts": {"$gte": day_ago}}),
        "events_total": db.events.count_documents({}),
        "alerts_open": db.alerts.count_documents({"status": "open"}),
        "alerts_critical": db.alerts.count_documents({"severity": "critical", "status": "open"}),
        "by_severity": {
            s: db.events.count_documents({"severity": s})
            for s in ("info", "warn", "critical")
        },
        "by_source": {
            s: db.events.count_documents({"source": s})
            for s in ("auth.log", "access.log", "app")
        },
        "top_ips": [
            {"ip": doc["_id"], "count": doc["count"]}
            for doc in db.events.aggregate([
                {"$match": {"action": "login_failed"}},
                {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
            ])
        ],
        "generated_at": now.isoformat(),
    }

    r.setex(cache_key, 30, json.dumps(data))
    return JSONResponse(data, headers={"X-Cache": "MISS"})


# ----------------------------------------------------------------------------
# JSON API — Ingesta (POST /api/ingest)
# ----------------------------------------------------------------------------

class IngestEvent(BaseModel):
    source: str = Field(..., description="auth.log | access.log | app")
    ts: Optional[datetime] = None
    host: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    action: str
    severity: str = Field("info", pattern="^(info|warn|critical)$")
    detail: dict = Field(default_factory=dict)
    raw: Optional[str] = None


@app.post("/api/ingest", status_code=201)
def api_ingest(evento: IngestEvent):
    """Ingesta directa: inserta el evento en Mongo y aplica reglas al toque.

    No depende del worker — el evento aparece inmediatamente en /eventos y las
    alertas que dispare aparecen en /alertas. Para ingesta masiva desde archivos
    de log, usar el colector + worker vía Redis Streams.
    """
    from src.common.rules import apply_rules
    from bson import ObjectId as _OID

    db = get_db()
    r = get_redis()

    ts = evento.ts or datetime.now(timezone.utc)
    event_doc = {
        "source": evento.source,
        "host": evento.host,
        "ts": ts,
        "ingested_at": datetime.now(timezone.utc),
        "user": evento.user,
        "ip": evento.ip,
        "action": evento.action,
        "detail": evento.detail,
        "severity": evento.severity,
        "raw": evento.raw or f"{ts.isoformat()} manual ingest",
    }
    res = db.events.insert_one(event_doc)
    event_doc["_id"] = res.inserted_id

    alerts = apply_rules(r, db, event_doc, res.inserted_id)

    return {
        "accepted": True,
        "event_id": str(res.inserted_id),
        "alerts_fired": len(alerts),
        "alerts": [{"rule_id": a["rule_id"], "title": a["title"]} for a in alerts],
    }


# ----------------------------------------------------------------------------
# POST /api/alerts — crear una alerta manual (útil para demo)
# ----------------------------------------------------------------------------

class AlertCreate(BaseModel):
    rule_id: str = Field(..., min_length=1)
    severity: str = Field("warn", pattern="^(info|warn|critical)$")
    title: str = Field(..., min_length=1)
    evidence: dict = Field(default_factory=dict)
    status: str = Field("open", pattern="^(open|acknowledged|closed)$")


@app.post("/api/alerts", status_code=201)
def api_create_alert(alert: AlertCreate):
    db = get_db()
    doc = {
        **alert.model_dump(),
        "fired_at": datetime.now(timezone.utc),
    }
    res = db.alerts.insert_one(doc)
    return {"created": True, "alert_id": str(res.inserted_id)}


# ----------------------------------------------------------------------------
# Vistas HTML
# ----------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return TEMPLATES.TemplateResponse(request, "dashboard.html")


@app.get("/eventos", response_class=HTMLResponse)
def view_events(request: Request):
    return TEMPLATES.TemplateResponse(request, "events.html")


@app.get("/alertas", response_class=HTMLResponse)
def view_alerts(request: Request):
    return TEMPLATES.TemplateResponse(request, "alerts.html")


@app.get("/ingesta", response_class=HTMLResponse)
def view_ingest(request: Request):
    return TEMPLATES.TemplateResponse(request, "ingesta.html")


@app.get("/exportar", response_class=HTMLResponse)
def view_export(request: Request):
    return TEMPLATES.TemplateResponse(request, "exportar.html")


@app.get("/subir", response_class=HTMLResponse)
def view_upload(request: Request):
    return TEMPLATES.TemplateResponse(request, "subir.html")


@app.get("/geo", response_class=HTMLResponse)
def view_geo(request: Request):
    return TEMPLATES.TemplateResponse(request, "geo.html")


# ----------------------------------------------------------------------------
# POST /api/reset — limpia events, alerts y claves Redis
# ----------------------------------------------------------------------------

@app.post("/api/reset")
def api_reset(
    scope: str = Query("all", description="all | events | alerts | redis"),
):
    """Limpia datos del sistema. Pensado para resetear después de pruebas."""
    db = get_db()
    r = get_redis()
    result = {"scope": scope, "events_deleted": 0, "alerts_deleted": 0, "redis_keys_deleted": 0}

    if scope in ("all", "events"):
        result["events_deleted"] = db.events.delete_many({}).deleted_count
    if scope in ("all", "alerts"):
        result["alerts_deleted"] = db.alerts.delete_many({}).deleted_count
    if scope in ("all", "redis"):
        # Borrar todas las claves con el prefijo del grupo
        pattern = key("")  # ej. "grupo4:auditalog:"
        keys = list(r.scan_iter(f"{pattern}*"))
        if keys:
            r.delete(*keys)
            result["redis_keys_deleted"] = len(keys)

    return result


# ----------------------------------------------------------------------------
# POST /api/export/xlsx — exporta análisis + eventos a Excel multi-hoja
# ----------------------------------------------------------------------------

@app.post("/api/export/xlsx")
def api_export_xlsx(
    include_events: bool = Query(True, description="Si True, incluye hoja Eventos (puede ser grande)"),
    events_limit: int = Query(5000, ge=100, le=50_000),
):
    """Exporta a Excel multi-hoja: Resumen, Alertas por regla, Top IPs,
    Alertas, (opcional) Eventos."""
    from io import BytesIO
    import tempfile, os as _os
    from fastapi.responses import FileResponse as _FR
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.chart import BarChart, DoughnutChart, Reference
        from openpyxl.chart.label import DataLabelList
        from openpyxl.formatting.rule import ColorScaleRule, CellIsRule
    except ImportError:
        raise HTTPException(status_code=500,
                            detail="openpyxl no está instalado. pip install openpyxl")

    db = get_db()
    now = datetime.now(timezone.utc)

    HEADER_FILL = PatternFill("solid", fgColor="0F172A")
    HEADER_FONT = Font(bold=True, color="FFFFFF")
    TITLE_FONT = Font(bold=True, size=16, color="0F172A")
    SECTION_FONT = Font(bold=True, size=12, color="0F172A")
    SUB_FONT = Font(italic=True, color="6B7280")
    KPI_FONT = Font(bold=True, size=20, color="059669")

    SEV_FILLS = {
        "critical": PatternFill("solid", fgColor="FEE2E2"),
        "warn":     PatternFill("solid", fgColor="FEF3C7"),
        "info":     PatternFill("solid", fgColor="DBEAFE"),
    }

    THIN_BORDER = Border(
        bottom=Side(style="thin", color="E5E7EB"),
    )

    def _header_row(ws, row: int, headers: list[str]):
        for col, h in enumerate(headers, start=1):
            c = ws.cell(row=row, column=col, value=h)
            c.fill = HEADER_FILL
            c.font = HEADER_FONT
            c.alignment = Alignment(horizontal="left", vertical="center")
            c.border = THIN_BORDER

    def _autosize(ws, cols: int, max_width: int = 60):
        for i in range(1, cols + 1):
            letter = get_column_letter(i)
            longest = 0
            for row in ws.iter_rows(min_col=i, max_col=i, values_only=True):
                v = row[0]
                if v is not None:
                    longest = max(longest, len(str(v)))
            ws.column_dimensions[letter].width = min(max(longest + 2, 10), max_width)

    def _iso(v):
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d %H:%M:%S")
        return str(v) if v is not None else ""

    wb = Workbook()

    # ===== Datos agregados (los usamos varias veces) =====
    total_events = db.events.count_documents({})
    total_alerts = db.alerts.count_documents({})
    open_alerts = db.alerts.count_documents({"status": "open"})
    crit_alerts = db.alerts.count_documents({"severity": "critical", "status": "open"})

    by_source = list(db.events.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]))
    by_severity = list(db.events.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]))
    by_rule = list(db.alerts.aggregate([
        {"$group": {"_id": "$rule_id", "count": {"$sum": 1},
                    "severity": {"$first": "$severity"}}},
        {"$sort": {"count": -1}},
    ]))
    top_ips = list(db.alerts.aggregate([
        {"$match": {"evidence.ip": {"$exists": True, "$ne": None}}},
        {"$group": {"_id": "$evidence.ip", "count": {"$sum": 1},
                    "rules": {"$addToSet": "$rule_id"}}},
        {"$sort": {"count": -1}},
        {"$limit": 100},
    ]))

    # -------- Hoja 1: Resumen (con KPI tiles y chart de severidad) --------
    ws = wb.active
    ws.title = "Resumen"

    ws["A1"] = "AuditaLog · Reporte del análisis"
    ws["A1"].font = TITLE_FONT
    ws.merge_cells("A1:F1")
    ws["A2"] = f"Generado: {now.strftime('%Y-%m-%d %H:%M UTC')}  ·  AuditaLog v{APP_VERSION}"
    ws["A2"].font = SUB_FONT
    ws.merge_cells("A2:F2")

    # KPI tiles (bloque de 4 celdas con número grande)
    kpis = [
        (3, "A", "Eventos auditados", total_events, "0F172A"),
        (3, "C", "Alertas totales", total_alerts, "0F172A"),
        (3, "E", "Alertas abiertas", open_alerts, "D97706"),
        (3, "G", "Alertas críticas", crit_alerts, "DC2626"),
    ]
    for row, col_letter, label, value, color in kpis:
        c = ws[f"{col_letter}{row}"]
        c.value = label
        c.font = Font(size=9, color="6B7280", bold=True)
        c = ws[f"{col_letter}{row+1}"]
        c.value = value
        c.font = Font(bold=True, size=22, color=color)
    ws.row_dimensions[4].height = 36

    # Encabezado "Eventos por fuente"
    ws.cell(row=7, column=1, value="📥 Eventos por fuente").font = SECTION_FONT
    _header_row(ws, 8, ["Fuente", "Cantidad"])
    for i, row in enumerate(by_source, start=9):
        ws.cell(row=i, column=1, value=row["_id"] or "(desconocido)")
        ws.cell(row=i, column=2, value=row["count"]).border = THIN_BORDER

    # Encabezado "Eventos por severidad" (con chart)
    sev_start = 9 + len(by_source) + 2
    ws.cell(row=sev_start - 1, column=1, value="⚠️ Eventos por severidad").font = SECTION_FONT
    _header_row(ws, sev_start, ["Severidad", "Cantidad"])
    for i, row in enumerate(by_severity, start=sev_start + 1):
        c_sev = ws.cell(row=i, column=1, value=row["_id"])
        c_cnt = ws.cell(row=i, column=2, value=row["count"])
        if row["_id"] in SEV_FILLS:
            c_sev.fill = SEV_FILLS[row["_id"]]
            c_cnt.fill = SEV_FILLS[row["_id"]]

    # Chart de dona para severidad
    if by_severity:
        chart = DoughnutChart()
        chart.title = "Eventos por severidad"
        chart.style = 10
        labels = Reference(ws, min_col=1, min_row=sev_start + 1, max_row=sev_start + len(by_severity))
        data = Reference(ws, min_col=2, min_row=sev_start, max_row=sev_start + len(by_severity))
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(labels)
        chart.width = 11
        chart.height = 8
        chart.dataLabels = DataLabelList(showPercent=True)
        ws.add_chart(chart, f"D{sev_start - 1}")

    _autosize(ws, 7)

    # -------- Hoja 2: Alertas por regla (con chart de barras) --------
    ws = wb.create_sheet("Alertas por regla")
    ws["A1"] = "Distribución de alertas por regla disparada"
    ws["A1"].font = TITLE_FONT
    ws.merge_cells("A1:D1")

    _header_row(ws, 3, ["Regla", "Severidad", "Cantidad"])
    for i, row in enumerate(by_rule, start=4):
        c_rule = ws.cell(row=i, column=1, value=row["_id"])
        c_sev = ws.cell(row=i, column=2, value=row.get("severity", "?"))
        c_cnt = ws.cell(row=i, column=3, value=row["count"])
        sev = row.get("severity")
        if sev in SEV_FILLS:
            c_sev.fill = SEV_FILLS[sev]
        c_rule.border = c_sev.border = c_cnt.border = THIN_BORDER

    # Formato condicional de barras de color sobre la columna Cantidad
    if by_rule:
        last_row = 3 + len(by_rule)
        ws.conditional_formatting.add(
            f"C4:C{last_row}",
            ColorScaleRule(
                start_type="min", start_color="DBEAFE",
                mid_type="percentile", mid_value=50, mid_color="FBBF24",
                end_type="max", end_color="DC2626",
            ),
        )

        # Chart de barras horizontal
        chart = BarChart()
        chart.type = "bar"
        chart.style = 11
        chart.title = "Top reglas por cantidad de alertas"
        chart.y_axis.title = "Regla"
        chart.x_axis.title = "Cantidad"
        labels = Reference(ws, min_col=1, min_row=4, max_row=last_row)
        data = Reference(ws, min_col=3, min_row=3, max_row=last_row)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(labels)
        chart.width = 18
        chart.height = max(10, min(20, len(by_rule) * 1.1))
        ws.add_chart(chart, "E3")

    _autosize(ws, 3)

    # -------- Hoja 3: Top IPs sospechosas (con chart y geo) --------
    try:
        from src.common.geoip import lookup_ip as _geolookup3
    except Exception:
        _geolookup3 = lambda ip: {"country_iso": "", "country": "", "asn": None, "organization": ""}

    ws = wb.create_sheet("Top IPs")
    ws["A1"] = "IPs con más alertas"
    ws["A1"].font = TITLE_FONT
    ws.merge_cells("A1:G1")

    _header_row(ws, 3, ["IP", "Alertas", "País", "Código", "ASN",
                        "Proveedor / ISP", "Reglas disparadas"])
    for i, row in enumerate(top_ips, start=4):
        ip = row["_id"]
        geo = _geolookup3(ip) if ip else {}
        ws.cell(row=i, column=1, value=ip).border = THIN_BORDER
        c = ws.cell(row=i, column=2, value=row["count"])
        c.border = THIN_BORDER
        c.font = Font(bold=True)
        ws.cell(row=i, column=3, value=geo.get("country", "")).border = THIN_BORDER
        ws.cell(row=i, column=4, value=geo.get("country_iso", "")).border = THIN_BORDER
        ws.cell(row=i, column=5, value=f"AS{geo['asn']}" if geo.get("asn") else "").border = THIN_BORDER
        ws.cell(row=i, column=6, value=geo.get("organization", "")).border = THIN_BORDER
        ws.cell(row=i, column=7, value=", ".join(sorted(row["rules"]))).border = THIN_BORDER

    # Formato condicional + chart de las top 15
    if top_ips:
        last_row = 3 + len(top_ips)
        ws.conditional_formatting.add(
            f"B4:B{last_row}",
            ColorScaleRule(
                start_type="min", start_color="FEF3C7",
                end_type="max", end_color="DC2626",
            ),
        )
        # Chart solo del top 15 para que sea legible
        top_n = min(15, len(top_ips))
        chart = BarChart()
        chart.type = "bar"
        chart.style = 12
        chart.title = f"Top {top_n} IPs sospechosas"
        chart.y_axis.title = "IP"
        chart.x_axis.title = "Alertas"
        labels = Reference(ws, min_col=1, min_row=4, max_row=3 + top_n)
        data = Reference(ws, min_col=2, min_row=3, max_row=3 + top_n)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(labels)
        chart.width = 18
        chart.height = max(10, top_n * 0.7)
        ws.add_chart(chart, "I3")

    _autosize(ws, 7, max_width=50)

    # -------- Hoja extra: Agrupación por país / ASN (GeoIP) --------
    try:
        from src.common.geoip import lookup_ip
        from collections import Counter

        country_cnt: Counter = Counter()
        country_iso: dict = {}
        asn_cnt: Counter = Counter()
        asn_org: dict = {}
        total_ip = 0
        for a in db.alerts.find({"evidence.ip": {"$exists": True, "$ne": None}}, {"evidence.ip": 1}):
            ip = (a.get("evidence") or {}).get("ip")
            if not ip:
                continue
            info = lookup_ip(ip)
            total_ip += 1
            country_cnt[info["country"]] += 1
            country_iso[info["country"]] = info["country_iso"]
            k_asn = f"AS{info['asn']}" if info["asn"] else "AS?"
            asn_cnt[k_asn] += 1
            asn_org[k_asn] = info["organization"]

        if total_ip:
            ws = wb.create_sheet("Por país")
            ws["A1"] = "Ataques agrupados por país"
            ws["A1"].font = TITLE_FONT
            ws.merge_cells("A1:E1")
            _header_row(ws, 3, ["#", "Código", "País", "Alertas", "% del total"])
            for i, (c, n) in enumerate(country_cnt.most_common(50), start=4):
                ws.cell(row=i, column=1, value=i-3)
                ws.cell(row=i, column=2, value=country_iso[c])
                ws.cell(row=i, column=3, value=c)
                cv = ws.cell(row=i, column=4, value=n)
                cv.font = Font(bold=True)
                ws.cell(row=i, column=5, value=round(n*100/total_ip, 1))
            # heatmap
            last = 3 + len(country_cnt)
            ws.conditional_formatting.add(
                f"D4:D{last}",
                ColorScaleRule(start_type="min", start_color="FEF3C7",
                               end_type="max", end_color="DC2626"),
            )
            # chart
            n_top = min(10, len(country_cnt))
            chart = BarChart()
            chart.type = "bar"
            chart.style = 11
            chart.title = f"Top {n_top} países por ataques"
            labels = Reference(ws, min_col=3, min_row=4, max_row=3+n_top)
            data = Reference(ws, min_col=4, min_row=3, max_row=3+n_top)
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(labels)
            chart.width = 18; chart.height = max(10, n_top*0.8)
            ws.add_chart(chart, "G3")
            _autosize(ws, 5)

            ws = wb.create_sheet("Por ASN")
            ws["A1"] = "Ataques agrupados por proveedor (ASN)"
            ws["A1"].font = TITLE_FONT
            ws.merge_cells("A1:E1")
            _header_row(ws, 3, ["#", "ASN", "Organización", "Alertas", "% del total"])
            for i, (a, n) in enumerate(asn_cnt.most_common(50), start=4):
                ws.cell(row=i, column=1, value=i-3)
                ws.cell(row=i, column=2, value=a)
                ws.cell(row=i, column=3, value=asn_org[a])
                cv = ws.cell(row=i, column=4, value=n)
                cv.font = Font(bold=True)
                ws.cell(row=i, column=5, value=round(n*100/total_ip, 1))
            last = 3 + len(asn_cnt)
            ws.conditional_formatting.add(
                f"D4:D{last}",
                ColorScaleRule(start_type="min", start_color="FEF3C7",
                               end_type="max", end_color="DC2626"),
            )
            n_top = min(10, len(asn_cnt))
            chart = BarChart()
            chart.type = "bar"
            chart.style = 11
            chart.title = f"Top {n_top} proveedores (ASN)"
            labels = Reference(ws, min_col=3, min_row=4, max_row=3+n_top)
            data = Reference(ws, min_col=4, min_row=3, max_row=3+n_top)
            chart.add_data(data, titles_from_data=True)
            chart.set_categories(labels)
            chart.width = 18; chart.height = max(10, n_top*0.8)
            ws.add_chart(chart, "G3")
            _autosize(ws, 5)
    except Exception:
        pass

    # Cargamos el lookup localmente para enriquecer columnas de geo
    try:
        from src.common.geoip import lookup_ip as _geolookup
    except Exception:
        _geolookup = lambda ip: {"country_iso": "", "country": "", "asn": None, "organization": ""}

    # -------- Hoja 4: Alertas (lista completa, con país y proveedor) --------
    ws = wb.create_sheet("Alertas")
    _header_row(ws, 1, ["Hora", "Severidad", "Regla", "Título", "Estado",
                        "IP", "País", "Código", "ASN", "Proveedor / ISP", "Usuario"])
    for i, a in enumerate(db.alerts.find().sort("fired_at", -1).limit(10_000), start=2):
        ev = a.get("evidence") or {}
        ip = ev.get("ip")
        geo = _geolookup(ip) if ip else {}
        ws.cell(row=i, column=1, value=_iso(a.get("fired_at")))
        c_sev = ws.cell(row=i, column=2, value=a.get("severity"))
        if a.get("severity") in SEV_FILLS:
            c_sev.fill = SEV_FILLS[a.get("severity")]
        ws.cell(row=i, column=3, value=a.get("rule_id"))
        ws.cell(row=i, column=4, value=a.get("title"))
        ws.cell(row=i, column=5, value=a.get("status"))
        ws.cell(row=i, column=6, value=ip)
        ws.cell(row=i, column=7, value=geo.get("country", "") if ip else "")
        ws.cell(row=i, column=8, value=geo.get("country_iso", "") if ip else "")
        ws.cell(row=i, column=9, value=(f"AS{geo['asn']}" if geo.get("asn") else "") if ip else "")
        ws.cell(row=i, column=10, value=geo.get("organization", "") if ip else "")
        ws.cell(row=i, column=11, value=ev.get("user"))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:K{max(1, db.alerts.count_documents({}))+1}"
    _autosize(ws, 11, max_width=45)

    # -------- Hoja 5: Eventos (opcional, con país y proveedor) --------
    if include_events:
        ws = wb.create_sheet("Eventos")
        _header_row(ws, 1, ["Hora", "Fuente", "Severidad", "Acción", "Usuario",
                            "IP", "País", "Código", "ASN", "Proveedor / ISP", "Host", "Raw"])
        n = 0
        for i, e in enumerate(db.events.find().sort("ts", -1).limit(events_limit), start=2):
            ip = e.get("ip")
            geo = _geolookup(ip) if ip else {}
            ws.cell(row=i, column=1, value=_iso(e.get("ts")))
            ws.cell(row=i, column=2, value=e.get("source"))
            c_sev = ws.cell(row=i, column=3, value=e.get("severity"))
            if e.get("severity") in SEV_FILLS:
                c_sev.fill = SEV_FILLS[e.get("severity")]
            ws.cell(row=i, column=4, value=e.get("action"))
            ws.cell(row=i, column=5, value=e.get("user"))
            ws.cell(row=i, column=6, value=ip)
            ws.cell(row=i, column=7, value=geo.get("country", "") if ip else "")
            ws.cell(row=i, column=8, value=geo.get("country_iso", "") if ip else "")
            ws.cell(row=i, column=9, value=(f"AS{geo['asn']}" if geo.get("asn") else "") if ip else "")
            ws.cell(row=i, column=10, value=geo.get("organization", "") if ip else "")
            ws.cell(row=i, column=11, value=e.get("host"))
            raw = (e.get("raw") or "")
            ws.cell(row=i, column=12, value=raw[:300])
            n = i
        ws.freeze_panes = "A2"
        if n > 1:
            ws.auto_filter.ref = f"A1:L{n}"
        _autosize(ws, 12, max_width=60)

    # Guardar a archivo temporal y devolver con FileResponse
    fd, path = tempfile.mkstemp(suffix=".xlsx", prefix="auditalog_")
    _os.close(fd)
    wb.save(path)

    filename = f"auditalog_reporte_{now.strftime('%Y%m%d_%H%M%S')}.xlsx"
    return _FR(
        path=path,
        filename=filename,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            # Evita que el navegador sirva una copia cacheada del endpoint;
            # cada request regenera el .xlsx con los datos actuales.
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# ----------------------------------------------------------------------------
# GET /api/report — resumen del análisis en texto (sin eventos crudos)
# ----------------------------------------------------------------------------

@app.get("/api/report")
def api_report():
    """Genera un resumen Markdown del análisis actual del sistema."""
    from fastapi.responses import PlainTextResponse

    db = get_db()
    now = datetime.now(timezone.utc)

    total_events = db.events.count_documents({})
    total_alerts = db.alerts.count_documents({})
    open_alerts = db.alerts.count_documents({"status": "open"})
    critical_alerts = db.alerts.count_documents({"severity": "critical"})

    # Alertas por regla
    by_rule = list(db.alerts.aggregate([
        {"$group": {"_id": "$rule_id", "count": {"$sum": 1}, "severity": {"$first": "$severity"}}},
        {"$sort": {"count": -1}},
    ]))

    # Top IPs por cantidad de alertas
    top_ips = list(db.alerts.aggregate([
        {"$match": {"evidence.ip": {"$exists": True, "$ne": None}}},
        {"$group": {"_id": "$evidence.ip", "count": {"$sum": 1},
                    "rules": {"$addToSet": "$rule_id"}}},
        {"$sort": {"count": -1}},
        {"$limit": 15},
    ]))

    # Fuentes de eventos
    by_source = list(db.events.aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]))

    # Últimas 10 alertas críticas
    recent_critical = list(db.alerts.find(
        {"severity": "critical"}, sort=[("fired_at", -1)]
    ).limit(10))

    lines = []
    lines.append("# Informe de Análisis · AuditaLog")
    lines.append("")
    lines.append(f"**Generado:** {now.strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"**Sistema:** AuditaLog v{APP_VERSION}")
    lines.append("")
    lines.append("## Resumen")
    lines.append("")
    lines.append(f"- Eventos auditados: **{total_events:,}**")
    lines.append(f"- Alertas totales: **{total_alerts:,}**")
    lines.append(f"- Alertas abiertas: **{open_alerts:,}**")
    lines.append(f"- Alertas críticas: **{critical_alerts:,}**")
    lines.append("")

    lines.append("## Eventos por fuente")
    lines.append("")
    lines.append("| Fuente | Cantidad |")
    lines.append("|---|---|")
    for row in by_source:
        lines.append(f"| {row['_id'] or '(desconocido)'} | {row['count']:,} |")
    lines.append("")

    lines.append("## Alertas por regla disparada")
    lines.append("")
    lines.append("| Regla | Severidad | Cantidad |")
    lines.append("|---|---|---|")
    for row in by_rule:
        lines.append(f"| {row['_id']} | {row.get('severity','?')} | {row['count']} |")
    lines.append("")

    if top_ips:
        lines.append("## Top IPs sospechosas (por cantidad de alertas)")
        lines.append("")
        lines.append("| IP | Alertas | Reglas disparadas |")
        lines.append("|---|---|---|")
        for row in top_ips:
            rules_s = ", ".join(sorted(row["rules"]))
            lines.append(f"| `{row['_id']}` | {row['count']} | {rules_s} |")
        lines.append("")

    # Agrupación por país y por ASN (local GeoIP)
    try:
        from src.common.geoip import lookup_ip
        from collections import Counter
        country_cnt: Counter = Counter()
        country_iso: dict = {}
        asn_cnt: Counter = Counter()
        asn_org: dict = {}
        total_ip = 0
        for alert in db.alerts.find({"evidence.ip": {"$exists": True, "$ne": None}}, {"evidence.ip": 1}):
            ip = (alert.get("evidence") or {}).get("ip")
            if not ip:
                continue
            info = lookup_ip(ip)
            total_ip += 1
            country_cnt[info["country"]] += 1
            country_iso[info["country"]] = info["country_iso"]
            k_asn = f"AS{info['asn']}" if info["asn"] else "AS?"
            asn_cnt[k_asn] += 1
            asn_org[k_asn] = info["organization"]

        if total_ip:
            lines.append("## Ataques agrupados por país")
            lines.append("")
            lines.append("| # | País | Alertas | % |")
            lines.append("|---|---|---|---|")
            for i, (c, n) in enumerate(country_cnt.most_common(10), start=1):
                lines.append(f"| {i} | {country_iso[c]} · {c} | {n} | {round(n*100/total_ip,1)}% |")
            lines.append("")

            lines.append("## Ataques agrupados por proveedor (ASN)")
            lines.append("")
            lines.append("| # | ASN | Organización | Alertas | % |")
            lines.append("|---|---|---|---|---|")
            for i, (a, n) in enumerate(asn_cnt.most_common(10), start=1):
                lines.append(f"| {i} | `{a}` | {asn_org[a]} | {n} | {round(n*100/total_ip,1)}% |")
            lines.append("")
    except Exception:
        pass

    if recent_critical:
        lines.append("## Últimas alertas críticas")
        lines.append("")
        for a in recent_critical:
            ts = a["fired_at"].strftime("%Y-%m-%d %H:%M") if isinstance(a["fired_at"], datetime) else str(a["fired_at"])
            lines.append(f"- **{ts}** · [{a['rule_id']}] {a['title']}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Este informe es un extracto. El paquete completo (`.db` SQLite) está disponible en /exportar.*")

    body = "\n".join(lines)
    return PlainTextResponse(
        content=body,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="informe_auditalog_{now.strftime("%Y%m%d_%H%M%S")}.md"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# ----------------------------------------------------------------------------
# POST /api/upload — recibe archivo de log, lo parsea y lo ingiere
# ----------------------------------------------------------------------------

def _pick_parser(source: str):
    """Devuelve (parser, needs_year) para una fuente. needs_year=True solo si
    el parser recibe un `default_year` para timestamps sin año (auth.log clásico)."""
    from src.common.parsers import (
        parse_auth_log, parse_access_log, parse_php_log,
        parse_fail2ban_log, parse_apache_error_log, parse_phpfpm_log,
        parse_kern_log, parse_mail_log, parse_dmesg,
    )
    # Todos los parsers del S4 aceptan default_year (lo ignoran si el formato
    # ya trae año), así que podemos tratarlos uniformemente.
    PARSERS = {
        "auth.log":     (parse_auth_log,         True),
        "access.log":   (parse_access_log,       False),
        "php_log":      (parse_php_log,          True),
        "fail2ban.log": (parse_fail2ban_log,     True),
        "error.log":    (parse_apache_error_log, True),
        "phpfpm.log":   (parse_phpfpm_log,       True),
        "kern.log":     (parse_kern_log,         True),
        "mail.log":     (parse_mail_log,         True),
        "dmesg":        (parse_dmesg,            True),
    }
    if source in PARSERS:
        return PARSERS[source]
    raise HTTPException(status_code=400, detail=f"Fuente no soportada: {source}")


def _guess_source(name: str) -> str:
    """Heurística: detecta el formato por el nombre del archivo.
    Útil para procesar varios archivos de un .zip sin que el usuario elija uno por uno.

    Precedencia (de más específico a más genérico):
      fail2ban → fail2ban.log
      php-fpm / phpfpm → phpfpm.log
      php_log (log de la app PHP tipo [DD-Mon-YYYY ...] PHP ...): nombre "php_log*" o cuando NO es php-fpm
      access.log* → access.log
      error.log* → error.log  (Apache/nginx)
      kern.log*  → kern.log
      mail.log*  → mail.log
      dmesg*     → dmesg
      cualquier otra cosa → auth.log  (default conservador para syslog)
    """
    low = name.lower()
    if "fail2ban" in low:
        return "fail2ban.log"
    if "php-fpm" in low or "php8" in low or "phpfpm" in low or "fpm" in low:
        return "phpfpm.log"
    if "php" in low:  # php_log.N, php.log, etc.
        return "php_log"
    if "access" in low:
        return "access.log"
    if "error" in low:
        return "error.log"
    if "kern" in low:
        return "kern.log"
    if "mail" in low:
        return "mail.log"
    if "dmesg" in low:
        return "dmesg"
    return "auth.log"


def _ingest_text(db, r, text: str, parser, parser_needs_year: bool,
                 year: int, source: str) -> dict:
    """Parsea un texto línea por línea, inserta eventos en Mongo y aplica reglas."""
    from src.common.rules import apply_rules

    lines = text.splitlines()
    read = inserted = skipped = alerts_count = 0
    now = datetime.now(timezone.utc)
    batch: list[dict] = []
    BATCH = 500

    for line in lines:
        read += 1
        if not line.strip():
            continue
        try:
            ev = parser(line, default_year=year) if parser_needs_year else parser(line)
        except Exception:
            skipped += 1
            continue
        if ev is None:
            skipped += 1
            continue
        ev["ingested_at"] = now
        batch.append(ev)
        if len(batch) >= BATCH:
            res = db.events.insert_many(batch, ordered=False)
            for ev2, oid in zip(batch, res.inserted_ids):
                alerts_count += len(apply_rules(r, db, ev2, oid))
            inserted += len(batch)
            batch = []
    if batch:
        res = db.events.insert_many(batch, ordered=False)
        for ev2, oid in zip(batch, res.inserted_ids):
            alerts_count += len(apply_rules(r, db, ev2, oid))
        inserted += len(batch)

    return {"source": source, "read": read, "inserted": inserted,
            "skipped": skipped, "alerts_fired": alerts_count}


@app.post("/api/upload")
async def api_upload(
    file: UploadFile = File(...),
    source: str = Query("auto", description="auto | auth.log | access.log | php_log | fail2ban.log | error.log | phpfpm.log | kern.log | mail.log | dmesg"),
    year: int = Query(2026),
):
    """Recibe un archivo de log (o un .zip con varios) y los procesa.

    - Si el archivo es .zip, extrae en memoria y procesa **cada archivo interno**.
      Si source=auto, adivina el formato por el nombre.
    - Si es un archivo plano, usa el `source` indicado.
    - **No borra los datos previos**: es carga acumulativa (el reset se hace manual).
    """
    import gzip
    import io
    import zipfile

    db = get_db()
    r = get_redis()
    content = await file.read()
    filename = (file.filename or "upload.log").lower()

    def _decompress_if_needed(name: str, raw: bytes) -> bytes:
        """Si el archivo está gzipeado (termina en .gz o empieza con el magic de gzip),
        lo descomprime. Devuelve los bytes planos."""
        low = name.lower()
        if low.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            try:
                return gzip.decompress(raw)
            except Exception:
                return raw  # fallback: devolver lo que había
        return raw

    def _strip_gz_suffix(name: str) -> str:
        """auth.log.2.gz → auth.log.2 (para que _guess_source funcione)."""
        return name[:-3] if name.lower().endswith(".gz") else name

    # Si es ZIP, procesar cada archivo interno
    if filename.endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="El .zip está dañado o no es válido")

        files_processed: list[dict] = []
        totals = {"read": 0, "inserted": 0, "skipped": 0, "alerts_fired": 0}

        for name in zf.namelist():
            # Saltar directorios y metadatos macOS/Windows
            if name.endswith("/") or name.startswith("__MACOSX/") or "/.DS_Store" in name or name.endswith(".DS_Store"):
                continue
            raw = zf.read(name)
            if len(raw) == 0:
                files_processed.append({"name": name, "error": "archivo vacío",
                                        "source": None, "read": 0, "inserted": 0,
                                        "skipped": 0, "alerts_fired": 0})
                continue

            # Descomprimir si es .gz dentro del zip (caso típico de /var/log rotados)
            raw = _decompress_if_needed(name, raw)
            logical_name = _strip_gz_suffix(name)

            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                files_processed.append({"name": name, "error": "no es texto",
                                        "source": None, "read": 0, "inserted": 0,
                                        "skipped": 0, "alerts_fired": 0})
                continue

            effective_source = _guess_source(logical_name) if source == "auto" else source
            try:
                parser, needs_year = _pick_parser(effective_source)
            except HTTPException as e:
                files_processed.append({"name": name, "error": str(e.detail),
                                        "source": effective_source, "read": 0, "inserted": 0,
                                        "skipped": 0, "alerts_fired": 0})
                continue

            res = _ingest_text(db, r, text, parser, needs_year, year, effective_source)
            res["name"] = name
            files_processed.append(res)
            for k in totals:
                totals[k] += res[k]

        return {
            "zip": True,
            "filename": file.filename,
            "files_count": len(files_processed),
            "files": files_processed,
            "totals": totals,
        }

    # Archivo plano (puede venir gzipeado si el usuario sube .log.1.gz directo)
    raw = _decompress_if_needed(filename, content)
    logical_name = _strip_gz_suffix(filename)
    effective_source = _guess_source(logical_name) if source == "auto" else source
    parser, needs_year = _pick_parser(effective_source)
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Archivo no es texto")

    res = _ingest_text(db, r, text, parser, needs_year, year, effective_source)
    res["zip"] = False
    res["filename"] = file.filename
    return res


# ----------------------------------------------------------------------------
# POST /api/export/sqlite — genera y devuelve el .db de evidencia
# ----------------------------------------------------------------------------

@app.post("/api/export/sqlite")
def api_export_sqlite(
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
):
    """Genera un .db SQLite con events + alerts y lo devuelve para descarga."""
    import os
    from datetime import datetime as _dt
    from pathlib import Path as _Path
    from src.exporter.sqlite_exporter import export as _export

    def _parse(s: str) -> datetime:
        if len(s) == 10:
            return datetime.fromisoformat(s + "T00:00:00+00:00")
        return datetime.fromisoformat(s)

    from_dt = _parse(from_date) if from_date else None
    to_dt = _parse(to_date) if to_date else None

    export_dir = _Path(os.getenv("SQLITE_EXPORT_DIR", "./data/exports"))
    tag = (from_dt or _dt.now(timezone.utc)).strftime("%Y-%m")
    stamp = _dt.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = export_dir / f"evidencia_{tag}_{stamp}.db"

    try:
        result = _export(from_dt, to_dt, out_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exportando: {e}")

    return FileResponse(
        path=result["path"],
        filename=out_path.name,
        media_type="application/x-sqlite3",
        headers={
            "X-Export-Events": str(result["events"]),
            "X-Export-Alerts": str(result["alerts"]),
            "X-Export-SHA256": result["sha256"],
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# ----------------------------------------------------------------------------
# PATCH /api/alerts/{id} — cambiar estado (acknowledge / close)
# ----------------------------------------------------------------------------

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|acknowledged|closed)$")
    notes: Optional[str] = None


@app.patch("/api/alerts/{alert_id}")
def api_update_alert(alert_id: str, patch: AlertStatusUpdate):
    try:
        oid = ObjectId(alert_id)
    except Exception:
        raise HTTPException(status_code=400, detail="alert_id inválido")

    db = get_db()
    update: dict = {"status": patch.status}
    if patch.notes is not None:
        update["notes"] = patch.notes

    res = db.alerts.update_one({"_id": oid}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="alerta no encontrada")

    return {"updated": True, "alert_id": alert_id, "status": patch.status}


# ----------------------------------------------------------------------------
# GET /api/events/{id} — detalle de un evento
# ----------------------------------------------------------------------------

@app.get("/api/events/{event_id}")
def api_get_event(event_id: str):
    try:
        oid = ObjectId(event_id)
    except Exception:
        raise HTTPException(status_code=400, detail="event_id inválido")

    db = get_db()
    doc = db.events.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="evento no encontrado")
    return _serialize(doc)
