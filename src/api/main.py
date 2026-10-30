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

app = FastAPI(
    title="AuditaLog",
    description="Bitácora de auditoría de accesos y cambios de configuración.",
    version="0.2.0",
)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


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
    return out


# ----------------------------------------------------------------------------
# Health
# ----------------------------------------------------------------------------

@app.get("/api/health")
def health():
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
    return status


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


# ----------------------------------------------------------------------------
# POST /api/upload — recibe archivo de log, lo parsea y lo ingiere
# ----------------------------------------------------------------------------

@app.post("/api/upload")
async def api_upload(
    file: UploadFile = File(...),
    source: str = Query("auth.log", description="auth.log | access.log"),
    year: int = Query(2026),
):
    """Recibe un archivo de log, lo parsea con el parser correspondiente,
    lo mete línea por línea en Mongo y aplica reglas al toque.
    """
    from src.common.parsers import parse_auth_log, parse_access_log
    from src.common.rules import apply_rules

    parser = parse_auth_log if source == "auth.log" else parse_access_log

    db = get_db()
    r = get_redis()

    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Archivo no es texto")

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
            ev = parser(line, default_year=year) if source == "auth.log" else parser(line)
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
            # Aplicar reglas por cada evento
            for ev2, oid in zip(batch, res.inserted_ids):
                alerts_count += len(apply_rules(r, db, ev2, oid))
            inserted += len(batch)
            batch = []

    if batch:
        res = db.events.insert_many(batch, ordered=False)
        for ev2, oid in zip(batch, res.inserted_ids):
            alerts_count += len(apply_rules(r, db, ev2, oid))
        inserted += len(batch)

    return {
        "filename": file.filename,
        "source": source,
        "read": read,
        "inserted": inserted,
        "skipped": skipped,
        "alerts_fired": alerts_count,
    }


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
