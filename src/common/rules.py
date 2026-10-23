"""Reglas de detección compartidas entre worker e ingesta directa.

Permiten que un evento aplique las mismas reglas tanto si entra por el
Stream (worker) como si entra por la API (POST /api/ingest).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import redis
from pymongo.database import Database

from src.common.config import key, settings


def rule_bruteforce(r: redis.Redis, event: dict, mongo_event_id) -> Optional[dict]:
    """Cuenta fallos por IP en una ventana con TTL; alerta al pasar el umbral."""
    if event.get("action") != "login_failed" or not event.get("ip"):
        return None

    k = key("bruteforce", event["ip"])
    fails = r.incr(k)
    r.expire(k, settings.bruteforce_window_sec)
    r.zincrby(key("suspicious:ips"), 1, event["ip"])

    if fails < settings.bruteforce_max_fails:
        return None

    return {
        "rule_id": "bruteforce_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Posible fuerza bruta desde {event['ip']}",
        "evidence": {
            "ip": event["ip"],
            "user": event.get("user"),
            "fails": int(fails),
            "window_sec": settings.bruteforce_window_sec,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_offhours(event: dict, mongo_event_id) -> Optional[dict]:
    """Loguearse fuera de horario laboral configurado."""
    if event.get("action") not in ("login_ok", "login_failed"):
        return None

    ts = event.get("ts")
    if not isinstance(ts, datetime):
        return None

    hour = ts.hour
    start = settings.offhours_start
    end = settings.offhours_end
    in_offhours = (hour >= start) or (hour < end) if start > end else (start <= hour < end)
    if not in_offhours:
        return None

    return {
        "rule_id": "offhours_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "warn",
        "title": f"Acceso fuera de horario ({hour:02d}:xx) de {event.get('user')}@{event.get('ip')}",
        "evidence": {
            "user": event.get("user"),
            "ip": event.get("ip"),
            "hour": hour,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def apply_rules(r: redis.Redis, db: Database, event: dict, mongo_event_id) -> list[dict]:
    """Corre todas las reglas sobre un evento y guarda las alertas que disparen."""
    alerts_fired: list[dict] = []
    for name, fn in (
        ("bruteforce", lambda: rule_bruteforce(r, event, mongo_event_id)),
        ("offhours",   lambda: rule_offhours(event, mongo_event_id)),
    ):
        try:
            alert = fn()
            if alert:
                db.alerts.insert_one(alert)
                alerts_fired.append(alert)
                r.publish(key("alerts"), alert["title"])
        except Exception:
            pass  # no romper la ingesta si una regla falla
    return alerts_fired
