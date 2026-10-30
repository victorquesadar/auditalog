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


# ----------------------------------------------------------------------------
# Nuevas reglas (S3)
# ----------------------------------------------------------------------------

# Patrones de SQL injection en URLs/payloads
_SQLI_PATTERNS = (
    "union select", "' or '1'='1", " or 1=1", "'--", "/**/",
    "sleep(", "benchmark(", "waitfor delay", "information_schema",
    "0x3a3a", "@@version",
)

# Patrones de XSS
_XSS_PATTERNS = (
    "<script", "javascript:", "onerror=", "onload=", "onclick=",
    "<iframe", "<svg", "alert(", "document.cookie",
)

# Patrones de directory traversal / LFI
_TRAVERSAL_PATTERNS = (
    "../", "..\\", "/etc/passwd", "/etc/shadow",
    "..%2f", "..%5c", "%2e%2e%2f", "boot.ini",
)

# User-Agents de bots conocidos (hostiles o escáneres sin consentimiento)
_BAD_USER_AGENTS = (
    "sqlmap", "nikto", "nmap", "masscan", "havij",
    "acunetix", "nessus", "dirbuster", "gobuster", "wpscan",
    "python-requests/", "curl/",  # cliente genérico, muchas veces usados por scripts
)

# Rutas sensibles que casi nadie debería tocar sin motivo
_SENSITIVE_PATHS = (
    "/.env", "/.git/", "/wp-admin", "/phpmyadmin", "/admin",
    "/.aws/", "/config.php", "/backup", "/.ssh/",
)


def _contains_any(haystack: str, needles) -> Optional[str]:
    """Devuelve la primera coincidencia case-insensitive, o None."""
    low = haystack.lower()
    for n in needles:
        if n in low:
            return n
    return None


def rule_sql_injection(event: dict, mongo_event_id) -> Optional[dict]:
    """Patrones de SQL injection en HTTP."""
    if event.get("source") != "access.log":
        return None
    path = (event.get("detail") or {}).get("path", "")
    raw = event.get("raw", "")
    hit = _contains_any(path, _SQLI_PATTERNS) or _contains_any(raw, _SQLI_PATTERNS)
    if not hit:
        return None
    return {
        "rule_id": "sqli_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Intento de SQL injection desde {event.get('ip')}",
        "evidence": {
            "ip": event.get("ip"),
            "pattern": hit,
            "path": path,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_xss(event: dict, mongo_event_id) -> Optional[dict]:
    """Patrones de XSS en HTTP."""
    if event.get("source") != "access.log":
        return None
    path = (event.get("detail") or {}).get("path", "")
    raw = event.get("raw", "")
    hit = _contains_any(path, _XSS_PATTERNS) or _contains_any(raw, _XSS_PATTERNS)
    if not hit:
        return None
    return {
        "rule_id": "xss_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Intento de XSS desde {event.get('ip')}",
        "evidence": {
            "ip": event.get("ip"),
            "pattern": hit,
            "path": path,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_directory_traversal(event: dict, mongo_event_id) -> Optional[dict]:
    """Patrones de directory traversal / LFI."""
    if event.get("source") != "access.log":
        return None
    path = (event.get("detail") or {}).get("path", "")
    hit = _contains_any(path, _TRAVERSAL_PATTERNS)
    if not hit:
        return None
    return {
        "rule_id": "traversal_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Intento de directory traversal desde {event.get('ip')}",
        "evidence": {
            "ip": event.get("ip"),
            "pattern": hit,
            "path": path,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_bad_user_agent(event: dict, mongo_event_id) -> Optional[dict]:
    """User-Agent de escáner / bot hostil (sqlmap, nikto, etc.)."""
    if event.get("source") != "access.log":
        return None
    detail = event.get("detail") or {}
    ua = detail.get("user_agent", "") or ""
    raw = event.get("raw", "")
    hit = _contains_any(ua, _BAD_USER_AGENTS) or _contains_any(raw, _BAD_USER_AGENTS)
    if not hit:
        return None
    return {
        "rule_id": "bad_ua_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "warn",
        "title": f"User-Agent sospechoso ({hit}) desde {event.get('ip')}",
        "evidence": {
            "ip": event.get("ip"),
            "user_agent_hit": hit,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_sensitive_path(event: dict, mongo_event_id) -> Optional[dict]:
    """Acceso a rutas sensibles (p.ej. /.env, /.git/, /phpmyadmin)."""
    if event.get("source") != "access.log":
        return None
    path = (event.get("detail") or {}).get("path", "")
    hit = _contains_any(path, _SENSITIVE_PATHS)
    if not hit:
        return None
    return {
        "rule_id": "sensitive_path_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "warn",
        "title": f"Acceso a ruta sensible {hit} desde {event.get('ip')}",
        "evidence": {
            "ip": event.get("ip"),
            "path": path,
            "pattern": hit,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_dir_scanning(r: redis.Redis, event: dict, mongo_event_id) -> Optional[dict]:
    """Muchos 404 desde la misma IP = probablemente escaneo de rutas (dirbuster)."""
    if event.get("source") != "access.log":
        return None
    detail = event.get("detail") or {}
    status = detail.get("status")
    ip = event.get("ip")
    if status != 404 or not ip:
        return None

    k = key("dir_scan", ip)
    cnt = r.incr(k)
    r.expire(k, 300)  # ventana de 5 minutos

    if cnt < 20:  # umbral: 20 404s en 5 min
        return None

    return {
        "rule_id": "dir_scan_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Posible escaneo de rutas desde {ip} ({cnt} 404 en 5 min)",
        "evidence": {
            "ip": ip,
            "fails_404": int(cnt),
            "window_sec": 300,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_sudo_fail(event: dict, mongo_event_id) -> Optional[dict]:
    """Intento de escalada de privilegios: sudo fallido."""
    if event.get("source") != "auth.log":
        return None
    raw = (event.get("raw") or "").lower()
    if "sudo" not in raw:
        return None
    if "authentication failure" not in raw and "incorrect password" not in raw:
        return None
    return {
        "rule_id": "sudo_fail_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "warn",
        "title": f"Sudo fallido de {event.get('user')} desde {event.get('ip')}",
        "evidence": {
            "user": event.get("user"),
            "ip": event.get("ip"),
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def apply_rules(r: redis.Redis, db: Database, event: dict, mongo_event_id) -> list[dict]:
    """Corre todas las reglas sobre un evento y guarda las alertas que disparen."""
    alerts_fired: list[dict] = []
    for name, fn in (
        ("bruteforce",        lambda: rule_bruteforce(r, event, mongo_event_id)),
        ("offhours",          lambda: rule_offhours(event, mongo_event_id)),
        ("sqli",              lambda: rule_sql_injection(event, mongo_event_id)),
        ("xss",               lambda: rule_xss(event, mongo_event_id)),
        ("traversal",         lambda: rule_directory_traversal(event, mongo_event_id)),
        ("bad_user_agent",    lambda: rule_bad_user_agent(event, mongo_event_id)),
        ("sensitive_path",    lambda: rule_sensitive_path(event, mongo_event_id)),
        ("dir_scanning",      lambda: rule_dir_scanning(r, event, mongo_event_id)),
        ("sudo_fail",         lambda: rule_sudo_fail(event, mongo_event_id)),
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
