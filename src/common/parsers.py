"""Parsers para las fuentes de log soportadas en el MVP.

Cada parser recibe una línea cruda y devuelve un dict normalizado con la
forma del evento o None si la línea no matchea.

Esquema de salida (debe coincidir con docs/arquitectura/modelo-datos-v1.md):
    {
        "source": "auth.log | access.log | app",
        "ts": datetime (UTC),
        "host": str | None,
        "user": str | None,
        "ip": str | None,
        "action": "login_failed | login_ok | config_changed | ...",
        "detail": dict,
        "severity": "info | warn | critical",
        "raw": str,
    }
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

# ----------------------------------------------------------------------------
# auth.log (OpenSSH / Linux PAM)
# ----------------------------------------------------------------------------

# Formato típico:
#   Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 183.62.140.253 port 48864 ssh2
#   Dec 10 06:55:48 LabSZ sshd[24200]: Accepted password for ana from 10.0.0.5 port 50123 ssh2
#   Dec 10 06:55:50 LabSZ sshd[24200]: Failed password for invalid user admin from 203.0.113.5 port 55555 ssh2

_AUTH_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<outcome>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?"
    r"(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"port\s+\d+"
)


def parse_auth_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea una línea de /var/log/auth.log (SSH).

    `default_year` se usa porque syslog clásico no incluye año en el timestamp;
    si no se pasa, usa el año actual.
    """
    line = line.rstrip("\n")
    m = _AUTH_RE.match(line)
    if not m:
        return None

    year = default_year if default_year is not None else datetime.now(timezone.utc).year
    # "Dec 10 06:55:46" -> datetime
    try:
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None

    outcome = m["outcome"]
    action = "login_failed" if outcome == "Failed" else "login_ok"
    severity = "warn" if outcome == "Failed" else "info"

    return {
        "source": "auth.log",
        "ts": ts,
        "host": m["host"],
        "user": m["user"],
        "ip": m["ip"],
        "action": action,
        "detail": {"method": "ssh"},
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# access.log (Apache / Nginx — Common Log Format)
# ----------------------------------------------------------------------------

# Formato típico:
#   192.0.2.45 - - [10/Oct/2026:13:55:36 +0000] "GET /wp-admin HTTP/1.1" 401 2326

_ACCESS_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\d+|-)"
)


def parse_access_log(line: str) -> Optional[dict]:
    """Parsea una línea de access.log en Common Log Format."""
    line = line.rstrip("\n")
    m = _ACCESS_RE.match(line)
    if not m:
        return None

    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None

    status = int(m["status"])
    severity = "warn" if status in (401, 403) else ("critical" if status >= 500 else "info")

    return {
        "source": "access.log",
        "ts": ts,
        "host": None,
        "user": m["user"] if m["user"] != "-" else None,
        "ip": m["ip"],
        "action": "http_request",
        "detail": {
            "method": m["method"],
            "path": m["path"],
            "status": status,
            "size": int(m["size"]) if m["size"].isdigit() else 0,
        },
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------------

PARSERS = {
    "auth.log": parse_auth_log,
    "access.log": parse_access_log,
}


def parse(source: str, line: str) -> Optional[dict]:
    """Elige el parser según el nombre de la fuente."""
    fn = PARSERS.get(source)
    if fn is None:
        raise ValueError(f"Esto es una fuente desconocida: {source!r}")
    return fn(line)
