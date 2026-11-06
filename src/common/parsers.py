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

# Formato syslog clásico (sin año):
#   Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 183.62.140.253 port 48864 ssh2
# Formato ISO 8601 (RFC5424/journald):
#   2026-10-16T18:02:06.239193-06:00 viernes sshd[343706]: Accepted publickey for ubuntu from 152.231.189.202 port 38967 ssh2: RSA SHA256:...

_AUTH_TS_SYSLOG = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
_AUTH_TS_ISO = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"

_AUTH_RE = re.compile(
    rf"^(?P<ts>{_AUTH_TS_SYSLOG}|{_AUTH_TS_ISO})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<outcome>Failed|Accepted)\s+(?P<method>password|publickey|keyboard-interactive)\s+for\s+"
    r"(?:invalid\s+user\s+)?"
    r"(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"port\s+\d+"
)


def _parse_auth_ts(ts_str: str, default_year: Optional[int]) -> Optional[datetime]:
    """Intenta parsear el timestamp en los dos formatos aceptados."""
    # Formato ISO 8601
    if "T" in ts_str:
        try:
            # Python 3.11+: fromisoformat soporta 'Z' y offsets
            iso = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(iso).astimezone(timezone.utc)
        except ValueError:
            return None
    # Formato syslog (sin año)
    year = default_year if default_year is not None else datetime.now(timezone.utc).year
    try:
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


# Patrones de scanner / probing SSH (sin login real):
# - "banner exchange: Connection from IP port N: invalid format"
# - "Invalid user xxx from IP port N"
# - "Connection reset by IP port N [preauth]"
# - "Did not receive identification string from IP"
_AUTH_PROBE_RE = re.compile(
    rf"^(?P<ts>{_AUTH_TS_SYSLOG}|{_AUTH_TS_ISO})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+"
    r"(?:"
    r"(?P<banner>banner exchange: Connection from )(?P<banner_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+: invalid format"
    r"|"
    r"Invalid user (?P<invalid_user>\S+) from (?P<invalid_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
    r"|"
    r"Connection reset by (?P<reset_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ \[preauth\]"
    r"|"
    r"Did not receive identification string from (?P<noid_ip>\d{1,3}(?:\.\d{1,3}){3})"
    r")"
)


def parse_auth_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea una línea de /var/log/auth.log (SSH).

    Soporta dos formatos de timestamp:
    - Syslog clásico: 'Dec 10 06:55:46' (sin año → usa default_year o año actual)
    - ISO 8601: '2026-10-16T18:02:06.239193-06:00' (incluye año y timezone)

    Reconoce:
    - Logins exitosos / fallidos (password | publickey | keyboard-interactive)
    - Patrones de scanner / probing: banner inválido, Invalid user, Connection reset, Did not receive identification
    """
    line = line.rstrip("\n")

    # Login real (Failed/Accepted)
    m = _AUTH_RE.match(line)
    if m:
        ts = _parse_auth_ts(m["ts"], default_year)
        if ts is None:
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
            "detail": {"method": m["method"]},
            "severity": severity,
            "raw": line,
        }

    # Scanner / probing
    mp = _AUTH_PROBE_RE.match(line)
    if mp:
        ts = _parse_auth_ts(mp["ts"], default_year)
        if ts is None:
            return None

        if mp.group("banner_ip"):
            ip = mp["banner_ip"]; sub = "banner_invalid"
            action = "ssh_probe"; user = None
        elif mp.group("invalid_user"):
            ip = mp["invalid_ip"]; sub = "invalid_user"
            action = "login_failed"  # tratarlo como fallo para que la regla bruteforce lo cuente
            user = mp["invalid_user"]
        elif mp.group("reset_ip"):
            ip = mp["reset_ip"]; sub = "preauth_reset"
            action = "ssh_probe"; user = None
        elif mp.group("noid_ip"):
            ip = mp["noid_ip"]; sub = "no_identification"
            action = "ssh_probe"; user = None
        else:
            return None

        return {
            "source": "auth.log",
            "ts": ts,
            "host": mp["host"],
            "user": user,
            "ip": ip,
            "action": action,
            "detail": {"probe_type": sub},
            "severity": "warn",
            "raw": line,
        }

    return None


# ----------------------------------------------------------------------------
# access.log (Apache / Nginx — Common Log Format)
# ----------------------------------------------------------------------------

# Formato típico (Common):
#   192.0.2.45 - - [10/Oct/2026:13:55:36 +0000] "GET /wp-admin HTTP/1.1" 401 2326
# Formato Combined (con referer + user agent):
#   192.0.2.45 - - [...] "GET /wp-admin HTTP/1.1" 401 2326 "-" "Mozilla/5.0..."

_ACCESS_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_access_log(line: str) -> Optional[dict]:
    """Parsea una línea de access.log en Common o Combined Log Format."""
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

    detail: dict = {
        "method": m["method"],
        "path": m["path"],
        "status": status,
        "size": int(m["size"]) if m["size"].isdigit() else 0,
    }
    if m.group("ua"):
        detail["user_agent"] = m["ua"]
    if m.group("referer"):
        detail["referer"] = m["referer"]

    return {
        "source": "access.log",
        "ts": ts,
        "host": None,
        "user": m["user"] if m["user"] != "-" else None,
        "ip": m["ip"],
        "action": "http_request",
        "detail": detail,
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# PHP error log
# ----------------------------------------------------------------------------

# Formato típico (PHP CLI o fcgi):
#   [10-Oct-2026 00:29:48 UTC] PHP Fatal error:  Uncaught Exception...
#   [10-Oct-2026 00:30:01 America/Costa_Rica] PHP Warning: file_get_contents(...)
#   [10-Oct-2026 00:30:15 UTC] PHP Notice: Undefined index: x in /var/www/...
# También soportamos líneas de stack trace (no las convertimos en eventos propios,
# pero no las descartamos como "basura" cuando están pegadas a un error).

_PHP_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"PHP\s+(?P<level>Fatal error|Parse error|Catchable fatal error|"
    r"Warning|Notice|Deprecated|Strict Standards|Recoverable fatal error)"
    r"\s*:\s*(?P<msg>.*)$",
    re.IGNORECASE,
)

# Posibles formatos de fecha dentro de los corchetes
_PHP_TS_FORMATS = (
    "%d-%b-%Y %H:%M:%S %Z",
    "%d-%b-%Y %H:%M:%S",
    "%Y-%m-%d %H:%M:%S %Z",
    "%Y-%m-%d %H:%M:%S",
)

# Severidad en nuestro esquema según el nivel de PHP
_PHP_SEVERITY = {
    "fatal error": "critical",
    "parse error": "critical",
    "catchable fatal error": "critical",
    "recoverable fatal error": "critical",
    "warning": "warn",
    "notice": "info",
    "deprecated": "info",
    "strict standards": "info",
}

_PATH_RE = re.compile(r"\s+in\s+(?P<path>[^\s:]+):(?P<line>\d+)\s*$")


def parse_php_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea una línea de PHP error log.

    Devuelve None si la línea es parte de un stack trace o es basura.
    Para líneas con `in /path/to/file.php:LINE`, extrae ese detalle.
    """
    line = line.rstrip("\n")
    m = _PHP_RE.match(line)
    if not m:
        return None

    # Timestamp
    ts_raw = m["ts"].strip()
    # Si tiene zona horaria con nombre tipo "America/Costa_Rica", recortamos a UTC
    # (strptime no la entiende; en producción se podría usar pytz).
    ts = None
    for fmt in _PHP_TS_FORMATS:
        try:
            ts = datetime.strptime(ts_raw.split(" America/")[0].split(" Europe/")[0], fmt.split(" %Z")[0]
                                   if "America/" in ts_raw or "Europe/" in ts_raw else fmt)
            break
        except ValueError:
            continue
    if ts is None:
        # último recurso: ignorar la fecha y usar now
        ts = datetime.now()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    level = m["level"].strip().lower()
    severity = _PHP_SEVERITY.get(level, "warn")

    msg = m["msg"].strip()

    # Intentar extraer path + línea
    detail: dict = {"level": level}
    pm = _PATH_RE.search(msg)
    if pm:
        detail["file"] = pm["path"]
        detail["line"] = int(pm["line"])

    action_map = {
        "critical": "php_fatal",
        "warn": "php_warning",
        "info": "php_notice",
    }

    return {
        "source": "php_log",
        "ts": ts,
        "host": None,
        "user": None,
        "ip": None,
        "action": action_map.get(severity, "php_warning"),
        "detail": {**detail, "message": msg[:500]},  # recortamos mensajes muy largos
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# fail2ban log  (jail SSH, HTTP, etc.)
# ----------------------------------------------------------------------------
# 2026-10-11 10:10:51,140 fail2ban.filter [3459308]: INFO  [sshd] Found 45.115.26.20 - 2026-10-11 10:10:50
# 2026-10-11 10:12:31,891 fail2ban.actions[3459308]: NOTICE [sshd] Ban 45.115.26.20
_FAIL2BAN_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+"
    r"\s+fail2ban\.(?P<module>\w+)\s+\[\d+\]:\s+"
    r"(?P<level>INFO|NOTICE|WARNING|ERROR)\s+"
    r"\[(?P<jail>[\w-]+)\]\s+"
    r"(?P<action>Found|Ban|Unban|Already banned|Restore Ban)"
    r"(?:\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+))?"
)


def parse_fail2ban_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea fail2ban.log (detecciones y baneos)."""
    line = line.rstrip("\n")
    m = _FAIL2BAN_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    action_raw = m["action"]
    action_map = {
        "Found": "f2b_detected",
        "Ban": "f2b_banned",
        "Unban": "f2b_unbanned",
        "Already banned": "f2b_already_banned",
        "Restore Ban": "f2b_restored_ban",
    }
    sev = "critical" if action_raw in ("Ban", "Restore Ban") else (
        "warn" if action_raw in ("Found", "Already banned") else "info"
    )
    return {
        "source": "fail2ban.log",
        "ts": ts,
        "host": None,
        "user": None,
        "ip": m["ip"],
        "action": action_map.get(action_raw, "f2b_other"),
        "detail": {"jail": m["jail"], "level": m["level"].lower()},
        "severity": sev,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# Apache error log  (error.log / error_log)
# ----------------------------------------------------------------------------
# [Sun Oct 18 00:00:07.170119 2026] [mpm_event:notice] [pid 248363:tid ...] AH00489: ...
# [Sun Oct 18 10:14:03.000000 2026] [authz_core:error] [pid 1234] [client 1.2.3.4:5678] AH01630: client denied by server configuration: /path
_APACHE_RE = re.compile(
    r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s+"
    r"\[(?P<module>[\w.-]+):(?P<level>trace\d?|debug|info|notice|warn|error|crit|alert|emerg)\]\s+"
    r"\[(?P<pid>[^\]]+)\]\s*"
    r"(?:\[client\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)(?::\d+)?\]\s*)?"
    r"(?P<msg>.*)$"
)

_APACHE_SEV = {
    "emerg": "critical", "alert": "critical", "crit": "critical", "error": "warn",
    "warn": "warn", "notice": "info", "info": "info",
    "debug": "info", "trace": "info", "trace1": "info", "trace2": "info",
    "trace3": "info", "trace4": "info", "trace5": "info", "trace6": "info",
}


def parse_apache_error_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea error.log de Apache."""
    line = line.rstrip("\n")
    m = _APACHE_RE.match(line)
    if not m:
        return None
    try:
        # "Sun Oct 18 00:00:07.170119 2026" → trunc microsegundos
        ts_str = m["ts"].split(".")[0] + " " + m["ts"].split(" ")[-1]
        # Resultado: "Sun Oct 18 00:00:07 2026"
        ts = datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None

    level = m["level"].lower()
    severity = _APACHE_SEV.get(level, "info")
    msg = m["msg"].strip()[:500]

    return {
        "source": "error.log",
        "ts": ts,
        "host": None,
        "user": None,
        "ip": m["ip"],
        "action": f"apache_{level}",
        "detail": {"module": m["module"], "level": level, "message": msg},
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# PHP-FPM log (php8.3-fpm.log)
# ----------------------------------------------------------------------------
# [11-Oct-2026 00:00:06] NOTICE: error log file re-opened
# [11-Oct-2026 00:00:15] WARNING: [pool www] child 1234 exited on signal 9 (SIGKILL)
_PHPFPM_RE = re.compile(
    r"^\[(?P<ts>\d{1,2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})\]\s+"
    r"(?P<level>NOTICE|WARNING|ERROR|ALERT|DEBUG)(?:\s*:\s*|\s+)"
    r"(?P<msg>.*)$"
)
_PHPFPM_SEV = {"NOTICE": "info", "DEBUG": "info", "WARNING": "warn",
               "ERROR": "critical", "ALERT": "critical"}


def parse_phpfpm_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea php8.3-fpm.log."""
    line = line.rstrip("\n")
    m = _PHPFPM_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d-%b-%Y %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    level = m["level"]
    severity = _PHPFPM_SEV.get(level, "info")
    return {
        "source": "phpfpm.log",
        "ts": ts,
        "host": None,
        "user": None,
        "ip": None,
        "action": f"phpfpm_{level.lower()}",
        "detail": {"level": level.lower(), "message": m["msg"].strip()[:500]},
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# syslog genérico ISO (kern.log, mail.log, dmesg con timestamp ISO)
# ----------------------------------------------------------------------------
# 2026-10-15T06:47:04.614443-06:00 viernes kernel: audit: type=1400 ... apparmor="DENIED" ...
# 2026-10-15T06:47:33.107116-06:00 viernes dovecot: master: Warning: Killed with signal 15 ...
_SYSLOG_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<prog>[\w\-\./]+)(?:\[\d+\])?:\s*"
    r"(?P<msg>.*)$"
)


def _parse_iso_ts(ts_str: str) -> Optional[datetime]:
    """Convierte un timestamp ISO (con o sin zona) a UTC."""
    try:
        s = ts_str.replace("Z", "+00:00")
        # Python requiere ±HH:MM (ya lo está); si vino ±HHMM, lo agregamos
        if len(s) >= 5 and s[-5] in "+-" and ":" not in s[-5:]:
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def parse_syslog_iso(line: str, source_hint: str = "syslog",
                     default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea mensajes syslog con timestamp ISO (kern.log, mail.log, dmesg moderno)."""
    line = line.rstrip("\n")
    m = _SYSLOG_ISO_RE.match(line)
    if not m:
        return None
    ts = _parse_iso_ts(m["ts"])
    if ts is None:
        return None

    prog = m["prog"]
    msg = m["msg"].strip()
    msg_lower = msg.lower()

    # Clasificar severidad por heurística
    if any(k in msg_lower for k in ("denied", "error", "fail", "refused", "killed", "attack")):
        severity = "warn"
    elif any(k in msg_lower for k in ("critical", "panic", "fatal", "oom")):
        severity = "critical"
    else:
        severity = "info"

    # ¿apparmor DENIED en kern.log?
    action = f"{source_hint}_entry"
    if "apparmor" in msg_lower and "denied" in msg_lower:
        action = "apparmor_denied"
        severity = "warn"

    return {
        "source": source_hint,
        "ts": ts,
        "host": m["host"],
        "user": None,
        "ip": None,
        "action": action,
        "detail": {"program": prog, "message": msg[:500]},
        "severity": severity,
        "raw": line,
    }


def parse_kern_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea kern.log (syslog ISO del kernel)."""
    return parse_syslog_iso(line, source_hint="kern.log")


def parse_mail_log(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea mail.log (postfix/dovecot)."""
    return parse_syslog_iso(line, source_hint="mail.log")


def parse_dmesg(line: str, default_year: Optional[int] = None) -> Optional[dict]:
    """Parsea dmesg. Soporta tanto formato con timestamp relativo [   0.000000] como ISO."""
    line = line.rstrip("\n")
    # Formato ISO: delega
    if line.startswith(("2", "1")) and "T" in line[:30]:
        return parse_syslog_iso(line, source_hint="dmesg")
    # Formato clásico [    0.000000] kernel: ...
    m = re.match(r"^\[\s*(?P<up>\d+\.\d+)\]\s+(?P<msg>.*)$", line)
    if not m:
        return None
    # Sin wall-clock, usamos "now - uptime" como aproximación
    now = datetime.now(timezone.utc)
    msg = m["msg"].strip()
    msg_lower = msg.lower()
    severity = "critical" if any(k in msg_lower for k in ("panic", "oom", "fatal")) else (
        "warn" if any(k in msg_lower for k in ("error", "fail")) else "info"
    )
    return {
        "source": "dmesg",
        "ts": now,
        "host": None,
        "user": None,
        "ip": None,
        "action": "kernel_msg",
        "detail": {"uptime": float(m["up"]), "message": msg[:500]},
        "severity": severity,
        "raw": line,
    }


# ----------------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------------

PARSERS = {
    "auth.log": parse_auth_log,
    "access.log": parse_access_log,
    "php_log": parse_php_log,
    "fail2ban.log": parse_fail2ban_log,
    "error.log": parse_apache_error_log,
    "phpfpm.log": parse_phpfpm_log,
    "kern.log": parse_kern_log,
    "mail.log": parse_mail_log,
    "dmesg": parse_dmesg,
}


def parse(source: str, line: str) -> Optional[dict]:
    """Elige el parser según el nombre de la fuente."""
    fn = PARSERS.get(source)
    if fn is None:
        raise ValueError(f"Fuente desconocida: {source!r}")
    return fn(line)
