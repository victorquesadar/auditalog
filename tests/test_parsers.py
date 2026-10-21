"""Tests unitarios para los parsers de log."""
from __future__ import annotations

from datetime import datetime, timezone

from src.common.parsers import parse_access_log, parse_auth_log, parse


# ----------------------------------------------------------------------------
# auth.log
# ----------------------------------------------------------------------------

def test_auth_failed_password_root():
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 183.62.140.253 port 48864 ssh2"
    ev = parse_auth_log(line, default_year=2026)
    assert ev is not None
    assert ev["source"] == "auth.log"
    assert ev["user"] == "root"
    assert ev["ip"] == "183.62.140.253"
    assert ev["action"] == "login_failed"
    assert ev["severity"] == "warn"
    assert ev["host"] == "LabSZ"
    assert ev["ts"] == datetime(2026, 12, 10, 6, 55, 46, tzinfo=timezone.utc)


def test_auth_accepted_password_user():
    line = "Dec 10 06:55:48 LabSZ sshd[24200]: Accepted password for ana from 10.0.0.5 port 50123 ssh2"
    ev = parse_auth_log(line, default_year=2026)
    assert ev is not None
    assert ev["user"] == "ana"
    assert ev["action"] == "login_ok"
    assert ev["severity"] == "info"


def test_auth_invalid_user():
    line = "Dec 10 06:55:50 LabSZ sshd[24200]: Failed password for invalid user admin from 203.0.113.5 port 55555 ssh2"
    ev = parse_auth_log(line, default_year=2026)
    assert ev is not None
    assert ev["user"] == "admin"
    assert ev["ip"] == "203.0.113.5"
    assert ev["action"] == "login_failed"


def test_auth_non_matching_line_returns_none():
    assert parse_auth_log("una linea cualquiera que no es ssh") is None
    assert parse_auth_log("") is None


# ----------------------------------------------------------------------------
# access.log
# ----------------------------------------------------------------------------

def test_access_401_wordpress():
    line = '192.0.2.45 - - [10/Oct/2026:13:55:36 +0000] "GET /wp-admin HTTP/1.1" 401 2326'
    ev = parse_access_log(line)
    assert ev is not None
    assert ev["source"] == "access.log"
    assert ev["ip"] == "192.0.2.45"
    assert ev["detail"]["method"] == "GET"
    assert ev["detail"]["path"] == "/wp-admin"
    assert ev["detail"]["status"] == 401
    assert ev["severity"] == "warn"
    assert ev["ts"] == datetime(2026, 10, 10, 13, 55, 36, tzinfo=timezone.utc)


def test_access_200_ok():
    line = '10.0.0.5 - ana [11/Oct/2026:08:00:01 +0000] "POST /api/orders HTTP/1.1" 200 128'
    ev = parse_access_log(line)
    assert ev is not None
    assert ev["user"] == "ana"
    assert ev["severity"] == "info"
    assert ev["detail"]["size"] == 128


def test_access_500_critical():
    line = '10.0.0.5 - - [11/Oct/2026:08:00:01 +0000] "GET /api/crash HTTP/1.1" 500 0"'
    ev = parse_access_log(line)
    assert ev is not None
    assert ev["severity"] == "critical"


# ----------------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------------

def test_dispatcher_picks_right_parser():
    line_auth = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 183.62.140.253 port 48864 ssh2"
    line_access = '192.0.2.45 - - [10/Oct/2026:13:55:36 +0000] "GET /wp-admin HTTP/1.1" 401 2326'

    assert parse("auth.log", line_auth)["user"] == "root"
    assert parse("access.log", line_access)["detail"]["status"] == 401


def test_dispatcher_unknown_source():
    try:
        parse("desconocido.log", "x")
    except ValueError as e:
        assert "Fuente desconocida" in str(e)
    else:
        assert False, "debería haber tirado ValueError"
