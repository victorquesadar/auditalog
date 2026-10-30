"""Tests de las reglas de detección nuevas de S3."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import redis as redis_lib

from src.common.rules import (
    rule_bad_user_agent,
    rule_bruteforce,
    rule_dir_scanning,
    rule_directory_traversal,
    rule_offhours,
    rule_sensitive_path,
    rule_sql_injection,
    rule_sudo_fail,
    rule_xss,
)


@pytest.fixture
def r():
    """Redis real local (los tests precisan de contadores)."""
    client = redis_lib.Redis(decode_responses=True)
    for k in client.scan_iter("grupo4:auditalog:*"):
        client.delete(k)
    return client


# ----------------------------------------------------------------------------
# Reglas HTTP (access.log)
# ----------------------------------------------------------------------------

def _access_event(path="/", status=200, raw=None, ip="1.2.3.4", ua=None):
    detail = {"path": path, "status": status, "method": "GET"}
    if ua:
        detail["user_agent"] = ua
    return {
        "source": "access.log",
        "ts": datetime.now(timezone.utc),
        "ip": ip,
        "action": "http_request",
        "severity": "info",
        "detail": detail,
        "raw": raw if raw is not None else f'{ip} - - "GET {path} HTTP/1.1" {status}',
    }


def test_sql_injection_detected():
    ev = _access_event(path="/products?id=1' OR '1'='1")
    assert rule_sql_injection(ev, "oid-1") is not None


def test_sql_injection_union_select():
    ev = _access_event(path="/search?q=UNION SELECT username FROM users")
    alert = rule_sql_injection(ev, "oid-2")
    assert alert["severity"] == "critical"
    assert "sqli_v1" == alert["rule_id"]


def test_sql_injection_benign_url_passes():
    assert rule_sql_injection(_access_event(path="/products?id=5"), "x") is None


def test_xss_script_tag():
    ev = _access_event(path="/comment?msg=<script>alert(1)</script>")
    assert rule_xss(ev, "oid")["severity"] == "critical"


def test_xss_onerror():
    ev = _access_event(path="/x?a=<img src=x onerror=alert(1)>")
    assert rule_xss(ev, "oid") is not None


def test_traversal_etc_passwd():
    ev = _access_event(path="/download?file=../../../etc/passwd")
    assert rule_directory_traversal(ev, "oid")["severity"] == "critical"


def test_traversal_url_encoded():
    ev = _access_event(path="/a/..%2f..%2fetc/passwd")
    assert rule_directory_traversal(ev, "oid") is not None


def test_bad_user_agent_sqlmap():
    ev = _access_event(ua="sqlmap/1.6.0")
    assert rule_bad_user_agent(ev, "oid") is not None


def test_bad_user_agent_benign():
    ev = _access_event(ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0")
    assert rule_bad_user_agent(ev, "oid") is None


def test_sensitive_path_env():
    ev = _access_event(path="/.env")
    assert rule_sensitive_path(ev, "oid")["evidence"]["pattern"] == "/.env"


def test_sensitive_path_phpmyadmin():
    ev = _access_event(path="/phpmyadmin/index.php")
    assert rule_sensitive_path(ev, "oid") is not None


def test_sensitive_path_normal():
    assert rule_sensitive_path(_access_event(path="/about"), "oid") is None


def test_dir_scanning_fires_after_threshold(r):
    ev = _access_event(path="/missing", status=404, ip="203.0.113.1")
    for i in range(19):
        assert rule_dir_scanning(r, ev, f"oid-{i}") is None
    alert = rule_dir_scanning(r, ev, "oid-20")
    assert alert is not None
    assert alert["evidence"]["fails_404"] == 20


def test_dir_scanning_ignores_non_404(r):
    ev = _access_event(path="/", status=200, ip="203.0.113.2")
    for _ in range(50):
        assert rule_dir_scanning(r, ev, "x") is None


# ----------------------------------------------------------------------------
# Reglas auth.log
# ----------------------------------------------------------------------------

def _auth_event(action="login_failed", user="ana", ip="10.0.0.1", raw=""):
    return {
        "source": "auth.log",
        "ts": datetime.now(timezone.utc).replace(hour=12),  # dentro de horario
        "user": user, "ip": ip, "action": action,
        "severity": "warn",
        "detail": {"method": "ssh"},
        "raw": raw,
    }


def test_sudo_fail_detected():
    ev = _auth_event(
        action="login_ok",
        user="ana",
        raw="Oct 29 12:00:00 vps sudo: ana : authentication failure; TTY=pts/0 USER=root",
    )
    assert rule_sudo_fail(ev, "oid") is not None


def test_sudo_fail_benign_login_passes():
    ev = _auth_event(
        action="login_ok",
        user="ana",
        raw="Oct 29 12:00:00 vps sshd: Accepted password for ana from 10.0.0.1",
    )
    assert rule_sudo_fail(ev, "oid") is None


# ----------------------------------------------------------------------------
# Reglas S2 — regresión
# ----------------------------------------------------------------------------

def test_bruteforce_still_works(r):
    """Las reglas viejas no se rompieron con las nuevas."""
    settings_window_before = None
    for i in range(1, 6):
        ev = {
            "source": "auth.log", "ts": datetime.now(timezone.utc),
            "user": "root", "ip": "198.51.100.1", "action": "login_failed",
            "severity": "warn", "detail": {}, "raw": f"fail {i}",
        }
        alert = rule_bruteforce(r, ev, f"oid-{i}")
        if i < 5:
            assert alert is None
        else:
            assert alert["rule_id"] == "bruteforce_v1"


def test_offhours_still_works():
    ev = {
        "source": "auth.log",
        "ts": datetime.now(timezone.utc).replace(hour=3),
        "user": "ana", "ip": "10.0.0.5",
        "action": "login_ok", "severity": "info", "detail": {}, "raw": "",
    }
    assert rule_offhours(ev, "oid") is not None
