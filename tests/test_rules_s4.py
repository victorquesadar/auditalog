"""Tests de las reglas nuevas del S4: fail2ban, apache denied, apparmor."""
from __future__ import annotations

from datetime import datetime, timezone

from src.common.rules import (
    rule_fail2ban_ban,
    rule_apache_client_denied,
    rule_apparmor_denied,
)


# ---------- rule_fail2ban_ban ----------

def test_fail2ban_ban_fires_on_ban_action():
    ev = {
        "source": "fail2ban.log", "action": "f2b_banned",
        "ip": "1.2.3.4", "detail": {"jail": "sshd"},
    }
    alert = rule_fail2ban_ban(ev, "ev1")
    assert alert is not None
    assert alert["rule_id"] == "f2b_ban_v1"
    assert alert["severity"] == "critical"
    assert "1.2.3.4" in alert["title"]
    assert "sshd" in alert["title"]


def test_fail2ban_ban_ignores_found_action():
    """`Found` NO debe disparar esta regla (solo baneos efectivos)."""
    ev = {
        "source": "fail2ban.log", "action": "f2b_detected",
        "ip": "1.2.3.4", "detail": {"jail": "sshd"},
    }
    assert rule_fail2ban_ban(ev, "ev1") is None


def test_fail2ban_ban_ignores_other_source():
    ev = {"source": "auth.log", "action": "login_failed"}
    assert rule_fail2ban_ban(ev, "ev1") is None


# ---------- rule_apache_client_denied ----------

def test_apache_denied_fires_on_client_denied():
    ev = {
        "source": "error.log", "ip": "9.9.9.9",
        "detail": {"message": "client denied by server configuration: /etc/passwd"},
    }
    alert = rule_apache_client_denied(ev, "ev1")
    assert alert is not None
    assert alert["rule_id"] == "apache_denied_v1"
    assert "9.9.9.9" in alert["title"]


def test_apache_denied_ignores_normal_notice():
    ev = {
        "source": "error.log",
        "detail": {"message": "Apache configured -- resuming normal operations"},
    }
    assert rule_apache_client_denied(ev, "ev1") is None


# ---------- rule_apparmor_denied ----------

def test_apparmor_denied_fires():
    ev = {
        "action": "apparmor_denied",
        "detail": {"message": 'apparmor="DENIED" profile="named" operation="open"'},
    }
    alert = rule_apparmor_denied(ev, "ev1")
    assert alert is not None
    assert alert["rule_id"] == "apparmor_denied_v1"
    assert "named" in alert["title"]


def test_apparmor_denied_ignores_other_actions():
    ev = {"action": "login_failed", "detail": {}}
    assert rule_apparmor_denied(ev, "ev1") is None
