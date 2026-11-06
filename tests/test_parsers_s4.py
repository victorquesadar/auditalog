"""Tests de los parsers nuevos del S4: fail2ban, apache error, php-fpm, syslog ISO."""
from __future__ import annotations

from src.common.parsers import (
    parse_fail2ban_log,
    parse_apache_error_log,
    parse_phpfpm_log,
    parse_kern_log,
    parse_mail_log,
    parse_dmesg,
)


# ---------- fail2ban ----------

def test_fail2ban_found_matches_ip():
    line = ("2026-10-11 10:10:51,140 fail2ban.filter         "
            "[3459308]: INFO    [sshd] Found 45.115.26.20 - 2026-10-11 10:10:50")
    ev = parse_fail2ban_log(line)
    assert ev is not None
    assert ev["source"] == "fail2ban.log"
    assert ev["ip"] == "45.115.26.20"
    assert ev["action"] == "f2b_detected"
    assert ev["severity"] == "warn"
    assert ev["detail"]["jail"] == "sshd"


def test_fail2ban_ban_is_critical():
    line = "2026-10-11 10:12:31,891 fail2ban.actions        [3459308]: NOTICE  [sshd] Ban 45.115.26.20"
    ev = parse_fail2ban_log(line)
    assert ev["action"] == "f2b_banned"
    assert ev["severity"] == "critical"


def test_fail2ban_rollover_is_skipped():
    # Startup noise, no se parsea (no hay IP ni acción de seguridad)
    line = "2026-10-11 00:00:06,477 fail2ban.server         [3459308]: INFO    rollover performed on /var/log/fail2ban.log"
    ev = parse_fail2ban_log(line)
    assert ev is None


# ---------- Apache error.log ----------

def test_apache_error_notice_parses():
    line = ("[Sun Oct 18 00:00:07.170119 2026] [mpm_event:notice] [pid 248363:tid 133051651417984] "
            "AH00489: Apache/2.4.58 (Ubuntu) configured")
    ev = parse_apache_error_log(line)
    assert ev is not None
    assert ev["source"] == "error.log"
    assert ev["detail"]["module"] == "mpm_event"
    assert ev["detail"]["level"] == "notice"
    assert ev["severity"] == "info"


def test_apache_error_with_client_extracts_ip():
    line = ("[Mon Oct 19 10:14:03.000000 2026] [authz_core:error] [pid 1234] "
            "[client 1.2.3.4:5678] AH01630: client denied by server configuration: /etc/passwd")
    ev = parse_apache_error_log(line)
    assert ev["ip"] == "1.2.3.4"
    assert ev["severity"] == "warn"  # 'error' level
    assert "client denied" in ev["detail"]["message"]


def test_apache_error_crit_is_critical():
    line = "[Mon Oct 19 10:00:00.000000 2026] [core:crit] [pid 1] AH00016: Configuration Failed"
    ev = parse_apache_error_log(line)
    assert ev["severity"] == "critical"


# ---------- PHP-FPM ----------

def test_phpfpm_notice():
    line = "[11-Oct-2026 00:00:06] NOTICE: error log file re-opened"
    ev = parse_phpfpm_log(line)
    assert ev is not None
    assert ev["source"] == "phpfpm.log"
    assert ev["severity"] == "info"


def test_phpfpm_error_is_critical():
    line = "[11-Oct-2026 12:34:56] ERROR: [pool www] failed to connect to socket"
    ev = parse_phpfpm_log(line)
    assert ev["severity"] == "critical"


# ---------- syslog ISO (kern/mail/dmesg) ----------

def test_kern_log_apparmor_denied():
    line = ('2026-10-15T06:47:04.614443-06:00 viernes kernel: audit: type=1400 '
            'audit(1792068424.613:157): apparmor="DENIED" operation="open" '
            'profile="named" name="/proc/version_signature"')
    ev = parse_kern_log(line)
    assert ev is not None
    assert ev["action"] == "apparmor_denied"
    assert ev["severity"] == "warn"
    assert ev["host"] == "viernes"


def test_mail_log_dovecot_warning():
    line = ("2026-10-15T06:47:33.107116-06:00 viernes dovecot: "
            "master: Warning: Killed with signal 15 (by pid=244715 uid=0 code=kill)")
    ev = parse_mail_log(line)
    assert ev is not None
    assert ev["source"] == "mail.log"
    assert ev["severity"] == "warn"  # "killed" en el mensaje


def test_dmesg_classic_format():
    line = "[    0.000000] kernel: Linux version 7.0.0-1012-aws"
    ev = parse_dmesg(line)
    assert ev is not None
    assert ev["action"] == "kernel_msg"
    assert ev["detail"]["uptime"] == 0.0


def test_dmesg_iso_format_delegates():
    line = "2026-10-15T06:46:59.485131-06:00 viernes kernel: workqueue: delayed_vfree_work"
    ev = parse_dmesg(line)
    assert ev is not None
    assert ev["source"] == "dmesg"


def test_garbage_line_returns_none():
    """Una línea que no matchea ningún patrón debe devolver None, no explotar."""
    for parser in (parse_fail2ban_log, parse_apache_error_log,
                   parse_phpfpm_log, parse_kern_log, parse_mail_log, parse_dmesg):
        assert parser("basura basura basura") is None
