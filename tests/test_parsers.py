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


# ----------------------------------------------------------------------------
# php_log — formato real que mandó el profesor
# ----------------------------------------------------------------------------

from src.common.parsers import parse_php_log


def test_php_fatal_error():
    line = "[10-Oct-2026 00:29:48 UTC] PHP Fatal error:  Uncaught MongoDB\\Driver\\Exception\\ConnectionTimeoutException: No suitable servers found in /home/grupo4/public_html/vendor/mongodb/mongodb/src/functions.php:625"
    ev = parse_php_log(line)
    assert ev is not None
    assert ev["source"] == "php_log"
    assert ev["severity"] == "critical"
    assert ev["action"] == "php_fatal"
    assert ev["detail"]["level"] == "fatal error"
    assert ev["detail"]["file"] == "/home/grupo4/public_html/vendor/mongodb/mongodb/src/functions.php"
    assert ev["detail"]["line"] == 625


def test_php_warning():
    line = "[10-Oct-2026 00:30:01 UTC] PHP Warning: file_get_contents(x.txt): failed to open stream in /var/www/app.php:42"
    ev = parse_php_log(line)
    assert ev is not None
    assert ev["severity"] == "warn"
    assert ev["action"] == "php_warning"
    assert ev["detail"]["file"] == "/var/www/app.php"
    assert ev["detail"]["line"] == 42


def test_php_notice():
    line = "[10-Oct-2026 00:31:00 UTC] PHP Notice: Undefined index: x in /var/www/app.php:88"
    ev = parse_php_log(line)
    assert ev is not None
    assert ev["severity"] == "info"


def test_php_parse_error_is_critical():
    line = "[11-Oct-2026 10:00:00 UTC] PHP Parse error: syntax error, unexpected '}' in /var/www/x.php on line 10"
    ev = parse_php_log(line)
    assert ev is not None
    assert ev["severity"] == "critical"


def test_php_stack_trace_line_returns_none():
    """Las líneas del stack trace no deben parsearse como eventos."""
    line = "#0 /home/grupo4/public_html/vendor/mongodb/mongodb/src/functions.php(625): MongoDB\\Driver\\Manager->selectServer()"
    assert parse_php_log(line) is None


def test_php_empty_and_garbage():
    assert parse_php_log("") is None
    assert parse_php_log("basura cualquiera") is None
    assert parse_php_log("#2 {main}") is None


def test_dispatcher_knows_php_log():
    line = "[10-Oct-2026 00:29:48 UTC] PHP Warning: test"
    ev = parse("php_log", line)
    assert ev is not None
    assert ev["source"] == "php_log"


# ----------------------------------------------------------------------------
# auth.log — formato ISO 8601 (RFC5424 / journald) — como el del VPS del profe
# ----------------------------------------------------------------------------

def test_auth_iso_accepted_publickey():
    line = "2026-10-16T18:02:06.239193-06:00 viernes sshd[343706]: Accepted publickey for ubuntu from 152.231.189.202 port 38967 ssh2: RSA SHA256:4HAiWOuXaE5EdlFjimVPTiQ5TymEnYIALYqaD9VSxLQ"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["action"] == "login_ok"
    assert ev["user"] == "ubuntu"
    assert ev["ip"] == "152.231.189.202"
    assert ev["detail"]["method"] == "publickey"
    assert ev["ts"].year == 2026
    assert ev["ts"].month == 10
    assert ev["host"] == "viernes"


def test_auth_iso_failed_password():
    line = "2026-10-11T00:06:07.110988-06:00 viernes sshd[4163380]: Failed password for root from 152.42.130.61 port 58006 ssh2"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["action"] == "login_failed"
    assert ev["severity"] == "warn"
    assert ev["user"] == "root"
    assert ev["ip"] == "152.42.130.61"


def test_auth_iso_without_microseconds():
    line = "2026-10-11T00:06:07-06:00 viernes sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["user"] == "root"


def test_auth_syslog_classic_still_works():
    """Regresión: el formato clásico sigue funcionando."""
    line = "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for root from 183.62.140.253 port 48864 ssh2"
    ev = parse_auth_log(line, default_year=2026)
    assert ev is not None
    assert ev["user"] == "root"
    assert ev["ip"] == "183.62.140.253"
    assert ev["detail"]["method"] == "password"


# Probes SSH (scanners / botnets)

def test_auth_banner_invalid():
    line = "2026-10-11T00:06:07.110988-06:00 viernes sshd[4163380]: banner exchange: Connection from 152.42.130.61 port 58006: invalid format"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["action"] == "ssh_probe"
    assert ev["ip"] == "152.42.130.61"
    assert ev["detail"]["probe_type"] == "banner_invalid"


def test_auth_invalid_user_as_login_failed():
    line = "2026-10-11T05:00:00.000000-06:00 viernes sshd[1]: Invalid user admin from 203.0.113.1 port 1234"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["action"] == "login_failed"   # cuenta para bruteforce
    assert ev["user"] == "admin"
    assert ev["ip"] == "203.0.113.1"


def test_auth_connection_reset_preauth():
    line = "2026-10-11T04:49:47.519590-06:00 viernes sshd[4175348]: Connection reset by 205.210.31.58 port 60536 [preauth]"
    ev = parse_auth_log(line)
    assert ev is not None
    assert ev["action"] == "ssh_probe"
    assert ev["detail"]["probe_type"] == "preauth_reset"


def test_auth_cron_sessions_still_ignored():
    """Las sesiones CRON del sistema NO se procesan como eventos."""
    line = "2026-10-11T00:05:01.127572-06:00 viernes CRON[4163360]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
    assert parse_auth_log(line) is None
