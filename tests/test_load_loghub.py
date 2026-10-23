"""Tests del generador sintético de Loghub.

No podemos probar la descarga real desde la red en CI, pero sí que:
  - el generador sintético crea un archivo parseable
  - cada línea generada es matcheable por el parser de auth.log
  - los patrones esperados (bruteforce, logins exitosos) están presentes
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from scripts.load_loghub import generate_synthetic_log, iter_events


def test_synthetic_log_is_parseable(tmp_path: Path):
    dest = tmp_path / "SSH.log"
    generate_synthetic_log(dest, lines=500)
    assert dest.exists()

    events = list(iter_events(dest, limit=500, year=2026))
    assert len(events) == 500, "todas las líneas sintéticas deben ser parseables"


def test_synthetic_log_includes_both_outcomes(tmp_path: Path):
    dest = tmp_path / "SSH.log"
    generate_synthetic_log(dest, lines=2000)
    events = list(iter_events(dest, limit=2000, year=2026))

    actions = Counter(e["action"] for e in events)
    assert actions["login_failed"] > 0
    assert actions["login_ok"] > 0


def test_synthetic_log_has_brute_force_patterns(tmp_path: Path):
    """Al menos una IP debe tener >=5 fallos (lo que dispararía la regla)."""
    dest = tmp_path / "SSH.log"
    generate_synthetic_log(dest, lines=2000)
    events = list(iter_events(dest, limit=2000, year=2026))

    fails_per_ip = Counter(
        e["ip"] for e in events if e["action"] == "login_failed"
    )
    top_ips_con_bruteforce = [ip for ip, n in fails_per_ip.most_common() if n >= 5]
    assert len(top_ips_con_bruteforce) >= 3, \
        f"deberían haber al menos 3 IPs con >=5 fallos, hubo {len(top_ips_con_bruteforce)}"
