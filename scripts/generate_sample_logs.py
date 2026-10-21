"""Genera un `auth.log` sintético para probar el flujo sin esperar logs reales.

Incluye tres patrones que las reglas deberían detectar:

  1. Fuerza bruta: 8 fallos consecutivos de la misma IP contra `root`.
  2. Acceso fuera de horario: login exitoso a las 03:30.
  3. Tráfico normal: logins exitosos durante el día.

Uso:
    python scripts/generate_sample_logs.py
    # genera data/samples/sample_auth.log
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "samples" / "sample_auth.log"
OUT.parent.mkdir(parents=True, exist_ok=True)

HOST = "vps-01"
RNG = random.Random(42)


def fmt(ts: datetime, outcome: str, user: str, ip: str, port: int, invalid: bool = False) -> str:
    user_part = f"invalid user {user}" if invalid else user
    return (
        f"{ts.strftime('%b %d %H:%M:%S')} {HOST} sshd[{RNG.randint(1000, 99999)}]: "
        f"{outcome} password for {user_part} from {ip} port {port} ssh2"
    )


def main() -> None:
    lines: list[str] = []

    # --- Patrón 1: fuerza bruta desde 203.0.113.5 contra root ---
    base = datetime(2026, 10, 15, 14, 30, 0)
    attacker_ip = "203.0.113.5"
    for i in range(8):
        ts = base + timedelta(seconds=i * 3)
        lines.append(fmt(ts, "Failed", "root", attacker_ip, 40000 + i))

    # Al 9no intento, pretende "entrar" (no debería, pero sirve para ver que la alerta ya se disparó)
    ts = base + timedelta(seconds=30)
    lines.append(fmt(ts, "Accepted", "root", attacker_ip, 40100))

    # --- Patrón 2: login fuera de horario (03:30) ---
    offhours_ts = datetime(2026, 10, 16, 3, 30, 0)
    lines.append(fmt(offhours_ts, "Accepted", "ana", "10.0.0.5", 50123))

    # --- Patrón 3: tráfico normal durante el día ---
    base_day = datetime(2026, 10, 16, 9, 0, 0)
    for i in range(10):
        ts = base_day + timedelta(minutes=RNG.randint(0, 240), seconds=RNG.randint(0, 59))
        user = RNG.choice(["ana", "jose", "carlos"])
        ip = RNG.choice(["10.0.0.5", "10.0.0.12", "10.0.0.33"])
        lines.append(fmt(ts, "Accepted", user, ip, RNG.randint(40000, 60000)))

    # --- Patrón 4: algunos fallos aislados de usuarios distintos (no deben disparar nada) ---
    for i in range(3):
        ts = base_day + timedelta(minutes=RNG.randint(0, 180))
        lines.append(fmt(ts, "Failed", "jose", "10.0.0.99", RNG.randint(40000, 60000), invalid=False))

    # --- Patrón 5: fuerza bruta contra "admin" desde IP distinta ---
    base2 = datetime(2026, 10, 16, 10, 15, 0)
    attacker2 = "198.51.100.33"
    for i in range(6):
        ts = base2 + timedelta(seconds=i * 10)
        lines.append(fmt(ts, "Failed", "admin", attacker2, 55000 + i, invalid=True))

    # Ordenar por timestamp (como vendría en syslog real)
    def _ts(line: str) -> datetime:
        return datetime.strptime(line[:15], "%b %d %H:%M:%S").replace(year=2026)
    lines.sort(key=_ts)

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[gen] escrito {len(lines)} líneas en {OUT}")


if __name__ == "__main__":
    main()
