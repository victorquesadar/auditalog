"""Integración: colector → Redis → worker → Mongo (mock).

Verifica que, al meter los 29 eventos del sample_auth.log en el stream,
el worker:
  - persista los 29 eventos en Mongo
  - genere al menos 1 alerta de fuerza bruta (203.0.113.5, 8 fallos)
  - genere al menos 1 alerta de fuerza bruta por admin (198.51.100.33, 6 fallos)
  - genere al menos 1 alerta de off-hours (ana a las 03:30)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import mongomock
import redis as redis_lib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.config import settings  # noqa: E402


def test_full_flow():
    # Limpieza previa en Redis
    r = redis_lib.Redis(decode_responses=True)
    for k in r.scan_iter("grupo4:auditalog:*"):
        r.delete(k)

    # 1. Generar sample
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_sample_logs.py")],
        check=True, cwd=ROOT,
    )

    # 2. Correr colector contra el stream real
    subprocess.run(
        [sys.executable, "-m", "src.collectors.auth_log_collector",
         "--file", str(ROOT / "data" / "samples" / "sample_auth.log"),
         "--mode", "batch", "--year", "2026"],
        cwd=ROOT, check=True,
    )

    assert r.xlen("grupo4:auditalog:ingest") == 29

    # 3. Mockear Mongo y correr el worker en-proceso una vez
    fake_mongo = mongomock.MongoClient()

    with patch("src.workers.ingest_worker.connect_mongo", return_value=fake_mongo):
        from src.workers import ingest_worker

        sys.argv = ["ingest_worker", "--once", "--block-ms", "500"]
        rc = ingest_worker.main()
        assert rc == 0

    db = fake_mongo[settings.mongo_db]
    events = list(db.events.find())
    alerts = list(db.alerts.find())

    assert len(events) == 29, f"esperaba 29 eventos, hubo {len(events)}"

    bruteforce = [a for a in alerts if a["rule_id"] == "bruteforce_v1"]
    offhours = [a for a in alerts if a["rule_id"] == "offhours_v1"]

    assert len(bruteforce) >= 2, f"faltan alertas de bruteforce (hubo {len(bruteforce)})"
    assert len(offhours) >= 1, f"faltan alertas de offhours (hubo {len(offhours)})"

    ips_atacantes = {a["evidence"]["ip"] for a in bruteforce}
    assert "203.0.113.5" in ips_atacantes
    assert "198.51.100.33" in ips_atacantes

    print(f"\n[OK] {len(events)} eventos, {len(bruteforce)} alertas bruteforce, "
          f"{len(offhours)} alertas offhours")
