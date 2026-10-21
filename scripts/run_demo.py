"""Demo end-to-end del flujo de ingesta.

Hace, en orden:
  1. Limpia el stream y las colecciones (de prueba, no toca Atlas en prod).
  2. Genera logs sintéticos si no existen.
  3. Lanza el worker en segundo plano.
  4. Corre el colector en modo batch.
  5. Espera a que el worker drene lo que llegó.
  6. Imprime cuántos eventos y alertas quedaron en Mongo.

Pensado para demostrar S2 en vivo:

    python scripts/run_demo.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import redis
from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.common.config import key, settings  # noqa: E402

SAMPLE = ROOT / "data" / "samples" / "sample_auth.log"


def reset_state() -> None:
    print("[demo] limpiando estado anterior...")
    r = redis.Redis(host=settings.redis_host, port=settings.redis_port,
                    password=settings.redis_password, db=settings.redis_db,
                    decode_responses=True)
    # Borrar el stream y claves de prueba (sin FLUSHALL)
    for k in (key("ingest"),
              key("suspicious:ips"),
              key("bruteforce", "203.0.113.5"),
              key("bruteforce", "198.51.100.33")):
        r.delete(k)

    m = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    db = m[settings.mongo_db]
    db.events.delete_many({})
    db.alerts.delete_many({})
    print("[demo] estado limpio")


def main() -> int:
    if not SAMPLE.exists():
        print("[demo] generando logs sintéticos...")
        subprocess.run([sys.executable, str(ROOT / "scripts" / "generate_sample_logs.py")],
                       check=True)

    reset_state()

    # 1. Lanzar el worker en segundo plano
    print("[demo] lanzando worker en segundo plano...")
    worker = subprocess.Popen(
        [sys.executable, "-m", "src.workers.ingest_worker", "--block-ms", "500"],
        cwd=ROOT,
    )
    time.sleep(2)  # darle tiempo a conectar

    try:
        # 2. Correr el colector en modo batch
        print("[demo] corriendo colector...")
        subprocess.run(
            [sys.executable, "-m", "src.collectors.auth_log_collector",
             "--file", str(SAMPLE), "--mode", "batch", "--year", "2026"],
            cwd=ROOT, check=True,
        )

        # 3. Esperar a que el worker drene
        print("[demo] esperando 5s a que el worker drene...")
        time.sleep(5)

    finally:
        print("[demo] deteniendo worker...")
        worker.terminate()
        try:
            worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()

    # 4. Reporte
    m = MongoClient(settings.mongo_uri)
    db = m[settings.mongo_db]
    n_events = db.events.count_documents({})
    n_alerts = db.alerts.count_documents({})
    alerts_bruteforce = db.alerts.count_documents({"rule_id": "bruteforce_v1"})
    alerts_offhours = db.alerts.count_documents({"rule_id": "offhours_v1"})

    print("\n" + "=" * 60)
    print(f"  Eventos en Mongo: {n_events}")
    print(f"  Alertas totales:  {n_alerts}")
    print(f"    · fuerza bruta: {alerts_bruteforce}")
    print(f"    · off-hours:    {alerts_offhours}")
    print("=" * 60)

    print("\nÚltimas 3 alertas:")
    for a in db.alerts.find().sort("fired_at", -1).limit(3):
        print(f"  [{a['severity'].upper():>8}] {a['title']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
