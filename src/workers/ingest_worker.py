"""Worker de ingesta.

Consume el stream `grupo4:auditalog:ingest`, aplica las reglas de detección
y persiste el evento (y las alertas que se disparen) en MongoDB.

Reglas implementadas en esta versión:
  - Fuerza bruta: N fallos de login desde la misma IP en una ventana (TTL).
  - Acceso fuera de horario: logins entre OFFHOURS_START y OFFHOURS_END.

Uso:
    python -m src.workers.ingest_worker
    python -m src.workers.ingest_worker --once      # procesa lo pendiente y sale
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timezone

import redis
from pymongo import MongoClient

from src.common.config import key, settings


STREAM_NAME = key("ingest")
GROUP_NAME = "auditalog_workers"
CONSUMER_NAME = "worker-1"

# ----------------------------------------------------------------------------
# Conexiones
# ----------------------------------------------------------------------------

def connect_redis() -> redis.Redis:
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        decode_responses=True,
    )


def connect_mongo() -> MongoClient:
    return MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)


def ensure_consumer_group(r: redis.Redis) -> None:
    """Crea el consumer group si no existe (idempotente)."""
    try:
        r.xgroup_create(STREAM_NAME, GROUP_NAME, id="0", mkstream=True)
        print(f"[worker] consumer group creado: {GROUP_NAME}")
    except redis.ResponseError as e:
        if "BUSYGROUP" in str(e):
            print(f"[worker] consumer group ya existe: {GROUP_NAME}")
        else:
            raise


# ----------------------------------------------------------------------------
# Normalización
# ----------------------------------------------------------------------------

def payload_to_event(payload: dict) -> dict:
    """Reconvierte el payload del stream al dict de evento normalizado."""
    return {
        "source": payload["source"],
        "host": payload.get("host") or None,
        "ts": datetime.fromisoformat(payload["ts"]),
        "ingested_at": datetime.now(timezone.utc),
        "user": payload.get("user") or None,
        "ip": payload.get("ip") or None,
        "action": payload["action"],
        "detail": json.loads(payload.get("detail", "{}") or "{}"),
        "severity": payload["severity"],
        "raw": payload["raw"],
    }


# ----------------------------------------------------------------------------
# Reglas de detección
# ----------------------------------------------------------------------------

def rule_bruteforce(r: redis.Redis, event: dict, mongo_event_id) -> dict | None:
    """Cuenta fallos por IP en una ventana con TTL; alerta al pasar el umbral."""
    if event["action"] != "login_failed" or not event["ip"]:
        return None

    k = key("bruteforce", event["ip"])
    fails = r.incr(k)
    r.expire(k, settings.bruteforce_window_sec)

    # Ranking de IPs sospechosas (sorted set global, se recorta en S3)
    r.zincrby(key("suspicious:ips"), 1, event["ip"])

    if fails < settings.bruteforce_max_fails:
        return None

    return {
        "rule_id": "bruteforce_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "critical",
        "title": f"Posible fuerza bruta desde {event['ip']}",
        "evidence": {
            "ip": event["ip"],
            "user": event["user"],
            "fails": int(fails),
            "window_sec": settings.bruteforce_window_sec,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


def rule_offhours(event: dict, mongo_event_id) -> dict | None:
    """Loguearse fuera de horario laboral configurado."""
    if event["action"] not in ("login_ok", "login_failed"):
        return None

    hour = event["ts"].hour
    start = settings.offhours_start
    end = settings.offhours_end
    # Ventana cruza medianoche: 22-06 → hour >= 22 OR hour < 6
    in_offhours = (hour >= start) or (hour < end) if start > end else (start <= hour < end)
    if not in_offhours:
        return None

    return {
        "rule_id": "offhours_v1",
        "fired_at": datetime.now(timezone.utc),
        "severity": "warn",
        "title": f"Acceso fuera de horario ({hour:02d}:xx) de {event['user']}@{event['ip']}",
        "evidence": {
            "user": event["user"],
            "ip": event["ip"],
            "hour": hour,
            "event_ids": [mongo_event_id],
        },
        "status": "open",
    }


RULES = [
    ("bruteforce", lambda r, ev, eid: rule_bruteforce(r, ev, eid)),
    ("offhours",   lambda r, ev, eid: rule_offhours(ev, eid)),
]


# ----------------------------------------------------------------------------
# Loop principal
# ----------------------------------------------------------------------------

_stop = False


def _handle_sigint(signum, frame):
    global _stop
    print("\n[worker] detención solicitada...")
    _stop = True


def process_message(r: redis.Redis, db, msg_id: str, payload: dict) -> None:
    event = payload_to_event(payload)
    res = db.events.insert_one(event)
    event_id = res.inserted_id

    for name, fn in RULES:
        try:
            alert = fn(r, event, event_id)
            if alert:
                db.alerts.insert_one(alert)
                r.publish(key("alerts"), json.dumps({
                    "rule_id": alert["rule_id"],
                    "title": alert["title"],
                    "severity": alert["severity"],
                }))
                print(f"[worker] 🚨 alerta: {alert['title']}")
        except Exception as e:
            print(f"[worker] ERROR en regla {name}: {e}", file=sys.stderr)

    r.xack(STREAM_NAME, GROUP_NAME, msg_id)


def main() -> int:
    ap = argparse.ArgumentParser(description="Worker de ingesta de AuditaLog")
    ap.add_argument("--once", action="store_true",
                    help="Procesa lo pendiente y sale (útil en tests)")
    ap.add_argument("--block-ms", type=int, default=2000,
                    help="Tiempo de bloqueo por iteración (ms)")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        r = connect_redis()
        r.ping()
    except redis.RedisError as e:
        print(f"[ERROR] Redis no responde: {e}", file=sys.stderr)
        return 2

    mongo = connect_mongo()
    mongo.admin.command("ping")
    db = mongo[settings.mongo_db]

    ensure_consumer_group(r)

    print(f"[worker] escuchando {STREAM_NAME} (bloqueo={args.block_ms}ms, once={args.once})")

    processed = 0
    while not _stop:
        try:
            resp = r.xreadgroup(
                GROUP_NAME, CONSUMER_NAME,
                {STREAM_NAME: ">"},
                count=50,
                block=args.block_ms,
            )
        except redis.RedisError as e:
            print(f"[worker] error leyendo stream: {e}", file=sys.stderr)
            time.sleep(1)
            continue

        if not resp:
            if args.once:
                break
            continue

        for _stream, messages in resp:
            for msg_id, payload in messages:
                try:
                    process_message(r, db, msg_id, payload)
                    processed += 1
                except Exception as e:
                    print(f"[worker] ERROR procesando {msg_id}: {e}", file=sys.stderr)

        if processed and processed % 100 == 0:
            print(f"[worker] {processed} eventos procesados")

    print(f"[worker] saliendo · {processed} eventos procesados")
    return 0


if __name__ == "__main__":
    sys.exit(main())
