"""Hola mundo · Redis.

Verifica la conexión, respeta el prefijo grupo4:auditalog:, prueba una clave
con TTL y publica un mensaje en el canal de alertas.

    python scripts/hello_redis.py
"""
from __future__ import annotations

import os
import sys
import time

import redis
from dotenv import load_dotenv


def main() -> int:
    load_dotenv()
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", "6379"))
    password = os.getenv("REDIS_PASSWORD") or None
    db = int(os.getenv("REDIS_DB", "0"))
    prefix = os.getenv("REDIS_PREFIX", "grupo4:auditalog:")

    if not prefix.startswith("grupo4:"):
        print(f"[ERROR] REDIS_PREFIX debe empezar con 'grupo4:' (recibido: {prefix!r})",
              file=sys.stderr)
        return 1

    print(f"[hello_redis] conectando a {host}:{port} db={db} prefix={prefix!r}")
    try:
        r = redis.Redis(host=host, port=port, password=password, db=db,
                        decode_responses=True, socket_connect_timeout=5)
        pong = r.ping()
        print(f"[hello_redis] ping OK → {pong}")

        # Contador con TTL (simula bruteforce)
        key = f"{prefix}bruteforce:192.0.2.45"
        r.incr(key)
        r.expire(key, 10)
        val = r.get(key)
        ttl = r.ttl(key)
        print(f"[hello_redis] {key} = {val} (ttl={ttl}s)")

        # Sorted set de IPs sospechosas
        zkey = f"{prefix}suspicious:ips"
        r.zincrby(zkey, 1, "192.0.2.45")
        top = r.zrevrange(zkey, 0, 2, withscores=True)
        print(f"[hello_redis] top IPs sospechosas → {top}")

        # Pub/Sub de alertas
        channel = f"{prefix}alerts"
        n = r.publish(channel, "hello from AuditaLog")
        print(f"[hello_redis] publicado en {channel} → {n} suscriptores")

        # Smoke test de Stream
        stream = f"{prefix}ingest"
        msg_id = r.xadd(stream, {"source": "smoke", "msg": "hello"}, maxlen=10)
        print(f"[hello_redis] XADD {stream} id={msg_id}")

        # Limpieza del smoke test (sin FLUSHDB/FLUSHALL)
        r.delete(key)
        print("[hello_redis] smoke test OK — todo listo")
        return 0

    except redis.RedisError as e:
        print(f"[ERROR] falla conectando a Redis: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
