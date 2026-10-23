"""Colector del `auth.log` (SSH).

Lee un archivo de log línea por línea y empuja cada evento parseado al
Stream `grupo4:auditalog:ingest` de Redis. Soporta dos modos:

  --mode batch   procesa todas las líneas y termina (útil para Loghub).
  --mode tail    sigue el archivo tipo `tail -f` (útil para producción).

Uso:
    python -m src.collectors.auth_log_collector --file data/samples/sample_auth.log
    python -m src.collectors.auth_log_collector --file /var/log/auth.log --mode tail
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import redis

from src.common.config import key, settings
from src.common.parsers import parse_auth_log


STREAM_NAME = key("ingest")           # grupo4:auditalog:ingest
MAX_STREAM_LEN = 100_000              # autotrim para no crecer sin control

#Conexión para el redis 
def connect_redis() -> redis.Redis:
    return redis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        decode_responses=True,
    )

#Evento del push para eventos XADD
def push_event(r: redis.Redis, evento: dict) -> str:
    """Serializa el evento y hace XADD al stream."""
    payload = {
        "source": evento["source"],
        "host": evento["host"] or "",
        "ts": evento["ts"].isoformat(),
        "user": evento["user"] or "",
        "ip": evento["ip"] or "",
        "action": evento["action"],
        "detail": json.dumps(evento["detail"]),
        "severity": evento["severity"],
        "raw": evento["raw"],
    }
    return r.xadd(STREAM_NAME, payload, maxlen=MAX_STREAM_LEN, approximate=True)


def process_batch(r: redis.Redis, path: Path, year: int) -> tuple[int, int]:
    """Procesa todas las líneas del archivo y termina.

    Devuelve (líneas_leídas, eventos_enviados)."""
    read = sent = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            read += 1
            evento = parse_auth_log(line, default_year=year)
            if evento is None:
                continue
            push_event(r, evento)
            sent += 1
            if sent % 500 == 0:
                print(f"[collector] {sent} eventos enviados...")
    return read, sent


def process_tail(r: redis.Redis, path: Path, year: int) -> None:
    """Se queda escuchando el archivo tipo `tail -f`."""
    print(f"[collector] siguiendo {path} (Ctrl+C para salir)")
    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # ir al final
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            evento = parse_auth_log(line, default_year=year)
            if evento is None:
                continue
            push_event(r, evento)
            print(f"[collector] → {evento['action']} {evento['user']}@{evento['ip']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Colector de auth.log para AuditaLog")
    ap.add_argument("--file", required=True, help="Archivo auth.log a leer")
    ap.add_argument("--mode", choices=("batch", "tail"), default="batch")
    ap.add_argument("--year", type=int, default=2026,
                    help="Año a asumir (syslog no lo incluye)")
    args = ap.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] no existe el archivo: {path}", file=sys.stderr)
        return 1

    try:
        r = connect_redis()
        r.ping()
    except redis.RedisError as e:
        print(f"[ERROR] Redis no responde: {e}", file=sys.stderr)
        return 2

    print(f"[collector] redis OK · stream={STREAM_NAME} · modo={args.mode}")

    if args.mode == "batch":
        read, sent = process_batch(r, path, args.year)
        print(f"[collector] terminado · {read} líneas leídas · {sent} eventos enviados")
    else:
        try:
            process_tail(r, path, args.year)
        except KeyboardInterrupt:
            print("\n[collector] detenido por el usuario")

    return 0


if __name__ == "__main__":
    sys.exit(main())
