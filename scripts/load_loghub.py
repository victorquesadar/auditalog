"""Descarga y carga eventos reales de Loghub en MongoDB.

Loghub (https://github.com/logpai/loghub) es un repositorio público con logs
reales anonimizados. Usamos el dataset de OpenSSH, que trae ~655k líneas de
intentos de SSH reales, incluyendo fuerza bruta real desde IPs de atacantes.

Qué hace este script:
  1. Descarga el archivo SSH.log de Loghub si no existe localmente.
  2. Parsea las primeras N líneas con el parser de auth.log.
  3. Las inserta en Mongo en **lotes** (insert_many) para rendimiento.
  4. Usa una **transacción** (si el cluster lo soporta — Atlas sí) para que
     o se cargan todas o no se carga ninguna. En clusters standalone sin
     replica set, cae a modo "best effort" sin transacción.

Uso:
    python scripts/load_loghub.py                 # 10 000 eventos (default)
    python scripts/load_loghub.py --limit 50000
    python scripts/load_loghub.py --reset         # borra events antes de cargar
    python scripts/load_loghub.py --dry-run       # solo parsea, no inserta
"""
from __future__ import annotations

import argparse
import gzip
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Permitir correr `python scripts/load_loghub.py` directo
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from src.common.config import settings
from src.common.parsers import parse_auth_log


# URLs del dataset de Loghub OpenSSH.
# El repo logpai/loghub mantiene los logs en Zenodo (DOI 10.5281/zenodo.8196385).
# Para una descarga directa de UN archivo sin tar.gz, usamos el espejo Hugging Face.
LOGHUB_URLS = (
    "https://huggingface.co/datasets/logpai/loghub/resolve/main/OpenSSH/SSH.log",
    "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/SSH.log",
)

DEFAULT_PATH = Path("data/loghub/SSH.log")
BATCH_SIZE = 1000


def download(dest: Path) -> bool:
    """Intenta descargar el dataset. Devuelve True si lo logró."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    for url in LOGHUB_URLS:
        print(f"[loghub] intentando descargar {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                total = 0
                with dest.open("wb") as f:
                    while True:
                        chunk = resp.read(1 << 16)
                        if not chunk:
                            break
                        f.write(chunk)
                        total += len(chunk)
                        if total >> 20 >= 1 and total % (1 << 20) < (1 << 16):
                            print(f"[loghub] ...{total >> 20} MB")
            print(f"[loghub] descargado · {total:,} bytes")
            return True
        except Exception as e:
            print(f"[loghub] fallo: {e}")
            if dest.exists():
                dest.unlink()
    return False


def generate_synthetic_log(dest: Path, lines: int = 15_000) -> None:
    """Fallback: genera un auth.log sintético con patrones realistas.

    Mezcla fuerza bruta de varias IPs, logins exitosos, accesos fuera de horario
    y fallos aislados — las mismas distribuciones que ve un servidor expuesto a
    internet por un día.
    """
    import random
    from datetime import datetime, timedelta

    dest.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(1337)
    base_ts = datetime(2026, 10, 1, 0, 0, 0)
    host = "vps-01"

    attackers = [f"203.0.113.{i}" for i in range(1, 11)] + \
                [f"198.51.100.{i}" for i in range(1, 11)]
    legit_ips = [f"10.0.0.{i}" for i in range(5, 30)]
    users_atacados = ["root", "admin", "oracle", "postgres", "ubuntu", "test", "user"]
    users_legit = ["ana", "jose", "carlos", "maria", "luis"]

    print(f"[loghub] generando {lines:,} líneas sintéticas en {dest}")
    with dest.open("w", encoding="utf-8") as f:
        for i in range(lines):
            ts = base_ts + timedelta(seconds=i * 5 + rng.randint(-2, 2))
            r = rng.random()

            if r < 0.70:  # 70% fuerza bruta de atacantes
                ip = rng.choice(attackers)
                user = rng.choice(users_atacados)
                outcome = "Failed"
                extra = "invalid user " if rng.random() < 0.4 else ""
            elif r < 0.90:  # 20% logins exitosos legítimos
                ip = rng.choice(legit_ips)
                user = rng.choice(users_legit)
                outcome = "Accepted"
                extra = ""
            else:  # 10% fallos aislados
                ip = rng.choice(legit_ips)
                user = rng.choice(users_legit)
                outcome = "Failed"
                extra = ""

            f.write(
                f"{ts.strftime('%b %d %H:%M:%S')} {host} "
                f"sshd[{rng.randint(1000, 99999)}]: "
                f"{outcome} password for {extra}{user} from {ip} "
                f"port {rng.randint(40000, 60000)} ssh2\n"
            )
    print(f"[loghub] archivo sintético listo · {dest.stat().st_size:,} bytes")


def iter_events(path: Path, limit: int, year: int):
    """Lee el archivo y yielda hasta `limit` eventos parseados."""
    with path.open("r", encoding="utf-8", errors="replace") as f:
        yielded = 0
        skipped = 0
        for line in f:
            if yielded >= limit:
                break
            ev = parse_auth_log(line, default_year=year)
            if ev is None:
                skipped += 1
                continue
            # Mongo necesita datetime, no datetime+tzinfo según algunas versiones;
            # dejamos tz-aware que pymongo serializa como ISODate.
            ev["ingested_at"] = datetime.now(timezone.utc)
            yielded += 1
            yield ev
        print(f"[loghub] {yielded} eventos parseados · {skipped} líneas descartadas")


def load_without_tx(db, events) -> int:
    """Carga por lotes sin transacción (compatible con standalone)."""
    inserted = 0
    batch: list = []
    for ev in events:
        batch.append(ev)
        if len(batch) >= BATCH_SIZE:
            db.events.insert_many(batch, ordered=False)
            inserted += len(batch)
            batch = []
            print(f"[loghub] insertados {inserted} eventos...")
    if batch:
        db.events.insert_many(batch, ordered=False)
        inserted += len(batch)
    return inserted


def load_with_tx(client, db_name: str, events) -> int:
    """Carga en una sola transacción. Requiere replica set (Atlas lo tiene)."""
    inserted = 0
    with client.start_session() as session:
        with session.start_transaction():
            db = client[db_name]
            batch: list = []
            for ev in events:
                batch.append(ev)
                if len(batch) >= BATCH_SIZE:
                    db.events.insert_many(batch, ordered=False, session=session)
                    inserted += len(batch)
                    batch = []
                    print(f"[loghub] insertados {inserted} (en transacción)...")
            if batch:
                db.events.insert_many(batch, ordered=False, session=session)
                inserted += len(batch)
    return inserted


def main() -> int:
    ap = argparse.ArgumentParser(description="Carga Loghub en MongoDB")
    ap.add_argument("--limit", type=int, default=10_000,
                    help="Cantidad máxima de eventos a cargar (default 10000)")
    ap.add_argument("--year", type=int, default=2023,
                    help="Año a asumir (Loghub es de 2015-2023 según dataset)")
    ap.add_argument("--path", type=Path, default=DEFAULT_PATH,
                    help="Dónde está el SSH.log (se descarga si no existe)")
    ap.add_argument("--reset", action="store_true",
                    help="Borra events antes de cargar")
    ap.add_argument("--dry-run", action="store_true",
                    help="Solo parsea, no inserta")
    ap.add_argument("--no-tx", action="store_true",
                    help="Fuerza modo sin transacción")
    args = ap.parse_args()

    if not args.path.exists():
        ok = download(args.path)
        if not ok:
            print("[loghub] no se pudo descargar; usando generador sintético como fallback")
            generate_synthetic_log(args.path, lines=max(args.limit * 2, 15_000))
    else:
        print(f"[loghub] usando archivo existente: {args.path}")

    if args.dry_run:
        count = sum(1 for _ in iter_events(args.path, args.limit, args.year))
        print(f"[loghub] dry-run: {count} eventos parseados correctamente")
        return 0

    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=10_000)
    client.admin.command("ping")
    db = client[settings.mongo_db]

    if args.reset:
        n = db.events.count_documents({})
        db.events.delete_many({})
        print(f"[loghub] borrados {n} eventos previos")

    t0 = time.time()
    try:
        if args.no_tx:
            raise OperationFailure("--no-tx: saltamos transacción", code=0)
        inserted = load_with_tx(
            client, settings.mongo_db,
            iter_events(args.path, args.limit, args.year),
        )
        mode = "con transacción"
    except OperationFailure as e:
        if "replica set" in str(e).lower() or "transaction" in str(e).lower() or args.no_tx:
            print(f"[loghub] transacciones no disponibles ({e}); cargando sin transacción")
            inserted = load_without_tx(
                db, iter_events(args.path, args.limit, args.year),
            )
            mode = "sin transacción"
        else:
            raise

    elapsed = time.time() - t0
    rate = inserted / elapsed if elapsed > 0 else 0
    print(f"\n[loghub] OK · {inserted:,} eventos insertados {mode}")
    print(f"[loghub] tiempo: {elapsed:.1f}s · velocidad: {rate:,.0f} eventos/s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
