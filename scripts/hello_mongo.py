"""Hola mundo · MongoDB.

Verifica la conexión, crea la base y las colecciones iniciales si no existen,
y muestra un ping. Se corre así:

    python scripts/hello_mongo.py
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError


def main() -> int:
    load_dotenv()
    uri = os.getenv("MONGO_URI")
    db_name = os.getenv("MONGO_DB", "auditalog")

    if not uri:
        print("[ERROR] MONGO_URI no está definido en .env", file=sys.stderr)
        return 1

    print(f"[hello_mongo] conectando a {uri[:40]}... db={db_name}")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        info = client.admin.command("ping")
        print(f"[hello_mongo] ping OK → {info}")

        db = client[db_name]
        existing = set(db.list_collection_names())

        for coll in ("events", "alerts", "rules"):
            if coll not in existing:
                db.create_collection(coll)
                print(f"[hello_mongo] colección creada: {coll}")

        # Índices iniciales (idempotentes)
        db.events.create_index([("ts", DESCENDING)])
        db.events.create_index([("source", ASCENDING), ("ts", DESCENDING)])
        db.events.create_index([("ip", ASCENDING), ("ts", DESCENDING)])
        db.events.create_index([("user", ASCENDING), ("ts", DESCENDING)])
        db.events.create_index([("severity", ASCENDING), ("ts", DESCENDING)])
        db.alerts.create_index([("fired_at", DESCENDING)])
        db.alerts.create_index([("rule_id", ASCENDING)])
        print("[hello_mongo] índices OK")

        # Documento de smoke test (se borra al final)
        res = db.events.insert_one({
            "source": "hello_world",
            "ts": datetime.now(timezone.utc),
            "ingested_at": datetime.now(timezone.utc),
            "action": "smoke_test",
            "severity": "info",
            "raw": "hello from AuditaLog",
        })
        print(f"[hello_mongo] insertado _id={res.inserted_id}")
        db.events.delete_one({"_id": res.inserted_id})
        print("[hello_mongo] smoke test OK — todo listo")
        return 0

    except PyMongoError as e:
        print(f"[ERROR] falla conectando a Mongo: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
