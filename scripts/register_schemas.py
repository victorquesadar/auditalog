"""Registra validadores JSON Schema en las colecciones de MongoDB.

El enunciado del S2 pide validación de datos; en Mongo esto se hace con
`$jsonSchema` como `validator` de la colección. Al activarlo:

- Insertar o actualizar un documento que no cumple el esquema → Mongo lo rechaza.
- Los documentos previos no se validan hacia atrás (nivel "moderate" se podría
  usar; acá usamos "strict" solo para inserts/updates nuevos).

Uso:
    python scripts/register_schemas.py          # aplica los schemas
    python scripts/register_schemas.py --off    # los quita (para debug)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pymongo import MongoClient

from src.common.config import settings


EVENT_SCHEMA = {
    "bsonType": "object",
    "required": ["source", "ts", "action", "severity", "raw"],
    "additionalProperties": True,
    "properties": {
        "source": {
            "bsonType": "string",
            "enum": ["auth.log", "access.log", "app", "php_log", "hello_world"],
            "description": "fuente del evento",
        },
        "host": {"bsonType": ["string", "null"]},
        "ts": {"bsonType": "date"},
        "ingested_at": {"bsonType": ["date", "null"]},
        "user": {"bsonType": ["string", "null"]},
        "ip": {
            "oneOf": [
                {"bsonType": "null"},
                {"bsonType": "string", "pattern": r"^\d{1,3}(\.\d{1,3}){3}$"},
            ],
        },
        "action": {"bsonType": "string", "minLength": 1},
        "severity": {
            "bsonType": "string",
            "enum": ["info", "warn", "critical"],
        },
        "detail": {"bsonType": "object"},
        "raw": {"bsonType": "string"},
        "tags": {"bsonType": "array", "items": {"bsonType": "string"}},
    },
}

ALERT_SCHEMA = {
    "bsonType": "object",
    "required": ["rule_id", "fired_at", "severity", "title", "evidence", "status"],
    "additionalProperties": True,
    "properties": {
        "rule_id": {"bsonType": "string", "minLength": 1},
        "fired_at": {"bsonType": "date"},
        "severity": {
            "bsonType": "string",
            "enum": ["info", "warn", "critical"],
        },
        "title": {"bsonType": "string", "minLength": 1},
        "evidence": {"bsonType": "object"},
        "status": {
            "bsonType": "string",
            "enum": ["open", "acknowledged", "closed"],
        },
        "notes": {"bsonType": ["string", "null"]},
    },
}

RULE_SCHEMA = {
    "bsonType": "object",
    "required": ["rule_id", "name", "type", "enabled", "params", "severity"],
    "additionalProperties": True,
    "properties": {
        "rule_id": {"bsonType": "string", "minLength": 1},
        "name": {"bsonType": "string", "minLength": 1},
        "type": {
            "bsonType": "string",
            "enum": ["threshold", "pattern", "schedule"],
        },
        "enabled": {"bsonType": "bool"},
        "params": {"bsonType": "object"},
        "severity": {
            "bsonType": "string",
            "enum": ["info", "warn", "critical"],
        },
        "updated_at": {"bsonType": ["date", "null"]},
    },
}


SCHEMAS = {
    "events": EVENT_SCHEMA,
    "alerts": ALERT_SCHEMA,
    "rules": RULE_SCHEMA,
}


def apply_validator(db, coll_name: str, schema: dict | None) -> None:
    cmd: dict = {
        "collMod": coll_name,
        "validationLevel": "strict",
        "validationAction": "error",
    }
    cmd["validator"] = {"$jsonSchema": schema} if schema else {}
    db.command(cmd)


def main() -> int:
    ap = argparse.ArgumentParser(description="Registra JSON Schema en MongoDB")
    ap.add_argument("--off", action="store_true",
                    help="Quita los validadores (los deja permisivos)")
    args = ap.parse_args()

    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client[settings.mongo_db]

    existing = set(db.list_collection_names())
    for name in SCHEMAS:
        if name not in existing:
            db.create_collection(name)
            print(f"[schemas] creada colección: {name}")

    if args.off:
        for name in SCHEMAS:
            apply_validator(db, name, None)
            print(f"[schemas] validator REMOVIDO en {name}")
        return 0

    for name, schema in SCHEMAS.items():
        try:
            apply_validator(db, name, schema)
            print(f"[schemas] validator aplicado en {name}")
        except Exception as e:
            print(f"[ERROR] no se pudo aplicar validator en {name}: {e}",
                  file=sys.stderr)
            return 1

    print("[schemas] OK · validación activa en events, alerts, rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
