"""Actualiza el validador $jsonSchema de la colección `events` en Atlas
para que acepte los 9 formatos de log del S4 (antes solo aceptaba 5).

Correr UNA sola vez:
    python scripts/update_mongo_validator.py

El script es idempotente: si el enum ya tiene los valores, no hace nada.
Usa MONGO_URI del .env.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from pymongo import MongoClient

# Fuentes válidas en S4 (las 5 originales + las 6 nuevas del S4)
VALID_SOURCES = [
    "auth.log",         # S2
    "access.log",       # S2
    "app",              # S2 (reservado para aplicaciones propias)
    "php_log",          # S3
    "hello_world",      # S1 (prueba inicial)
    # Nuevos en S4 ↓
    "fail2ban.log",
    "error.log",        # Apache / nginx
    "phpfpm.log",
    "kern.log",
    "mail.log",
    "dmesg",
]

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB", "grupo4_db")

if not MONGO_URI:
    print("[ERROR] MONGO_URI no está en .env. Abortando.")
    sys.exit(1)

print(f"Conectando a {MONGO_URI[:40]}... (db: {MONGO_DB})")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
db = client[MONGO_DB]

# ---------- Leer el validador actual ----------
print("\n1) Leyendo validador actual de la colección 'events'...")
collections = db.command("listCollections", filter={"name": "events"})["cursor"]["firstBatch"]
if not collections:
    print("[ERROR] La colección 'events' no existe. Nada que hacer.")
    sys.exit(1)

current_options = collections[0].get("options", {})
current_validator = current_options.get("validator", {})
print(f"   Validador actual: {'$jsonSchema' if '$jsonSchema' in current_validator else 'ninguno'}")

if "$jsonSchema" in current_validator:
    schema = current_validator["$jsonSchema"]
    props = schema.get("properties", {})
    src_rule = props.get("source", {})
    current_enum = src_rule.get("enum", [])
    print(f"   Enum actual de 'source' ({len(current_enum)} valores): {current_enum}")

    missing = [s for s in VALID_SOURCES if s not in current_enum]
    if not missing:
        print("\n[OK] El enum ya tiene todas las fuentes del S4. Nada que hacer.")
        sys.exit(0)

    print(f"\n   Faltan {len(missing)} valores por agregar: {missing}")

    # Combinar y deduplicar manteniendo orden
    new_enum = list(dict.fromkeys(current_enum + VALID_SOURCES))
    src_rule["enum"] = new_enum
    props["source"] = src_rule
    schema["properties"] = props

    new_validator = {"$jsonSchema": schema}
else:
    # No había validador: creamos uno mínimo con solo el enum de source
    print("   No había validador. Creando uno nuevo con el enum completo.")
    new_validator = {
        "$jsonSchema": {
            "bsonType": "object",
            "properties": {
                "source": {
                    "bsonType": "string",
                    "description": "fuente del evento",
                    "enum": VALID_SOURCES,
                }
            }
        }
    }

# ---------- Aplicar collMod ----------
print("\n2) Aplicando collMod con el nuevo enum...")
try:
    result = db.command({
        "collMod": "events",
        "validator": new_validator,
        "validationLevel": current_options.get("validationLevel", "moderate"),
        "validationAction": current_options.get("validationAction", "error"),
    })
    print(f"   collMod OK: {result}")
except Exception as e:
    print(f"[ERROR] collMod falló: {e}")
    print("   Puede ser porque el usuario de Mongo no tiene permiso dbAdmin.")
    print("   Alternativa manual en Atlas → Database → Collections → events →")
    print("   Validator → editar JSON y agregar al enum de 'source':")
    for s in VALID_SOURCES:
        if s not in current_enum:
            print(f"     \"{s}\",")
    sys.exit(2)

# ---------- Verificar ----------
print("\n3) Verificando...")
after = db.command("listCollections", filter={"name": "events"})["cursor"]["firstBatch"]
after_enum = after[0].get("options", {}).get("validator", {}).get(
    "$jsonSchema", {}
).get("properties", {}).get("source", {}).get("enum", [])
print(f"   Enum después: {after_enum}")

ok = all(s in after_enum for s in VALID_SOURCES)
print(f"\n{'[OK]' if ok else '[FAIL]'} Validador {'actualizado correctamente' if ok else 'NO quedó con todos los valores'}.")
if ok:
    print("\nPodés volver a subir dmesg, fail2ban, error.log, kern, mail, phpfpm sin que te den error 121.")
