"""Hola mundo · SQLite.

Crea un paquete de evidencia vacío con el DDL definido en el modelo de datos v1,
inserta un evento de prueba, lo consulta y borra el archivo. Confirma que la
plantilla del exportador funciona.

    python scripts/hello_sqlite.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv

DDL = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mongo_id    TEXT    NOT NULL UNIQUE,
    source      TEXT    NOT NULL,
    host        TEXT,
    ts          TEXT    NOT NULL,
    user        TEXT,
    ip          TEXT,
    action      TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    detail_json TEXT,
    raw         TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts     ON events(ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_user_ts   ON events(user, ts);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity, ts);
CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mongo_id      TEXT NOT NULL UNIQUE,
    rule_id       TEXT NOT NULL,
    fired_at      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS package_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def main() -> int:
    load_dotenv()
    export_dir = Path(os.getenv("SQLITE_EXPORT_DIR", "./data/exports"))
    export_dir.mkdir(parents=True, exist_ok=True)
    db_path = export_dir / "evidencia_smoketest.db"

    if db_path.exists():
        db_path.unlink()

    print(f"[hello_sqlite] creando {db_path}")
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(DDL)
        conn.execute("PRAGMA journal_mode = WAL;")  # ya listo para S3
        conn.commit()

        conn.execute(
            """INSERT INTO events
               (mongo_id, source, host, ts, user, ip, action, severity, detail_json, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "smoke_mongo_id_001",
                "auth.log",
                "vps-01",
                "2026-10-16T15:22:11Z",
                "root",
                "192.0.2.45",
                "login_failed",
                "warn",
                '{"method":"ssh","port":22}',
                "Oct 16 15:22:11 vps-01 sshd: Failed password for root from 192.0.2.45",
            ),
        )
        conn.commit()

        row = conn.execute(
            "SELECT id, source, ip, action FROM events WHERE mongo_id = ?",
            ("smoke_mongo_id_001",),
        ).fetchone()
        print(f"[hello_sqlite] insertado y leído → {row}")

        # EXPLAIN QUERY PLAN para dejar el patrón listo para S3
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM events WHERE ip = ? AND ts >= ?",
            ("192.0.2.45", "2026-10-01T00:00:00Z"),
        ).fetchall()
        print(f"[hello_sqlite] EXPLAIN QUERY PLAN → {plan}")

    finally:
        conn.close()

    db_path.unlink()  # limpieza del smoke test
    print("[hello_sqlite] smoke test OK — todo listo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
