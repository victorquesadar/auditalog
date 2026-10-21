"""Exportador del paquete de evidencia a SQLite.

Toma los events y alerts de MongoDB de un período y los vuelca en un archivo
`.db` autocontenido, con índices y vistas pregeneradas para el auditor.

Uso:
    python -m src.exporter.sqlite_exporter --from 2026-10-01 --to 2026-10-31
    python -m src.exporter.sqlite_exporter --all     # todo el histórico
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from pymongo import MongoClient

from src.common.config import settings

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

CREATE INDEX IF NOT EXISTS idx_alerts_fired_at ON alerts(fired_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS package_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Vistas para el auditor
CREATE VIEW IF NOT EXISTS v_fuerza_bruta AS
SELECT ip, COUNT(*) AS fallos, MIN(ts) AS primer_intento, MAX(ts) AS ultimo
FROM events
WHERE action = 'login_failed' AND ip IS NOT NULL
GROUP BY ip
HAVING fallos >= 5
ORDER BY fallos DESC;

CREATE VIEW IF NOT EXISTS v_cambios_config AS
SELECT ts, user, ip, json_extract(detail_json, '$.config_file') AS archivo
FROM events
WHERE action = 'config_changed'
ORDER BY ts DESC;

CREATE VIEW IF NOT EXISTS v_accesos_offhours AS
SELECT ts, user, ip, action
FROM events
WHERE action IN ('login_ok', 'login_failed')
  AND (CAST(strftime('%H', ts) AS INTEGER) >= 22
       OR CAST(strftime('%H', ts) AS INTEGER) < 6)
ORDER BY ts DESC;

CREATE VIEW IF NOT EXISTS v_resumen_por_dia AS
SELECT substr(ts, 1, 10) AS fecha,
       COUNT(*) AS eventos,
       SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS criticos,
       SUM(CASE WHEN severity='warn'     THEN 1 ELSE 0 END) AS warnings
FROM events
GROUP BY fecha
ORDER BY fecha DESC;
"""


def chunks(it: Iterator, size: int = 1000):
    buf = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def _iso(v) -> str:
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


def export(from_dt: datetime | None, to_dt: datetime | None, out_path: Path) -> dict:
    """Exporta events y alerts a `out_path`. Devuelve metadatos."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    mongo = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)
    db = mongo[settings.mongo_db]

    q_events: dict = {}
    q_alerts: dict = {}
    if from_dt or to_dt:
        rng: dict = {}
        if from_dt: rng["$gte"] = from_dt
        if to_dt:   rng["$lte"] = to_dt
        q_events["ts"] = rng
        q_alerts["fired_at"] = rng

    conn = sqlite3.connect(out_path)
    try:
        conn.executescript(DDL)
        conn.execute("PRAGMA journal_mode = WAL;")

        n_events = 0
        for batch in chunks(db.events.find(q_events).sort("ts", 1), 1000):
            conn.executemany(
                """INSERT INTO events
                   (mongo_id, source, host, ts, user, ip, action, severity, detail_json, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [(
                    str(e["_id"]), e.get("source", ""), e.get("host"),
                    _iso(e["ts"]), e.get("user"), e.get("ip"),
                    e.get("action", ""), e.get("severity", "info"),
                    json.dumps(e.get("detail", {})), e.get("raw", ""),
                ) for e in batch],
            )
            n_events += len(batch)
        conn.commit()

        n_alerts = 0
        for batch in chunks(db.alerts.find(q_alerts).sort("fired_at", 1), 1000):
            conn.executemany(
                """INSERT INTO alerts
                   (mongo_id, rule_id, fired_at, severity, title, evidence_json, status)
                   VALUES (?,?,?,?,?,?,?)""",
                [(
                    str(a["_id"]), a.get("rule_id", ""),
                    _iso(a["fired_at"]), a.get("severity", "info"),
                    a.get("title", ""),
                    json.dumps(a.get("evidence", {}), default=str),
                    a.get("status", "open"),
                ) for a in batch],
            )
            n_alerts += len(batch)
        conn.commit()

        now_iso = datetime.now(timezone.utc).isoformat()
        meta = {
            "generated_at": now_iso,
            "period_from": from_dt.isoformat() if from_dt else "all",
            "period_to":   to_dt.isoformat() if to_dt else "all",
            "event_count": str(n_events),
            "alert_count": str(n_alerts),
            "source_db":   settings.mongo_db,
        }
        conn.executemany(
            "INSERT INTO package_meta (key, value) VALUES (?, ?)",
            list(meta.items()),
        )
        conn.commit()

    finally:
        conn.close()

    # Hash de integridad
    h = hashlib.sha256()
    with open(out_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    sha = h.hexdigest()

    # Re-abrimos solo para guardar el sha del propio archivo (no cuenta en sí mismo)
    conn = sqlite3.connect(out_path)
    try:
        conn.execute("INSERT INTO package_meta (key, value) VALUES (?, ?)",
                     ("sha256_payload", sha))
        conn.commit()
    finally:
        conn.close()

    return {"path": str(out_path), "events": n_events, "alerts": n_alerts, "sha256": sha}


def main() -> int:
    ap = argparse.ArgumentParser(description="Exportador de evidencia a SQLite")
    ap.add_argument("--from", dest="from_", help="Fecha desde (YYYY-MM-DD o ISO)")
    ap.add_argument("--to", dest="to_", help="Fecha hasta (YYYY-MM-DD o ISO)")
    ap.add_argument("--all", action="store_true", help="Exportar todo el histórico")
    ap.add_argument("--out", default=None, help="Ruta de salida (opcional)")
    args = ap.parse_args()

    def parse(s: str) -> datetime:
        if len(s) == 10:
            return datetime.fromisoformat(s + "T00:00:00+00:00")
        return datetime.fromisoformat(s)

    from_dt = parse(args.from_) if args.from_ else None
    to_dt = parse(args.to_) if args.to_ else None
    if not args.all and not (from_dt or to_dt):
        print("[ERROR] indicá --from/--to o --all", file=sys.stderr)
        return 1

    if args.out:
        out_path = Path(args.out)
    else:
        tag = (from_dt or datetime.now(timezone.utc)).strftime("%Y-%m")
        out_path = Path(settings.__dict__.get("sqlite_export_dir",
                                              "./data/exports")) / f"evidencia_{tag}.db"
        # settings no tiene sqlite_export_dir en el dataclass; usamos env directo
        import os
        out_path = Path(os.getenv("SQLITE_EXPORT_DIR", "./data/exports")) / f"evidencia_{tag}.db"

    print(f"[export] exportando a {out_path}")
    result = export(from_dt, to_dt, out_path)
    print(f"[export] OK · {result['events']} eventos · {result['alerts']} alertas")
    print(f"[export] sha256={result['sha256'][:16]}...")
    print(f"[export] archivo: {result['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
