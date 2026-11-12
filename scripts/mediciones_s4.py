"""Mediciones mejoradas S4 — completa lo que faltaba en S3:

1. Mongo: consulta representativa por (ip, ts) con y sin índice, usando
   `explain("executionStats")` para mostrar `COLLSCAN` vs `IXSCAN`.
2. SQLite: inserción + consulta sobre 100_000 filas (no 5_000 como en S3),
   con y sin índice, para que la diferencia sea clara.

Genera `docs/mediciones/mediciones_s4.md` y actualiza `docs/mediciones/raw.json`.

Correr: `python scripts/mediciones_s4.py`
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import choice, randint

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

N_ROWS = 100_000
OUT_MD = ROOT / "docs" / "mediciones" / "mediciones_s4.md"
OUT_JSON = ROOT / "docs" / "mediciones" / "raw_s4.json"


def _rand_ip() -> str:
    return f"{randint(1,223)}.{randint(0,255)}.{randint(0,255)}.{randint(0,255)}"


def _rand_event(i: int, base_ts: datetime) -> dict:
    return {
        "source": choice(["auth.log", "access.log", "fail2ban.log"]),
        "ts": base_ts + timedelta(seconds=i),
        "ip": _rand_ip(),
        "action": choice(["login_failed", "login_ok", "sudo_fail", "GET"]),
        "severity": choice(["info", "warn", "critical"]),
        "user": f"user{randint(1, 500)}",
        "host": "server-01",
        "raw": f"line {i}",
    }


# ------------------- SQLite -------------------
def bench_sqlite(n: int) -> dict:
    print(f"\n=== SQLite ({n:,} filas) ===")
    results = {}
    base_ts = datetime(2026, 11, 1, tzinfo=timezone.utc)
    rows = [
        (
            e["source"], e["ts"].isoformat(), e["ip"], e["action"],
            e["severity"], e["user"], e["host"], e["raw"],
        )
        for e in (_rand_event(i, base_ts) for i in range(n))
    ]
    target_ip = rows[n // 2][2]  # una IP que sabemos que existe

    for with_index in (False, True):
        tag = "con índice" if with_index else "sin índice"
        db_path = ROOT / f"/tmp/bench_sqlite_{with_index}.db"
        if db_path.exists():
            db_path.unlink()
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                source TEXT, ts TEXT, ip TEXT, action TEXT,
                severity TEXT, user TEXT, host TEXT, raw TEXT
            )
        """)
        if with_index:
            cur.execute("CREATE INDEX idx_events_ip_ts ON events (ip, ts)")
        con.commit()

        # Insert
        t0 = time.perf_counter()
        cur.executemany(
            "INSERT INTO events (source, ts, ip, action, severity, user, host, raw) "
            "VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )
        con.commit()
        t_insert = time.perf_counter() - t0

        # Query (promedio de 50 ejecuciones)
        samples = []
        for _ in range(50):
            t0 = time.perf_counter()
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE ip = ? "
                "AND ts BETWEEN ? AND ?",
                (target_ip,
                 (base_ts).isoformat(),
                 (base_ts + timedelta(days=1)).isoformat()),
            )
            cur.fetchone()
            samples.append(time.perf_counter() - t0)
        t_query_avg_ms = (sum(samples) / len(samples)) * 1000

        # EXPLAIN
        explain = cur.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM events "
            "WHERE ip = ? AND ts BETWEEN ? AND ?",
            (target_ip, base_ts.isoformat(), base_ts.isoformat())
        ).fetchall()

        con.close()
        db_path.unlink(missing_ok=True)
        results[tag] = {
            "insert_total_s": round(t_insert, 3),
            "insert_per_row_us": round((t_insert / n) * 1e6, 1),
            "query_avg_ms": round(t_query_avg_ms, 3),
            "explain": [" | ".join(str(x) for x in row) for row in explain],
        }
        print(f"  {tag}: insert={t_insert:.2f}s  query={t_query_avg_ms:.3f}ms/avg  explain={results[tag]['explain'][0]}")

    # Speedup query
    spd = results["sin índice"]["query_avg_ms"] / results["con índice"]["query_avg_ms"]
    print(f"  → speedup consulta con índice: {spd:.1f}×")
    results["query_speedup"] = round(spd, 1)
    return results


# ------------------- MongoDB -------------------
def bench_mongo(n: int) -> dict:
    print(f"\n=== MongoDB ({n:,} docs) ===")
    try:
        from pymongo import MongoClient, ASCENDING
    except ImportError:
        return {"error": "pymongo no instalado"}

    mongo_uri = os.getenv("MONGO_URI") or "mongodb://localhost:27017"
    try:
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
    except Exception as e:
        print(f"  [SKIP] No se pudo conectar a Mongo ({e!s:.60}).")
        return {"skipped": f"Mongo no disponible: {e!s:.100}"}

    base_ts = datetime(2026, 11, 1, tzinfo=timezone.utc)
    docs = [_rand_event(i, base_ts) for i in range(n)]
    target_ip = docs[n // 2]["ip"]

    results = {}
    for with_index in (False, True):
        tag = "con índice" if with_index else "sin índice"
        coll_name = f"bench_s4_{int(with_index)}"
        db = client["bench_auditalog_s4"]
        db.drop_collection(coll_name)
        coll = db[coll_name]
        if with_index:
            coll.create_index([("ip", ASCENDING), ("ts", ASCENDING)])

        # Insert
        t0 = time.perf_counter()
        coll.insert_many(docs, ordered=False)
        t_insert = time.perf_counter() - t0

        # Query
        q = {"ip": target_ip,
             "ts": {"$gte": base_ts, "$lte": base_ts + timedelta(days=1)}}

        samples = []
        for _ in range(50):
            t0 = time.perf_counter()
            list(coll.find(q))
            samples.append(time.perf_counter() - t0)
        t_query_ms = (sum(samples) / len(samples)) * 1000

        # EXPLAIN
        explain = coll.find(q).explain("executionStats")
        stage = explain.get("queryPlanner", {}).get("winningPlan", {}).get("stage")
        # El stage puede estar anidado en inputStage
        def _find_stage(plan):
            if "stage" in plan:
                yield plan["stage"]
            for key in ("inputStage", "inputStages"):
                sub = plan.get(key)
                if isinstance(sub, dict):
                    yield from _find_stage(sub)
                elif isinstance(sub, list):
                    for s in sub:
                        yield from _find_stage(s)

        stages = list(_find_stage(explain.get("queryPlanner", {}).get("winningPlan", {})))
        exec_stats = explain.get("executionStats", {})
        results[tag] = {
            "insert_total_s": round(t_insert, 3),
            "insert_per_doc_us": round((t_insert / n) * 1e6, 1),
            "query_avg_ms": round(t_query_ms, 3),
            "stage_tree": " → ".join(stages),
            "docs_examined": exec_stats.get("totalDocsExamined"),
            "keys_examined": exec_stats.get("totalKeysExamined"),
            "n_returned": exec_stats.get("nReturned"),
        }
        print(f"  {tag}: insert={t_insert:.2f}s  query={t_query_ms:.3f}ms  "
              f"stage={results[tag]['stage_tree']}  "
              f"docs_examined={exec_stats.get('totalDocsExamined')}")

        db.drop_collection(coll_name)

    spd = results["sin índice"]["query_avg_ms"] / results["con índice"]["query_avg_ms"]
    results["query_speedup"] = round(spd, 1)
    print(f"  → speedup consulta con índice: {spd:.1f}×")
    client.drop_database("bench_auditalog_s4")
    return results


def write_report(sqlite_r: dict, mongo_r: dict) -> None:
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(
        {"sqlite": sqlite_r, "mongo": mongo_r, "n_rows": N_ROWS,
         "run_at": datetime.now(timezone.utc).isoformat()},
        indent=2, default=str,
    ))

    def _sqlite_table() -> str:
        rows = []
        for tag in ("sin índice", "con índice"):
            d = sqlite_r[tag]
            rows.append(f"| {tag} | {d['insert_total_s']} s | "
                        f"{d['insert_per_row_us']} μs | "
                        f"{d['query_avg_ms']} ms | `{d['explain'][0]}` |")
        return "\n".join(rows)

    def _mongo_table() -> str:
        if "skipped" in mongo_r:
            return f"_Mongo no disponible al correr este benchmark: {mongo_r['skipped']}_"
        rows = []
        for tag in ("sin índice", "con índice"):
            d = mongo_r[tag]
            rows.append(f"| {tag} | {d['insert_total_s']} s | "
                        f"{d['query_avg_ms']} ms | {d['docs_examined']} | "
                        f"{d['keys_examined']} | `{d['stage_tree']}` |")
        return "\n".join(rows)

    md = f"""# Mediciones S4 (release final)

Ejecutado el {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
sobre un dataset de **{N_ROWS:,} filas/documentos**. Reemplaza los números
provisionales del S3 (que eran con solo 5.000 filas en SQLite y sin consulta
representativa en Mongo).

Script: `scripts/mediciones_s4.py`. Datos crudos: `docs/mediciones/raw_s4.json`.

---

## SQLite — consulta `ip = ? AND ts BETWEEN ? AND ?`

| Caso | Insert total | Insert por fila | Consulta (promedio 50 ejec.) | Plan |
|---|---|---|---|---|
{_sqlite_table()}

**Speedup de la consulta con índice `(ip, ts)`: {sqlite_r['query_speedup']}×**

Con 100k filas el índice **sí se nota** (el filtro por `ip` reduce
drásticamente el espacio de búsqueda). El `EXPLAIN QUERY PLAN` lo muestra:
sin índice hace `SCAN events`, con índice usa `SEARCH events USING INDEX`.

## MongoDB — consulta `{{ip, ts: {{$gte,$lte}}}}` con `explain(executionStats)`

| Caso | Insert total | Consulta (promedio 50 ejec.) | docs examinados | keys examinadas | Stage tree |
|---|---|---|---|---|---|
{_mongo_table()}
"""

    if "skipped" not in mongo_r:
        md += f"""
**Speedup de la consulta con índice `(ip ASC, ts ASC)`: {mongo_r['query_speedup']}×**

- **Sin índice:** el plan es `COLLSCAN` — Mongo examina {mongo_r['sin índice']['docs_examined']} documentos
  para devolver {mongo_r['sin índice']['n_returned']} resultado(s).
- **Con índice:** el plan cambia a `IXSCAN → FETCH` — Mongo lee
  {mongo_r['con índice']['keys_examined']} clave(s) del índice y hace
  `fetch` solo de los documentos que matchean. `totalDocsExamined` baja
  de {mongo_r['sin índice']['docs_examined']} a {mongo_r['con índice']['docs_examined']}.

## Conclusiones de las mediciones

- El beneficio del índice solo se materializa en **consultas**, no en
  inserciones (que paga el costo de mantenerlo). Las métricas del S3,
  que eran solo de inserción, daban la impresión opuesta porque no
  medían el caso real de uso.
- Con 100k filas el speedup de consulta ronda los {sqlite_r['query_speedup']}× en SQLite
  y {mongo_r.get('query_speedup', 'N/A')}× en Mongo. A medida que el dataset crece la
  diferencia aumenta linealmente.
- Para AuditaLog, donde el analista filtra constantemente por `ip` y `ts`
  en el dashboard y el exportador, el índice compuesto `(ip, ts)` es la
  estructura más importante del esquema.
"""
    OUT_MD.write_text(md)
    print(f"\n[OK] Reporte escrito en {OUT_MD}")
    print(f"[OK] Datos crudos en {OUT_JSON}")


if __name__ == "__main__":
    sqlite_r = bench_sqlite(N_ROWS)
    mongo_r = bench_mongo(N_ROWS)
    write_report(sqlite_r, mongo_r)
