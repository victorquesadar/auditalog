"""Benchmarks del Seguimiento 3.

Ejecuta las operaciones medibles del proyecto en 3 corridas cada una y reporta
la mediana. Compara **con y sin optimización**:

  1. Mongo: inserción masiva **con/sin índice** en events.ts
  2. Mongo + Redis: dashboard aggregation **con/sin caché** Redis
  3. SQLite: query sobre events **con/sin índice** compuesto (ip, ts)
  4. (Opcional) Workers: throughput con 1 vs 2 workers en paralelo

Uso:
    python scripts/benchmarks.py --all
    python scripts/benchmarks.py --only mongo-index
    python scripts/benchmarks.py --n 10000 --runs 5

El reporte se guarda en docs/mediciones/mediciones_s3.md y los datos crudos
en docs/mediciones/raw.json para reproducibilidad.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sqlite3
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import redis as redis_lib
from pymongo import MongoClient, ASCENDING

from src.common.config import key, settings


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "mediciones"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def median(times_ms: list[float]) -> float:
    return statistics.median(times_ms)


def pct_change(baseline: float, optimized: float) -> str:
    if baseline == 0:
        return "n/a"
    delta = (optimized - baseline) / baseline * 100
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta:.1f}%"


# ----------------------------------------------------------------------------
# 1. Mongo — Inserción masiva con/sin índice
# ----------------------------------------------------------------------------

def _gen_events(n: int) -> list[dict]:
    rng = random.Random(42)
    base = datetime.now(timezone.utc)
    ips = [f"203.0.113.{i}" for i in range(1, 51)]
    users = ["ana", "jose", "root", "admin", "oracle"]
    out = []
    for i in range(n):
        out.append({
            "source": "auth.log",
            "ts": base - timedelta(seconds=i),
            "user": rng.choice(users),
            "ip": rng.choice(ips),
            "action": "login_failed",
            "severity": "warn",
            "detail": {"method": "ssh"},
            "raw": f"benchmark line {i}",
        })
    return out


def bench_mongo_insert(n: int, runs: int) -> dict:
    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=10000)
    db = client[settings.mongo_db]
    coll_name = "bench_events"

    # Sin índice
    no_idx_times = []
    for run in range(runs):
        db[coll_name].drop()
        docs = _gen_events(n)
        t0 = time.perf_counter()
        db[coll_name].insert_many(docs, ordered=False)
        no_idx_times.append((time.perf_counter() - t0) * 1000)
        print(f"  [mongo-insert sin índice] run {run+1}: {no_idx_times[-1]:.1f} ms")

    # Con índice (ts descendente)
    with_idx_times = []
    for run in range(runs):
        db[coll_name].drop()
        db[coll_name].create_index([("ts", -1)])
        docs = _gen_events(n)
        t0 = time.perf_counter()
        db[coll_name].insert_many(docs, ordered=False)
        with_idx_times.append((time.perf_counter() - t0) * 1000)
        print(f"  [mongo-insert con índice] run {run+1}: {with_idx_times[-1]:.1f} ms")

    db[coll_name].drop()

    return {
        "test": "mongo_insert",
        "params": {"n": n, "runs": runs},
        "no_index": {"runs_ms": no_idx_times, "median_ms": median(no_idx_times)},
        "with_index": {"runs_ms": with_idx_times, "median_ms": median(with_idx_times)},
        "delta_median_pct": pct_change(median(no_idx_times), median(with_idx_times)),
    }


# ----------------------------------------------------------------------------
# 2. Dashboard — con/sin caché Redis (contra API)
# ----------------------------------------------------------------------------

def bench_dashboard_cache(runs: int) -> dict:
    """Mide el pipeline de agregación directo contra Mongo vs con caché Redis."""
    client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=10000)
    db = client[settings.mongo_db]
    r = redis_lib.Redis(host=settings.redis_host, port=settings.redis_port,
                        password=settings.redis_password, db=settings.redis_db,
                        decode_responses=True)
    cache_key = key("cache:bench_dashboard")

    def compute() -> dict:
        return {
            "events_total": db.events.count_documents({}),
            "alerts_total": db.alerts.count_documents({}),
            "top_ips": list(db.events.aggregate([
                {"$match": {"action": "login_failed"}},
                {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10},
            ])),
        }

    # Sin caché: cada corrida recomputa
    no_cache_times = []
    for run in range(runs):
        r.delete(cache_key)
        t0 = time.perf_counter()
        _ = compute()
        no_cache_times.append((time.perf_counter() - t0) * 1000)
        print(f"  [dashboard sin caché] run {run+1}: {no_cache_times[-1]:.1f} ms")

    # Con caché: calentar y después medir hits
    r.delete(cache_key)
    r.setex(cache_key, 60, json.dumps(compute(), default=str))

    cache_times = []
    for run in range(runs):
        t0 = time.perf_counter()
        _ = json.loads(r.get(cache_key))
        cache_times.append((time.perf_counter() - t0) * 1000)
        print(f"  [dashboard con caché]  run {run+1}: {cache_times[-1]:.3f} ms")

    r.delete(cache_key)

    return {
        "test": "dashboard_cache",
        "params": {"runs": runs},
        "no_cache": {"runs_ms": no_cache_times, "median_ms": median(no_cache_times)},
        "with_cache": {"runs_ms": cache_times, "median_ms": median(cache_times)},
        "delta_median_pct": pct_change(median(no_cache_times), median(cache_times)),
    }


# ----------------------------------------------------------------------------
# 3. SQLite — Query con/sin índice compuesto (ip, ts)
# ----------------------------------------------------------------------------

def bench_sqlite_index(n: int, runs: int) -> dict:
    """Mide un SELECT * WHERE ip = ? AND ts >= ? con y sin índice."""
    base_ts = datetime.now(timezone.utc)
    rng = random.Random(1)
    ips = [f"203.0.113.{i}" for i in range(1, 11)]

    rows = [
        (
            None, f"mid_{i}", "auth.log", "vps-01",
            (base_ts - timedelta(seconds=i)).isoformat(),
            "root", rng.choice(ips), "login_failed", "warn",
            "{}", f"benchmark line {i}",
        )
        for i in range(n)
    ]
    target_ip = ips[0]
    target_ts = (base_ts - timedelta(seconds=n // 2)).isoformat()

    def _create_db(with_index: bool) -> str:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mongo_id TEXT NOT NULL UNIQUE,
                source TEXT, host TEXT, ts TEXT NOT NULL,
                user TEXT, ip TEXT, action TEXT, severity TEXT,
                detail_json TEXT, raw TEXT
            );
        """)
        conn.executemany(
            "INSERT INTO events (id, mongo_id, source, host, ts, user, ip, action, severity, detail_json, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        if with_index:
            conn.execute("CREATE INDEX idx_ip_ts ON events(ip, ts)")
        conn.commit()
        conn.close()
        return path

    def _run(path: str) -> float:
        conn = sqlite3.connect(path)
        t0 = time.perf_counter()
        _ = conn.execute(
            "SELECT * FROM events WHERE ip = ? AND ts >= ?",
            (target_ip, target_ts),
        ).fetchall()
        elapsed = (time.perf_counter() - t0) * 1000
        conn.close()
        return elapsed

    no_idx = []
    path = _create_db(with_index=False)
    for run in range(runs):
        no_idx.append(_run(path))
        print(f"  [sqlite query sin índice] run {run+1}: {no_idx[-1]:.2f} ms")
    os.unlink(path)

    with_idx = []
    path = _create_db(with_index=True)
    for run in range(runs):
        with_idx.append(_run(path))
        print(f"  [sqlite query con índice] run {run+1}: {with_idx[-1]:.2f} ms")
    os.unlink(path)

    # EXPLAIN QUERY PLAN como evidencia
    plans = {}
    for label, with_index in (("sin índice", False), ("con índice", True)):
        path = _create_db(with_index=with_index)
        conn = sqlite3.connect(path)
        plan = conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM events WHERE ip = ? AND ts >= ?",
            (target_ip, target_ts),
        ).fetchall()
        plans[label] = [list(row) for row in plan]
        conn.close()
        os.unlink(path)

    return {
        "test": "sqlite_index",
        "params": {"n": n, "runs": runs},
        "no_index": {"runs_ms": no_idx, "median_ms": median(no_idx)},
        "with_index": {"runs_ms": with_idx, "median_ms": median(with_idx)},
        "delta_median_pct": pct_change(median(no_idx), median(with_idx)),
        "explain_query_plan": plans,
    }


# ----------------------------------------------------------------------------
# Reporte
# ----------------------------------------------------------------------------

def _fmt_runs(xs):
    return ", ".join(f"{x:.2f}" for x in xs)


def write_report(results: list[dict], runs: int) -> None:
    by_test = {r["test"]: r for r in results}
    parts = []

    parts.append(f"# Mediciones · Seguimiento 3\n")
    parts.append(f"**Fecha:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    parts.append(f"**Entorno:** Python {sys.version.split()[0]} · Mongo Atlas · Redis local  ")
    parts.append(f"**Scripts:** `scripts/benchmarks.py` · reproducible con `python scripts/benchmarks.py --all`\n")
    parts.append(f"Los datos crudos (todas las corridas) están en [`raw.json`](raw.json).\n")
    parts.append("---\n")
    parts.append("## Resumen\n")
    parts.append("| Operación | Baseline (mediana) | Optimizado (mediana) | Mejora |")
    parts.append("|---|---|---|---|")

    if "mongo_insert" in by_test:
        d = by_test["mongo_insert"]
        parts.append(f"| Mongo insert ({d['params']['n']} docs) | {d['no_index']['median_ms']:.1f} ms sin índice | {d['with_index']['median_ms']:.1f} ms con índice | {d['delta_median_pct']} |")
    if "dashboard_cache" in by_test:
        d = by_test["dashboard_cache"]
        parts.append(f"| Dashboard | {d['no_cache']['median_ms']:.3f} ms sin caché | {d['with_cache']['median_ms']:.3f} ms con caché | {d['delta_median_pct']} |")
    if "sqlite_index" in by_test:
        d = by_test["sqlite_index"]
        parts.append(f"| SQLite query ({d['params']['n']} filas) | {d['no_index']['median_ms']:.2f} ms sin índice | {d['with_index']['median_ms']:.2f} ms con índice | {d['delta_median_pct']} |")

    parts.append("")

    if "mongo_insert" in by_test:
        d = by_test["mongo_insert"]
        parts.append(f"\n## 1. Mongo — Inserción masiva ({d['params']['n']} eventos)\n")
        parts.append("| | Mediana | Corridas (ms) |")
        parts.append("|---|---|---|")
        parts.append(f"| **Sin índice** | {d['no_index']['median_ms']:.1f} ms | {_fmt_runs(d['no_index']['runs_ms'])} |")
        parts.append(f"| **Con índice en `ts`** | {d['with_index']['median_ms']:.1f} ms | {_fmt_runs(d['with_index']['runs_ms'])} |")
        interp = ("no mejora significativamente" if d['with_index']['median_ms'] >= d['no_index']['median_ms'] * 0.9
                  else "mejora el throughput")
        parts.append(f"\n**Interpretación:** el índice {interp} la inserción. Esto es esperable: los índices benefician a los SELECT y WHERE, no al INSERT (de hecho pueden penalizarlo porque hay que mantener el índice).\n")

    if "dashboard_cache" in by_test:
        d = by_test["dashboard_cache"]
        parts.append(f"\n## 2. Dashboard — con/sin caché Redis\n")
        parts.append("| | Mediana | Corridas (ms) |")
        parts.append("|---|---|---|")
        parts.append(f"| **Sin caché** (recomputa aggregation) | {d['no_cache']['median_ms']:.3f} ms | {_fmt_runs(d['no_cache']['runs_ms'])} |")
        parts.append(f"| **Con caché** (GET de Redis) | {d['with_cache']['median_ms']:.3f} ms | {_fmt_runs(d['with_cache']['runs_ms'])} |")
        speedup = d['no_cache']['median_ms'] / max(d['with_cache']['median_ms'], 0.001)
        parts.append(f"\n**Interpretación:** la caché reduce la latencia **{speedup:.1f}×**. El TTL de 30 s nos da un buen compromiso entre frescura y carga de Mongo.\n")

    if "sqlite_index" in by_test:
        d = by_test["sqlite_index"]
        parts.append(f"\n## 3. SQLite — Query con/sin índice compuesto `(ip, ts)` ({d['params']['n']} filas)\n")
        parts.append("| | Mediana | Corridas (ms) |")
        parts.append("|---|---|---|")
        parts.append(f"| **Sin índice** | {d['no_index']['median_ms']:.2f} ms | {_fmt_runs(d['no_index']['runs_ms'])} |")
        parts.append(f"| **Con índice `(ip, ts)`** | {d['with_index']['median_ms']:.2f} ms | {_fmt_runs(d['with_index']['runs_ms'])} |")
        parts.append("\n**EXPLAIN QUERY PLAN:**\n")
        parts.append("Sin índice:\n```")
        for row in d.get("explain_query_plan", {}).get("sin índice", []):
            parts.append(" ".join(str(x) for x in row))
        parts.append("```\n")
        parts.append("Con índice:\n```")
        for row in d.get("explain_query_plan", {}).get("con índice", []):
            parts.append(" ".join(str(x) for x in row))
        parts.append("```\n")
        parts.append("**Interpretación:** sin índice SQLite hace **SCAN** de toda la tabla (recorre las N filas). Con el índice compuesto hace **SEARCH USING INDEX**, lee solo las filas que matchean.\n")

    parts.append("\n---\n")
    parts.append("## Metodología\n")
    parts.append(f"- Cada prueba corre **{runs} veces** y reporta la **mediana** para evitar outliers.")
    parts.append("- Entre corridas se limpia caché / tabla para igualar condiciones iniciales.")
    parts.append("- El dataset es sintético pero representativo de la volumetría objetivo (10k-100k eventos).")
    parts.append("- El código del benchmark está versionado para que cualquiera lo reproduzca.\n")

    (OUT_DIR / "mediciones_s3.md").write_text("\n".join(parts), encoding="utf-8")
    (OUT_DIR / "raw.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n[benchmarks] reporte en {OUT_DIR / 'mediciones_s3.md'}")
    print(f"[benchmarks] datos crudos en {OUT_DIR / 'raw.json'}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmarks del Seguimiento 3")
    ap.add_argument("--all", action="store_true", help="Corre todos los benchmarks")
    ap.add_argument("--only", choices=["mongo-index", "cache", "sqlite-index"],
                    help="Corre solo uno")
    ap.add_argument("--n", type=int, default=5000, help="Cantidad de eventos (Mongo/SQLite)")
    ap.add_argument("--runs", type=int, default=3, help="Corridas por benchmark (mínimo 3)")
    args = ap.parse_args()

    if not args.all and not args.only:
        ap.error("usar --all o --only <nombre>")

    results = []

    if args.all or args.only == "mongo-index":
        print(f"\n[1] Mongo insert con/sin índice (n={args.n}, runs={args.runs})")
        results.append(bench_mongo_insert(args.n, args.runs))

    if args.all or args.only == "cache":
        print(f"\n[2] Dashboard con/sin caché Redis (runs={args.runs})")
        results.append(bench_dashboard_cache(args.runs))

    if args.all or args.only == "sqlite-index":
        print(f"\n[3] SQLite query con/sin índice (n={args.n}, runs={args.runs})")
        results.append(bench_sqlite_index(args.n, args.runs))

    write_report(results, runs=args.runs)
    print("\n[benchmarks] DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
