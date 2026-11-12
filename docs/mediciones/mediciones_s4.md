# Mediciones S4 (release final)

Ejecutado el 2026-11-12 03:47 UTC
sobre un dataset de **100,000 filas/documentos**. Reemplaza los números
provisionales del S3 (que eran con solo 5.000 filas en SQLite y sin consulta
representativa en Mongo).

Script: `scripts/mediciones_s4.py`. Datos crudos: `docs/mediciones/raw_s4.json`.

---

## SQLite — consulta `ip = ? AND ts BETWEEN ? AND ?`

| Caso | Insert total | Insert por fila | Consulta (promedio 50 ejec.) | Plan |
|---|---|---|---|---|
| sin índice | 0.126 s | 1.3 μs | 7.328 ms | `3 | 0 | 0 | SCAN events` |
| con índice | 0.301 s | 3.0 μs | 0.01 ms | `3 | 0 | 0 | SEARCH events USING COVERING INDEX idx_events_ip_ts (ip=? AND ts>? AND ts<?)` |

**Speedup de la consulta con índice `(ip, ts)`: 732.8×**

Con 100k filas el índice **sí se nota** (el filtro por `ip` reduce
drásticamente el espacio de búsqueda). El `EXPLAIN QUERY PLAN` lo muestra:
sin índice hace `SCAN events`, con índice usa `SEARCH events USING INDEX`.

## MongoDB — consulta `{ip, ts: {$gte,$lte}}` con `explain(executionStats)`

| Caso | Insert total | Consulta (promedio 50 ejec.) | docs examinados | keys examinadas | Stage tree |
|---|---|---|---|---|---|
_Mongo no disponible al correr este benchmark: Mongo no disponible: localhost:27017: [Errno 111] Connection refused (configured timeouts: socketTimeoutMS: 20000.0ms, co_
