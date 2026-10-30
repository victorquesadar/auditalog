# Changelog

Todas las versiones relevantes del proyecto. Formato basado en
[Keep a Changelog](https://keepachangelog.com/) y
[Versionado semántico](https://semver.org/lang/es/).

## [Unreleased]

## [0.3.0] — 2026-10-30 · Seguimiento 3
### Added — Mediciones (lo central del S3)
- **`scripts/benchmarks.py`** reproducible, con 3 corridas por operación y mediana reportada.
- **`docs/mediciones/mediciones_s3.md`** con los 3 benchmarks pedidos:
  - Mongo: inserción masiva con/sin índice
  - Dashboard: con/sin caché Redis
  - SQLite: query con/sin índice compuesto + EXPLAIN QUERY PLAN
- **`docs/mediciones/raw.json`** con los datos crudos de cada corrida.

### Added — Reglas de detección (de 2 → 9 reglas activas)
- `sqli_v1` — SQL injection en URLs (critical)
- `xss_v1` — XSS en URLs (critical)
- `traversal_v1` — directory traversal / LFI (critical)
- `bad_ua_v1` — User-Agent de escáner conocido (warn)
- `sensitive_path_v1` — acceso a `/.env`, `/.git/`, `/phpmyadmin`, etc. (warn)
- `dir_scan_v1` — ≥20 respuestas 404 desde una IP en 5 min = escaneo de rutas (critical)
- `sudo_fail_v1` — intento de escalada de privilegios (warn)
- Parser de `access.log` ampliado para Combined Log Format (user_agent + referer).

### Added — Subida de archivos de log
- Página `/subir` con form multipart y barra de progreso.
- Endpoint `POST /api/upload` que parsea, mete por lotes de 500 y aplica reglas.

### Added — Decisiones técnicas documentadas
- `docs/decisiones.md` con D-11 a D-15 (nuevas) + histórico de S1 y S2.

### Changed
- UI: quitados botones **"+ Agregar evento"** de `/eventos` y **"+ Agregar alerta"** de `/alertas` (ver D-12).
- `/eventos` ahora muestra botón **"⬆ Subir log"** que redirige a `/subir`.
- 20 tests nuevos: 18 de reglas HTTP + 2 del endpoint upload. Total: **50 tests pasando**.

## [0.2.0] — 2026-10-23 · Seguimiento 2
### Added — flujo end-to-end funcional
- **Colector `auth.log`** (`src/collectors/auth_log_collector.py`) con modos `batch` y `tail`; empuja eventos normalizados al Stream `grupo4:auditalog:ingest`.
- **Worker de ingesta** (`src/workers/ingest_worker.py`) con consumer group, `XREADGROUP` + `XACK`, aplica reglas y persiste en Mongo.
- **Reglas de detección en vivo**:
  - Fuerza bruta por IP (contador Redis con TTL).
  - Acceso fuera de horario configurable (`RULE_OFFHOURS_START`/`END`).
- **Parsers** para `auth.log` (SSH) y `access.log` (Apache/Nginx CLF) en `src/common/parsers.py`.

### Added — API y Dashboard
- **FastAPI** en `src/api/main.py` con:
  - `GET /api/health` — ping de los 3 motores.
  - `GET /api/events` — CRUD con filtros (source, severity, ip, user) y paginación.
  - `GET /api/alerts` — listado con filtros.
  - `GET /api/dashboard` — KPIs cacheados en Redis (TTL 30 s, header `X-Cache`).
  - `POST /api/ingest` — ingesta por API con validación Pydantic.
  - `GET /`, `/eventos`, `/alertas` — vistas HTML con Jinja2 + Chart.js.
- **Dashboard** con 5 KPI tiles, chart de top IPs sospechosas, donut por severidad, feed de alertas.
- Indicador de salud de motores en el topbar (polling cada 15 s).

### Added — Validación
- Script `scripts/register_schemas.py` que registra validadores `$jsonSchema` en Mongo para `events`, `alerts`, `rules`.
- Validación Pydantic en `/api/ingest` (rechaza severidad inválida con 422).

### Added — Carga de datos reproducible
- `scripts/load_loghub.py` descarga Loghub (dataset OpenSSH, ~655k líneas reales) con fallback a generador sintético.
- Insertado en Mongo por lotes dentro de una **transacción** (si el cluster lo soporta).
- `scripts/generate_sample_logs.py` genera 29 líneas con los patrones de prueba del S2.

### Added — Exportador SQLite (adelantado de S4)
- `src/exporter/sqlite_exporter.py` genera `evidencia_<YYYY-MM>.db` con:
  - Tablas espejo de events y alerts, con índices.
  - 4 vistas pregeneradas (`v_fuerza_bruta`, `v_cambios_config`, `v_accesos_offhours`, `v_resumen_por_dia`).
  - Metadatos de paquete (período, cantidades, SHA-256 de integridad).
  - `PRAGMA journal_mode = WAL` activado.

### Added — Pruebas (de 0 a 29)
- `tests/test_parsers.py` — 9 tests de parseo.
- `tests/test_api.py` — 9 tests de la API (health, CRUD, filtros, caché, validación).
- `tests/test_schemas.py` — 7 tests de los validadores JSON Schema.
- `tests/test_load_loghub.py` — 3 tests del generador sintético.
- `tests/test_worker_integration.py` — 1 test end-to-end (colector → stream → worker → Mongo).

### Added — Documentación
- `docs/seguimientos/S2.md` — bitácora de la semana.
- `docs/COMO_PROBAR_S2.md` — guía del flujo end-to-end.
- `docs/COMO_PROBAR_API.md` — guía de la API y el dashboard.

### Changed
- `requirements.txt` — agregadas: `fastapi`, `uvicorn[standard]`, `jinja2`, `pydantic`, `mongomock`, `httpx`.
- Prefijo Redis definitivamente adoptado: `grupo4:auditalog:` en todas las claves.

## [0.1.0] — 2026-10-16 · Seguimiento 1
### Added
- Estructura de repositorio (`src/`, `docs/`, `data/`, `scripts/`, `tests/`).
- Licencia MIT, `.gitignore`, `.env.example`, `requirements.txt`.
- README inicial con problema, usuarios y alcance del MVP.
- Diagrama de arquitectura v1 (`docs/arquitectura/arquitectura-v1.md`).
- Modelo de datos v1 para MongoDB, Redis y SQLite (`docs/arquitectura/modelo-datos-v1.md`).
- Scripts "hola mundo" para los tres motores (`scripts/hello_*.py`).
- Módulo de configuración común (`src/common/config.py`).
- Bitácora del seguimiento 1 (`docs/seguimientos/S1.md`).
