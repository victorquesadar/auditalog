# Cómo probar la API y el dashboard de AuditaLog

## 1. Instalar las nuevas dependencias

```bash
pip install fastapi "uvicorn[standard]" jinja2 pydantic httpx
```

(O con el nuevo `requirements.txt`: `pip install -r requirements.txt`)

## 2. Correr los tests

```bash
python -m pytest tests/ -v
```

Deben pasar **19/19**:
- 9 tests de parsers
- 9 tests de la API (health, events, alerts, dashboard con caché, ingest, HTML)
- 1 test de integración completa (colector → worker → Mongo)

## 3. Levantar la API en desarrollo

```bash
uvicorn src.api.main:app --reload
```

- API: http://localhost:8000/
- Docs interactivos: http://localhost:8000/docs
- Dashboard: http://localhost:8000/
- Eventos: http://localhost:8000/eventos
- Alertas: http://localhost:8000/alertas

## 4. Flujo completo end-to-end (en 3 terminales)

### Terminal 1 — Worker
```bash
python -m src.workers.ingest_worker
```

### Terminal 2 — API
```bash
uvicorn src.api.main:app --reload
```

### Terminal 3 — Simulador
```bash
# Opción A: cargar logs sintéticos
python scripts/generate_sample_logs.py
python -m src.collectors.auth_log_collector --file data/samples/sample_auth.log --year 2026

# Opción B: enviar un evento por API
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"source":"app","action":"test","user":"victor","ip":"127.0.0.1","severity":"info"}'
```

Abrí **http://localhost:8000/** y vas a ver el dashboard con los KPIs,
el chart de top IPs, y la lista de alertas que fueron apareciendo.

## 5. Exportar paquete de evidencia (SQLite)

```bash
# Todo el histórico
python -m src.exporter.sqlite_exporter --all

# Un período específico
python -m src.exporter.sqlite_exporter --from 2026-10-01 --to 2026-10-31
```

Genera `data/exports/evidencia_<YYYY-MM>.db`. El auditor lo abre con:
- **DB Browser for SQLite** (gratis, Windows/Mac/Linux)
- **DBeaver** (gratis, multiplataforma)
- Cualquier CLI de SQL

Vistas pregeneradas que ya trae el `.db`:
- `v_fuerza_bruta` — IPs con ≥5 fallos
- `v_cambios_config` — modificaciones a archivos de configuración
- `v_accesos_offhours` — logins entre 22:00 y 06:00
- `v_resumen_por_dia` — eventos/críticos/warnings por fecha

Y la tabla `package_meta` con metadatos (fecha de generación, período,
cantidad de eventos, SHA256 de integridad).

## 6. Endpoints de la API

| Método | Ruta | Qué hace |
|---|---|---|
| GET | `/api/health` | Ping a los 3 motores |
| GET | `/api/events` | Lista eventos con filtros (source, severity, ip, user) + paginación |
| GET | `/api/alerts` | Lista alertas con filtros |
| GET | `/api/dashboard` | KPIs y gráficos (caché Redis TTL 30s) |
| POST | `/api/ingest` | Recibe un evento JSON desde apps propias |
| GET | `/` | Dashboard web |
| GET | `/eventos` | Página con tabla filtrable de eventos |
| GET | `/alertas` | Página con tabla de alertas |
| GET | `/docs` | Documentación interactiva Swagger |

## 7. ¿Por qué este stack cubre S2?

El enunciado del Seguimiento 2 pide:
- ✅ Flujo principal end-to-end con el motor principal → colector→stream→worker→Mongo→API→dashboard
- ✅ CRUD mínimo sobre el modelo central → `/api/events` y `/api/alerts` con filtros
- ✅ Primer uso real de Redis → stream `grupo4:auditalog:ingest` + caché TTL del dashboard
- ✅ Validación de datos → Pydantic en el endpoint `/api/ingest`
- ✅ Carga reproducible → `scripts/generate_sample_logs.py` (y `load_loghub.py` pendiente)
- ✅ Trabajo verificable con tests → 19/19 pasando
