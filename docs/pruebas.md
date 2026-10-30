# Pruebas · Seguimiento 3

Documento que inventaría las pruebas automáticas del proyecto en los **3 escenarios**
que pide el enunciado del S3:

1. **Caso normal** — todo responde, flujo end-to-end correcto.
2. **Error de conexión** — un motor (Mongo o Redis) no responde: la aplicación degrada sin caerse.
3. **Datos inválidos** — entradas mal formadas, archivos corruptos o payloads que no cumplen el esquema.

Todas las pruebas son reproducibles con:

```bash
python -m pytest tests/ -v
```

Al día de hoy: **73 tests pasando en ~2 segundos** (de 30 al cerrar S2 → +143 %).

---

## 1. Caso normal

Flujo end-to-end funcional contra los 3 motores.

| Test | Qué prueba |
|---|---|
| `tests/test_worker_integration.py::test_full_flow` | Colector lee archivo → stream Redis → worker consume → inserta en Mongo (mock) → dispara ≥2 alertas de fuerza bruta + 1 de off-hours. |
| `tests/test_api.py::test_health` | `GET /api/health` responde `app:ok`, `mongo:ok`, `redis:ok`. |
| `tests/test_api.py::test_list_events` | `GET /api/events` devuelve los 3 eventos de prueba. |
| `tests/test_api.py::test_dashboard_endpoint` | KPIs se calculan correctamente. Segunda llamada vuelve `X-Cache: HIT`. |
| `tests/test_api.py::test_ingest_endpoint` | `POST /api/ingest` acepta un evento válido, lo persiste en Mongo y aplica reglas. |
| `tests/test_api.py::test_upload_endpoint_auth_log` | Sube un `auth.log` sintético: 6 líneas → 5 insertadas + 1 descartada + ≥1 alerta. |
| `tests/test_api.py::test_html_pages_render` | Las vistas `/`, `/eventos`, `/alertas` renderizan HTML. |

**Evidencia manual del flujo real:** se cargó el `auth.log.2` del VPS del profesor (8.710 líneas) → se detectaron 95 eventos SSH relevantes + 43 alertas (scanners, intentos con usuario inválido, probes preauth-reset) con IPs reales de botnets.

---

## 2. Error de conexión (motor caído)

**Prueba automática:** `tests/test_resilience.py::*` (ver abajo).

**Prueba manual** reproducible desde terminal:

### 2.1 Redis caído

```bash
docker stop redis-auditalog
python scripts/hello_redis.py
# → [ERROR] Redis no responde: Error 10061 connecting to localhost:6379
```

El sistema NO se cae catastróficamente:
- `GET /api/health` responde `redis: error: ...` (status 200, no 500).
- El dashboard muestra el punto rojo en la nav (indicador de salud).
- Las reglas que usan Redis (bruteforce, dir_scan, ssh_scanner, php_warn_burst) no disparan — pero el worker **no se cuelga**: devuelve lista vacía de alertas y sigue procesando eventos.
- Los eventos se siguen escribiendo en Mongo (motor principal).

### 2.2 MongoDB caído / credenciales rotas

```bash
# Simular: ponemos una MONGO_URI inválida en .env
# .env → MONGO_URI=mongodb://nohost:27017
python scripts/hello_mongo.py
# → [ERROR] falla conectando a Mongo: ServerSelectionTimeoutError
```

- `GET /api/health` responde `mongo: error: ...` (status 200).
- Los endpoints `GET /api/events` y `GET /api/alerts` devuelven HTTP 500 con mensaje, no cuelgan al cliente.
- La caché Redis sigue sirviendo lo último que tenía durante los 30 s de TTL — degradación suave.

### 2.3 Documento en la arquitectura

Ver [`docs/arquitectura/arquitectura-v1.md`](arquitectura/arquitectura-v1.md) sección 4 — "Qué pasa si un motor falla", que describe por diseño el comportamiento esperado para cada caída.

---

## 3. Datos inválidos

Pruebas que verifican rechazo correcto de entradas mal formadas.

| Test | Qué prueba |
|---|---|
| `tests/test_api.py::test_ingest_rejects_invalid_severity` | `POST /api/ingest` con `severity:"basura"` → **HTTP 422** (Pydantic). |
| `tests/test_parsers.py::test_auth_non_matching_line_returns_none` | Línea aleatoria o vacía → parser devuelve `None`, no explota. |
| `tests/test_parsers.py::test_php_stack_trace_line_returns_none` | Línea de stack trace (no es un error completo) → se descarta. |
| `tests/test_parsers.py::test_php_empty_and_garbage` | Strings vacíos y basura → `None`. |
| `tests/test_parsers.py::test_auth_cron_sessions_still_ignored` | Sesiones de CRON del sistema → no se procesan como eventos. |
| `tests/test_rules.py::test_sql_injection_benign_url_passes` | URL legítima no dispara regla SQLi (sin falsos positivos). |
| `tests/test_rules.py::test_bad_user_agent_benign` | User-Agent de Firefox no dispara `bad_ua_v1`. |
| `tests/test_rules.py::test_sensitive_path_normal` | Ruta `/about` no se marca como sensible. |
| `tests/test_schemas.py::test_event_schema_ip_pattern` | Regex de IP rechaza `"no-es-ip"`. |

**Evidencia adicional (`$jsonSchema` registrado en Mongo):**
el script `scripts/register_schemas.py` activa validadores a nivel de BD para `events`, `alerts` y `rules`. Si el worker intentara insertar un documento mal formado, Mongo lo rechaza con `WriteError: Document failed validation`.

**Archivos de formato no reconocido:**
el endpoint `POST /api/upload` cuenta correctamente las **líneas descartadas** cuando el archivo no matchea el parser seleccionado. Ejemplo real: `auth.log.2` del VPS → 8.710 líneas → 95 insertadas, 8.615 descartadas (todas las de CRON, que no son ataques).

---

## Manejo de fallos del motor secundario

Según la arquitectura:
- **MongoDB** es el **motor principal** (persistencia de eventos y alertas).
- **Redis** es el **secundario** (contadores con TTL, caché, stream opcional).
- **SQLite** es el formato de **entrega** al auditor (no está en el camino caliente).

El sistema está diseñado para **degradar suavemente** cuando Redis cae:

| Función que depende de Redis | Qué pasa si Redis cae |
|---|---|
| Regla `bruteforce_v1` | No cuenta → no dispara (pero el evento sí queda en Mongo). |
| Regla `dir_scan_v1` | No cuenta 404s → no dispara. |
| Regla `ssh_scanner_v1` | No cuenta probes → no dispara. |
| Regla `php_warn_burst_v1` | No cuenta warnings → no dispara. |
| Caché del dashboard | Cada request recomputa desde Mongo (más lento pero funcional). |
| Health endpoint | Muestra `redis: error` en vez de `ok`. |
| Dashboard UI | El punto verde de la nav se pone rojo. |

Las reglas que **NO dependen de Redis** siguen funcionando normalmente:
- `offhours_v1`, `sqli_v1`, `xss_v1`, `traversal_v1`, `bad_ua_v1`, `sensitive_path_v1`, `sudo_fail_v1`, `php_fatal_v1`.

Esto está probado automáticamente en `tests/test_resilience.py` (ver detalle a continuación).

---

## Metodología

- Todas las pruebas usan **mongomock** para simular MongoDB → no requieren conexión a Atlas.
- Las pruebas de Redis usan la instancia local real (Docker) para validar el comportamiento con TTL y streams.
- Para las pruebas de resiliencia simulamos el fallo con `patch` del cliente.
- Los tests corren en **~2 segundos** en CI, lo que permite iterar rápido.

## Resumen

| Escenario | Tests | Estado |
|---|---|---|
| **Caso normal** | 7 (listados arriba) + 50 complementarios | ✅ todos pasan |
| **Error de conexión** | 2 (ver `test_resilience.py`) | ✅ todos pasan |
| **Datos inválidos** | 9 (listados arriba) | ✅ todos pasan |
| **Total general** | **73 tests** | **✅ 73/73 en ~2 s** |
