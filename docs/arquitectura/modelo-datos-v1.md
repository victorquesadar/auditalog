# Modelo de datos v1 · AuditaLog

**Versión:** 1.0 (Seguimiento 1) · **Fecha:** 2026-10-16

## 1. MongoDB

Base: `auditalog`.

### Colección `events`

Un documento por evento normalizado. Guarda el `raw` original para no perder información.

```json
{
  "_id": "ObjectId",
  "source": "auth.log | access.log | app",
  "host": "vps-01.example.cr",
  "ts": "2026-10-16T15:22:11Z",
  "ingested_at": "2026-10-16T15:22:12Z",
  "user": "root",
  "ip": "192.0.2.45",
  "action": "login_failed | login_ok | config_changed | http_request",
  "detail": {
    "method": "ssh | password | pubkey | http",
    "status": 401,
    "path": "/wp-admin",
    "config_file": "/etc/ssh/sshd_config"
  },
  "severity": "info | warn | critical",
  "raw": "Oct 16 15:22:11 vps-01 sshd[12345]: Failed password for root from 192.0.2.45 port 55123 ssh2",
  "tags": ["ssh", "linux"]
}
```

**Índices:**
- `{ ts: -1 }`
- `{ source: 1, ts: -1 }`
- `{ ip: 1, ts: -1 }`
- `{ user: 1, ts: -1 }`
- `{ severity: 1, ts: -1 }`

### Colección `alerts`

```json
{
  "_id": "ObjectId",
  "rule_id": "bruteforce_v1",
  "fired_at": "2026-10-16T15:30:00Z",
  "severity": "critical",
  "title": "Posible fuerza bruta SSH desde 192.0.2.45",
  "evidence": {
    "ip": "192.0.2.45",
    "user": "root",
    "fails": 7,
    "window_sec": 600,
    "event_ids": ["ObjectId", "ObjectId", "..."]
  },
  "status": "open | acknowledged | closed",
  "notes": ""
}
```

### Colección `rules`

```json
{
  "_id": "ObjectId",
  "rule_id": "bruteforce_v1",
  "name": "Fuerza bruta SSH",
  "type": "threshold",
  "enabled": true,
  "params": { "window_sec": 600, "max_fails": 5 },
  "severity": "critical",
  "updated_at": "2026-10-16T15:00:00Z"
}
```

**Decisión embebido vs. referencia (S1):**
- Los `event_ids` en `alerts.evidence` se guardan **por referencia** (ObjectId): una alerta puede
  tener decenas de eventos, embeberlos haría crecer el documento sin necesidad.
- El `raw` del evento sí va **embebido** en `events`: siempre se consulta junto con el evento.
- Las `rules` son pequeñas y no se repiten: colección aparte, no embebidas en cada alerta.

## 2. Redis

**Prefijo obligatorio:** `grupo4:auditalog:` (en todas las claves).
**Prohibido:** `FLUSHALL`, `FLUSHDB`.

| Clave | Estructura | TTL | Uso |
|---|---|---|---|
| `grupo4:auditalog:ingest` | Stream | — | Cola de ingesta (XADD / XREADGROUP) |
| `grupo4:auditalog:ingest:group` | Consumer group | — | Grupo de consumidores del worker |
| `grupo4:auditalog:bruteforce:<ip>` | String (contador INCR) | 600 s | Fallos por IP en la ventana |
| `grupo4:auditalog:bruteforce:user:<user>` | String (contador INCR) | 600 s | Fallos por usuario |
| `grupo4:auditalog:suspicious:ips` | Sorted set | — | Score = total de fallos; se recorta diario |
| `grupo4:auditalog:cache:dashboard:v1` | Hash | 30 s | KPIs del dashboard |
| `grupo4:auditalog:cache:events:recent` | List | 60 s | Últimos 50 eventos para el feed |
| `grupo4:auditalog:alerts` | Pub/Sub | — | Canal para refrescar el tablero en vivo |

**Mapa de claves:** se mantiene en [`docs/arquitectura/redis-keys.md`](redis-keys.md) *(se completa en S4)*.

## 3. SQLite (paquete de evidencia)

Archivo: `evidencia_<YYYY-MM>.db` generado por el exportador.

```sql
-- Tabla principal: eventos del período
CREATE TABLE events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mongo_id        TEXT    NOT NULL UNIQUE,       -- trazabilidad al origen
    source          TEXT    NOT NULL,              -- auth.log | access.log | app
    host            TEXT,
    ts              TEXT    NOT NULL,              -- ISO-8601
    user            TEXT,
    ip              TEXT,
    action          TEXT    NOT NULL,
    severity        TEXT    NOT NULL,              -- info | warn | critical
    detail_json     TEXT,                          -- JSON como texto
    raw             TEXT    NOT NULL
);

CREATE INDEX idx_events_ts        ON events(ts);
CREATE INDEX idx_events_ip_ts     ON events(ip, ts);
CREATE INDEX idx_events_user_ts   ON events(user, ts);
CREATE INDEX idx_events_severity  ON events(severity, ts);
CREATE INDEX idx_events_source_ts ON events(source, ts);

-- Alertas emitidas en el período
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mongo_id      TEXT    NOT NULL UNIQUE,
    rule_id       TEXT    NOT NULL,
    fired_at      TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    title         TEXT    NOT NULL,
    evidence_json TEXT    NOT NULL,
    status        TEXT    NOT NULL
);

CREATE INDEX idx_alerts_fired_at ON alerts(fired_at);
CREATE INDEX idx_alerts_rule     ON alerts(rule_id);

-- Metadatos del paquete (inmutable)
CREATE TABLE package_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Filas de ejemplo:
-- ('generated_at', '2026-11-01T08:00:00Z')
-- ('period_from', '2026-10-01T00:00:00Z')
-- ('period_to',   '2026-10-31T23:59:59Z')
-- ('event_count', '142387')
-- ('sha256',      '...')  -- hash del dump para integridad

-- Vistas para el auditor
CREATE VIEW v_fuerza_bruta AS
SELECT ip, COUNT(*) AS fallos, MIN(ts) AS primer_intento, MAX(ts) AS ultimo
FROM events
WHERE action = 'login_failed'
GROUP BY ip
HAVING fallos >= 5
ORDER BY fallos DESC;

CREATE VIEW v_cambios_config AS
SELECT ts, user, ip, json_extract(detail_json, '$.config_file') AS archivo
FROM events
WHERE action = 'config_changed'
ORDER BY ts DESC;

CREATE VIEW v_accesos_offhours AS
SELECT ts, user, ip, action
FROM events
WHERE action IN ('login_ok', 'login_failed')
  AND (CAST(strftime('%H', ts) AS INTEGER) >= 22
       OR CAST(strftime('%H', ts) AS INTEGER) < 6)
ORDER BY ts DESC;
```

**Nota S3:** se activará **WAL** y se medirá con y sin índice usando `EXPLAIN QUERY PLAN`.
