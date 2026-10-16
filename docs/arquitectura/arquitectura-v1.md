# Arquitectura v1 · AuditaLog

**Versión:** 1.0 (Seguimiento 1) · **Fecha:** 2026-10-16

## 1. Visión general

AuditaLog es una tubería de ingesta → detección → persistencia → consulta → exportación para
registros de auditoría (accesos y cambios de configuración). Está pensada para una PYME: un
servidor pequeño o VPS, sin equipo de SOC.

## 2. Diagrama lógico

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                               AuditaLog · v1                                 │
└──────────────────────────────────────────────────────────────────────────────┘

   Fuentes de log                 Ingesta                   Detección en vivo
   ──────────────                 ───────                   ──────────────────
 ┌─────────────────┐        ┌────────────────┐           ┌────────────────────┐
 │ /var/log/auth   │──┐     │  Colectores    │           │ Redis              │
 │ (SSH, PAM)      │  │     │  Python        │           │                    │
 └─────────────────┘  │     │  (src/         │           │ • contadores TTL   │
                      ├────►│   collectors/) │──────────►│   (fuerza bruta)   │
 ┌─────────────────┐  │     │                │  Streams  │ • sorted set       │
 │ access.log      │──┤     │  Normaliza y   │  (XADD)   │   IPs sospechosas  │
 │ (Apache/Nginx)  │  │     │  envía a Redis │           │ • caché dashboard  │
 └─────────────────┘  │     └────────────────┘           │   (TTL 30 s)       │
                      │                                   └────────┬───────────┘
 ┌─────────────────┐  │                                            │
 │ app events JSON │──┘                                            │ XREADGROUP
 │ (app propias)   │                                               ▼
 └─────────────────┘                                      ┌────────────────────┐
                                                          │  Worker Python     │
                                                          │  (src/workers/)    │
                                                          │                    │
                                                          │  • parsea evento   │
                                                          │  • aplica reglas   │
                                                          │  • escribe en Mongo│
                                                          └────────┬───────────┘
                                                                   │
                                                                   ▼
                                                          ┌────────────────────┐
                                                          │  MongoDB (Atlas)   │
                                                          │                    │
                                                          │  • events          │
                                                          │  • alerts          │
                                                          │  • rules           │
                                                          └────────┬───────────┘
                                                                   │
                              ┌────────────────────────────────────┤
                              ▼                                    ▼
                   ┌────────────────────┐              ┌────────────────────┐
                   │  API FastAPI       │              │  Exportador SQLite │
                   │  + Dashboard       │              │  (src/exporter/)   │
                   │  (src/api/)        │              │                    │
                   │                    │              │  evidencia_        │
                   │  /events  /alerts  │              │  <periodo>.db      │
                   │  /dashboard        │              │  (archivo .db      │
                   └────────┬───────────┘              │   autocontenido)   │
                            │                          └────────┬───────────┘
                            ▼                                    ▼
                   ┌────────────────────┐              ┌────────────────────┐
                   │  Admin de TI       │              │  Auditor           │
                   │  (navegador)       │              │  (DB Browser,      │
                   │                    │              │   DBeaver, SQL)    │
                   └────────────────────┘              └────────────────────┘
```

## 3. Responsabilidad de cada motor

### MongoDB — almacén central
- **Colección `events`**: cada log normalizado con su campo `raw` (texto original).
- **Colección `alerts`**: alertas emitidas por el worker.
- **Colección `rules`**: reglas de detección configurables en caliente.
- Índices: `{source, ts}`, `{ip, ts}`, `{user, ts}`, `{severity, ts}`.
- Usa agregaciones (`$group`, `$lookup`) para los paneles del dashboard.

### Redis — operación en tiempo real
- **Stream `grupo4:auditalog:ingest`**: cola de ingesta (XADD / XREADGROUP).
- **Contadores**: `grupo4:auditalog:bruteforce:<ip>` con TTL = 600 s.
- **Sorted set**: `grupo4:auditalog:suspicious:ips` con score = cantidad de fallos.
- **Caché dashboard**: `grupo4:auditalog:cache:dashboard:v1` con TTL 30 s.
- **Pub/Sub**: canal `grupo4:auditalog:alerts` para refrescar el tablero.

### SQLite — paquete de evidencia
- Un archivo `.db` por período (p. ej. `evidencia_2026-10.db`).
- Tablas espejo de las colecciones Mongo del período auditado.
- Vistas pregeneradas para los reportes más comunes.
- Modo WAL para lectura concurrente del auditor.

## 4. Qué pasa si un motor falla

| Falla | Impacto | Respuesta |
|---|---|---|
| **Redis cae** | No hay detección en vivo ni caché | Colectores escriben a buffer local (archivo); worker procesa cuando Redis vuelve. API degrada: dashboard sin KPIs calientes pero sigue mostrando eventos de Mongo. |
| **Mongo cae** | No se persisten eventos nuevos; API devuelve 503 en `/events` | Worker reintenta con backoff; eventos quedan en el Stream (que aguanta). Dashboard muestra banner "Mongo no disponible". |
| **SQLite falla al exportar** | No se genera el paquete del auditor | El exportador es un script offline; se reintenta sin afectar producción. |

## 5. Decisiones iniciales (se amplían en `docs/decisiones.md` en S3)

- **Python + FastAPI** por rapidez de desarrollo, soporte asíncrono y buenos drivers para los tres motores.
- **MongoDB Atlas** (no local) para que el profesor pueda verificar la instalación desde fuera.
- **Redis compartido del curso** con prefijo `grupo4:auditalog:` obligatorio.
- **SQLite** solo como formato de entrega al auditor, no como almacén principal.

## 6. Diagrama de secuencia — detección de fuerza bruta

```
Colector      Redis Stream        Worker          Redis contador        Mongo
   │               │                 │                  │                  │
   │ XADD evento   │                 │                  │                  │
   ├──────────────►│                 │                  │                  │
   │               │  XREADGROUP     │                  │                  │
   │               │◄────────────────┤                  │                  │
   │               │                 │ INCR + EXPIRE    │                  │
   │               │                 ├─────────────────►│                  │
   │               │                 │   valor = n      │                  │
   │               │                 │◄─────────────────┤                  │
   │               │                 │                  │                  │
   │               │                 │   si n ≥ 5:      │                  │
   │               │                 │   insert alert   │                  │
   │               │                 ├─────────────────────────────────────►│
   │               │                 │                  │                  │
   │               │                 │   insert event (siempre)            │
   │               │                 ├─────────────────────────────────────►│
```
