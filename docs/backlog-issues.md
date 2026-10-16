# Backlog inicial · Issues sugeridos para GitHub

Copiar cada bloque como un issue en el repo. Asignar responsable y agregar al
milestone correspondiente (`S1`, `S2`, `S3`, `S4`).

---

## Milestone S1 (semana 13) — ya hechos, cerrar al crear

### #1 · Crear estructura inicial del repo
**Labels:** `chore`, `milestone:S1`
**Asignado:** líder del grupo
Carpetas `src/`, `docs/`, `data/`, `scripts/`, `tests/`; licencia MIT; `.gitignore`; `.env.example`.

### #2 · README inicial
**Labels:** `docs`, `milestone:S1`
Problema, usuario, alcance del MVP, tecnologías.

### #3 · Diagrama de arquitectura v1
**Labels:** `docs`, `milestone:S1`
En `docs/arquitectura/arquitectura-v1.md`.

### #4 · Modelo de datos v1 (Mongo + Redis + SQLite)
**Labels:** `docs`, `milestone:S1`
Colecciones, mapa de claves con TTL, DDL inicial.

### #5 · Scripts hello_mongo / hello_redis / hello_sqlite
**Labels:** `feat`, `milestone:S1`
Verifican conexión y crean esquema mínimo.

### #6 · Bitácora S1 + tag v0.1.0
**Labels:** `docs`, `milestone:S1`

---

## Milestone S2 (semana 14) — abrir todos

### #7 · Colector de auth.log
**Labels:** `feat`, `milestone:S2`, `area:collectors`
**Asignado:** B
Lee `/var/log/auth.log` (o archivo de Loghub), parsea líneas de SSH, hace XADD al stream.

### #8 · Worker de ingesta
**Labels:** `feat`, `milestone:S2`, `area:workers`
**Asignado:** B
Consume el stream con XREADGROUP, normaliza y escribe en Mongo `events`.

### #9 · CRUD de eventos (API)
**Labels:** `feat`, `milestone:S2`, `area:api`
**Asignado:** A
Endpoints `GET /events`, `GET /events/{id}`, con paginación.

### #10 · Validación JSON Schema de events
**Labels:** `feat`, `milestone:S2`, `area:mongo`
**Asignado:** A
Registrar schema de validación en la colección `events`.

### #11 · Página /eventos del dashboard
**Labels:** `feat`, `milestone:S2`, `area:api`
**Asignado:** C
Lista los últimos 50 eventos, filtro por `source` y `severity`.

### #12 · Script load_loghub.py
**Labels:** `feat`, `milestone:S2`, `area:data`
**Asignado:** D
Descarga un subconjunto de Loghub y carga 10k eventos en bulk a Mongo (transacción).

### #13 · `.env.example` revisado + CI de "no secretos"
**Labels:** `chore`, `milestone:S2`
**Asignado:** cualquiera
Verifica con un script que no haya URIs reales en el repo.

### #14 · Trabajo en ramas + PRs obligatorios
**Labels:** `process`, `milestone:S2`
**Asignado:** líder
Proteger `main`, requerir 1 review para merge.

---

## Milestone S3 (semana 15) — crear al cerrar S2

### #15 · Regla fuerza bruta con Redis
**Labels:** `feat`, `milestone:S3`, `area:workers`
Contador por IP con TTL + alerta en Mongo.

### #16 · Regla accesos fuera de horario
**Labels:** `feat`, `milestone:S3`, `area:workers`

### #17 · Regla cambios de configuración
**Labels:** `feat`, `milestone:S3`, `area:workers`

### #18 · Caché del dashboard en Redis (TTL 30s)
**Labels:** `feat`, `milestone:S3`, `area:api`

### #19 · Comportamiento si Redis cae
**Labels:** `feat`, `milestone:S3`, `area:workers`
Buffer local + reintentos.

### #20 · Mediciones (≥3 operaciones, mediana de ≥3 corridas)
**Labels:** `test`, `milestone:S3`
- Inserción masiva con y sin índice
- Consulta top-10 IPs con y sin caché
- Aggregation pipeline del dashboard

### #21 · EXPLAIN QUERY PLAN en SQLite
**Labels:** `test`, `milestone:S3`, `area:sqlite`

### #22 · `docs/decisiones.md` con alternativas y justificación
**Labels:** `docs`, `milestone:S3`

---

## Milestone S4 (semana 16) — crear al cerrar S3

### #23 · README completo + capturas
**Labels:** `docs`, `milestone:S4`

### #24 · Instalación desde cero probada por otra persona
**Labels:** `test`, `milestone:S4`

### #25 · Video demo 3–5 min enlazado
**Labels:** `docs`, `milestone:S4`

### #26 · `portal.yml` para el portal del curso
**Labels:** `docs`, `milestone:S4`

### #27 · Borrador de la presentación final
**Labels:** `docs`, `milestone:S4`
