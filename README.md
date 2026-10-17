# AuditaLog

> Bitácora de auditoría de accesos y cambios de configuración para PYMEs e instituciones pequeñas.

**Curso:** Tópicos Avanzados de Bases de Datos · Universidad Nacional
**Grupo:** 04 · Viernes
**Período:** II-2026
**Versión actual:** `v0.1.0` (Seguimiento 1)

---

## 1. Problema

Las PYMEs y las instituciones pequeñas no pueden pagar un SIEM comercial (Splunk, QRadar, Datadog).
Cuando un auditor pide evidencia de **quién accedió**, **quién cambió una configuración** o
**cuántos intentos fallidos de inicio de sesión hubo**, no hay forma ordenada de entregarla: los
registros están dispersos entre servidores Linux, Apache/Nginx y aplicaciones propias.

AuditaLog centraliza esos logs, aplica reglas de detección (fuerza bruta, accesos fuera de
horario, cambios en archivos de configuración), muestra alertas en un tablero y exporta un
paquete de evidencia reproducible en SQLite para el auditor.

## 2. Usuarios

| Usuario | Qué hace con AuditaLog |
|---|---|
| **Administrador de TI** | Monitorea alertas en tiempo real, detecta anomalías y responde |
| **Auditor interno / externo** | Recibe un `.db` autocontenido y lo analiza con SQL localmente |

## 3. Alcance del MVP (3-4 semanas)

### Entra en el MVP
- Ingesta de **3 tipos de log**: `auth.log` (SSH/Linux), `access.log` (Apache/Nginx) y eventos JSON de aplicaciones propias.
- **Reglas de detección configurables**:
  - Fuerza bruta: 5 fallos en 10 min desde la misma IP → alerta.
  - Acceso fuera de horario (configurable, p. ej. 22:00–06:00) → alerta.
  - Cambios en archivos de configuración (`/etc/...`) → alerta.
- **Tablero web** con alertas abiertas, top de IPs sospechosas y últimos eventos.
- **Exportador** a un paquete SQLite (`evidencia_<periodo>.db`) con los eventos del período auditado.

### Fuera del MVP
- Agentes de ingesta en producción (se usan scripts/colectores para el MVP).
- Autenticación multi-usuario con roles finos (una sola cuenta admin en el MVP).
- Correlación avanzada tipo SIEM (solo reglas simples).
- Alertas por correo/Slack (solo tablero).

## 4. Arquitectura

Ver [`docs/arquitectura/arquitectura-v1.md`](docs/arquitectura/arquitectura-v1.md).

**Flujo resumido:**

```
[Loghub + VPS logs]
      │
      ▼
[Colectores Python]  ──►  [Redis Streams]  ──►  [Worker Python]
                                                       │
                             ┌─────────────────────────┼─────────────────────────┐
                             ▼                         ▼                         ▼
                   [Redis contadores TTL]      [MongoDB `events`]       [Reglas de detección]
                   (fuerza bruta, rankings)    (evento normalizado          │
                                                + raw)                      ▼
                                                                     [Alertas en MongoDB]
                                                                            │
                                                                            ▼
                                                        [API FastAPI + Dashboard web]
                                                                            │
                                                                            ▼
                                                        [Exportador → SQLite evidencia.db]
```

### Rol de cada motor

| Motor | Qué dato vive aquí | Por qué este motor |
|---|---|---|
| **MongoDB** | Eventos normalizados + original; alertas | Cada fuente tiene estructura distinta; esquema flexible + agregaciones |
| **Redis** | Contadores con TTL (fuerza bruta), Streams de ingesta, sorted sets de IPs sospechosas, caché del tablero | Operaciones por segundo + expiración automática |
| **SQLite** | Paquete de evidencia por período (archivo `.db` autocontenido, inmutable) | Un solo archivo que el auditor abre con cualquier cliente SQL |

MariaDB u otro motor relacional **no se usa**.

## 5. Instalación (preliminar — se completa en S4)

```bash
git clone https://github.com/<org>/auditalog.git
cd auditalog
cp .env.example .env            # editar con tus credenciales
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/hello_mongo.py    # verifica MongoDB
python scripts/hello_redis.py    # verifica Redis
python scripts/hello_sqlite.py   # verifica SQLite
```

Variables de entorno: ver [`.env.example`](.env.example).

## 6. Datos de prueba

- **[Loghub](https://github.com/logpai/loghub)**: logs reales de Linux, Apache, OpenSSH y más (millones de líneas).
- Logs anonimizados del propio VPS/Plesk del grupo.
- Nunca datos personales reales.

## 7. Tecnologías

Python 3.11 · FastAPI · Redis 7 · MongoDB 7 (Atlas, cluster AWS Oregon) · SQLite 3 · Chart.js · Docker Compose.

## 8. Integrantes

| Rol | Nombre | GitHub |
|---|---|---|
| Backend / Mongo | Eithel Núñez | [@Eithel2003](https://github.com/Eithel2003) |
| Workers / Redis | Víctor Quesada | [@victorquesadar](https://github.com/victorquesadar) |
| API / Dashboard | Andrey Ortiz | [@andreyortizcr](https://github.com/andreyortizcr) |
| SQLite / Export | Angelly Cortes Herrera| [@Angelly15](https://github.com/Angelly15) |

Cada integrante entiende y puede explicar su parte del código, incluido el que se produjo con ayuda de IA.

## 9. Licencia

[MIT](LICENSE)

## 10. Enlaces

- Issues y backlog: GitHub Projects del repo
- Bitácoras de seguimiento: [`docs/seguimientos/`](docs/seguimientos/)
- Decisiones técnicas: [`docs/decisiones.md`](docs/decisiones.md) *(se abre en S3)*
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
