# AuditaLog

> Bitácora de auditoría de accesos y cambios de configuración para PYMEs
> e instituciones pequeñas.

**Curso:** Tópicos Avanzados de Bases de Datos · Universidad Nacional
**Grupo:** 04 · Viernes
**Período:** II-2026
**Versión actual:** `v1.0.0` (Seguimiento 4 · release final)
**Tests:** 122/122 ✅

---

## 1. Problema

Las PYMEs y las instituciones pequeñas no pueden pagar un SIEM comercial
(Splunk, QRadar, Datadog). Cuando un auditor pide evidencia de **quién
accedió**, **quién cambió una configuración** o **cuántos intentos fallidos
de inicio de sesión hubo**, no hay forma ordenada de entregarla: los
registros están dispersos entre servidores Linux, Apache/Nginx, fail2ban
y aplicaciones propias.

AuditaLog centraliza esos logs, aplica reglas de detección (fuerza bruta,
accesos fuera de horario, inyecciones, IPs baneadas por fail2ban,
denegaciones de AppArmor, errores PHP críticos), muestra alertas en un
tablero web y exporta un paquete de evidencia firmado (SQLite).

## 2. Usuarios

- **Analista** — revisa alertas y eventos, filtra por IP/país/ASN, exporta
  reportes para auditoría.
- **Administrador del sistema** — opera la instalación, sube los logs
  rotados, configura reglas, maneja el login.

## 3. Alcance del MVP

El sistema soporta **9 formatos de log** nativos del ecosistema Linux:

| Formato | Dispara reglas de |
|---|---|
| `auth.log` (SSH / syslog) | Fuerza bruta, sudo fail, escaneo SSH, fuera de horario |
| `access.log` (Apache / Nginx) | SQLi, XSS, directory traversal, User-Agent malicioso, path sensible |
| `error.log` (Apache) | Denegación de cliente, errores críticos |
| `fail2ban.log` | IP baneada, detecciones (`Found`) |
| `phpfpm.log` (PHP-FPM) | Workers caídos, errores de pool |
| `php_log` (PHP app) | Fatal errors, warning bursts |
| `kern.log` | AppArmor denied, mensajes críticos del kernel |
| `mail.log` (postfix/dovecot) | Errores de entrega, servicios caídos |
| `dmesg` | OOM, panic, fallas de hardware |

Entradas y salidas:

- **Entrada:** subida web (acepta `.log`, `.log.N`, `.gz`, `.zip` con varios
  logs dentro).
- **Procesamiento:** parsers nativos + 15 reglas de correlación + enriquecimiento
  GeoIP automático (país + ASN).
- **Salida:** tablero web, API REST, Excel multi-hoja con agrupaciones por
  país/ASN, paquete SQLite firmado (SHA-256) para evidencia.

## 4. Arquitectura

```
                    ┌──────────────┐
    Logs .zip/.gz ─▶│ POST /upload │
                    └──────┬───────┘
                           ▼
                    ┌──────────────────┐
                    │ Parsers (9)      │──▶ eventos  ──▶ MongoDB (grupo4_db.events)
                    └──────┬───────────┘
                           ▼
                    ┌──────────────────┐     counters
                    │ Reglas (15)      │◀──▶ Redis (grupo4:*)
                    └──────┬───────────┘
                           ▼
                    ┌──────────────────┐
                    │ Alertas          │──▶ MongoDB (grupo4_db.alerts)
                    └──────┬───────────┘
                           │   ┌─ Dashboard (/, /eventos, /alertas, /geo)
                           ├──▶│─ Excel (/api/export/xlsx)
                           │   └─ Informe MD (/api/export/md)
                           ▼
                    ┌──────────────────┐
                    │ Paquete evidencia│──▶ SQLite firmado (SHA-256)
                    └──────────────────┘
```

**¿Por qué 3 motores?** Cada uno hace lo que mejor sabe hacer:

- **MongoDB** — almacén principal (esquema flexible, búsqueda rápida por
  filtros ad-hoc del analista: `source`, `ip`, `ts`, `action`).
- **Redis** — contadores efímeros para las reglas (fuerza bruta, dedup de
  alertas) y estado de salud. Tiempos sub-milisegundo.
- **SQLite** — paquete de evidencia inmutable y portable: el analista
  descarga un solo archivo firmado que un auditor puede abrir con
  `sqlite3` sin instalar nada.

Detalle completo: [`docs/arquitectura/arquitectura-v1.md`](docs/arquitectura/arquitectura-v1.md)
y [`docs/arquitectura/modelo-datos-v1.md`](docs/arquitectura/modelo-datos-v1.md).

## 5. Capacidades destacadas (S4 · release final)

### 🌍 GeoIP local, sin APIs HTTP
Cada IP se resuelve a **país + ASN/ISP** con 3 capas en cascada:
1. Detección de IP privada (RFC1918).
2. Dataset embebido de ~210 rangos (AWS, Azure, GCP, Cloudflare, OVH, cloud chino,
   ICE/Cabletica…).
3. Base MMDB local opcional (DB-IP Lite gratis sin registro, o MaxMind GeoLite2).

Descarga opcional: `python scripts/download_geoip.py`.

### 📦 Subida acumulativa multi-archivo
`POST /api/upload` acepta `.zip` con varios logs adentro (incluso comprimidos
como `.gz`). Autodetecta el formato por nombre. **No borra datos previos**
entre subidas — permite analizar logs rotados (`auth.log.1`, `auth.log.2`, …)
en conjunto.

### 🔐 Autenticación opcional
Login con cookie HMAC-SHA256. Se activa poniendo `AUTH_USER` y `AUTH_PASS`
en `.env`. Sin esas variables, el sistema corre en modo dev sin auth.

### 📊 Reportes Excel con agrupaciones
Hojas: `Resumen`, `Alertas`, `Eventos`, `Top IPs`, **`Por país`**, **`Por ASN`**,
`Reglas`. Cada fila de alerta/evento trae columnas **País / Código / ASN /
Proveedor** para pivotar en Excel.

### 🔗 Enriquecimiento con enlaces externos
Por cada IP, el dashboard linkea a **AbuseIPDB · Shodan · IPinfo · VirusTotal**
(URLs públicas, sin consumir API) para que el analista consulte reputación
en tiempo real desde su navegador.

## 6. Capturas

> Las capturas viven en `docs/img/`

https://github.com/user-attachments/assets/3bf62c42-f787-432f-b444-0b31fa7d4dea



- `docs/img/dashboard.png` — portada con eventos, alertas, charts por país y ASN.
- `docs/img/geo.png` — página `/geo` con dona por país y barras por ASN.
- `docs/img/alertas.png` — alertas críticas de `f2b_ban_v1`.
- `docs/img/subir.png` — upload `.zip` con varios logs del profesor.
- `docs/img/excel.png` — pestañas "Por país" y "Por ASN" del Excel exportado.

## 7. Instalación (3 pasos)

> Guía detallada: [`docs/INSTALACION.md`](docs/INSTALACION.md).
> Despliegue en producción con Virtualmin: [`docs/DEPLOY_VIRTUALMIN.md`](docs/DEPLOY_VIRTUALMIN.md).

### 7.1 Requisitos
- **Python 3.11+**
- **Redis** local (Docker: `docker run -d --name redis-auditalog -p 6379:6379 redis`)
- **MongoDB Atlas** (cluster del curso) o Mongo local

### 7.2 Setup
```bash
git clone https://github.com/victorquesadar/auditalog.git
cd auditalog

python -m venv .venv
source .venv/bin/activate         # Linux / macOS
# .venv\Scripts\activate          # Windows PowerShell

pip install -r requirements.txt
cp .env.example .env               # editar con tu MONGO_URI
```

### 7.3 Arrancar
```bash
uvicorn src.api.main:app --reload
# → http://localhost:8000
```

**Opcional — descargar bases GeoIP para cobertura completa:**
```bash
python scripts/download_geoip.py   # DB-IP Lite gratis, sin registro
```

**Opcional — activar login:**
```bash
# En .env agregar:
AUTH_USER=admin
AUTH_PASS=tu-contraseña
# Reiniciar uvicorn
```

## 8. Uso rápido

| Acción | Dónde |
|---|---|
| Ver eventos y alertas | `http://localhost:8000/` |
| Subir un log (soporta `.zip`, `.gz`) | `/subir` |
| Ver mapa geográfico de IPs | `/geo` |
| Descargar Excel | `/exportar` → Excel |
| Descargar paquete SQLite firmado | `/exportar` → SQLite |
| Health check | `/api/health` |
| API docs interactiva | `/docs` |

Datos de prueba reales (logs rotados del VPS del profesor): usar los `.gz`
que compartió en el aula virtual y arrastrarlos al `/subir` dentro de un
`.zip`.

## 9. Tests

```bash
# Requiere Redis corriendo en localhost:6379
pytest tests/ -v
# → 122 passed
```

Si no hay Redis disponible, varios tests fallan con `ConnectionError`.
En CI se usa `fakeredis` como fallback (ver `tests/conftest.py`).

## 10. Roadmap

### Corto plazo (1 mes)
- Agente ligero que lea `/var/log` directo del servidor remoto y publique
  a AuditaLog por API (reemplazo de la subida manual).
- Alertas por correo electrónico y webhooks (Slack, Discord).
- Importación de IoCs desde MISP / OpenCTI para enriquecer las reglas.

### Mediano plazo (6 meses)
- Reglas YAML editables desde la UI, sin desplegar.
- Correlación multi-fuente (SIEM-light): "la misma IP intentó SSH y después
  escaneó HTTP".
- Multi-tenant con organizaciones y permisos por rol.

### Largo plazo (candidato a TFG)
- Modelo de clasificación de anomalías (sklearn / PyOD) sobre las features
  que ya extraemos: tasas por IP/ASN, horarios, países, cambios de pattern.
- Encadenamiento de evidencias para construir "timelines" de incidente
  automáticos con export a formato legal (ej. STIX 2.1).

## 11. Tecnologías

- **Lenguaje:** Python 3.11 — **Web:** FastAPI + Jinja2 + Uvicorn
- **Datos:** MongoDB · Redis · SQLite
- **Librerías clave:** `pydantic`, `pymongo`, `redis`, `openpyxl`,
  `maxminddb`, `pytest`, `mongomock`, `httpx`
- **Charts:** Chart.js 4.4

## 12. Documentación

| Documento | Para qué |
|---|---|
| [`docs/seguimientos/S4.md`](docs/seguimientos/S4.md) | Bitácora de la entrega final |
| [`docs/seguimientos/S1.md`](docs/seguimientos/S1.md) → [`S3.md`](docs/seguimientos/S3.md) | Bitácoras de seguimientos previos |
| [`docs/arquitectura/arquitectura-v1.md`](docs/arquitectura/arquitectura-v1.md) | Diagrama de componentes |
| [`docs/arquitectura/modelo-datos-v1.md`](docs/arquitectura/modelo-datos-v1.md) | Esquema de colecciones e índices |
| [`docs/decisiones.md`](docs/decisiones.md) | 20 decisiones técnicas (ADR) |
| [`docs/pruebas.md`](docs/pruebas.md) | Plan de pruebas y escenarios |
| [`docs/mediciones/mediciones_s3.md`](docs/mediciones/mediciones_s3.md) | Mediciones de performance |
| [`docs/INSTALACION.md`](docs/INSTALACION.md) | Guía detallada de instalación |
| [`docs/DEPLOY_VIRTUALMIN.md`](docs/DEPLOY_VIRTUALMIN.md) | Guía de despliegue en Virtualmin |
| [`CHANGELOG.md`](CHANGELOG.md) | Historial de versiones |

## 13. Video

Video demo (3-5 min): **pendiente — grabar y enlazar aquí** antes del
cierre del semestre.

## 14. Integrantes

| Rol | Responsabilidad principal |
|---|---|
| Backend / Mongo | Schema, índices, API CRUD |
| Workers / Redis | Reglas de correlación, contadores, dedup |
| API / Dashboard | FastAPI, templates, Chart.js |
| SQLite / Datos | Paquete de evidencia firmado |

Los nombres completos solo aparecen en `portal.yml` para quienes
autorizaron su publicación.

## 15. Licencia

[MIT](LICENSE)

## 16. Enlaces

- Repositorio: <https://github.com/victorquesadar/auditalog>
- Release `v1.0.0`: <https://github.com/victorquesadar/auditalog/releases/tag/v1.0.0>
