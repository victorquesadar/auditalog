# Decisiones técnicas · AuditaLog

Registro de las decisiones de diseño que tomamos durante el proyecto, con
la alternativa que descartamos y el motivo. Se actualiza en cada seguimiento.

## S1 — Semana 13

### D-01 · Python + FastAPI como stack
**Elegida:** Python 3.11 + FastAPI + Uvicorn + Pydantic.
**Alternativas:** PHP + Laravel, Node.js + Express.
**Motivo:** mejor soporte asíncrono para ingesta, drivers maduros para los
3 motores (pymongo, redis-py, sqlite3 stdlib), tipado con Pydantic.

### D-02 · MongoDB Atlas en vez de local
**Elegida:** cluster M0 en AWS Oregon, usuario compartido del grupo.
**Alternativas:** Mongo local en el VPS, Mongo en Docker.
**Motivo:** el profesor puede verificar la BD desde fuera, los 4 integrantes
atacan la misma BD sin levantar servicios cada uno.

### D-03 · Prefijo Redis `grupo4:auditalog:`
**Elegida:** todas las claves y streams con prefijo `grupo4:auditalog:`.
**Alternativas:** solo `grupo4:`, sin prefijo.
**Motivo:** el enunciado lo exige para no chocar con otros grupos en el
Redis compartido. El sub-prefijo deja espacio a futuros proyectos del grupo.

### D-04 · `raw` embebido, `event_ids` por referencia
**Elegida:** el campo `raw` del evento vive dentro del documento; los
`event_ids` dentro de `alerts.evidence` son referencias (ObjectId).
**Alternativas:** todo embebido, o `raw` en una colección aparte.
**Motivo:** una alerta puede tener decenas de eventos — embeberlos haría
crecer el documento. El `raw` sí embebido porque siempre se consulta junto.

### D-05 · SQLite solo como paquete de evidencia
**Elegida:** SQLite se genera a demanda como archivo `.db` autocontenido
para el auditor.
**Alternativas:** SQLite como almacén caliente, archivo WAL compartido.
**Motivo:** es la justificación del motor según la propuesta (archivo
portable, autocontenido, sin dependencias del servidor para abrirlo).

## S2 — Semana 14

### D-06 · Reglas de detección en código, no en BD
**Elegida:** las reglas viven en `src/common/rules.py` como funciones
Python.
**Alternativas:** reglas en documentos Mongo con DSL propio.
**Motivo:** evitamos reinventar un motor de reglas. En S3 podríamos
agregar la colección `rules` con config dinámica (ventanas, umbrales),
pero la lógica queda en código versionado para que sea testeable.

### D-07 · Ingesta directa por API aplica reglas en el mismo request
**Elegida:** `POST /api/ingest` escribe directo a Mongo **y** llama
`apply_rules` sincrónicamente.
**Alternativas:** publicar al Stream y que el worker procese; dejar la
ingesta fire-and-forget.
**Motivo:** el usuario que crea un evento vía API ve inmediatamente las
alertas disparadas (feedback inmediato en la UI). El worker queda para
archivos de log masivos con batching.

### D-08 · Consumer group del worker (XREADGROUP + XACK)
**Elegida:** el worker lee con `XREADGROUP` + `XACK`.
**Alternativas:** `XREAD` plano, suscribirse al Stream sin grupo.
**Motivo:** `XREADGROUP` permite escalar a múltiples workers paralelos sin
procesar un mismo mensaje dos veces. Lo probamos en S3 (ver mediciones).

### D-09 · Caché del dashboard con TTL de 30 s
**Elegida:** `GET /api/dashboard` cachea en `grupo4:auditalog:cache:dashboard:v1`
con TTL 30 s, header `X-Cache: HIT/MISS` para medir.
**Alternativas:** sin caché, caché con invalidación por eventos.
**Motivo:** el dashboard es la vista más consultada del sistema. 30 s es
suficiente para operación humana y nos deja medir en S3 el speedup de la
caché.

### D-10 · No implementar `DELETE` en events ni alerts
**Elegida:** la API no expone endpoints de borrado.
**Alternativas:** `DELETE /api/events/{id}` con rol admin.
**Motivo:** AuditaLog es bitácora forense. ISO 27001 y PCI DSS exigen
inmutabilidad. Las alertas usan transiciones de estado (open →
acknowledged → closed), nunca se borran.

## S3 — Semana 15

### D-11 · Reglas HTTP ampliadas (SQLi, XSS, directory traversal, UA, path, dir-scan)
**Elegida:** 6 reglas nuevas en S3 además de las 2 de S2, todas en
`src/common/rules.py`.
**Alternativas:** usar ModSecurity rules, importar un ruleset externo tipo
OWASP CRS.
**Motivo:** el objetivo del curso es demostrar el patrón, no competir con
un WAF. 6 reglas con firmas estáticas cubren los OWASP Top 10 más
comunes y son testeables.

### D-12 · Quitar botones "Agregar evento" y "Agregar alerta" del UI
**Elegida:** `/eventos` y `/alertas` solo permiten lectura y acciones de
estado; para generar datos hay que usar `/subir` (archivo) o `/ingesta`
(simulación).
**Alternativas:** dejar los botones solo visibles con un flag `?dev=1`.
**Motivo:** en producción un admin no agrega eventos manualmente — eso
viola la auditoría. La página `/subir` reemplaza al colector para archivos
puntuales, y `/ingesta` sigue para probar reglas.

### D-13 · Subida de archivos vía `POST /api/upload`
**Elegida:** endpoint multipart que recibe archivo, parsea, inserta por
lotes de 500 y aplica reglas en el request.
**Alternativas:** subir el archivo a disco y procesarlo con un job
background; usar el colector apuntando al archivo subido.
**Motivo:** para archivos chicos (<50 MB) el request completo funciona
bien. Para archivos grandes queda como mejora de S4 pasar a procesamiento
asíncrono con un job queue.

### D-14 · Benchmarks reproducibles en `scripts/benchmarks.py`
**Elegida:** un solo script orquesta las 3 pruebas (Mongo índice, cache
Redis, SQLite índice) con 3 corridas cada una y reporta mediana.
**Alternativas:** notebooks Jupyter, scripts separados.
**Motivo:** reproducibilidad — `python scripts/benchmarks.py --all`
regenera el reporte. Los datos crudos quedan en `raw.json` para análisis
externo. Las medianas evitan los outliers del primer run (cold start).

### D-15 · Mediciones con y sin optimización, misma volumetría
**Elegida:** cada prueba corre dos veces (con/sin índice/caché) sobre
exactamente el mismo dataset.
**Alternativas:** solo medir el optimizado, usar datasets distintos.
**Motivo:** es la forma rigurosa de atribuir mejoras a la optimización y
no a diferencias del dataset. El enunciado del S3 exige "con y sin
optimización" explícitamente.

## S4 — Semana 16

### D-16 · GeoIP local, sin APIs HTTP
**Elegida:** 2 capas en `src/common/geoip.py` — primero MMDB (MaxMind
GeoLite2 o DB-IP Lite) cuando están descargadas, luego un fallback
embebido en código con ~210 redes conocidas (AWS, Azure, GCP, DigitalOcean,
OVH, Hetzner, Cloudflare, cloud chino, ICE/Cabletica de Costa Rica, etc.).
**Alternativas:** ip-api.com, ipapi.co, ipgeolocation.io con request HTTP
por IP.
**Motivo:** el profesor fue explícito en que las APIs HTTP tienen límite
de ratio y pueden fallar durante la defensa. Las bases MaxMind/DB-IP se
distribuyen como archivo y se consultan offline en microsegundos.
Mantenemos el fallback embebido para que el sistema funcione sin descargar
nada (indispensable para la evaluación).

### D-17 · Carga acumulativa, no reemplazo
**Elegida:** `POST /api/upload` inserta en Mongo sin borrar lo previo;
botón explícito "🗑️ Limpiar sistema" para resetear.
**Alternativas:** cada upload limpia la BD primero.
**Motivo:** el profesor aclaró que los archivos de log rotados (`.log.1`,
`.log.2`, `.log.3`) son del mismo servidor en distintas fechas y hay que
analizarlos **juntos** para detectar patrones. El botón de limpieza queda
para repetir demos desde cero.

### D-18 · Login opcional por variable de entorno
**Elegida:** auth se activa solo si `AUTH_USER` y `AUTH_PASS` están en
`.env`. Sesión por cookie HMAC-SHA256 firmada con `AUTH_SECRET`.
**Alternativas:** OAuth2 con Google, JWT con refresh tokens, Keycloak.
**Motivo:** el profesor pidió "lo más simple posible". Sin librerías
adicionales (sin `python-jose`, sin `passlib`), usando solo `hmac`+`hashlib`
de la stdlib. El modo sin login queda intacto para desarrollo local;
Virtualmin solo necesita exportar las 3 variables. No mantenemos tabla
de usuarios en Mongo — es un panel de administrador único, no multi-tenant.

### D-19 · Enlaces externos como `<a>`, sin fetch backend
**Elegida:** la página `/geo` muestra por cada IP enlaces estáticos a
AbuseIPDB, Shodan, IPinfo y VirusTotal usando sus URLs públicas de
búsqueda.
**Alternativas:** scrapear esas páginas desde el backend y mostrar la
reputación.
**Motivo:** respeta el ToS de los servicios (no es scraping ni consumo de
API gratuita masiva), es instantáneo, y el analista decide a cuál servicio
consultar según el caso. No requiere registrar claves de API por grupo.

### D-20 · Excel enriquecido con geo en las 3 hojas principales
**Elegida:** las columnas País / Código / ASN / Proveedor se agregan a
Alertas, Eventos y Top IPs. Las hojas "Por país" y "Por ASN" quedan como
agrupadores con porcentajes.
**Alternativas:** una sola hoja "Geo" dedicada, o hojas separadas por
país.
**Motivo:** el profesor pidió "reportes y gráficos agrupados por país y
ASN, con porcentajes, ordenados descendente". Al tener la info en las
hojas principales, el auditor filtra y pivota en Excel directamente;
las hojas de resumen dan el ranking agregado para incluir en el informe.
