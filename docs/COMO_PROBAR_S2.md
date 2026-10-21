# Cómo probar el flujo end-to-end de S2

Lo que esto demuestra:
**auth.log → colector → Redis Stream → worker (3 reglas) → MongoDB**

Toma ~1 minuto.

## 1. Preparar el entorno

Asegurate de que tus 3 motores funcionen:

```bash
python scripts/hello_all.py
# los 3 deben decir "OK"
```

Si falla alguno, no sigas — revisá el `.env`.

## 2. Instalar la nueva dep de tests

```bash
pip install mongomock==4.3.0
```

## 3. Generar el `auth.log` de prueba

```bash
python scripts/generate_sample_logs.py
# → genera data/samples/sample_auth.log con 29 líneas
```

El archivo contiene:
- 8 fallos consecutivos de `root` desde `203.0.113.5` → **debe disparar bruteforce**
- 6 fallos de `admin` desde `198.51.100.33` → **debe disparar bruteforce**
- 1 login exitoso a las 03:30 de `ana` → **debe disparar off-hours**
- Tráfico normal de día (no debe disparar nada)

## 4. Correr los tests unitarios

```bash
python -m pytest tests/ -v
```

Deben pasar 10/10. Esto prueba:
- Parsers de `auth.log` y `access.log` con casos reales de Loghub.
- Integración completa colector → Redis → worker → Mongo (mock).

## 5. Correr la demo end-to-end contra tus motores reales

Esta versión usa el Mongo Atlas del grupo:

```bash
python scripts/run_demo.py
```

Al final imprime algo como:
```
============================================================
  Eventos en Mongo: 29
  Alertas totales:  7
    · fuerza bruta: 6
    · off-hours:    1
============================================================

Últimas 3 alertas:
  [    WARN] Acceso fuera de horario (03:xx) de ana@10.0.0.5
  [CRITICAL] Posible fuerza bruta desde 198.51.100.33
  [CRITICAL] Posible fuerza bruta desde 203.0.113.5
```

> ⚠️ El script **borra todos los events y alerts de Mongo** antes de correr. No lo uses contra una BD con datos reales.

## 6. Probar manualmente (en 2 terminales)

**Terminal 1 — worker en modo continuo:**
```bash
python -m src.workers.ingest_worker
```

**Terminal 2 — colector en modo batch:**
```bash
python -m src.collectors.auth_log_collector --file data/samples/sample_auth.log --year 2026
```

Mirá cómo el worker va imprimiendo las alertas que se disparan en vivo.

## 7. Verificar en Mongo Compass o Atlas

Abrí tu cluster `grupo4_db`:
- Colección `events`: 29 documentos.
- Colección `alerts`: 7 documentos (6 bruteforce + 1 offhours).

Un documento de alerta se ve así:
```json
{
  "rule_id": "bruteforce_v1",
  "fired_at": ISODate("..."),
  "severity": "critical",
  "title": "Posible fuerza bruta desde 203.0.113.5",
  "evidence": {
    "ip": "203.0.113.5",
    "user": "root",
    "fails": 5,
    "window_sec": 600,
    "event_ids": [...]
  },
  "status": "open"
}
```

## Comandos útiles para debuggear

```bash
# Ver cuántos mensajes hay en el stream
redis-cli XLEN grupo4:auditalog:ingest

# Ver los últimos 2 mensajes
redis-cli XRANGE grupo4:auditalog:ingest - + COUNT 2

# Ver contadores de bruteforce activos
redis-cli KEYS "grupo4:auditalog:bruteforce:*"
redis-cli GET grupo4:auditalog:bruteforce:203.0.113.5

# Ver top IPs sospechosas
redis-cli ZREVRANGE grupo4:auditalog:suspicious:ips 0 10 WITHSCORES

# Resetear todo (sin FLUSHALL)
redis-cli DEL grupo4:auditalog:ingest
```
