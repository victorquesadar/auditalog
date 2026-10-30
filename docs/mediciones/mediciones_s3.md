# Mediciones · Seguimiento 3

**Fecha:** 2026-10-30 02:25 UTC  
**Entorno:** Python 3.12.10 · Mongo Atlas · Redis local  
**Scripts:** `scripts/benchmarks.py` · reproducible con `python scripts/benchmarks.py --all`

Los datos crudos (todas las corridas) están en [`raw.json`](raw.json).

---

## Resumen

| Operación | Baseline (mediana) | Optimizado (mediana) | Mejora |
|---|---|---|---|
| Mongo insert (5000 docs) | 11527.5 ms sin índice | 13400.4 ms con índice | +16.2% |
| Dashboard | 733.439 ms sin caché | 1.061 ms con caché | -99.9% |
| SQLite query (5000 filas) | 1.65 ms sin índice | 1.34 ms con índice | -18.9% |


## 1. Mongo — Inserción masiva (5000 eventos)

| | Mediana | Corridas (ms) |
|---|---|---|
| **Sin índice** | 11527.5 ms | 13096.69, 11527.48, 10864.77 |
| **Con índice en `ts`** | 13400.4 ms | 9848.67, 13400.44, 14167.50 |

**Interpretación:** el índice no mejora significativamente la inserción. Esto es esperable: los índices benefician a los SELECT y WHERE, no al INSERT (de hecho pueden penalizarlo porque hay que mantener el índice).


## 2. Dashboard — con/sin caché Redis

| | Mediana | Corridas (ms) |
|---|---|---|
| **Sin caché** (recomputa aggregation) | 733.439 ms | 2761.59, 691.18, 733.44 |
| **Con caché** (GET de Redis) | 1.061 ms | 1.11, 1.06, 1.02 |

**Interpretación:** la caché reduce la latencia **691.3×**. El TTL de 30 s nos da un buen compromiso entre frescura y carga de Mongo.


## 3. SQLite — Query con/sin índice compuesto `(ip, ts)` (5000 filas)

| | Mediana | Corridas (ms) |
|---|---|---|
| **Sin índice** | 1.65 ms | 1.65, 1.66, 1.46 |
| **Con índice `(ip, ts)`** | 1.34 ms | 1.34, 1.63, 1.11 |

**EXPLAIN QUERY PLAN:**

Sin índice:
```
2 0 216 SCAN events
```

Con índice:
```
3 0 50 SEARCH events USING INDEX idx_ip_ts (ip=? AND ts>?)
```

**Interpretación:** sin índice SQLite hace **SCAN** de toda la tabla (recorre las N filas). Con el índice compuesto hace **SEARCH USING INDEX**, lee solo las filas que matchean.


---

## Metodología

- Cada prueba corre **3 veces** y reporta la **mediana** para evitar outliers.
- Entre corridas se limpia caché / tabla para igualar condiciones iniciales.
- El dataset es sintético pero representativo de la volumetría objetivo (10k-100k eventos).
- El código del benchmark está versionado para que cualquiera lo reproduzca.
