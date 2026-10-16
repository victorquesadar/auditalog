# Pasos para hoy · Viernes 16-oct 2026 · Seguimiento 1

**Cierre:** 6:00 p.m. hora Costa Rica (tag `v0.1.0` creado y bitácora subida).
**Reunión en Teams:** 6:00 p.m. en adelante (horario rotativo del profesor).

> **Idea general**
> Un solo integrante crea el repo y sube la base. Los otros tres clonan, hacen
> **cada uno su commit propio** (requisito del seguimiento), y entre todos abren
> los issues del backlog. Al final el líder crea el tag y revisa que todo esté
> en su sitio.

---

## 🔖 Convención de nombres para esta guía

| Nombre | Rol | Responsable S2 |
|---|---|---|
| **Integrante A** | Líder / Backend-Mongo | CRUD + validación JSON Schema |
| **Integrante B** | Workers / Redis | Colector + worker de ingesta |
| **Integrante C** | API / Dashboard | Página /eventos |
| **Integrante D** | SQLite / Datos | Script de carga Loghub |

Repartan los roles entre ustedes antes de empezar; no importa el orden.

---

## PASO 0 · Antes de empezar (los 4, 5 min)

- [ ] Confirmar en Teams quién es A, B, C, D.
- [ ] Todos tienen cuenta de GitHub y están logueados.
- [ ] Confirmar hora de la reunión con el profesor (6:00pm o la que les toque).
- [ ] Instalar git si no lo tienen: https://git-scm.com/downloads

---

## PASO 1 · Integrante A · Crear el repo (10 min)

1. Entrar a https://github.com/new
2. Datos:
   - **Owner:** cuenta personal o una org del grupo.
   - **Repository name:** `auditalog`
   - **Description:** `Bitácora de auditoría de accesos y cambios de configuración para PYMEs — Grupo 04, Tópicos Avanzados de BD, UNA`
   - **Public** ✅ (requisito del enunciado)
   - **Add a README file:** ❌ (lo subimos nosotros)
   - **Add .gitignore:** None
   - **License:** None (ya la subimos nosotros)
3. Click **Create repository**.
4. Copiar la URL (ej. `https://github.com/<usuario>/auditalog.git`).
5. En la terminal, ir a la carpeta donde está el proyecto que les armó Claude y:

   ```bash
   cd auditalog
   git init
   git add .
   git commit -m "chore: estructura inicial del proyecto (S1)"
   git branch -M main
   git remote add origin https://github.com/<usuario>/auditalog.git
   git push -u origin main
   ```

---

## PASO 2 · Integrante A · Agregar colaboradores (3 min)

1. En el repo → **Settings** → **Collaborators** → **Add people**.
2. Agregar los usuarios GitHub de **B, C y D**.
3. Enviar las invitaciones por Teams para que acepten en el momento.

---

## PASO 3 · Integrante A · Crear milestones y labels (5 min)

### Milestones
Issues → Milestones → **New milestone** para cada uno:
- `S1 · Semana 13` · due date 2026-10-16
- `S2 · Semana 14` · due date 2026-10-23
- `S3 · Semana 15` · due date 2026-10-30
- `S4 · Semana 16` · due date 2026-11-06

### Labels (crear si no existen)
`feat`, `chore`, `docs`, `test`, `process`, `bug`,
`area:collectors`, `area:workers`, `area:api`, `area:mongo`, `area:sqlite`, `area:data`,
`milestone:S1`, `milestone:S2`, `milestone:S3`, `milestone:S4`.

---

## PASO 4 · Integrantes B, C, D · Clonar y hacer su commit propio (10 min cada uno, en paralelo)

Cada uno abre su terminal:

```bash
git clone https://github.com/<usuario>/auditalog.git
cd auditalog
```

Luego cada uno edita el `README.md` en la **sección 8 "Integrantes"** y pone su nombre y su usuario GitHub en la fila que le corresponde.

```bash
git checkout -b docs/add-<tu-nombre>
# edita README.md con tu editor favorito
git add README.md
git commit -m "docs: agrega nombre y GitHub de <TuNombre>"
git push -u origin docs/add-<tu-nombre>
```

Después, cada uno abre un **Pull Request** desde su rama hacia `main` y lo hace **merge** (puede ser auto-merge, con mensaje "docs: add <nombre>"). Esto garantiza que **los 4 tengan commits propios en el historial**, que es exactamente lo que el profesor revisa.

> ⚠️ Si prefieren rapidez: cada uno puede editar el README **directamente desde github.com** usando el botón ✏️ ("Edit this file"), y confirmar como commit a `main` o a una rama con PR. Igual queda registrado como commit suyo.

---

## PASO 5 · Entre todos · Crear los issues del backlog (15 min)

Abrir `docs/backlog-issues.md` y crear **cada bloque como un issue** en GitHub:

1. **Issues del milestone S1** (del #1 al #6) → **cerrarlos de una** porque ya están hechos. Esto sirve de evidencia al profesor de que la lista de la semana se cumplió.
2. **Issues del milestone S2** (del #7 al #14) → dejar **abiertos**, con **responsable asignado** (A, B, C o D) y **milestone S2**.
3. Los milestones S3 y S4 se crean como ya está, pero sus issues se abren más adelante.

Reparto sugerido:
- Integrante A crea #1, #2, #9, #10
- Integrante B crea #3, #7, #8
- Integrante C crea #4, #11, #14
- Integrante D crea #5, #6, #12, #13

Así vuelve a quedar historial de participación en issues también.

---

## PASO 6 · Integrante A · Opcional pero recomendado · Probar los smoke tests (10 min)

Si tienen Python 3.11+ a mano y pueden crear credenciales de Mongo Atlas y Redis **ya hoy**:

```bash
python -m venv .venv
source .venv/bin/activate            # Linux/Mac
# .venv\Scripts\activate             # Windows
pip install -r requirements.txt
cp .env.example .env
# editar .env con MONGO_URI, REDIS_HOST, etc.
python scripts/hello_all.py
```

Si no les da tiempo, no bloquea el seguimiento 1: basta con que el **código de los scripts esté en el repo** y lo expliquen oralmente. La conexión real queda para la demo de S2.

---

## PASO 7 · Entre todos · Revisar la bitácora S1 (5 min)

Abrir `docs/seguimientos/S1.md` y:
- [ ] Reemplazar `A`, `B`, `C`, `D` por los nombres reales en la sección 5 (Responsables S2).
- [ ] Marcar los nombres también en la sección 6 (Participación).
- [ ] Verificar que los enlaces del final (repo, próxima reunión) sean correctos.

Commit:

```bash
git add docs/seguimientos/S1.md
git commit -m "docs: completa nombres en bitácora S1"
git push
```

---

## PASO 8 · Integrante A · Crear el tag v0.1.0 (3 min) — ANTES DE LAS 6PM

Opción 1 (desde consola):

```bash
git tag -a v0.1.0 -m "Seguimiento 1 — estructura, arquitectura y modelo de datos"
git push origin v0.1.0
```

Opción 2 (desde web): repo → **Releases** → **Create a new release** → Tag `v0.1.0` → Title "v0.1.0 — Seguimiento 1" → en la descripción, pegar la sección `[0.1.0]` del `CHANGELOG.md` → **Publish release**.

---

## PASO 9 · Los 4 · Reunión en Teams (6:00pm — 20 min máx)

Formato que pide el profesor:
- **5 min de demo** del avance: enseñar el repo, el README, el diagrama, los scripts.
- **5 min de revisión** del repo y preguntas del profesor.
- **5 min de retroalimentación** y acuerdos para S2.

Preparar antes:
- Pantalla compartida lista con el repo abierto.
- `docs/arquitectura/arquitectura-v1.md` abierto en una pestaña.
- `docs/seguimientos/S1.md` abierto en otra.
- Cada quien debe poder explicar su parte (eso vale 15% individual del seguimiento).
- **Cámara encendida los 4.**

Posibles preguntas del profesor y respuesta corta:
- *"¿Qué dato vive en cada motor?"* → tabla de la §4 del README.
- *"¿Qué pasa si Redis cae?"* → §4 de `arquitectura-v1.md` (buffer local + Mongo sigue sirviendo histórico).
- *"¿Dónde está el prefijo de Redis?"* → `.env.example` → `REDIS_PREFIX=grupo4:auditalog:`.
- *"¿Qué van a medir en S3?"* → mínimo 3 operaciones × ≥3 corridas, mediana reportada (ver bitácora, backlog #20).

---

## ✅ Checklist final antes de las 6pm

Repasar antes de la reunión:

- [ ] Repo público en GitHub con nombre `auditalog`.
- [ ] Licencia MIT visible en el repo.
- [ ] `.gitignore` y `.env.example` subidos. No hay `.env` real.
- [ ] Los 4 integrantes aparecen como colaboradores.
- [ ] Los 4 tienen al menos 1 commit propio en el historial.
- [ ] README con problema, usuario, alcance del MVP.
- [ ] `docs/arquitectura/arquitectura-v1.md` publicado.
- [ ] `docs/arquitectura/modelo-datos-v1.md` publicado.
- [ ] `scripts/hello_mongo.py`, `hello_redis.py`, `hello_sqlite.py` en el repo.
- [ ] Issues creados y repartidos entre los 4; milestones S1–S4.
- [ ] Issues de S1 cerrados.
- [ ] `docs/seguimientos/S1.md` subido con nombres reales.
- [ ] Tag `v0.1.0` creado y publicado como Release.
- [ ] Los 4 están en Teams a la hora, con cámara.

---

## Si algo sale mal

| Problema | Qué hacer |
|---|---|
| No alcanzamos a crear Atlas / Redis hoy | Dejar los scripts en el repo y decir en la reunión que la conexión real se demostrará en S2. No se pierde S1 por eso. |
| Un integrante no puede conectarse a la reunión | Avisar al profesor **antes de las 6pm** por mensaje. Esa persona pierde el 15% individual del S1 pero el grupo mantiene el resto. |
| GitHub pide verificar email para colaboradores | Que cada uno verifique su correo de GitHub en https://github.com/settings/emails antes del paso 2. |
| Nos olvidamos del tag después de las 6pm | Igual crearlo apenas se recuerde y avisar al profesor. El criterio estricto es la hora de subida, pero el tag sin la bitácora puntúa menos. |

---

**Suerte 🙌 — con esto el Seguimiento 1 queda con los 10/10 de la rúbrica si lo exponen bien.**
