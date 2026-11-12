"""Configuración global de pytest para AuditaLog.

Hace dos cosas:

1. **Fuerza `fakeredis`** si no hay un Redis real escuchando en localhost:6379.
   Así `pytest` corre en una máquina limpia sin tener que levantar Redis
   primero (CI, revisores externos, auditores que prueban el repo).

2. **Autouse fixture `clean_state`** que limpia el estado de Redis antes
   de cada test, para evitar cross-contamination entre tests que usan
   el mismo cliente.
"""
from __future__ import annotations

import os
import socket

import pytest

# ------------------------------------------------------------------
# DESACTIVAR AUTH EN TESTS
# ------------------------------------------------------------------
# Si el .env del desarrollador tiene AUTH_USER/AUTH_PASS (p.ej. para la
# demo), los tests de la API devolverían 401 porque el middleware
# exige login. Forzamos la ausencia de auth ANTES de que auth.py se
# importe por primera vez:
#
#   1. Vaciamos las vars con string vacío. python-dotenv NO sobrescribe
#      vars ya presentes en el ambiente (override=False por defecto),
#      así que el posterior load_dotenv() del proyecto no las repondrá.
#   2. Monkey-patch de load_dotenv a no-op como cinturón-y-tirantes,
#      por si algún módulo llama con override=True.
for _k in ("AUTH_USER", "AUTH_PASS", "AUTH_SECRET"):
    os.environ[_k] = ""

try:
    import dotenv as _dotenv
    _dotenv.load_dotenv = lambda *a, **kw: False  # type: ignore[assignment]
except ImportError:
    pass

# ------------------------------------------------------------------
# DESACTIVAR MMDB REALES EN TESTS
# ------------------------------------------------------------------
# Si el desarrollador descargó GeoLite2 o DB-IP Lite, los tests de
# geoip pueden devolver otros ASN/países más precisos que los del
# dataset embebido (con el que fueron escritos). Apuntamos la ruta de
# MMDB a un directorio vacío para que SIEMPRE caiga al fallback
# embebido durante los tests → resultados reproducibles.
os.environ["AUDITALOG_GEOIP_DIR"] = "/__nonexistent_geoip_dir__"


def _redis_available(host: str = "localhost", port: int = 6379,
                     timeout: float = 0.5) -> bool:
    """Chequea en <0.5s si hay algo escuchando en el puerto de Redis."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


# Si no hay Redis real al arrancar la sesión, parcheamos `redis.Redis` para
# que todas las instancias (incluso las que crea el propio test con
# `redis.Redis(...)` directamente) sean en realidad `fakeredis.FakeRedis`.
# Esto cubre a `get_redis()` y también a tests que instancian su propio
# cliente para limpiar claves.
if not _redis_available():
    os.environ.setdefault("AUDITALOG_USE_FAKEREDIS", "1")
    try:
        import redis as _redis_module
        import fakeredis

        # Un pool global compartido: todas las llamadas devuelven el mismo
        # FakeRedis para que lo que escribe un módulo lo lea otro.
        _shared_fake = fakeredis.FakeRedis(decode_responses=True)

        def _fake_redis_factory(*args, **kwargs):
            # Ignoramos los kwargs — fakeredis ya decidió el "backend".
            return _shared_fake

        _redis_module.Redis = _fake_redis_factory  # type: ignore[assignment]
    except ImportError:
        pass  # sin fakeredis instalado: los tests que necesitan Redis fallarán


@pytest.fixture(autouse=True)
def clean_state():
    """Limpia estado entre tests para evitar que una alerta deduplicada en
    un test contamine al siguiente."""
    # Import diferido para que el env var se propague ANTES.
    try:
        from src.api.main import get_redis
        r = get_redis()
        # Solo limpiamos claves del prefijo del grupo, nunca `flushall`
        # para no pisar un Redis real compartido.
        try:
            keys = list(r.scan_iter("grupo4:auditalog:*"))
            if keys:
                r.delete(*keys)
        except Exception:
            pass
    except Exception:
        pass
    yield
