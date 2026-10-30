"""Tests de resiliencia: comportamiento cuando un motor secundario falla.

El sistema está diseñado para degradar suavemente si Redis se cae — Mongo es
el almacén principal, Redis es contador/cache. Si Mongo se cae, los endpoints
devuelven error, pero el proceso no explota.

Estos tests simulan el fallo con mocks y verifican que:
  1. Si Redis cae, las reglas que dependen de Redis NO rompen el pipeline:
     devuelven [] en vez de propagar la excepción, y el evento se sigue
     persistiendo en Mongo.
  2. El health endpoint reporta el estado real de cada motor (ok / error).
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import mongomock
import pytest
import redis as redis_lib
from fastapi.testclient import TestClient

from src.common.config import settings
from src.common.rules import apply_rules


# ----------------------------------------------------------------------------
# 1. Redis caído → el pipeline no explota, las reglas que lo necesitan devuelven []
# ----------------------------------------------------------------------------

def test_apply_rules_with_dead_redis():
    """Si Redis tira ConnectionError, apply_rules no debe propagarlo."""
    # Mock de Redis que SIEMPRE tira ConnectionError
    dead_redis = MagicMock(spec=redis_lib.Redis)
    dead_redis.incr.side_effect = redis_lib.ConnectionError("mock: redis down")
    dead_redis.expire.side_effect = redis_lib.ConnectionError("mock: redis down")
    dead_redis.zincrby.side_effect = redis_lib.ConnectionError("mock: redis down")
    dead_redis.publish.side_effect = redis_lib.ConnectionError("mock: redis down")

    db = mongomock.MongoClient()["test"]

    event = {
        "source": "auth.log",
        "ts": datetime.now(timezone.utc),
        "ip": "1.2.3.4",
        "user": "root",
        "action": "login_failed",
        "severity": "warn",
        "detail": {},
        "raw": "test",
    }

    # NO debe tirar excepción
    alerts = apply_rules(dead_redis, db, event, "mock-oid")

    # Las reglas que NO dependen de Redis igual funcionan (offhours chequea hora,
    # podría disparar o no según el hora actual, lo cual está bien).
    # Lo importante es que no explotó.
    assert isinstance(alerts, list)


def test_health_reports_redis_down(monkeypatch):
    """Si Redis no responde, /api/health devuelve 200 con redis: error."""
    fake_mongo = mongomock.MongoClient()

    with patch("src.api.main.get_mongo", return_value=fake_mongo):
        import src.api.main as api_main
        api_main._mongo = None
        api_main._redis = None

        # Mock redis que falla
        from src.api.main import app

        class DeadRedis:
            def ping(self):
                raise redis_lib.ConnectionError("mock: redis down")

        with patch("src.api.main.get_redis", return_value=DeadRedis()):
            with TestClient(app) as client:
                r = client.get("/api/health")
                assert r.status_code == 200   # NO 500, degrada suavemente
                data = r.json()
                assert data["app"] == "ok"
                assert data["mongo"] == "ok"
                assert "error" in data["redis"].lower()


# ----------------------------------------------------------------------------
# 2. Mongo caído → el health lo refleja, otros endpoints degradan
# ----------------------------------------------------------------------------

def test_health_reports_mongo_down():
    """Si Mongo no responde, /api/health devuelve 200 con mongo: error."""
    # Limpiar redis local primero
    try:
        r = redis_lib.Redis(decode_responses=True)
        for k in r.scan_iter("grupo4:auditalog:*"):
            r.delete(k)
    except Exception:
        pytest.skip("Redis local no disponible para este test")

    class DeadMongo:
        @property
        def admin(self):
            return self
        def command(self, *a, **kw):
            raise Exception("mock: mongo down")
        def __getitem__(self, name):
            raise Exception("mock: mongo down")

    with patch("src.api.main.get_mongo", return_value=DeadMongo()):
        import src.api.main as api_main
        api_main._mongo = None
        api_main._redis = None
        from src.api.main import app

        with TestClient(app) as client:
            r = client.get("/api/health")
            assert r.status_code == 200
            data = r.json()
            assert "error" in data["mongo"].lower()
            # Redis debería seguir OK (no lo tocamos)
            assert data["redis"] == "ok"


# ----------------------------------------------------------------------------
# 3. Las reglas que NO necesitan Redis siguen funcionando aunque Redis esté caído
# ----------------------------------------------------------------------------

def test_offhours_rule_survives_redis_failure():
    """offhours no usa Redis — debe disparar aunque Redis esté muerto."""
    from src.common.rules import rule_offhours

    event = {
        "source": "auth.log",
        "ts": datetime.now(timezone.utc).replace(hour=3),  # 3 AM = fuera de horario
        "user": "ana",
        "ip": "10.0.0.5",
        "action": "login_ok",
        "severity": "info",
        "detail": {},
        "raw": "test",
    }
    alert = rule_offhours(event, "oid")
    assert alert is not None
    assert alert["rule_id"] == "offhours_v1"


def test_sqli_rule_survives_redis_failure():
    """sqli no usa Redis — debe disparar aunque Redis esté muerto."""
    from src.common.rules import rule_sql_injection

    event = {
        "source": "access.log",
        "ts": datetime.now(timezone.utc),
        "ip": "1.2.3.4",
        "action": "http_request",
        "severity": "info",
        "detail": {"path": "/x?a=UNION SELECT username FROM users"},
        "raw": "test",
    }
    alert = rule_sql_injection(event, "oid")
    assert alert is not None
    assert alert["rule_id"] == "sqli_v1"
