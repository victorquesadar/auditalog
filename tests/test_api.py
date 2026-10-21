"""Tests de la API FastAPI con Mongo mockeado y Redis real local."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import mongomock
import pytest
import redis as redis_lib
from fastapi.testclient import TestClient

from src.common.config import settings


@pytest.fixture
def client():
    """Monta la API con un Mongo mockeado y limpia Redis antes de cada test."""
    r = redis_lib.Redis(decode_responses=True)
    for k in r.scan_iter("grupo4:auditalog:*"):
        r.delete(k)

    fake_mongo = mongomock.MongoClient()

    with patch("src.api.main.get_mongo", return_value=fake_mongo):
        import src.api.main as api_main
        api_main._mongo = None
        api_main._redis = None

        from src.api.main import app
        with TestClient(app) as c:
            # Seed de datos de prueba en la MISMA BD que lee la API
            db = fake_mongo[settings.mongo_db]
            db.events.insert_many([
                {"source": "auth.log", "ts": datetime.now(timezone.utc),
                 "user": "root", "ip": "1.2.3.4", "action": "login_failed",
                 "severity": "warn", "raw": "fail 1", "detail": {}},
                {"source": "auth.log", "ts": datetime.now(timezone.utc),
                 "user": "ana", "ip": "10.0.0.5", "action": "login_ok",
                 "severity": "info", "raw": "ok", "detail": {}},
                {"source": "access.log", "ts": datetime.now(timezone.utc),
                 "user": None, "ip": "5.6.7.8", "action": "http_request",
                 "severity": "critical", "raw": "500 err", "detail": {"status": 500}},
            ])
            db.alerts.insert_one({
                "rule_id": "bruteforce_v1",
                "fired_at": datetime.now(timezone.utc),
                "severity": "critical",
                "title": "Fuerza bruta desde 1.2.3.4",
                "evidence": {"ip": "1.2.3.4", "fails": 5},
                "status": "open",
            })
            yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["app"] == "ok"
    assert data["mongo"] == "ok"
    assert data["redis"] == "ok"


def test_list_events(client):
    r = client.get("/api/events?limit=10")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3


def test_filter_events_by_severity(client):
    r = client.get("/api/events?severity=critical")
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_filter_events_by_source(client):
    r = client.get("/api/events?source=auth.log")
    assert r.status_code == 200
    assert r.json()["total"] == 2


def test_list_alerts(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 1
    assert data["items"][0]["rule_id"] == "bruteforce_v1"


def test_dashboard_endpoint(client):
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert data["events_total"] == 3
    assert data["alerts_open"] == 1
    assert data["alerts_critical"] == 1
    assert "top_ips" in data

    r2 = client.get("/api/dashboard")
    assert r2.headers.get("x-cache") == "HIT"


def test_ingest_endpoint(client):
    r = client.post("/api/ingest", json={
        "source": "app",
        "action": "user_login",
        "user": "test",
        "ip": "127.0.0.1",
        "severity": "info",
        "detail": {"from_api": True},
    })
    assert r.status_code == 202
    data = r.json()
    assert data["accepted"] is True
    assert "stream_id" in data

    r2 = redis_lib.Redis(decode_responses=True)
    assert r2.xlen("grupo4:auditalog:ingest") == 1


def test_html_pages_render(client):
    for path in ("/", "/eventos", "/alertas"):
        r = client.get(path)
        assert r.status_code == 200
        assert "AuditaLog" in r.text


def test_ingest_rejects_invalid_severity(client):
    r = client.post("/api/ingest", json={
        "source": "app",
        "action": "x",
        "severity": "invalid-level",
    })
    assert r.status_code == 422
