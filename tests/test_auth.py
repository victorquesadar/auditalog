"""Tests de la autenticación opcional (cookie firmada)."""
from __future__ import annotations

import os
from unittest.mock import patch

import mongomock
import pytest
import redis as redis_lib
from fastapi.testclient import TestClient


@pytest.fixture
def auth_client(monkeypatch):
    """Cliente con auth activa."""
    # Set env vars antes de que se importe auth.py
    monkeypatch.setenv("AUTH_USER", "admin")
    monkeypatch.setenv("AUTH_PASS", "s3cret")
    monkeypatch.setenv("AUTH_SECRET", "test-secret-for-hmac")

    # Recargar el módulo auth para que tome las env vars
    import importlib
    from src.api import auth as auth_module
    importlib.reload(auth_module)
    from src.api import main as main_module
    importlib.reload(main_module)

    r = redis_lib.Redis(decode_responses=True)
    for k in r.scan_iter("grupo4:auditalog:*"):
        r.delete(k)

    fake_mongo = mongomock.MongoClient()
    with patch("src.api.main.get_mongo", return_value=fake_mongo):
        main_module._mongo = None
        main_module._redis = None
        with TestClient(main_module.app, follow_redirects=False) as c:
            yield c

    # Limpiar para no afectar a otros tests
    monkeypatch.delenv("AUTH_USER", raising=False)
    monkeypatch.delenv("AUTH_PASS", raising=False)
    importlib.reload(auth_module)
    importlib.reload(main_module)


def test_auth_redirect_to_login_when_not_authenticated(auth_client):
    r = auth_client.get("/")
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_login_page_renders(auth_client):
    r = auth_client.get("/login")
    assert r.status_code == 200
    assert "Iniciar sesión" in r.text or "Usuario" in r.text


def test_login_wrong_password(auth_client):
    r = auth_client.post(
        "/login",
        data={"username": "admin", "password": "wrong", "next": "/"},
    )
    assert r.status_code == 401
    assert "Usuario o contraseña incorrectos" in r.text


def test_login_success_sets_cookie_and_redirects(auth_client):
    r = auth_client.post(
        "/login",
        data={"username": "admin", "password": "s3cret", "next": "/"},
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    cookies = r.cookies
    assert "auditalog_session" in cookies


def test_authenticated_request_succeeds(auth_client):
    # Login
    r = auth_client.post(
        "/login",
        data={"username": "admin", "password": "s3cret", "next": "/"},
    )
    cookie = r.cookies.get("auditalog_session")
    assert cookie

    # Request con cookie
    r = auth_client.get("/", cookies={"auditalog_session": cookie})
    # No redirige (status != 303)
    assert r.status_code == 200


def test_logout_clears_cookie(auth_client):
    r = auth_client.post(
        "/login",
        data={"username": "admin", "password": "s3cret", "next": "/"},
    )
    cookie = r.cookies.get("auditalog_session")

    r2 = auth_client.get("/logout", cookies={"auditalog_session": cookie})
    assert r2.status_code == 303
    assert r2.headers["location"] == "/login"


def test_health_endpoint_is_public(auth_client):
    """/api/health NO requiere login para que monitoreo externo funcione."""
    r = auth_client.get("/api/health")
    assert r.status_code == 200


def test_static_files_are_public(auth_client):
    """Los archivos estáticos no requieren login."""
    r = auth_client.get("/static/style.css")
    # 200 o 404 (si no existe), pero NUNCA 303 a login
    assert r.status_code != 303


def test_api_returns_401_json_not_redirect(auth_client):
    """Las rutas /api/ sin auth devuelven 401, no redirect (para apps cliente)."""
    r = auth_client.get("/api/events")
    assert r.status_code == 401
