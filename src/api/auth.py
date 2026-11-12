"""Autenticación básica con sesión por cookie.

Diseño:
    - UN solo usuario admin, configurado por .env (AUTH_USER / AUTH_PASS).
    - Si AUTH_USER NO está definido → la auth está desactivada (modo dev).
      Útil para que los tests y el desarrollo local sigan funcionando sin login.
    - Sesión por cookie firmada con AUTH_SECRET usando HMAC-SHA256 de la stdlib
      (hmac + hashlib). NO depende de itsdangerous ni passlib.
    - Middleware ASGI que redirige a /login si no está autenticado.
    - Rutas excluidas de auth: /login, /logout, /static/*, /api/health.

Pensado para el despliegue en Virtualmin (donde el sistema queda público).
"""
from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Carga .env si no se cargó ya (idempotente): esto es importante cuando
# auth.py es importado antes que config.py en algún test.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

AUTH_USER = os.getenv("AUTH_USER", "")
AUTH_PASS = os.getenv("AUTH_PASS", "")
# AUTH_SECRET: si no está en .env, derivarlo de AUTH_PASS para que sea ESTABLE
# entre reinicios de uvicorn (incluido --reload). Sin esto, cada arranque
# generaba un secret random y las cookies previas quedaban inválidas,
# forzando al usuario a volver a loguear.
_env_secret = os.getenv("AUTH_SECRET")
if _env_secret:
    AUTH_SECRET = _env_secret
elif AUTH_PASS:
    # Derivamos un secret estable a partir del password + salt fijo del proyecto.
    AUTH_SECRET = sha256(
        (AUTH_PASS + "::auditalog::grupo4::salt").encode()
    ).hexdigest()
else:
    # Modo dev (sin auth): un secret vacío es irrelevante porque el middleware
    # no se activa cuando AUTH_USER/AUTH_PASS no están definidos.
    AUTH_SECRET = "dev-mode-no-auth"

SESSION_COOKIE = "auditalog_session"
SESSION_MAX_AGE = 8 * 3600  # 8 horas

# Rutas que NO requieren login
_PUBLIC_PATHS = {"/login", "/logout", "/api/health"}
_PUBLIC_PREFIXES = ("/static/", "/favicon")


def auth_enabled() -> bool:
    """La auth está activa solo si AUTH_USER y AUTH_PASS están configurados."""
    return bool(AUTH_USER and AUTH_PASS)


def _sign(username: str) -> str:
    """Devuelve una firma HMAC del username con AUTH_SECRET."""
    return hmac.new(AUTH_SECRET.encode(), username.encode(), sha256).hexdigest()


def make_session_value(username: str) -> str:
    """Construye el valor firmado de la cookie de sesión."""
    return f"{username}|{_sign(username)}"


def verify_session_value(value: str) -> Optional[str]:
    """Verifica la cookie y devuelve el username si es válida, None si no."""
    if not value or "|" not in value:
        return None
    user, sig = value.rsplit("|", 1)
    expected = _sign(user)
    if not hmac.compare_digest(sig, expected):
        return None
    return user


def check_credentials(username: str, password: str) -> bool:
    """Verifica usuario y contraseña contra las vars de entorno."""
    if not auth_enabled():
        return False
    return (hmac.compare_digest(username, AUTH_USER)
            and hmac.compare_digest(password, AUTH_PASS))


def get_current_user(request: Request) -> Optional[str]:
    """Devuelve el username del request si está autenticado, None si no."""
    if not auth_enabled():
        return "dev"  # modo abierto
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        return None
    return verify_session_value(cookie)


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware que protege todas las rutas salvo las públicas."""

    async def dispatch(self, request: Request, call_next):
        # Si la auth está desactivada, dejar pasar todo
        if not auth_enabled():
            return await call_next(request)

        path = request.url.path
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Verificar sesión
        user = get_current_user(request)
        if user is None:
            if path.startswith("/api/"):
                return HTMLResponse(
                    '{"detail":"No autenticado. Iniciar sesión en /login"}',
                    status_code=401,
                    media_type="application/json",
                )
            return RedirectResponse(f"/login?next={path}", status_code=303)

        return await call_next(request)


LOGIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Iniciar sesión · AuditaLog</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body style="background:#0f172a; display:flex; align-items:center; justify-content:center; min-height:100vh;">
<div style="background:white; padding:2.5rem; border-radius:12px; box-shadow:0 10px 40px rgba(0,0,0,.4); max-width:380px; width:90%;">
    <h1 style="margin:0 0 .5rem 0; font-size:1.6rem; display:flex; align-items:center; gap:.5rem;">
        🛡️ AuditaLog
    </h1>
    <p class="muted" style="margin:0 0 1.5rem 0; font-size:.9rem;">
        Panel de administración de auditoría. Iniciá sesión para continuar.
    </p>
    {error_html}
    <form method="post" action="/login">
        <input type="hidden" name="next" value="{next}">
        <label style="display:block; margin-bottom:1rem;">
            <span style="display:block; font-size:.75rem; color:#64748b; text-transform:uppercase; font-weight:600; margin-bottom:.25rem;">Usuario</span>
            <input type="text" name="username" required autofocus
                   style="width:100%; padding:.6rem .8rem; border:1px solid #e5e7eb; border-radius:6px; font:inherit;">
        </label>
        <label style="display:block; margin-bottom:1.5rem;">
            <span style="display:block; font-size:.75rem; color:#64748b; text-transform:uppercase; font-weight:600; margin-bottom:.25rem;">Contraseña</span>
            <input type="password" name="password" required
                   style="width:100%; padding:.6rem .8rem; border:1px solid #e5e7eb; border-radius:6px; font:inherit;">
        </label>
        <button type="submit" style="width:100%; padding:.7rem; background:#059669; color:white; border:none; border-radius:6px; font:inherit; font-weight:600; cursor:pointer;">
            Iniciar sesión
        </button>
    </form>
    <p style="margin:1.5rem 0 0 0; font-size:.75rem; color:#94a3b8; text-align:center;">
        AuditaLog v1.0 · Grupo 04
    </p>
</div>
</body>
</html>
"""


def render_login_page(error: Optional[str] = None, next_url: str = "/") -> str:
    err = (
        f'<div style="background:#fee2e2; color:#991b1b; padding:.6rem .8rem; border-radius:6px; margin-bottom:1rem; font-size:.85rem;">{error}</div>'
        if error else ""
    )
    # Evitar interpolación accidental con otros braces
    safe_next = (next_url or "/").replace('"', "&quot;")
    return LOGIN_HTML.replace("{error_html}", err).replace("{next}", safe_next)
