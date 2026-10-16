"""Carga de configuración desde .env. Importar desde cualquier módulo."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    # Mongo
    mongo_uri: str = os.getenv("MONGO_URI", "")
    mongo_db: str = os.getenv("MONGO_DB", "auditalog")

    # Redis
    redis_host: str = os.getenv("REDIS_HOST", "localhost")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))
    redis_password: str | None = os.getenv("REDIS_PASSWORD") or None
    redis_db: int = int(os.getenv("REDIS_DB", "0"))
    redis_prefix: str = os.getenv("REDIS_PREFIX", "grupo4:auditalog:")

    # App
    app_host: str = os.getenv("APP_HOST", "0.0.0.0")
    app_port: int = int(os.getenv("APP_PORT", "8000"))

    # Reglas
    bruteforce_window_sec: int = int(os.getenv("RULE_BRUTEFORCE_WINDOW_SEC", "600"))
    bruteforce_max_fails: int = int(os.getenv("RULE_BRUTEFORCE_MAX_FAILS", "5"))
    offhours_start: int = int(os.getenv("RULE_OFFHOURS_START", "22"))
    offhours_end: int = int(os.getenv("RULE_OFFHOURS_END", "6"))


settings = Settings()


def key(*parts: str) -> str:
    """Construye una clave Redis con el prefijo del grupo."""
    return settings.redis_prefix + ":".join(parts)
