"""Configuración leída exclusivamente de variables de entorno.

Ningún secreto (contraseña de PostgreSQL, clave de cifrado) vive en el repo.
"""

import base64
import os
import secrets

ENCRYPTION_KEY_BYTES = 32  # AES-256


class ConfigError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Falta la variable de entorno {name}")
    return value


def db_conninfo() -> dict[str, str]:
    """Parámetros de conexión para psycopg.connect(**db_conninfo())."""
    return {
        "host": _require("DB_HOST"),
        "port": os.environ.get("DB_PORT", "5432"),
        "dbname": _require("DB_NAME"),
        "user": _require("DB_USER"),
        "password": _require("DB_PASSWORD"),
    }


def encryption_key() -> bytes:
    """Clave AES-256 (32 bytes) para cifrar PII/TOTP, desde APP_ENCRYPTION_KEY."""
    raw = _require("APP_ENCRYPTION_KEY")
    try:
        key = base64.urlsafe_b64decode(raw)
    except ValueError as exc:
        raise ConfigError("APP_ENCRYPTION_KEY no es base64 válido") from exc
    if len(key) != ENCRYPTION_KEY_BYTES:
        raise ConfigError(
            f"APP_ENCRYPTION_KEY debe decodificar a {ENCRYPTION_KEY_BYTES} bytes"
        )
    return key


def generate_encryption_key() -> str:
    """Genera una clave criptográficamente segura en base64 url-safe."""
    return base64.urlsafe_b64encode(secrets.token_bytes(ENCRYPTION_KEY_BYTES)).decode()


def main() -> None:
    print(generate_encryption_key())


if __name__ == "__main__":
    main()
