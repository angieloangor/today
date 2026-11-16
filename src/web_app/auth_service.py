import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote, urlencode

import psycopg
from psycopg.rows import dict_row


PASSWORD_ITERATIONS = 600_000
TOTP_PERIOD = 30
TOTP_DIGITS = 6
ISSUER = "Today"


def _connect() -> psycopg.Connection:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL no está definida")
    return psycopg.connect(database_url, row_factory=dict_row)


def initialize_database() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )
            """
        )


def create_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(email: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{email}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": ISSUER,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def _totp_for_counter(secret: str, counter: int) -> str:
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, timestamp: int | None = None) -> bool:
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return False
    counter = (timestamp if timestamp is not None else int(time.time())) // TOTP_PERIOD
    return any(
        hmac.compare_digest(_totp_for_counter(secret, counter + offset), code)
        for offset in (-1, 0, 1)
    )


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()}"


def hash_password(password: str) -> str:
    return _hash_password(password)


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        salt_text, digest_text = encoded_hash.split(":", maxsplit=1)
        salt = base64.b64decode(salt_text)
        expected_digest = base64.b64decode(digest_text)
    except (ValueError, TypeError):
        return False
    actual_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual_digest, expected_digest)


def create_user(name: str, email: str, password_hash: str, totp_secret: str) -> bool:
    try:
        with _connect() as connection:
            connection.execute(
                "INSERT INTO users (email, name, password_hash, totp_secret) VALUES (%s, %s, %s, %s)",
                (email.strip().lower(), name.strip(), password_hash, totp_secret),
            )
    except psycopg.errors.UniqueViolation:
        return False
    return True


def authenticate(email: str, password: str, otp_code: str) -> dict[str, str] | None:
    initialize_database()
    with _connect() as connection:
        user = connection.execute(
            "SELECT email, name, password_hash, totp_secret FROM users WHERE email = %s",
            (email.strip().lower(),),
        ).fetchone()
    if user is None or not _verify_password(password, user["password_hash"]):
        return None
    if not verify_totp(user["totp_secret"], otp_code):
        return None
    return {"name": user["name"], "email": user["email"]}