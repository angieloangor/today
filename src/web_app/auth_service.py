import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

import psycopg

from web_app import security
from web_app.database import get_connection


TOTP_PERIOD = 30
TOTP_DIGITS = 6
ISSUER = "Today"


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


def hash_password(password: str) -> str:
    return security.hash_password(password)


def create_user(name: str, email: str, password_hash: str, totp_secret: str) -> bool:
    normalized_email = email.strip().lower()
    ciphertext, nonce = security.encrypt_totp_secret(totp_secret, normalized_email)
    try:
        with get_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    email,
                    full_name,
                    password_hash,
                    totp_secret_ciphertext,
                    totp_secret_nonce
                )
                VALUES (%s, %s, %s, %s, %s)
                """,
                (normalized_email, name.strip(), password_hash, ciphertext, nonce),
            )
    except psycopg.errors.UniqueViolation:
        return False
    return True


def authenticate(email: str, password: str, otp_code: str) -> dict[str, str] | None:
    normalized_email = email.strip().lower()
    with get_connection() as connection:
        user = connection.execute(
            """
            SELECT email, full_name, password_hash,
                   totp_secret_ciphertext, totp_secret_nonce
            FROM users
            WHERE email = %s
            """,
            (normalized_email,),
        ).fetchone()

    # Se verifica la contraseña aunque el usuario no exista (mismo tiempo de respuesta).
    if not security.verify_password(password, user["password_hash"] if user else None):
        return None
    totp_secret = security.decrypt_totp_secret(
        user["totp_secret_ciphertext"], user["totp_secret_nonce"], user["email"]
    )
    if not verify_totp(totp_secret, otp_code):
        return None
    return {"name": user["full_name"], "email": user["email"]}
