"""Primitivas de seguridad: hash de contraseñas, política y cifrado del TOTP."""

import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from web_app import config

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
AES_GCM_NONCE_BYTES = 12

# Argon2id con los parámetros recomendados por argon2-cffi (RFC 9106).
password_hasher = PasswordHasher()

# Hash de referencia para igualar el tiempo de respuesta cuando el correo no existe
# y así no revelar qué cuentas están registradas.
_DUMMY_HASH = password_hasher.hash("dummy-password-for-timing")

# Contraseñas muy comunes que se rechazan aunque cumplan la longitud mínima.
_WEAK_PASSWORDS = {
    "123456789012",
    "1234567890123",
    "12345678901234",
    "qwertyuiopas",
    "qwerty123456",
    "password1234",
    "password12345",
    "passwordpassword",
    "contraseña123",
    "contraseña1234",
    "contrasena123",
    "contrasena1234",
    "aaaaaaaaaaaa",
    "abcdefghijkl",
    "abc123abc123",
    "iloveyou1234",
    "administrador",
    "admin1234567",
    "bienvenido123",
    "holamundo123",
    "today1234567",
}


# --- Contraseñas -----------------------------------------------------------


def password_policy_error(password: str, email: str = "", name: str = "") -> str | None:
    """Devuelve un mensaje de error si la contraseña no cumple la política, o None."""
    if len(password) < PASSWORD_MIN_LENGTH:
        return f"La contraseña debe tener al menos {PASSWORD_MIN_LENGTH} caracteres."
    if len(password) > PASSWORD_MAX_LENGTH:
        return f"La contraseña no puede superar {PASSWORD_MAX_LENGTH} caracteres."

    lowered = password.lower()
    if lowered in _WEAK_PASSWORDS or len(set(lowered)) <= 3:
        return "Esa contraseña es demasiado común. Elige otra."

    personal = [email.split("@")[0].lower(), name.strip().lower()]
    if any(len(part) >= 4 and part in lowered for part in personal):
        return "La contraseña no puede contener tu nombre ni tu correo."
    return None


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verifica la contraseña. Con password_hash=None hace el mismo trabajo y falla."""
    try:
        password_hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


# --- Cifrado del secreto TOTP (AES-256-GCM) --------------------------------


def encrypt_totp_secret(secret: str, email: str) -> tuple[bytes, bytes]:
    """Cifra el secreto TOTP. Devuelve (ciphertext, nonce).

    El correo se usa como dato asociado (AAD): el ciphertext queda ligado a esa
    cuenta y no se puede copiar a la fila de otro usuario.
    """
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(config.encryption_key()).encrypt(
        nonce, secret.encode("ascii"), email.encode("utf-8")
    )
    return ciphertext, nonce


def decrypt_totp_secret(ciphertext: bytes, nonce: bytes, email: str) -> str:
    plaintext = AESGCM(config.encryption_key()).decrypt(
        bytes(nonce), bytes(ciphertext), email.encode("utf-8")
    )
    return plaintext.decode("ascii")
