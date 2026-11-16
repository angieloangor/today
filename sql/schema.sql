-- Esquema de la base de datos today_db (PostgreSQL).
-- Se ejecuta una sola vez con un usuario administrador, no desde la app:
--   psql -h 192.168.123.21 -U postgres -d today_db -f sql/schema.sql

CREATE TABLE IF NOT EXISTS users (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email                   TEXT        NOT NULL UNIQUE
                                        CHECK (email = lower(email)),
    full_name               TEXT        NOT NULL
                                        CHECK (length(full_name) BETWEEN 1 AND 200),
    -- Hash Argon2id ($argon2id$v=19$m=...), nunca la contraseña en claro.
    password_hash           TEXT        NOT NULL
                                        CHECK (password_hash LIKE '$argon2id$%'),
    -- Secreto TOTP cifrado con AES-256-GCM. La clave NO está en la base de datos.
    totp_secret_ciphertext  BYTEA       NOT NULL,
    totp_secret_nonce       BYTEA       NOT NULL
                                        CHECK (octet_length(totp_secret_nonce) = 12),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Mínimo privilegio: la app solo lee e inserta usuarios; no puede crear ni
-- borrar tablas.
GRANT SELECT, INSERT ON users TO today_app;
