-- Migración desde el esquema de la Fase 12 (tabla users con columna "id").
-- Ejecutar desde la raíz del repo, como administrador:
--   psql -h 192.168.123.21 -U postgres -d today_db -f sql/migrations/002_pii_credito_phi.sql

BEGIN;

ALTER TABLE users RENAME COLUMN id TO user_id;
ALTER SEQUENCE IF EXISTS users_id_seq RENAME TO users_user_id_seq;

ALTER TABLE users
    ALTER COLUMN email TYPE VARCHAR(255),
    ALTER COLUMN full_name TYPE VARCHAR(200),
    ALTER COLUMN totp_secret_ciphertext DROP NOT NULL,
    ALTER COLUMN totp_secret_nonce DROP NOT NULL,
    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_login_attempts >= 0),
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD CONSTRAINT users_totp_pair CHECK (
        (totp_secret_ciphertext IS NULL AND totp_secret_nonce IS NULL)
        OR (totp_secret_ciphertext IS NOT NULL AND octet_length(totp_secret_nonce) = 12)
    );

COMMIT;

-- Crea las tablas nuevas, triggers y permisos (todo es idempotente).
\ir ../schema.sql
