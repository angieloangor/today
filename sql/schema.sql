-- Esquema de la base de datos today_db (PostgreSQL).
-- Se ejecuta una sola vez con un usuario administrador, no desde la app:
--   psql -h 192.168.123.21 -U postgres -d today_db -f sql/schema.sql
--
-- Si la base ya tiene la tabla users de la Fase 12, usa en su lugar:
--   sql/migrations/002_pii_credito_phi.sql
--
-- Regla general: todo campo sensible se guarda como <campo>_ciphertext +
-- <campo>_nonce (AES-256-GCM, nonce de 12 bytes). La clave AES vive solo en el
-- webserver (APP_ENCRYPTION_KEY): ni en la base de datos ni en GitHub.

BEGIN;

-- ---------------------------------------------------------------------------
-- updated_at automático
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- users: autenticación
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id BIGSERIAL PRIMARY KEY,

    email VARCHAR(255) NOT NULL UNIQUE
        CHECK (email = lower(email)),
    full_name VARCHAR(200) NOT NULL
        CHECK (length(full_name) >= 1),

    -- Hash Argon2id ($argon2id$v=19$m=...), nunca la contraseña en claro.
    password_hash TEXT NOT NULL
        CHECK (password_hash LIKE '$argon2id$%'),

    totp_secret_ciphertext BYTEA,
    totp_secret_nonce BYTEA,

    failed_login_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT users_totp_pair CHECK (
        (totp_secret_ciphertext IS NULL AND totp_secret_nonce IS NULL)
        OR (totp_secret_ciphertext IS NOT NULL AND octet_length(totp_secret_nonce) = 12)
    )
);

-- ---------------------------------------------------------------------------
-- user_pii: datos personales (1 fila por usuario)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_pii (
    user_id BIGINT PRIMARY KEY
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    phone_ciphertext BYTEA,
    phone_nonce BYTEA,

    document_type VARCHAR(30),

    document_number_ciphertext BYTEA,
    document_number_nonce BYTEA,

    birth_date_ciphertext BYTEA,
    birth_date_nonce BYTEA,

    address_ciphertext BYTEA,
    address_nonce BYTEA,

    city VARCHAR(100),
    country VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT user_pii_phone_pair CHECK (
        (phone_ciphertext IS NULL AND phone_nonce IS NULL)
        OR (phone_ciphertext IS NOT NULL AND octet_length(phone_nonce) = 12)),
    CONSTRAINT user_pii_document_pair CHECK (
        (document_number_ciphertext IS NULL AND document_number_nonce IS NULL)
        OR (document_number_ciphertext IS NOT NULL AND octet_length(document_number_nonce) = 12)),
    CONSTRAINT user_pii_birth_date_pair CHECK (
        (birth_date_ciphertext IS NULL AND birth_date_nonce IS NULL)
        OR (birth_date_ciphertext IS NOT NULL AND octet_length(birth_date_nonce) = 12)),
    CONSTRAINT user_pii_address_pair CHECK (
        (address_ciphertext IS NULL AND address_nonce IS NULL)
        OR (address_ciphertext IS NOT NULL AND octet_length(address_nonce) = 12))
);

-- ---------------------------------------------------------------------------
-- credit_profiles: datos crediticios
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS credit_profiles (
    credit_profile_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    credit_score INTEGER,

    monthly_income_ciphertext BYTEA,
    monthly_income_nonce BYTEA,

    total_debt_ciphertext BYTEA,
    total_debt_nonce BYTEA,

    credit_limit_ciphertext BYTEA,
    credit_limit_nonce BYTEA,

    credit_status VARCHAR(20)
        CHECK (
            credit_status IN (
                'GOOD',
                'STANDARD',
                'POOR',
                'UNKNOWN'
            )
        ),

    risk_level VARCHAR(30),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT credit_income_pair CHECK (
        (monthly_income_ciphertext IS NULL AND monthly_income_nonce IS NULL)
        OR (monthly_income_ciphertext IS NOT NULL AND octet_length(monthly_income_nonce) = 12)),
    CONSTRAINT credit_debt_pair CHECK (
        (total_debt_ciphertext IS NULL AND total_debt_nonce IS NULL)
        OR (total_debt_ciphertext IS NOT NULL AND octet_length(total_debt_nonce) = 12)),
    CONSTRAINT credit_limit_pair CHECK (
        (credit_limit_ciphertext IS NULL AND credit_limit_nonce IS NULL)
        OR (credit_limit_ciphertext IS NOT NULL AND octet_length(credit_limit_nonce) = 12))
);

CREATE INDEX IF NOT EXISTS credit_profiles_user_id_idx ON credit_profiles (user_id);

-- ---------------------------------------------------------------------------
-- health_information: PHI
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS health_information (
    health_record_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    medical_record_number_ciphertext BYTEA,
    medical_record_number_nonce BYTEA,

    health_condition_ciphertext BYTEA,
    health_condition_nonce BYTEA,

    medication_ciphertext BYTEA,
    medication_nonce BYTEA,

    insurance_number_ciphertext BYTEA,
    insurance_number_nonce BYTEA,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT health_mrn_pair CHECK (
        (medical_record_number_ciphertext IS NULL AND medical_record_number_nonce IS NULL)
        OR (medical_record_number_ciphertext IS NOT NULL AND octet_length(medical_record_number_nonce) = 12)),
    CONSTRAINT health_condition_pair CHECK (
        (health_condition_ciphertext IS NULL AND health_condition_nonce IS NULL)
        OR (health_condition_ciphertext IS NOT NULL AND octet_length(health_condition_nonce) = 12)),
    CONSTRAINT health_medication_pair CHECK (
        (medication_ciphertext IS NULL AND medication_nonce IS NULL)
        OR (medication_ciphertext IS NOT NULL AND octet_length(medication_nonce) = 12)),
    CONSTRAINT health_insurance_pair CHECK (
        (insurance_number_ciphertext IS NULL AND insurance_number_nonce IS NULL)
        OR (insurance_number_ciphertext IS NOT NULL AND octet_length(insurance_number_nonce) = 12))
);

CREATE INDEX IF NOT EXISTS health_information_user_id_idx ON health_information (user_id);

-- ---------------------------------------------------------------------------
-- Triggers updated_at
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS users_set_updated_at ON users;
CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS user_pii_set_updated_at ON user_pii;
CREATE TRIGGER user_pii_set_updated_at BEFORE UPDATE ON user_pii
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS credit_profiles_set_updated_at ON credit_profiles;
CREATE TRIGGER credit_profiles_set_updated_at BEFORE UPDATE ON credit_profiles
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS health_information_set_updated_at ON health_information;
CREATE TRIGGER health_information_set_updated_at BEFORE UPDATE ON health_information
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Mínimo privilegio para la app (sin DELETE, sin DDL)
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON users TO today_app;
GRANT UPDATE (failed_login_attempts, locked_until,
              totp_secret_ciphertext, totp_secret_nonce) ON users TO today_app;
GRANT SELECT, INSERT, UPDATE ON user_pii, credit_profiles, health_information TO today_app;
GRANT USAGE ON SEQUENCE users_user_id_seq,
                        credit_profiles_credit_profile_id_seq,
                        health_information_health_record_id_seq TO today_app;

COMMIT;
