-- =============================================================================
-- AUTH SERVER - PRODUCTION DATABASE SCHEMA
-- =============================================================================
-- Features:
--   - Multi-Tenant support (shared JWT secret via environment variable)
--   - Refresh Token Rotation with theft detection
--   - Session management with device tracking
--   - Full audit/security log
--   - Password reset & email verification flows
-- Compatible: PostgreSQL 14+
-- =============================================================================


-- -----------------------------------------------------------------------------
-- EXTENSIONS
-- -----------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive email


-- =============================================================================
-- TENANTS
-- Represents each project / application using this auth server.
-- JWT signing uses a single global secret from the environment (JWT_SECRET).
-- =============================================================================

CREATE TABLE tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(100)    NOT NULL,
    slug                VARCHAR(50)     NOT NULL UNIQUE,         -- e.g. "projekt-a"

    -- Token TTL settings per tenant
    access_token_ttl    INTEGER         NOT NULL DEFAULT 900,    -- seconds (default: 15 min)
    refresh_token_ttl   INTEGER         NOT NULL DEFAULT 2592000,-- seconds (default: 30 days)

    -- Security settings
    max_sessions_per_user       INTEGER NOT NULL DEFAULT 10,
    refresh_token_rotation      BOOLEAN NOT NULL DEFAULT TRUE,
    revoke_all_on_theft         BOOLEAN NOT NULL DEFAULT TRUE,
    require_email_verification  BOOLEAN NOT NULL DEFAULT TRUE,

    -- Status
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,

    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);


-- =============================================================================
-- USERS
-- Core identity — email/password only, no project-specific data
-- =============================================================================

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    email               CITEXT          NOT NULL,
    password_hash       TEXT            NOT NULL,                -- argon2id hash

    -- Email verification
    email_verified      BOOLEAN         NOT NULL DEFAULT FALSE,
    email_verified_at   TIMESTAMPTZ,

    -- Account status
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    is_locked           BOOLEAN         NOT NULL DEFAULT FALSE,
    locked_at           TIMESTAMPTZ,
    locked_reason       VARCHAR(255),

    -- Failed login tracking (brute force protection)
    failed_login_count  INTEGER         NOT NULL DEFAULT 0,
    last_failed_login   TIMESTAMPTZ,

    -- Timestamps
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_users_email_tenant UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant    ON users(tenant_id);
CREATE INDEX idx_users_email     ON users(tenant_id, email);
CREATE INDEX idx_users_is_active ON users(is_active) WHERE is_active = TRUE;


-- =============================================================================
-- USER ROLES
-- =============================================================================

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(50)     NOT NULL,                        -- e.g. "admin", "editor"
    description TEXT,
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_roles_tenant_name UNIQUE (tenant_id, name)
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);


-- =============================================================================
-- SESSIONS
-- One session = one logged-in device
-- Refresh tokens are tied to sessions
-- =============================================================================

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Current active refresh token (rotated on every use)
    refresh_token_hash  TEXT            NOT NULL UNIQUE,         -- SHA-256 of raw token
    token_family        UUID            NOT NULL DEFAULT gen_random_uuid(),

    -- Device & location info
    device_name         VARCHAR(200),                            -- e.g. "Chrome 124 on Windows 11"
    device_type         VARCHAR(20)     CHECK (device_type IN ('desktop', 'mobile', 'tablet', 'unknown')),
    os                  VARCHAR(100),
    browser             VARCHAR(100),
    ip_address          INET,
    country             VARCHAR(2),                              -- ISO 3166-1 alpha-2
    city                VARCHAR(100),
    user_agent          TEXT,

    -- Status
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    last_used_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ     NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      VARCHAR(50)     CHECK (revoked_reason IN (
                            'logout',
                            'forced_logout',
                            'expired',
                            'token_theft',
                            'password_changed',
                            'account_locked'
                        ))
);

CREATE INDEX idx_sessions_user         ON sessions(user_id);
CREATE INDEX idx_sessions_tenant       ON sessions(tenant_id);
CREATE INDEX idx_sessions_token_hash   ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_token_family ON sessions(token_family);
CREATE INDEX idx_sessions_active       ON sessions(user_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_sessions_expires      ON sessions(expires_at) WHERE is_active = TRUE;


-- =============================================================================
-- SESSION EVENTS
-- Tracks every action within a session
-- =============================================================================

CREATE TABLE session_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID            NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id         UUID            NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    tenant_id       UUID            NOT NULL REFERENCES tenants(id)  ON DELETE CASCADE,

    event_type      VARCHAR(50)     NOT NULL CHECK (event_type IN (
                        'login',
                        'token_refreshed',
                        'logout',
                        'forced_logout',
                        'token_theft_detected',
                        'session_expired'
                    )),

    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB           DEFAULT '{}',

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_events_session ON session_events(session_id);
CREATE INDEX idx_session_events_user    ON session_events(user_id);
CREATE INDEX idx_session_events_type    ON session_events(event_type);
CREATE INDEX idx_session_events_created ON session_events(created_at DESC);


-- =============================================================================
-- SECURITY AUDIT LOG
-- Immutable log — never delete rows from this table
-- =============================================================================

CREATE TABLE security_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID            REFERENCES tenants(id)  ON DELETE SET NULL,
    user_id     UUID            REFERENCES users(id)    ON DELETE SET NULL,
    session_id  UUID            REFERENCES sessions(id) ON DELETE SET NULL,

    event_type  VARCHAR(80)     NOT NULL,
    severity    VARCHAR(10)     NOT NULL CHECK (severity IN ('info', 'warn', 'critical')),

    ip_address  INET,
    user_agent  TEXT,
    country     VARCHAR(2),
    description TEXT,
    metadata    JSONB           DEFAULT '{}',

    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- Event types reference:
-- info:     login_success, logout, token_refreshed, email_verified,
--           password_changed, session_revoked, role_assigned
-- warn:     login_failed, unknown_device_login, new_country_login,
--           password_reset_requested, multiple_failed_logins
-- critical: token_theft_detected, account_locked, all_sessions_revoked,
--           brute_force_detected

CREATE INDEX idx_audit_tenant   ON security_audit_log(tenant_id);
CREATE INDEX idx_audit_user     ON security_audit_log(user_id);
CREATE INDEX idx_audit_severity ON security_audit_log(severity);
CREATE INDEX idx_audit_event    ON security_audit_log(event_type);
CREATE INDEX idx_audit_created  ON security_audit_log(created_at DESC);
CREATE INDEX idx_audit_ip       ON security_audit_log(ip_address);


-- =============================================================================
-- REFRESH TOKEN ROTATION HISTORY
-- Full rotation chain per token family — used to detect theft
-- =============================================================================

CREATE TABLE token_rotation_history (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          UUID            NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_family        UUID            NOT NULL,

    previous_token_hash TEXT            NOT NULL,
    new_token_hash      TEXT,

    ip_address          INET,
    user_agent          TEXT,

    rotated_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rotation_session   ON token_rotation_history(session_id);
CREATE INDEX idx_rotation_family    ON token_rotation_history(token_family);
CREATE INDEX idx_rotation_prev_hash ON token_rotation_history(previous_token_hash);


-- =============================================================================
-- EMAIL VERIFICATION TOKENS
-- =============================================================================

CREATE TABLE email_verification_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    token_hash  TEXT            NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ     NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    used_at     TIMESTAMPTZ,

    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_verify_user    ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verify_expires ON email_verification_tokens(expires_at);


-- =============================================================================
-- PASSWORD RESET TOKENS
-- =============================================================================

CREATE TABLE password_reset_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID            NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    UUID            NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    token_hash   TEXT            NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ     NOT NULL DEFAULT (NOW() + INTERVAL '1 hour'),
    used_at      TIMESTAMPTZ,
    ip_requested INET,

    created_at   TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pw_reset_user    ON password_reset_tokens(user_id);
CREATE INDEX idx_pw_reset_expires ON password_reset_tokens(expires_at);


-- =============================================================================
-- TRIGGERS — updated_at
-- =============================================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();


-- =============================================================================
-- FUNCTION: expire_sessions
-- Run via cron every 15 minutes
-- =============================================================================

CREATE OR REPLACE FUNCTION expire_sessions()
RETURNS INTEGER AS $$
DECLARE
    rows_affected INTEGER;
BEGIN
    UPDATE sessions
    SET
        is_active      = FALSE,
        revoked_at     = NOW(),
        revoked_reason = 'expired'
    WHERE
        is_active  = TRUE
        AND expires_at < NOW();

    GET DIAGNOSTICS rows_affected = ROW_COUNT;
    RETURN rows_affected;
END;
$$ LANGUAGE plpgsql;


-- =============================================================================
-- FUNCTION: revoke_all_user_sessions
-- Used on password change, account lock, "logout all devices"
-- =============================================================================

CREATE OR REPLACE FUNCTION revoke_all_user_sessions(
    p_user_id           UUID,
    p_reason            VARCHAR(50),
    p_except_session_id UUID DEFAULT NULL
)
RETURNS INTEGER AS $$
DECLARE
    rows_affected INTEGER;
BEGIN
    UPDATE sessions
    SET
        is_active      = FALSE,
        revoked_at     = NOW(),
        revoked_reason = p_reason
    WHERE
        user_id    = p_user_id
        AND is_active  = TRUE
        AND (p_except_session_id IS NULL OR id != p_except_session_id);

    GET DIAGNOSTICS rows_affected = ROW_COUNT;
    RETURN rows_affected;
END;
$$ LANGUAGE plpgsql;


-- =============================================================================
-- VIEW: Active sessions (for "angemeldete Geräte" UI)
-- =============================================================================

CREATE VIEW v_active_sessions AS
SELECT
    s.id,
    s.user_id,
    s.tenant_id,
    s.device_name,
    s.device_type,
    s.os,
    s.browser,
    s.ip_address,
    s.country,
    s.city,
    s.last_used_at,
    s.created_at,
    s.expires_at
FROM sessions s
WHERE
    s.is_active = TRUE
    AND s.expires_at > NOW();


-- =============================================================================
-- VIEW: Security overview per user
-- =============================================================================

CREATE VIEW v_user_security_overview AS
SELECT
    u.id                AS user_id,
    u.tenant_id,
    u.email,
    u.email_verified,
    u.is_locked,
    u.failed_login_count,
    u.last_login_at,
    COUNT(s.id) FILTER (
        WHERE s.is_active = TRUE AND s.expires_at > NOW()
    )                   AS active_session_count,
    MAX(s.last_used_at) AS last_session_activity
FROM users u
LEFT JOIN sessions s ON s.user_id = u.id
GROUP BY u.id;


-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE tenants                IS 'Each row = one project using this auth server. JWT secret is global (JWT_SECRET env var).';
COMMENT ON TABLE users                  IS 'Core user identity — auth data only, no project-specific fields';
COMMENT ON TABLE sessions               IS 'One session per logged-in device; holds the active refresh token hash';
COMMENT ON TABLE session_events         IS 'Per-session activity log';
COMMENT ON TABLE security_audit_log     IS 'Immutable security event log — never delete rows';
COMMENT ON TABLE token_rotation_history IS 'Refresh token rotation chain for theft detection';

COMMENT ON COLUMN sessions.token_family          IS 'All rotations of the same original token share this UUID — detects reuse after rotation';
COMMENT ON COLUMN sessions.refresh_token_hash    IS 'SHA-256 of the raw refresh token — never store raw tokens';
COMMENT ON COLUMN tenants.access_token_ttl       IS 'Access token lifetime in seconds per tenant';
COMMENT ON COLUMN tenants.refresh_token_ttl      IS 'Refresh token lifetime in seconds per tenant';
