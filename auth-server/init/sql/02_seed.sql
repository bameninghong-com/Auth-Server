-- =============================================================================
-- SEED DATA (optional)
-- Erstellt einen ersten Tenant + Admin-User zum Testen.
-- Password Hash ersetzen vor dem ersten Start.
-- =============================================================================

-- Erster Tenant
INSERT INTO tenants (id, name, slug, access_token_ttl, refresh_token_ttl)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Projekt Alpha',
    'projekt-alpha',
    900,       -- 15 Minuten Access Token
    2592000    -- 30 Tage Refresh Token
);

-- Admin-Rolle
INSERT INTO roles (id, tenant_id, name, description)
VALUES (
    '00000000-0000-0000-0000-000000000010',
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'Voller Zugriff'
);

-- Admin-User
-- Hash generieren: node -e "require('argon2').hash('deinPasswort').then(console.log)"
INSERT INTO users (id, tenant_id, email, password_hash, email_verified, email_verified_at)
VALUES (
    '00000000-0000-0000-0000-000000000100',
    '00000000-0000-0000-0000-000000000001',
    'admin@example.com',
    'REPLACE_WITH_ARGON2ID_HASH',
    TRUE,
    NOW()
);

-- Admin-Rolle zuweisen
INSERT INTO user_roles (user_id, role_id)
VALUES (
    '00000000-0000-0000-0000-000000000100',
    '00000000-0000-0000-0000-000000000010'
);
