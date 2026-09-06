-- OpenID Connect Provider: клиентские приложения (relying party),
-- authorization-коды и access-токены /userinfo. Коды и токены хранятся
-- только хешами SHA-256; коды одноразовые (погашение used_at).

CREATE TABLE IF NOT EXISTS oidc_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL DEFAULT '',  -- "salt$hash"; пусто у public-клиентов (только PKCE)
    name               TEXT NOT NULL,
    redirect_uris      TEXT[] NOT NULL,
    is_public          BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_codes (
    code_hash             BYTEA PRIMARY KEY,      -- SHA-256 authorization-кода
    client_id             TEXT NOT NULL,
    user_id               UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    auth_time             TIMESTAMPTZ NOT NULL,   -- момент входа пользователя (создание сессии)
    amr                   TEXT NOT NULL DEFAULT '',  -- методы аутентификации, через запятую
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',  -- S256 | plain | '' (PKCE не применялся)
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ             -- одноразовость: погашение атомарным UPDATE
);
CREATE INDEX IF NOT EXISTS oidc_codes_expires_idx ON oidc_codes (expires_at);

CREATE TABLE IF NOT EXISTS oidc_tokens (
    token_hash BYTEA PRIMARY KEY,                 -- SHA-256 access-токена
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    amr        TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS oidc_tokens_expires_idx ON oidc_tokens (expires_at);
