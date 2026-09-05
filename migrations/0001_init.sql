-- 0001_init: начальная схема (спека §5).

CREATE TABLE users (
  id UUID PRIMARY KEY, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
  enabled BOOL NOT NULL DEFAULT true, email TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '', telegram_chat_id BIGINT,
  prefer_channels JSONB NOT NULL DEFAULT '["totp","email","sms"]',
  radius_push BOOL NOT NULL DEFAULT false, radius_reply JSONB,
  webauthn_id BYTEA UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE totp_secrets (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret_enc BYTEA NOT NULL, digits INT NOT NULL DEFAULT 6,
  period INT NOT NULL DEFAULT 30, confirmed_at TIMESTAMPTZ,
  last_timestep BIGINT NOT NULL DEFAULT 0);

CREATE TABLE backup_codes (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  code_hash BYTEA NOT NULL UNIQUE, used_at TIMESTAMPTZ);

CREATE TABLE challenges (
  id UUID PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL, code_hash BYTEA, push_state TEXT,
  expires_at TIMESTAMPTZ NOT NULL, attempts_left INT NOT NULL DEFAULT 5,
  used_at TIMESTAMPTZ, purpose TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX ON challenges(user_id, expires_at);

CREATE TABLE sessions (
  token_hash BYTEA PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE settings (key TEXT PRIMARY KEY, value JSONB NOT NULL);

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  username TEXT, event TEXT NOT NULL, detail JSONB, src_ip TEXT, result TEXT);
CREATE INDEX ON audit_log(ts);
CREATE INDEX ON audit_log(username, ts);

CREATE TABLE trusted_devices (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE, ua TEXT, ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL);

CREATE TABLE webauthn_credentials (
  id BIGSERIAL PRIMARY KEY, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA NOT NULL UNIQUE, rpid TEXT NOT NULL,
  public_key BYTEA NOT NULL, sign_count BIGINT NOT NULL DEFAULT 0,
  clone_warning BOOL NOT NULL DEFAULT false, aaguid TEXT,
  attestation_type TEXT, attestation_format TEXT, attachment TEXT,
  transports TEXT NOT NULL DEFAULT '',
  present BOOL NOT NULL DEFAULT false, verified BOOL NOT NULL DEFAULT false,
  backup_eligible BOOL NOT NULL DEFAULT false, backup_state BOOL NOT NULL DEFAULT false,
  name TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ);
