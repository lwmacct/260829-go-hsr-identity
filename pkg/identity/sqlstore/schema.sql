CREATE TABLE IF NOT EXISTS identity_users (
    id TEXT PRIMARY KEY NOT NULL,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    disabled_at TIMESTAMP,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_passwords (
    user_id TEXT PRIMARY KEY NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    scheme TEXT NOT NULL,
    hash TEXT NOT NULL,
    password_changed_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    login_ip TEXT NOT NULL DEFAULT '',
    last_ip TEXT NOT NULL DEFAULT '',
    binding_hash BYTEA,
    user_agent_hash BYTEA NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    revoked_reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS identity_sessions_user_expiry_idx ON identity_sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS identity_sessions_expiry_idx ON identity_sessions(expires_at);
