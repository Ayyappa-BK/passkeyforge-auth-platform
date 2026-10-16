CREATE TABLE accounts (
 id UUID PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE, handle BYTEA NOT NULL UNIQUE,
 totp_secret TEXT, pending_totp TEXT, pending_until TIMESTAMPTZ,
 totp_step BIGINT NOT NULL DEFAULT -1, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE credentials (
 id TEXT PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 public_key BYTEA NOT NULL, signature_count BIGINT NOT NULL, label VARCHAR(80) NOT NULL,
 backup_eligible BOOLEAN NOT NULL, backed_up BOOLEAN NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_used_at TIMESTAMPTZ
);
CREATE INDEX credentials_owner ON credentials(account_id);
CREATE TABLE challenges (
 id UUID PRIMARY KEY, binding TEXT NOT NULL, kind VARCHAR(24) NOT NULL,
 account_id UUID NOT NULL, payload TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX challenges_expiry ON challenges(expires_at);
CREATE TABLE recovery_codes (
 account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 digest CHAR(64) NOT NULL, PRIMARY KEY(account_id,digest)
);
CREATE TABLE rate_buckets (key TEXT PRIMARY KEY, hits INTEGER NOT NULL, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX rate_expiry ON rate_buckets(expires_at);
CREATE TABLE audit_events (
 id UUID PRIMARY KEY, account_id UUID, event VARCHAR(48) NOT NULL, outcome VARCHAR(16) NOT NULL,
 trace_id VARCHAR(32), occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_owner_time ON audit_events(account_id,occurred_at DESC);
CREATE TABLE spring_session (
 primary_id CHAR(36) NOT NULL PRIMARY KEY, session_id CHAR(36) NOT NULL UNIQUE,
 creation_time BIGINT NOT NULL, last_access_time BIGINT NOT NULL, max_inactive_interval INT NOT NULL,
 expiry_time BIGINT NOT NULL, principal_name VARCHAR(100)
);
CREATE INDEX spring_session_expiry ON spring_session(expiry_time);
CREATE INDEX spring_session_principal ON spring_session(principal_name);
CREATE TABLE spring_session_attributes (
 session_primary_id CHAR(36) NOT NULL REFERENCES spring_session(primary_id) ON DELETE CASCADE,
 attribute_name VARCHAR(200) NOT NULL, attribute_bytes BYTEA NOT NULL,
 PRIMARY KEY(session_primary_id, attribute_name)
);
