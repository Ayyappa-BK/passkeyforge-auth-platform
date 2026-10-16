-- Run as the schema owner after Flyway. Create roles/passwords through a secret manager.
-- Replace database/role names to match your deployment. No credentials belong in SQL files.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE passkeyforge TO passkeyforge_runtime;
GRANT USAGE ON SCHEMA public TO passkeyforge_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON accounts, credentials, challenges,
 recovery_codes, rate_buckets, spring_session, spring_session_attributes TO passkeyforge_runtime;
GRANT SELECT, INSERT ON audit_events TO passkeyforge_runtime;
-- No audit UPDATE/DELETE and no schema CREATE for runtime. Migration owner is a separate role.
