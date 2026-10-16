# Deployment, operations and publication

## Docker

`./scripts/init-env.sh && docker compose up --build -d` starts PostgreSQL, API, web dashboard, Prometheus and an OTLP collector. API and database ports are not published. Web and monitoring ports bind to loopback. Secrets are generated locally with restrictive file permissions; `.env` is ignored by Git. `docker compose down` keeps database volume data. `down -v` destroys local accounts and credentials.

The collector's debug exporter demonstrates trace delivery. Replace it with your production OTLP backend and appropriate authentication. Prometheus scrapes `forge_auth_events_total` and normal JVM/HTTP/database metrics. Exclude account IDs from metric labels to keep cardinality bounded.

## Kubernetes

`deploy/kubernetes.yaml` supplies namespace, API and web Deployments, ClusterIP Services, TLS ingress, resource limits, probes, non-root/read-only security contexts, disruption budget and network policy. It deliberately does not deploy a single-node database as a production dependency. Supply managed PostgreSQL and a protected OTLP collector/Prometheus deployment. Replace image and DNS placeholders before applying.

1. Provision a database/schema owner and a separate runtime role. Run Flyway with migration credentials; use `deploy/runtime-grants.sql` as the grant checklist. In production prefer a dedicated migration job before rolling out application pods, then set `SPRING_FLYWAY_ENABLED=false` for runtime pods.
2. Create a namespaced `passkeyforge-secrets` Secret through your secret manager containing `DB_URL`, `DB_USER`, `DB_PASSWORD`, and `TOTP_ENCRYPTION_KEY`. Never put a real Secret manifest in this repository. Add separate `SPRING_FLYWAY_USER` / `SPRING_FLYWAY_PASSWORD` only to the migration job.
3. Configure the real RP ID, exact HTTPS origin, issuer-managed TLS certificate and deployment image digests. Keep cookies secure. The manifest expects an existing TLS secret.
4. Configure ingress IP rate limits, request-size limits, HTTPS redirects, HSTS, network egress and trusted certificate verification on PostgreSQL. The supplied Nginx strips forwarded headers; backend quotas see the trusted proxy as a shared anonymous source.
5. Scope the supplied NetworkPolicy to the actual database/collector/monitoring topology. The example allows outbound TCP only on PostgreSQL, OTLP and DNS ports and is effective only with a NetworkPolicy-capable CNI.
6. Apply manifests in staging. Run physical authenticator, session revocation, concurrent replay, backup/restore, failure recovery and TLS tests before external release.

The Docker example performs migrations on startup. For Kubernetes with independent migrations, keep Flyway history managed by the schema owner. The application does not need table-owner or superuser privileges.

## Backup and rotation

Back up PostgreSQL and the encryption key separately under access controls. Restore both into isolated staging and verify a TOTP login. Rotate database credentials without changing the data encryption key. A new TOTP master key requires a controlled re-encryption of every non-null `totp_secret` and `pending_totp` envelope with the same account UUID as GCM AAD. Preserve old key material until all relevant backups expire.

Expired challenges, pending enrollment secrets and quota rows are cleaned every minute by all replicas using idempotent SQL. Spring Session cleans expired sessions. Audit rows are retained until an operator's retention/export job removes them under an administrative role. Monitor database storage and pool saturation.

## CI/CD and release

Every main-branch push and pull request verifies Java 21 + PostgreSQL integration, TypeScript build, Chromium WebAuthn/MFA and both Docker builds. Version tags `v*` run the same checks then publish backend/frontend OCI images to GHCR using GitHub's short-lived workflow token. No production cluster credentials are embedded. Deployment to a real cluster is a separately controlled operation.

```bash
# Publish a new release after reviewing main's passing verification:
git tag v1.0.0
git push origin v1.0.0
# Inspect verification:
gh run list --workflow ci.yml
gh run view RUN_ID --log-failed
```

If GitHub credentials are unavailable in a fresh environment:

```bash
gh auth login --hostname github.com
git init -b main
git add .
git commit -m "Build PasskeyForge authentication platform"
gh repo create passkeyforge-auth-platform --public --source=. --remote=origin --push
gh run list --workflow ci.yml
gh run watch RUN_ID --exit-status
gh repo view --web
```

Do not run `git init` again inside an already cloned repository. If the remote already exists, set it explicitly and use `git push -u origin main`.
