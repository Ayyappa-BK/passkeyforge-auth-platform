# PasskeyForge

[![CI](https://github.com/Ayyappa-BK/passkeyforge-auth-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/Ayyappa-BK/passkeyforge-auth-platform/actions/workflows/ci.yml)

A passwordless identity platform built with **Java 21, Spring Boot, Spring Security, PostgreSQL, React and TypeScript**. Genuine WebAuthn ceremonies are verified by Yubico's `webauthn-server-core`; RFC 6238 TOTP is calculated by `java-totp`. The server never receives authenticator private keys.

## Start locally

Requires Docker Engine with Compose. Open the application using **localhost**, not an IP address, so browser WebAuthn secure-context rules and RP configuration agree.

```bash
git clone https://github.com/Ayyappa-BK/passkeyforge-auth-platform.git
cd passkeyforge-auth-platform
./scripts/init-env.sh
docker compose up --build -d
```

- Dashboard: <http://localhost:8080>
- Health: <http://localhost:9090/actuator/health>
- Prometheus: <http://localhost:9091>
- Collector traces: `docker compose logs otel`

Create an account using a device passkey or a FIDO2 security key with resident-credential and user-verification support. The authenticator needs a PIN, biometric or equivalent user verification. No password or email verification is required; the account name is an application-local identifier, not a verified real-world identity.

1. Create an account and save the first passkey.
2. Register a spare passkey before removing any existing credential.
3. Set up an authenticator app, scan the QR code and confirm its code.
4. Download the ten recovery codes. They are shown once and stored only as hashes.
5. Sign out and sign in. An enrolled account requires a passkey and a fresh TOTP or recovery code.
6. Use “Lost access to your passkey?” to redeem a recovery code. The temporary recovery session can only enroll a replacement passkey. TOTP remains required if enabled.

A TOTP timestep can be accepted only once across enrollment and login. After confirming enrollment, wait for the app's next code before using TOTP again. The verifier allows ±1 30-second step for clock skew; synchronize server clocks.

## Development and tests

Requires Java 21, Maven 3.9+, Node 24 and PostgreSQL 16+. Create a dedicated empty database. Never point integration tests at a production database: they truncate platform tables.

```bash
export DB_URL=jdbc:postgresql://localhost:5432/passkeyforge
export DB_USER=passkeyforge
export DB_PASSWORD=your-local-database-password
export TOTP_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export COOKIE_SECURE=false
# Protocol integration fixtures use localhost:8080.
mvn -f backend/pom.xml verify
cd frontend
npm ci
npm run build
cd ..
# Browser development uses the Vite origin through its API proxy.
RP_ORIGIN=http://localhost:5173 java -jar backend/target/passkeyforge-1.0.0.jar
# In another terminal:
cd frontend
npm run dev
# Or let Playwright start Vite, with backend already running:
npx playwright install chromium
npm run test:e2e
```

CI provisions PostgreSQL, runs the full JUnit suite, builds the TypeScript dashboard, runs Chromium with a CTAP2 virtual authenticator under a least-privilege database role, verifies JDBC session revocation and Prometheus output, and builds both container images. Test reports, browser traces and a dashboard screenshot are uploaded as `verification-evidence`. Browser tests use virtual hardware; verify real platform/roaming hardware and mobile compatibility before an external launch.

## Repository

| Directory | Purpose |
| --- | --- |
| `backend` | WebAuthn relying party, TOTP, recovery, session and ownership controls |
| `frontend` | Responsive React dashboard and browser integration test |
| `deploy` | Kubernetes, least-privilege SQL, Prometheus and OpenTelemetry configuration |
| `docs` | Architecture, sequences, API contract, security notes and verification record |
| `.github/workflows` | Verification and version-tagged GHCR publishing |

Read [architecture](docs/architecture.md), [API](docs/api.md), [OpenAPI](docs/openapi.yaml), [security](docs/security.md), [operations](docs/operations.md), and [verification](docs/verification.md).

This is a production-style reference implementation. External production deployment requires your TLS hostname, secret manager, database roles, backup/rotation process, network controls and hardware validation. Kubernetes resources are explicit templates and are not automatically applied to a cluster.
