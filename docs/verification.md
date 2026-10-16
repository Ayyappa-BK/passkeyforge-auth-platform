# Verification record

The executable record is the [CI workflow](https://github.com/Ayyappa-BK/passkeyforge-auth-platform/actions/workflows/ci.yml). Each run records its exact Git commit and uploads JUnit XML/text results, browser traces on failure, a dashboard screenshot, and application/container logs in `verification-evidence`. See the run's conclusion before treating a commit as verified.

## Automated checks

| Check | Evidence and assertions |
| --- | --- |
| Java 21 build | Maven compilation, unit tests and packaged Spring Boot JAR |
| WebAuthn protocol fixture | Real P-256 key pair; COSE public key; CBOR `none` attestation; DER ES256 assertion signatures; Yubico verifier, without mocked verification |
| Registration | New-account commit, added credential, registration replay, expired challenge, wrong origin/RP/challenge, missing UV |
| Authentication | Signed discoverable assertion, invalid signature, mismatched user handle, expired/reused challenge, counter rollback, cross-session challenge isolation |
| RFC 6238 | All six published SHA1 eight-digit test vectors; application's six-digit code/window checks |
| TOTP integration | Encrypted pending enrollment, PNG QR generation, confirmation, incorrect code, reused timestep, expired enrollment, pending session expiry, successful second factor, disable with fresh code |
| Recovery | Hashed storage, rotation, restricted recovery session, replacement passkey enrollment, second-factor redemption, one-time use and concurrent redemption |
| Concurrency | Exactly one winner for simultaneous challenge consumption and recovery redemption |
| Authorization | Anonymous/restricted sessions blocked, CSRF enforcement, unowned deletion rejected, last passkey protected, stale recent-auth blocked |
| Abuse | Shared PostgreSQL quota state and 429 response |
| Encryption | Unique GCM nonces, decrypt round-trip, wrong-owner AAD and wrong-key rejection |
| Browser | Chromium's CTAP2 virtual authenticator and native WebAuthn JSON API; signup, enrollment, sign-in, incorrect OTP, recovery MFA, credential removal, logout |
| Persistent sessions | Separate browser contexts; second context signs in using a copied test-only virtual credential; revocation blocks its next request |
| Least privilege | Browser tests run the packaged JAR with a database role that cannot modify schema or update/delete audit records |
| Observability | Browser test checks the real Prometheus endpoint contains authentication-event metrics |
| Deployment | Build both OCI images; start Compose; repeat browser tests against Nginx and the containerized API/PostgreSQL |

Local checks also compile using the installed Java 21 runtime, run the cryptography/TOTP and WebAuthn protocol unit tests, and build the React/TypeScript production bundle. Runtime frontend dependency audit reported zero known advisories when checked on October 15, 2026; this is a point-in-time dependency report, not a security audit.

The local execution sandbox prevented a separate PostgreSQL instance from allocating shared memory, and Docker was not installed locally. Database and container execution are therefore performed on the GitHub runner. CI uses real PostgreSQL, not H2 or a mocked verifier. Servlet protocol tests isolate the in-memory test session implementation; browser tests exercise actual Spring Session JDBC persistence and cookies.

## Manual acceptance before external deployment

1. On your final HTTPS hostname, register and sign in using physical platform and roaming authenticators supporting resident keys and user verification.
2. Test Safari, Firefox, Android/iOS and hybrid transports you intend to support.
3. Verify TLS, cookie Secure/SameSite behavior, ingress limits, management-port isolation and database certificate validation.
4. Restore the database plus its encryption key into staging and complete TOTP/recovery login.
5. Review key rotation, audit retention, operational alerting, incident response and recovery-code handling.
6. Apply Kubernetes templates in your staging cluster and verify probes, network policies, rolling updates and multi-replica session revocation.

No physical hardware certification, live Kubernetes rollout, independent penetration test or external production deployment is claimed by the automated checks.
