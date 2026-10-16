# Security properties and limits

## Implemented controls

| Threat | Control |
| --- | --- |
| Phishing / credential forwarding | Exact configured origin and RP validation by Yubico; no origin wildcard or subdomain relaxation |
| Invalid signatures / authenticator data | Established WebAuthn verifier; P-256 ES256 tests with real signatures; UV and UP enforced |
| Challenge replay / stale challenge | Random WebAuthn challenge, session binding, 120-second TTL, atomic committed one-time consume |
| OTP replay / concurrent guesses | ±1 timestep window; persisted highest accepted step; account `FOR UPDATE` lock |
| TOTP database exposure | AES-256-GCM encryption with fresh 96-bit nonces and account UUID as authenticated data |
| Ciphertext moved to another user | GCM associated data validation fails |
| Recovery database exposure | 160-bit CSPRNG codes; account-bound SHA-256 digest; no recoverable plaintext |
| Recovery reuse / racing requests | Account lock and atomic hash deletion; concurrency integration test |
| Session fixation / browser script access | Session rotation; HttpOnly, SameSite=Strict, production Secure cookies; cookie-only tracking |
| CSRF | Spring Security's session-bound CSRF token on all mutating requests, including anonymous ceremonies |
| Unauthorized management | Exact account-scoped database mutations; full session plus five-minute recent authentication |
| Accidental total lockout | Last-passkey deletion blocked; reserve at least one usable credential |
| Guessing / abuse | PostgreSQL-backed quotas: 120 API requests/minute per observed IP; 20 authentication or registration requests/minute; 8 MFA/recovery attempts per account per five minutes |
| Injection | Parameterized JDBC; React escaping; CSP; no HTML injection or third-party QR service |
| Audit leakage | Fixed event types, account UUID and trace IDs only; no authentication material in logs |

No passwords are accepted. WebAuthn private keys never cross the authenticator boundary. TOTP secrets exist transiently in process/browser memory and in the enrollment URI/QR; persistence contains only authenticated encryption. This is necessary to verify shared-secret TOTP. Recovery codes are plaintext only in the single issuance response and any user-downloaded file. Responses use `Cache-Control: no-store`.

`java-totp` supplies secret generation and HMAC-based RFC 6238 code calculation. The application checks the six-digit format, compares generated codes using `MessageDigest.isEqual`, and persists the accepted timestep. It does not implement a replacement cryptographic primitive. Default HMAC-SHA1 TOTP is used for authenticator compatibility; this is the RFC 6238 OTP construction, not use of SHA-1 as a collision-resistant signature.

## Session policy

- Full session: 20-minute idle timeout and eight-hour absolute lifetime.
- Pending MFA and recovery: five-minute absolute lifetime.
- Security mutations: full authentication verified within the last five minutes. Reauthenticate from the dashboard after that interval.
- Recovery, TOTP configuration changes, credential deletion and explicit session revocation delete existing persisted sessions; the active browser gets a replacement session where appropriate.
- CSRF tokens are fetched fresh before each mutation to handle session rotation.
- Authenticated credential operations derive the account from server-side session state. A client-supplied owner ID is never trusted.

A request already executing on another replica may finish during revocation. Database session deletion prevents subsequent requests, but does not cancel in-flight work. Critical transactions retain account ownership and row-lock checks.

## Production configuration

Use a dedicated HTTPS origin and matching RP ID. Secure cookies default to true; only the loopback Docker example disables them. Do not broaden origin matching to accommodate a deployment error. RP ID is a durable authenticator binding: changing it makes existing credentials unusable for the new RP.

Set a unique 256-bit `TOTP_ENCRYPTION_KEY` through a secret manager. `v1` envelopes identify the present key format. A changed key cannot decrypt old secrets: use an offline, controlled decrypt/re-encrypt migration and key-retention plan before rotating it. A database backup without its encryption key cannot restore TOTP. This repository does not silently rotate keys or offer an unsafe development fallback.

`forward-headers-strategy=none` deliberately ignores spoofable forwarding headers. In the supplied reverse-proxy deployment, the backend sees the proxy IP; its anonymous IP quotas are therefore coarse shared limits. Apply per-client rate limiting at your trusted ingress/WAF, and tune backend limits for deployment traffic. Per-account MFA/recovery quotas remain independent across replicas. Do not expose the backend API port directly to the Internet or accept arbitrary forwarded headers. Add limits at the edge against distributed floods and unbounded account creation.

Use the supplied runtime-role grants with a separate database migration owner. The local Compose database role is intentionally simplified for development. Metrics and health run on port 9090; they have no public authentication and must remain restricted to cluster monitoring. Never expose them through the public ingress. Use TLS to PostgreSQL in production with server identity verification.

Audit history needs a retention/export policy and protected storage. The runtime role can insert and read audit records but cannot change or remove them. Configure collection and backup retention under an administrative role. Never enable HTTP request-body logging on authentication routes. OTP secrets and recovery codes must not be exported to telemetry.

## Deliberate scope and remaining validation

- No attestation trust policy or authenticator certification allowlist is configured. `none` attestation supports consumer passkeys and user-owned FIDO2 keys. Enterprise hardware restrictions require a separate metadata/trust policy.
- Account names are not verified email addresses. There is no administrator impersonation or password reset backdoor.
- Recovery codes intentionally allow recovery from lost passkeys; possessing one carries account-recovery authority. Protect them like other authenticators.
- Physical authenticator, Safari/Firefox, mobile hybrid transport and actual Kubernetes/TLS behavior need environment-specific validation. CI virtual hardware is not a physical-device certification.
- Auth libraries and dependencies are versioned; run dependency/security updates and review advisories before launch. A passing CI suite is not an independent penetration test or proof of absence of vulnerabilities.
- No multi-region consistency design or distributed audit event bus is claimed. PostgreSQL is the single consistency boundary.
