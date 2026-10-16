# API contract

All endpoints live under `/api`, accept JSON when a body is present, and use same-origin cookies. No token is stored in localStorage. Error bodies for application errors are `{"error":"..."}`; Spring Security/filter errors can use the container's standard error response. Use HTTP status as the stable machine-readable signal. Do not depend on a specific generic authentication-error string.

Get `/api/csrf` before each mutation and send the returned `headerName` and `token` as a request header. Authentication/session transitions rotate the session and its CSRF state. The browser fetches a new token before its next mutation.

| Method and path | Session / purpose | Request |
| --- | --- | --- |
| GET `/csrf` | Anonymous or any session | None; returns `{token,headerName}` |
| POST `/registration/options` | Anonymous signup, recent FULL enrollment, or RECOVERY | `{username}` for signup; existing account ignores username |
| POST `/registration/finish` | Same browser as options; ownership rechecked | `{ceremonyId,credential,label?}` |
| POST `/authentication/options` | Any browser; discoverable login | `{}` |
| POST `/authentication/finish` | Same browser as options | `{ceremonyId,credential}` |
| POST `/mfa/totp` | PENDING | `{code}` (six digits) |
| POST `/mfa/recovery` | PENDING | `{code}` (unused recovery code) |
| POST `/recovery` | Anonymous/restricted | `{username,code}`; grants RECOVERY only |
| GET `/me` | FULL | Account ID, username, TOTP flag, remaining recovery count |
| GET `/credentials` | FULL | Owned public metadata, never encrypted TOTP or recovery digests |
| DELETE `/credentials/{id}` | Recent FULL | Removes owned credential; refuses last credential |
| POST `/totp/enrollment` | Recent FULL | `{}`; returns `{uri,qrDataUrl}` |
| POST `/totp/confirmation` | Recent FULL | `{code}`; returns `{recoveryCodes:[...]}` once |
| POST `/totp/disable` | Recent FULL + valid unused OTP | `{code}`; removes TOTP encryption envelope |
| POST `/recovery-codes` | Recent FULL | `{}`; replaces hashes, returns ten codes once |
| GET `/audit` | FULL | Latest 50 owned events |
| POST `/sessions/revoke` | Recent FULL | `{}`; revokes sessions, replaces current session |
| POST `/logout` | Any | `{}`; invalidates current session |

Options endpoints return `{ceremonyId,options:{publicKey:...}}`. Supply `options` to the WebAuthn browser API after JSON/binary conversion. Send its complete credential JSON back as `credential`. The server retains the authoritative request; it never uses client-supplied options for validation. Registration labels are 1–80 characters; account names contain 3–64 ASCII letters, digits or underscores and are normalized to lowercase.

Registration/authentication finish returns `{mfaRequired:boolean}`. If true, the session cannot access `/me` or credential APIs until MFA completes. Successful MFA returns `{authenticated:true}`. Recovery returns `{enrollPasskeyRequired:true}` and can only start/finish enrollment for its own account.

Common statuses: `400` malformed input, `401` authentication/expired state, `403` CSRF or stale recent authentication, `404` unowned/missing credential, `409` account or credential-state conflict, `413` oversized body, and `429` quota exceeded. Endpoint account/session requirements may produce 401 or 403 depending on whether authentication or authorization rejects the request.

Example anonymous ceremony (actual credential response must come from a WebAuthn-capable browser):

```bash
curl -c cookies.txt http://localhost:8080/api/csrf
# Copy returned token and headerName, then:
curl -b cookies.txt -c cookies.txt -H 'Content-Type: application/json' \
  -H 'X-CSRF-TOKEN: TOKEN_FROM_PREVIOUS_RESPONSE' \
  -d '{"username":"alice"}' http://localhost:8080/api/registration/options
```

The machine-readable [OpenAPI contract](openapi.yaml) describes request and session requirements. Management/Actuator endpoints run separately and are not part of the public contract.
