# Security

## Token types

Every token carries a `type` claim. Each verifier accepts only the types it is meant for.

| `type` | Lifetime | Issued by | Accepted by |
|---|---|---|---|
| `access` | `accessExpiresIn` (15 min) | login, register, refresh, MFA completion, `issueRefreshSession` | `accessTokenMiddleware`, `verifyAccessToken` |
| `refresh` | `refreshExpiresIn` (7 days) | login, register, refresh, `issueRefreshSession` | refresh endpoint only (`verifyRefreshToken`) |
| `mfa_pending` | 5 min | login for MFA accounts | `verifyMFAToken` only |
| `mfa_setup_required` | 10 min | login blocked by admin MFA enforcement | `verifyMfaSetupToken` only |
| `service` | 1 hour | `issueServiceToken` | `verifyServiceToken` only (RS256, issuer `iam-lib`) |

Access, refresh and MFA tokens share one RS256 key. Separation comes from the `type` claim, and the verifier checks it on every request. HS256 uses separate access and refresh secrets. A token signed with one never verifies under the other.

Tokens minted before the `type` claim existed carry no `type`. The access middleware still accepts them so sessions survive an upgrade. Set `strictTokenType: true` after the longest old token has expired.

## Controls

**Authentication**

- bcrypt password hashes, cost 10.
- Login returns one generic failure for unknown email and wrong password. An unknown email still pays a bcrypt comparison, so timing does not reveal existence. A locked account gets a distinct 429, because revealing the lock is not an enumeration risk.
- Lockout per account (`lockout`). A successful login clears the counter.
- Account-state checks (`checkAccountState`) run only after the password matches.
- Admin MFA enforcement (`requireMfaForAdmins`) blocks the login and issues a narrow setup token.
- Password reset with an MFA account requires `verifyMfa`. Without it the reset is refused.
- Password reset revokes every session and marks the reset token used, atomically. Change-password does not revoke other sessions by default. Add that in `onPasswordChanged`.

**Sessions**

- Refresh tokens are single-use. Each rotation records the successor. Presenting a rotated or revoked token revokes the whole family (replay detection).
- Refresh rejects access tokens and every other type.
- Logout revokes the family, and with `tokenBlacklist` also blacklists the access token. Without a body, logout revokes all sessions for the bearer.
- Session start (`issueRefreshSession`) records the family, so SSO and MFA logins can rotate.

**Authorization**

- `requireRole` compares against an ordered ladder. Unknown roles deny. Role aliases normalize.
- Profile: reads, updates and deletes act on the caller. Reading another user needs `profile.canAccessOtherUsers`. Updates use an allowlist. Secret-looking fields are stripped from responses.
- `GET /me` returns an allowlist (`meFields`).

**Input and transport**

- Joi validation on every body. Non-string emails are rejected before any query.
- Registration strips unknown keys before insert. `role` is always `user`.
- Passwords: 8+ characters with upper, lower and digit. `security.password_*` settings can only tighten.
- Forgot-password pads every response to 350-400 ms, so timing does not reveal existence.
- Reset tokens: 32 random bytes, stored as SHA-256, valid 1 hour, single use.
- hCaptcha verification is server-side, with a 5 second timeout. Missing secret, network failure, or unexpected response all refuse.
- JWT library errors are mapped to generic 401s. Internal messages are not returned.
- Rate limiting per route (default 60/min per IP). Use `trust proxy` behind a proxy.

**Logging**

- Audit events go to the logger and to `onAudit`. Audit failures never break the auth flow.
- Passwords, tokens and reset links are never logged.

## Fixed in 2.0

These were defects in 1.x:

| Area | Problem | Fix |
|---|---|---|
| Access tokens | An MFA challenge token (`mfa_pending`) passed the access middleware. A password-only holder got a full session for 5 minutes. | Access middleware accepts only `access` (or untyped, unless strict). |
| Refresh (HS256) | Refresh tokens were verified with the access secret, so refresh failed whenever the secrets differed. | Refresh verified with `refreshSecret`. |
| Profile | `GET /:id` returned any user's profile to any authenticated caller. | Other-user reads need `canAccessOtherUsers`. |
| Profile | `PUT` wrote the entire request body to the user row (mass assignment). | Allowlist `updatableFields`. |
| Registration | Refresh token issued at registration was not recorded, so the first refresh failed. | Recorded via `issueRefreshToken`. |
| Access middleware | Verification failures returned library messages (for example `invalid signature`) to the client. | Generic client message; reason goes to `req.authFailureReason` only. |
| Logout | Revocation errors were swallowed and 204 returned. | Errors propagate. |
| Captcha | In non-production with no secret, captcha passed. | Missing secret refuses everywhere. |
| Password reset | Reset tokens were stored in plaintext. A database read gave working reset links. | SHA-256 digest stored. |
| Password reset | With no `verifyMfa`, MFA accounts reset without a second factor. | Refused unless `verifyMfa` is configured. |
| Service accounts | `issueServiceToken` had no way to register accounts, so it always failed. `verifyServiceToken` accepted any token. | `registerServiceAccount`; verify checks issuer and `type: service`. |
| Packaging | Imports of host-application paths (`${cwd}/src/...`, relative `../../core/...`). Breaks outside the host. | Removed. Everything is a hook. |
| Packaging | No `dependencies` declared. | Declared. |

## Known limits

- **Registration reveals existence.** A duplicate email returns 409 `already registered`. This is a deliberate trade-off for UX. If enumeration matters more, handle 409 in an override and return the same response as success, then send a notification to the existing address.
- **Access tokens outlive logout** unless `tokenBlacklist` is set. Their lifetime is `accessExpiresIn` (15 min by default). Keep the lifetime short.
- **Lockout is per account, not per IP.** Combine with `rateLimits` and your edge rate limits to cover credential stuffing across accounts.
- **Rate limiting is in-memory per process.** Multi-instance deployments need a shared store. Pass a store with `rateLimits`, or limit at the proxy.
- **MFA is not implemented here.** The library issues challenge tokens and calls `verifyMfa`. TOTP enrollment and verification are your code.
- **Captcha is off by default** (`CAPTCHA_PROVIDER=none`). Enable hCaptcha on public registration.
- **Refresh tokens are not bound to a device or IP.** Logged for audit, not enforced.

## Reporting

Report suspected vulnerabilities privately through the repository's security advisory feature. Do not open a public issue for them.
