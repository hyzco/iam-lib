# Migrating from 1.x to 2.0

2.0 turns platform-specific behaviour into hooks. A 1.x install that depended on the host's internal modules must now pass those behaviours in. Nothing is discovered automatically.

## 1. Dependencies

2.0 declares `bcrypt`, `express-rate-limit`, `http-errors`, `joi` and `jsonwebtoken`. Install them through `npm install iam-lib`. If your package manager is pnpm, run `pnpm install` after upgrading. A `file:` dependency is copied at install time, so an old copy keeps running until you reinstall.

## 2. Replace implicit host lookups with hooks

1.x read these from the host, implicitly. Each is now an option:

| 1.x behaviour | 2.0 option |
|---|---|
| Lockout values from settings | `lockout: async () => ({ maxAttempts, duration })` |
| Suspended/closed/forced-reset refusal | `checkAccountState(user, { audit, phase })` |
| `last_login_at` written on login | `onLoginSuccess(user, req)` |
| Registration on/off, admin approval from settings | `allowRegistration`, `requireAdminApproval` (boolean or resolver) |
| Consent flags required and stored | `registerSchema` (Joi) + `extraUserFields(data, req)` |
| Tenant from host header | `resolveTenantId(req)` |
| Onboarding, `user.registered` event | `onUserCreated(user, ctx)` |
| Forced-reset flag cleared on reset | `extraPasswordUpdateFields(userId, trx)` |
| Token denylist writes | `tokenBlacklist.add(entry)` |
| Admin-only profile reads | `profile.canAccessOtherUsers(req, targetId)` |
| Default tenant id `"theycloud"` (host-specific) | `defaultTenantId` |
| Settings read for password and session policy | `setSettingsProvider((scope, key, fallback) => …)` |

Settings the library reads: `security.password_min_length`, `security.password_require_special_chars`, `security.session_timeout`. Pass them through `setSettingsProvider`.

Call `setSettingsProvider` before the first request. A missing provider means defaults apply silently.

## 3. Sessions started outside login

Any code that calls `tokenService.signRefreshToken` directly creates a refresh token that is not recorded. The first refresh of that token fails. Use `iam.issueRefreshSession(userId, req)` and put the returned `familyId` in the access token as `sid`.

## 4. Behaviour changes to check

| Change | What to verify |
|---|---|
| Captcha with no secret refuses in every environment. | Staging config has `HCAPTCHA_SECRET_KEY`, or `CAPTCHA_PROVIDER=none`. |
| Reset tokens stored as digests. | Reset links issued just before the upgrade stop working. Users request a new one. |
| Access middleware rejects `mfa_pending`, `refresh`, `mfa_setup_required`. | Clients never send these as Bearer tokens. Test the MFA completion flow. |
| `PUT` profile accepts only `updatableFields` (default `name`, `surname`, `ext`, `phone`). Empty result is 400. | Clients send only those fields. |
| `GET /:id` profile needs `canAccessOtherUsers`. | Admin screens still resolve. |
| Change password refuses the same password. | Acceptable for your product. |
| Failed logins emit `user.login` with `status: "failure"`. | Your `onAudit` ignores non-success events, or handles them. |
| MFA challenge message text is generic. | Clients do not parse `message`. Use `mfaRequired` and `mfaToken`. |
| `verifyMFAToken` throws 401 for a wrong-type token. | Callers that catch and map to 401 keep working. |
| Logout propagates revocation errors (500) instead of returning 204. | Expected; investigate DB failures. |
| `verifyServiceToken` requires `type: "service"` and issuer `iam-lib`. | Re-issue service tokens. |

## 5. Schema changes

None are required by the library itself. The DB requirements are in [DATABASE.md](DATABASE.md). The main changes are:

- `password_reset_tokens.token` holds a digest (same column, different content).
- `refresh_tokens` must exist and be written on every session start.
- `users.updated_at` is written by reset-password.

## 6. Verification checklist

- [ ] Login, logout, refresh rotation, and replay (second use of a refresh token returns 401).
- [ ] Registration with each consent/approval/tenant setting you use.
- [ ] Lockout after the configured number of failures, and reset after success.
- [ ] Forgot → email → reset → login with the new password, and the old refresh token rejected.
- [ ] MFA: challenge, completion, and that the challenge token is refused on a normal route.
- [ ] Profile: own read/update works, other-user read is 403 for non-admins.
- [ ] Any SSO/OAuth/MFA-completion path that starts a session: its refresh token rotates.
