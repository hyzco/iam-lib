# Configuration reference

Everything passed to `createIamHandlers(config)` and `createTokenService(config)`, plus the process-wide settings provider.

## `createTokenService(config)`

| Option | Default | Notes |
|---|---|---|
| `algorithm` | `"RS256"` | `"RS256"` or `"HS256"`. Other values throw. |
| `privateKey` | — | RS256 signing key (PEM). Required for RS256. |
| `publicKey` | — | RS256 verification key (PEM). Required for RS256. |
| `extraPublicKeys` | `[]` | Retired public keys still accepted while rotating keys. Signing always uses `privateKey`. |
| `accessSecret` | — | HS256 access secret. Required for HS256. |
| `refreshSecret` | `accessSecret` | HS256 refresh secret. Use a different value. Refresh tokens are verified with this secret only. |
| `accessExpiresIn` | `"15m"` | Duration string, or a function returning one. |
| `refreshExpiresIn` | `"7d"` | Duration string, or a function returning one. |

Returns: `signAccessToken`, `signRefreshToken`, `verifyAccessToken`, `verifyRefreshToken`, `signMFAToken`, `verifyMFAToken`, `signMfaSetupToken`, `verifyMfaSetupToken`, `decodeToken`, `getArgs`.

Token `type` claims: `access`, `refresh`, `mfa_pending` (5 min), `mfa_setup_required` (10 min). See [SECURITY.md](SECURITY.md#token-types).

## `createIamHandlers(config)`

### Required

| Option | Type | Notes |
|---|---|---|
| `db` | Knex instance | Throws at construction if missing. |
| `tokenService` | object | From `createTokenService`. |
| `userRepo` | `{ getById, update, delete }` | `getById` is required. `update`/`delete` back the profile routes. |

### Infrastructure

| Option | Default | Notes |
|---|---|---|
| `logger` | `console` | Needs `info`, `warn`, `error`, `debug`/`log` as available. Optional-call, so partial loggers work. |
| `redis` | — | Optional. Legacy session cache: `redis.del(userId)` on logout. |
| `roles` | `[]` | Ordered ladder, lowest first. Empty with no `rbacMiddleware` logs a warning and denies every `requireRole`. |
| `getRole` | — | `async (userId) => role`. Null means 404 (user gone). Empty means 403 (no role). |
| `rbacMiddleware` | — | Replaces the built-in `requireRole`. |
| `overrides` | `{}` | Per-handler replacement. Function → wrapped in array. Array → whole chain. Keys: `me`, `login`, `register`, `logout`, `changePw`, `refreshToken`, `forgotPassword`, `resetPassword`. |
| `defaultTenantId` | `"default"` | Used for `tenant_id` claims when a user has none. |
| `strictTokenType` | `false` | Reject untyped (pre-`type`-claim) access tokens. Enable after old tokens expire. |
| `rateLimits` | `{}` | Per-handler `{ windowMs, max }`. Default `{ windowMs: 60000, max: 60 }`. |

### Login

| Option | Default | Notes |
|---|---|---|
| `lockout` | disabled | `{ maxAttempts, duration }`, or an async function returning that or `null`. `duration` is minutes or `"15m"`, `"2h"`, `"1d"`. Requires `failed_login_attempts` and `locked_until` columns. A resolver failure disables lockout for that attempt. |
| `checkAccountState` | — | `async (user, { audit, phase }) => void`. Throw to refuse. `phase` is `"login"` (after the password matches) or `"refresh"`. Receives the full `users` row. |
| `onLoginSuccess` | — | `async (user, req)`. Runs after a session is issued, not on MFA challenges. |
| `requireMfaForAdmins` | — | `async (user) => boolean`. When true for an account without MFA, login returns 403 `MFA_SETUP_REQUIRED` with a setup token. Fails open if the check throws. |

### Registration

| Option | Default | Notes |
|---|---|---|
| `allowRegistration` | `true` | Boolean or resolver. `false` returns 403. |
| `requireAdminApproval` | unset | Boolean or resolver. When set, `users.is_active` is written as `!approvalRequired`. Unset means the column is not written. |
| `registerSchema` | — | Joi object concatenated onto the base schema (email, password, name, surname, ext, phone, captchaToken). Use it for required consent flags. |
| `resolveTenantId` | — | `async (req) => tenantId`. Falls back to `defaultTenantId`. |
| `extraUserFields` | — | `async (data, req) => columns`. Merged into the insert. The client cannot set `role` or other columns. |
| `onUserCreated` | — | `async (user, { data, req })`. Errors are logged, not returned to the client. |

Passwords must meet the policy in [Password policy](#password-policy). Captcha is controlled by `CAPTCHA_PROVIDER` (see [Captcha](#captcha)).

### Password and MFA

| Option | Default | Notes |
|---|---|---|
| `verifyMfa` | — | `async (userId, code) => { verified }`. Required for resets of MFA accounts. Without it, such resets are refused. |
| `extraPasswordUpdateFields` | — | `async (userId, trx) => columns`. Written with the new password on reset. |
| `onPasswordChanged` | — | `async (userId, { trx })`. Runs inside the change-password transaction. |
| `onPasswordResetRequested` | — | `async ({ email, userName, resetToken, expiresIn })`. Send the reset email here. |
| `onPasswordReset` | — | `async ({ email, userName })`. Confirmation email. |

Reset tokens expire after 1 hour and are single-use. A successful reset revokes every refresh token for the user.

### Profile and `/me`

| Option | Default | Notes |
|---|---|---|
| `meFields` | `DEFAULT_ME_FIELDS` | Allowlist of fields returned by `GET /me`. |
| `profile.updatableFields` | `["name", "surname", "ext", "phone"]` | Allowlist for `PUT` profile. Other keys are ignored. An empty result is a 400. |
| `profile.canAccessOtherUsers` | deny | `async (req, targetId) => boolean`. Needed to read another user's profile through `GET /:id`. |

### Sessions and observability

| Option | Default | Notes |
|---|---|---|
| `tokenBlacklist` | — | `{ add(entry) }`. Receives `{ token, userId, tokenType, expiresAt, reason, ip }` on logout. Without it, a logged-out access token stays valid until it expires. |
| `onAudit` | — | `async (event)`. Events: `user.login`, `user.login.locked_out`, `user.login.lockout_triggered`, `user.login.mfa_required`, `user.login.mfa_setup_required`, `user.login.refused_account_status` (host-emitted), `user.register`, `user.pw.change`, `user.password.reset.requested`, `user.password.reset.completed`, `user.password.reset.mfa_failed`. Errors are logged and swallowed. |

### Return value

`me`, `login`, `register`, `logout`, `changePw`, `refreshToken`, `forgotPassword`, `resetPassword` are arrays (`[rateLimiter, handler]`) and spread directly into a route. Also: `requireRole`, `profile`, `verifyAccessToken`, `accessTokenMiddleware`, `rateLimiter`, `tokenService`, `registerServiceAccount`, `issueServiceToken`, `verifyServiceToken`, `issueRefreshSession`.

## Settings provider

```js
import { setSettingsProvider } from "iam-lib";
setSettingsProvider((scope, key, fallback) => mySettings.get(scope, key, fallback));
```

Process-wide. Read by:

| Scope.key | Used for | Default |
|---|---|---|
| `security.password_min_length` | Password floor. Can only raise the 8-character floor. | `8` |
| `security.password_require_special_chars` | Require a non-alphanumeric character. | `false` |
| `security.session_timeout` | `getRefreshIdleTimeoutMinutes()`, for an idle-session sweeper. | env `REFRESH_TOKEN_IDLE_TIMEOUT_MINUTES`, then 4320 (3 days) |

Provider throws or returns `undefined` → fallback. The library never fails a request because a setting is unreadable.

## Password policy

Always enforced: at least 8 characters, one uppercase, one lowercase, one digit. The `security.*` settings above can only add requirements. The same policy applies to register, change, and reset.

## Captcha

`CAPTCHA_PROVIDER` environment variable:

| Value | Behaviour |
|---|---|
| `none` (default) | Always passes. |
| `hcaptcha` | Verifies `captchaToken` with hCaptcha using `HCAPTCHA_SECRET_KEY`. Missing secret, network error, or a non-`success` response all refuse. |
| anything else | Refuses. |

## Environment variables read

| Variable | Used by |
|---|---|
| `CAPTCHA_PROVIDER` | captcha selection |
| `HCAPTCHA_SECRET_KEY` | hCaptcha verification |
| `REFRESH_TOKEN_IDLE_TIMEOUT_MINUTES` | idle timeout fallback |
| `ACCESS_TOKEN_LIFE`, `REFRESH_TOKEN_LIFE` | `createTokenService` defaults for the lifetime options (read at construction) |
