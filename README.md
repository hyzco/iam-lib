# iam-lib

Authentication, session and role-based authorization building blocks for Express applications.

- Login, registration, logout, password change, forgot/reset password
- Access tokens plus rotating, single-use refresh tokens with replay detection (session families)
- Token `type` claims, so a refresh token, MFA challenge or enrollment token can never act as a session
- Account lockout, admin MFA enforcement, MFA challenge tokens (verification is your code)
- Role ladder (`requireRole`) with alias normalization
- Service-account tokens (RS256)
- Profile CRUD with explicit authorization
- Audit events, rate limiting, captcha (none or hCaptcha)
- Every platform-specific behaviour is an injected hook. The library has no dependency on your application code.

Node.js 20+. Works with MySQL and Knex. Documentation: [Configuration](docs/CONFIGURATION.md) · [Database](docs/DATABASE.md) · [Security](docs/SECURITY.md) · [Migrating from 1.x](docs/MIGRATION.md) · [Changelog](CHANGELOG.md)

---

## Install

```bash
npm install iam-lib
```

Peer requirements: a Knex instance (`db`) and an Express app. Express is optional, for the middleware types only.

## Quick start

```js
import express from "express";
import knex from "knex";
import fs from "node:fs";
import { createIamHandlers, createTokenService } from "iam-lib";

const db = knex({ client: "mysql2", connection: process.env.DATABASE_URL });

const tokenService = createTokenService({
  algorithm: "RS256",
  privateKey: fs.readFileSync("keys/private.pem", "utf8"),
  publicKey: fs.readFileSync("keys/public.pem", "utf8"),
});

const iam = createIamHandlers({
  db,
  tokenService,
  roles: ["user", "moderator", "admin"], // lowest first
  getRole: async (userId) => (await db("users").where({ id: userId }).first())?.role,
  userRepo: {
    getById: (id) => db("users").where({ id }).first(),
    update: (id, data) => db("users").where({ id }).update(data),
    delete: (id) => db("users").where({ id }).delete(),
  },
});

const app = express();
app.use(express.json());

app.post("/auth/register", iam.register);          // array of handlers
app.post("/auth/login", iam.login);
app.post("/auth/refresh", iam.refreshToken);
app.post("/auth/logout", iam.accessTokenMiddleware, iam.logout);
app.get("/auth/me", iam.accessTokenMiddleware, iam.me);
app.post("/auth/forgot-password", iam.forgotPassword);
app.post("/auth/reset-password", iam.resetPassword);
app.post("/auth/change-password", iam.accessTokenMiddleware, iam.changePw);

app.get("/admin/stats", iam.accessTokenMiddleware, iam.requireRole("admin"), (req, res) => {
  res.send({ ok: true });
});

app.listen(3000);
```

Register and refresh return raw tokens. Login returns `accessToken` already prefixed with `Bearer `. Send the access token as `Authorization: Bearer <token>`.

The database must match [docs/DATABASE.md](docs/DATABASE.md) before you start.

## Keys

RS256 is recommended. Generate a key pair once and keep the private key on the auth service only:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```

HS256 is supported for single-service deployments. Pass `accessSecret` and `refreshSecret` as two different values. Refresh tokens are verified with `refreshSecret` only.

```js
createTokenService({
  algorithm: "HS256",
  accessSecret: process.env.ACCESS_TOKEN_SECRET,
  refreshSecret: process.env.REFRESH_TOKEN_SECRET,
});
```

Token lifetimes: `accessExpiresIn` (default `15m`) and `refreshExpiresIn` (default `7d`). Both accept a function for values that change at runtime.

## Hooks

Platform policy is passed as hooks, not imported. Each hook is optional. Without it, the library uses the strict default.

| Area | Options |
|---|---|
| Lockout | `lockout` |
| Account states | `checkAccountState`, `onLoginSuccess` |
| Admin MFA | `requireMfaForAdmins`, `verifyMfa` |
| Registration | `allowRegistration`, `requireAdminApproval`, `registerSchema`, `resolveTenantId`, `extraUserFields`, `onUserCreated` |
| Password | `extraPasswordUpdateFields`, `onPasswordChanged`, `onPasswordResetRequested`, `onPasswordReset` |
| Profile | `profile.updatableFields`, `profile.canAccessOtherUsers` |
| Sessions | `tokenBlacklist`, `strictTokenType` |
| Observability | `onAudit`, `logger` |
| Limits | `rateLimits` |
| Settings | `setSettingsProvider(fn)` |

Full reference: [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

### Example: admin-only profile reads and a lockout policy

```js
const iam = createIamHandlers({
  // ...required options from the quick start
  lockout: { maxAttempts: 5, duration: "15m" },
  profile: {
    canAccessOtherUsers: async (req) => req.payload?.role === "admin",
    updatableFields: ["name", "phone"],
  },
});
```

### Example: runtime-tunable policy

```js
import { setSettingsProvider } from "iam-lib";

setSettingsProvider(async (scope, key, fallback) => {
  const row = await db("settings").where({ scope, key }).first();
  return row ? row.value : fallback;
});
```

The provider is read on each use, so changes apply without a restart. Provider failures fall back to the default. They never open or close the platform.

## Overriding handlers

Replace any endpoint's chain. A function is wrapped in an array. An array replaces the whole chain, including the rate limiter.

```js
const iam = createIamHandlers({
  // ...
  overrides: {
    login: [loginRateLimiter, myLoginHandler],
  },
});
```

## Service accounts

```js
iam.registerServiceAccount({ id: "billing-worker", privateKey: svcPrivateKeyPem, scopes: ["usage:write"] });

const token = iam.issueServiceToken("billing-worker");       // 1 hour, RS256, type "service"
const payload = iam.verifyServiceToken(token, svcPublicKeyPem);
```

User tokens are rejected by `verifyServiceToken` because the `type` and issuer checks differ.

## Starting a session outside the built-in login

SSO callbacks and MFA completion must create tracked refresh tokens. Otherwise the first refresh fails.

```js
const { refreshToken, familyId } = await iam.issueRefreshSession(user.id, req);
const accessToken = await iam.tokenService.signAccessToken(user.id, {
  role: user.role,
  email: user.email,
  sid: familyId, // lets session lists identify this session
});
```

## Middleware

| Export | Purpose |
|---|---|
| `iam.accessTokenMiddleware` | Verifies `Authorization: Bearer`, sets `req.payload` (`aud` = user id). Rejects every token type except `access`. |
| `iam.requireRole(role \| roles)` | Passes when the user's role ranks at or above any listed role. Denies when no listed role is known. |
| `iam.rateLimiter` | Default 60 requests/minute per IP. Tune per endpoint with `rateLimits`. |

Behind a proxy, set Express's `trust proxy` so `req.ip` is the client address.

## Testing

```bash
npm test
```

The suite uses `node:test` and an in-memory stand-in for Knex. It covers token types and key separation, login/lockout/MFA gates, registration, refresh rotation and replay, logout, profile authorization, password reset, policy, captcha, and the role ladder.

## Status

Version 2.x. Breaking changes from 1.x are listed in [docs/MIGRATION.md](docs/MIGRATION.md). Security-relevant behaviour and known limits are in [docs/SECURITY.md](docs/SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
