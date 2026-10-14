# Database requirements

iam-lib does not ship migrations. Your schema must provide the tables and columns below. Each column is required only by the feature listed. Examples use MySQL.

## `users`

| Column | Type (example) | Required by |
|---|---|---|
| `id` | `BIGINT UNSIGNED` PK auto-increment | everything |
| `email` | `VARCHAR(255)` UNIQUE | login, register, forgot-password |
| `password` | `VARCHAR(255)` | login, change/reset password (bcrypt hash) |
| `role` | `VARCHAR(64)` | `getRole` / `requireRole`, login claims |
| `name`, `surname`, `ext`, `phone` | `VARCHAR` NULL | register (written when supplied), profile update |
| `updated_at` | `DATETIME` | reset password writes it |
| `mfa_enabled` | `BOOLEAN` | MFA challenge, admin MFA enforcement, reset MFA gate. Missing means no MFA. |
| `tenant_id` | `VARCHAR(64)` NULL | `resolveTenantId`, token `tenantId` claim. Missing means `defaultTenantId`. |
| `is_active` | `BOOLEAN` | written by register only when `requireAdminApproval` is configured |
| `failed_login_attempts` | `INT` DEFAULT 0 | `lockout` |
| `locked_until` | `DATETIME` NULL | `lockout` |
| `last_login_at` | `DATETIME` NULL | written by your `onLoginSuccess` hook, not by the library |
| `account_status`, `force_password_reset` | host-defined | your `checkAccountState` / `extraPasswordUpdateFields` hooks |

Any extra columns you need (consent timestamps, locale, plan) are yours. Write them through `extraUserFields`.

## `refresh_tokens`

Required by every login, registration, refresh, logout and `issueRefreshSession`.

| Column | Type (example) | Notes |
|---|---|---|
| `jti` | `CHAR(36)` UNIQUE | one per refresh token |
| `family_id` | `CHAR(36)` INDEX | session id (`sid` claim). One family per login. |
| `user_id` | same as `users.id` INDEX | |
| `expires_at` | `DATETIME` | taken from the token's `exp` |
| `last_used_at` | `DATETIME` | |
| `ip` | `VARCHAR(45)` NULL | |
| `user_agent` | `VARCHAR(255)` NULL | truncated by the library |
| `replaced_by_jti` | `CHAR(36)` NULL | set on rotation |
| `revoked` | `BOOLEAN` DEFAULT false INDEX | |
| `revoked_reason` | `VARCHAR(100)` NULL | |
| `revoked_at` | `DATETIME` NULL | |

## `password_reset_tokens`

Required by forgot-password and reset-password.

| Column | Type (example) | Notes |
|---|---|---|
| `id` | PK auto-increment | |
| `user_id` | same as `users.id` INDEX | |
| `token` | `CHAR(64)` UNIQUE | stores the SHA-256 **digest** of the token, not the token |
| `expires_at` | `DATETIME` | |
| `used_at` | `DATETIME` NULL | set on successful reset |
| `created_at` | `DATETIME` | |

Tokens issued before 2.0 stored the raw value. Those rows no longer match and expire within an hour.

## `tenants` (optional)

Only if you use `resolveTenantId`. The library does not query this table itself. Your hook does.

## Transactions

Reset-password, change-password, and forgot-password use `db.transaction`. Use a driver with transactions (InnoDB for MySQL). Registration assumes `insert()` returns `[insertId]`, which is MySQL and MariaDB behaviour. On PostgreSQL, add `returning("id")` in an override or fork the handler.
