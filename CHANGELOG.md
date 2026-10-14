# Changelog

## 2.0.0

Public-release hardening. Platform-specific code removed, and several security defects fixed. See [docs/MIGRATION.md](docs/MIGRATION.md) for breaking changes.

### Breaking

- Host-specific imports are removed. Platform policy is passed as hooks (`lockout`, `checkAccountState`, `onLoginSuccess`, `allowRegistration`, `requireAdminApproval`, `registerSchema`, `resolveTenantId`, `extraUserFields`, `onUserCreated`, `extraPasswordUpdateFields`, `tokenBlacklist`, `profile.canAccessOtherUsers`, `defaultTenantId`).
- `setSettingsProvider` replaces implicit settings reads.
- Access tokens with `type` other than `access` are refused. MFA challenge and setup tokens no longer work as session tokens.
- Reset tokens are stored as SHA-256 digests.
- Profile update uses an allowlist. Profile read of another user needs `canAccessOtherUsers`.
- `verifyServiceToken` requires `type: "service"`. Service accounts are registered with `registerServiceAccount`.
- Captcha refuses when no secret is configured, in every environment.

### Security fixes

- MFA challenge tokens (`mfa_pending`) were accepted as session tokens.
- HS256 refresh tokens were verified with the access secret.
- `GET /profile/:id` had no authorization check beyond the caller being authenticated.
- `PUT profile` performed mass assignment.
- Registration did not record its refresh token, so the first refresh failed.
- Password reset tokens were stored in plaintext.
- Password reset with an MFA account proceeded without a second factor when no `verifyMfa` was configured.
- Logout swallowed revocation errors.
- Library error messages (`jwt malformed`, `invalid signature`) reached clients.

### Added

- `issueRefreshSession(userId, req)` for SSO and MFA completion.
- `registerServiceAccount`, `issueServiceToken`, `verifyServiceToken` (per-instance registry).
- `setSettingsProvider`, `readSetting`, `TOKEN_TYPES`, `isSessionTokenType`, `verifyWithKeys`, `DEFAULT_ME_FIELDS`, `DEFAULT_UPDATABLE_FIELDS`.
- `verifyMfaSetupToken`, `decodeToken` on the token service.
- `rateLimits` per handler. `strictTokenType` option.
- Configuration validation at construction (`db`, `tokenService`, `userRepo.getById`).
- `index.d.ts` rewritten to match the runtime API. Checked by `npm run typecheck`.
- Test suite (`node:test`, 77 specs) and docs: README, CONFIGURATION, DATABASE, SECURITY, MIGRATION.

### Changed

- Declared dependencies. Package `main` points at the root `index.js`.
- Password policy is shared by register, change and reset, and is settings-tunable upward only.
- Forgot-password response timing padded to 350-400 ms.
- Registration maps duplicate-key races to 409.

### Removed

- Host-path dynamic imports and host-specific audit identifiers in comments.
- Stub `pnpm-lock.yaml`.

## 1.0.0

- Initial release.
