import createError from "http-errors";
import bcrypt from "bcrypt";
import { loginSchema } from "../utils/validate.js";
import { issueRefreshToken } from "../services/refreshTokenStore.js";
import { parseDurationToMinutes } from "../config/runtime.js";

// Single generic failure message for every bad-login path. Distinct messages
// would let an attacker tell a registered email from an unknown one.
const LOGIN_FAILED_MESSAGE = "Invalid email or password";

// Throwaway hash (same cost as register) compared when the account does not
// exist, so the request still pays the bcrypt cost. Without it, user-not-found
// returns in about 1 ms and a real comparison takes tens of ms, which undoes the
// generic message.
const DUMMY_BCRYPT_HASH = bcrypt.hashSync("timing-equalizer-not-a-real-password", 10);

/**
 * Resolve the lockout policy. Accepts:
 *   - undefined / false          lockout disabled
 *   - { maxAttempts, duration }  static policy; duration is minutes or "15m", "2h", "1d"
 *   - async () => policy | null  resolved per attempt (for runtime settings); null disables
 *
 * Lockout needs the `failed_login_attempts` and `locked_until` columns on `users`.
 * A resolver failure disables lockout for that attempt rather than locking every account.
 */
async function resolveLockout(lockout, logger) {
  if (!lockout) {return null;}
  let policy;
  try {
    policy = typeof lockout === "function" ? await lockout() : lockout;
  } catch (err) {
    logger?.error?.("[iam-lib] lockout policy lookup failed; lockout disabled for this attempt:", err?.message);
    return null;
  }
  if (!policy) {return null;}
  const maxAttempts = Number.parseInt(policy.maxAttempts, 10);
  const durationMinutes = typeof policy.duration === "number"
    ? policy.duration
    : parseDurationToMinutes(policy.duration ?? "15m");
  if (!Number.isFinite(maxAttempts) || maxAttempts <= 0 || !durationMinutes) {
    logger?.error?.("[iam-lib] invalid lockout policy; lockout disabled:", policy);
    return null;
  }
  return { maxAttempts, durationMinutes };
}

/**
 * @param {object} deps
 * @param {import('knex').Knex} deps.db
 * @param {object} deps.tokenService
 * @param {object} deps.logger
 * @param {Function} deps.audit
 * @param {Function} [deps.requireMfaForAdmins]  async (user) => boolean
 * @param {object|Function|false} [deps.lockout]  see resolveLockout
 * @param {Function} [deps.checkAccountState]     async (user, { audit, phase: 'login' }) => void; throw to refuse
 * @param {Function} [deps.onLoginSuccess]        async (user, req) => void
 * @param {string} [deps.defaultTenantId='default']
 */
export default function loginHandler({
  db,
  tokenService,
  logger,
  audit,
  requireMfaForAdmins,
  lockout,
  checkAccountState,
  onLoginSuccess,
  defaultTenantId = "default",
}) {
  return async (req, res, next) => {
    try {
      const data = await loginSchema.validateAsync(req.body);

      const user = await db("users").where({ email: data.email }).first();

      if (!user) {
        // Pay the same bcrypt cost, then fail with the identical message.
        await bcrypt.compare(data.password, DUMMY_BCRYPT_HASH);
        throw createError.Unauthorized(LOGIN_FAILED_MESSAGE);
      }

      // Lockout is checked before the password so a locked account cannot be used to probe passwords.
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        const retryAfterSeconds = Math.max(1, Math.ceil((new Date(user.locked_until) - new Date()) / 1000));
        audit({ action: "user.login.locked_out", userId: user.id, status: "failure" });
        res.set("Retry-After", String(retryAfterSeconds));
        throw createError(429, "Too many failed login attempts. Try again later.", {
          code: "ACCOUNT_LOCKED",
          retryAfterSeconds,
        });
      }

      const valid = await bcrypt.compare(data.password, user.password);
      if (!valid) {
        const policy = await resolveLockout(lockout, logger);
        if (policy) {
          const attempts = (user.failed_login_attempts || 0) + 1;
          const update = { failed_login_attempts: attempts };
          if (attempts >= policy.maxAttempts) {
            update.locked_until = new Date(Date.now() + policy.durationMinutes * 60 * 1000);
            audit({ action: "user.login.lockout_triggered", userId: user.id, status: "failure", meta: { attempts } });
          }
          await db("users").where({ id: user.id }).update(update);
        }
        audit({ action: "user.login", userId: user.id, status: "failure", ip: req.ip || req.connection?.remoteAddress });
        throw createError.Unauthorized(LOGIN_FAILED_MESSAGE);
      }

      // Host-defined account states (suspended, closed, forced reset, ...) are
      // checked only after the password, so they never reveal account existence.
      if (checkAccountState) {
        await checkAccountState(user, { audit, phase: "login" });
      }

      if (user.failed_login_attempts > 0 || user.locked_until) {
        await db("users").where({ id: user.id }).update({ failed_login_attempts: 0, locked_until: null });
      }

      // Admin MFA enforcement. Runs before the MFA gate because an admin without
      // enrolled MFA has no TOTP to challenge. Fails open on check errors so a
      // policy lookup failure cannot cause a login outage.
      if (!user.mfa_enabled && requireMfaForAdmins) {
        let mustEnforce = false;
        try {
          mustEnforce = await requireMfaForAdmins(user);
        } catch (err) {
          logger?.error?.("[iam-lib] requireMfaForAdmins check failed; failing open:", err?.message);
        }
        if (mustEnforce) {
          const setupToken = await tokenService.signMfaSetupToken(user.id, {
            role: user.role,
            email: user.email,
            tenantId: user.tenant_id || defaultTenantId,
          });
          audit({ action: "user.login.mfa_setup_required", userId: user.id, status: "failure" });
          return res.status(403).send({
            code: "MFA_SETUP_REQUIRED",
            mfaSetupRequired: true,
            setupToken,
            message: "Administrator accounts need two-factor authentication. Set it up to continue.",
          });
        }
      }

      if (user.mfa_enabled) {
        const mfaToken = await tokenService.signMFAToken({
          userId: user.id,
          role: user.role,
          email: user.email,
          tenantId: user.tenant_id || defaultTenantId,
        });
        audit({ action: "user.login.mfa_required", userId: user.id, status: "pending" });
        return res.send({
          mfaRequired: true,
          mfaToken,
          message: "MFA verification required. Submit your code to the MFA verification endpoint.",
        });
      }

      // Session: create the refresh family first so its id can be embedded as `sid`
      // on the access token. This lets access-token-only requests identify their session.
      const { token: refreshToken, familyId } = await issueRefreshToken({
        db,
        tokenService,
        userId: user.id,
        req,
      });
      const accessToken = await tokenService.signAccessToken(user.id, {
        role: user.role,
        email: user.email,
        tenantId: user.tenant_id || defaultTenantId,
        sid: familyId,
      });

      if (onLoginSuccess) {
        await onLoginSuccess(user, req);
      }

      audit({
        action: "user.login",
        userId: user.id,
        status: "success",
        ip: req.ip || req.connection?.remoteAddress,
        meta: { userAgent: req.get?.("user-agent") },
      });
      res.send({ accessToken: `Bearer ${accessToken}`, refreshToken });
    } catch (err) {
      if (err.isJoi) {err.status = 422;}
      logger?.error?.("[iam-lib] login error:", err?.message);
      next(err);
    }
  };
}
