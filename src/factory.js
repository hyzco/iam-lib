import jwt from "jsonwebtoken";
import loginHandler from "./handlers/login.js";
import registerHandler from "./handlers/register.js";
import refreshTokenHandler from "./handlers/refreshToken.js";
import logoutHandler from "./handlers/logout.js";
import meHandler from "./handlers/me.js";
import changePwHandler from "./handlers/changePw.js";
import forgotPasswordHandler from "./handlers/forgotPassword.js";
import resetPasswordHandler from "./handlers/resetPassword.js";
import { accessTokenMiddleware, createAccessTokenVerifier } from "./middleware/verifyAccessToken.js";
import requireRole from "./middleware/requireRole.js";
import createRateLimiter from "./middleware/rateLimiter.js";
import createProfileHandlers from "./profile/index.js";
import auditLogger from "./events/auditLogger.js";
import { issueRefreshToken } from "./services/refreshTokenStore.js";

const SERVICE_TOKEN_ISSUER = "iam-lib";
const SERVICE_TOKEN_TTL = "1h";

/**
 * Creates the IAM handler set.
 *
 * Required: db (Knex), tokenService, userRepo ({ getById, update, delete }).
 * Everything else is optional. Host-specific policy (account states, registration
 * rules, tenancy, audit persistence, email, MFA) is injected through the hooks
 * documented in docs/CONFIGURATION.md. Behaviour without hooks is the strict default.
 *
 * @param {object} config
 * @returns {import('../index.js').IamHandlers}
 */
export function createIamHandlers(config = {}) {
  const {
    db,
    redis,
    logger = console,
    roles = [],
    rbacMiddleware,
    userRepo,
    tokenService,
    getRole,
    overrides = {},
    defaultTenantId = "default",
    strictTokenType = false,
    rateLimits = {},
    // Auth policy hooks
    lockout,
    allowRegistration,
    requireAdminApproval,
    registerSchema,
    resolveTenantId,
    extraUserFields,
    onUserCreated,
    checkAccountState,
    onLoginSuccess,
    requireMfaForAdmins,
    // Password and MFA hooks
    verifyMfa,
    extraPasswordUpdateFields,
    onPasswordChanged,
    onPasswordResetRequested,
    onPasswordReset,
    // Profile and /me
    meFields,
    profile = {},
    // Observability
    onAudit,
    tokenBlacklist,
  } = config;

  if (!db) {throw new TypeError("createIamHandlers: `db` (Knex instance) is required");}
  if (!tokenService) {throw new TypeError("createIamHandlers: `tokenService` is required (see createTokenService)");}
  if (!userRepo || typeof userRepo.getById !== "function") {
    throw new TypeError("createIamHandlers: `userRepo.getById` is required");
  }
  if (roles.length === 0 && !rbacMiddleware) {
    logger?.warn?.("[iam-lib] `roles` is empty: requireRole() will deny every request");
  }

  const stdoutAudit = auditLogger({ logger });
  // Every handler audits through here. Persistence failures are logged and
  // swallowed: a broken audit sink must never break the auth flow it describes.
  const audit = async (event) => {
    stdoutAudit(event);
    if (onAudit) {
      try {
        await onAudit(event);
      } catch (err) {
        logger?.error?.("[iam-lib] onAudit persist failed:", err?.message || err);
      }
    }
  };

  const limiterFor = (name) => {
    const override = rateLimits[name];
    return override ? createRateLimiter(override) : rateLimiter;
  };
  const rateLimiter = createRateLimiter({ windowMs: 60000, max: 60 });

  const { key, keys, algorithm } = tokenService.getArgs();
  const verifyAccessToken = createAccessTokenVerifier({ key, keys, algorithm });
  const accessToken = accessTokenMiddleware({ key, keys, algorithm, strictTokenType });
  const requireRoleMiddleware = requireRole({ roles, getRole });

  // Override semantics: a function is wrapped, an array replaces the chain, and
  // anything else falls back to the default chain.
  const wrap = (override, fallback) => {
    if (Array.isArray(override)) {return override;}
    if (typeof override === "function") {return [override];}
    return fallback;
  };

  const fallbacks = {
    me: [limiterFor("me"), meHandler({ userRepo, meFields })],
    login: [limiterFor("login"), loginHandler({
      db, tokenService, logger, audit, requireMfaForAdmins, lockout, checkAccountState, onLoginSuccess, defaultTenantId,
    })],
    register: [limiterFor("register"), registerHandler({
      db, tokenService, logger, audit, allowRegistration, requireAdminApproval, registerSchema,
      resolveTenantId, extraUserFields, onUserCreated, defaultTenantId,
    })],
    logout: [limiterFor("logout"), logoutHandler({ redis, tokenService, logger, db, tokenBlacklist })],
    refreshToken: [limiterFor("refreshToken"), refreshTokenHandler({
      tokenService, db, checkAccountState, audit, defaultTenantId,
    })],
    changePw: [limiterFor("changePw"), changePwHandler({ db, userRepo, logger, audit, onPasswordChanged })],
    forgotPassword: [limiterFor("forgotPassword"), forgotPasswordHandler({
      db, logger, audit, onTokenGenerated: onPasswordResetRequested,
    })],
    resetPassword: [limiterFor("resetPassword"), resetPasswordHandler({
      db, logger, audit, onPasswordReset, verifyMfa, extraPasswordUpdateFields,
    })],
  };

  const profileHandlers = createProfileHandlers({
    getUserById: userRepo.getById,
    updateUser: userRepo.update,
    deleteUser: userRepo.delete,
    logger,
    updatableFields: profile.updatableFields,
    canAccessOtherUsers: profile.canAccessOtherUsers,
  });

  // Service accounts: per-instance registry, so two IAM instances never share credentials.
  const serviceAccounts = new Map();

  return {
    me: wrap(overrides.me, fallbacks.me),
    login: wrap(overrides.login, fallbacks.login),
    register: wrap(overrides.register, fallbacks.register),
    logout: wrap(overrides.logout, fallbacks.logout),
    changePw: wrap(overrides.changePw, fallbacks.changePw),
    refreshToken: wrap(overrides.refreshToken, fallbacks.refreshToken),
    forgotPassword: wrap(overrides.forgotPassword, fallbacks.forgotPassword),
    resetPassword: wrap(overrides.resetPassword, fallbacks.resetPassword),

    requireRole: rbacMiddleware || requireRoleMiddleware,
    profile: profileHandlers,

    verifyAccessToken,
    accessTokenMiddleware: accessToken,

    /**
     * Register a service account. The secret is the RS256 private key PEM used to sign its tokens.
     * @param {{ id: string, privateKey: string, scopes?: string[] }} account
     */
    registerServiceAccount({ id, privateKey, scopes = [] }) {
      if (!id || !privateKey) {throw new TypeError("registerServiceAccount: id and privateKey are required");}
      serviceAccounts.set(String(id), { privateKey, scopes });
    },

    /**
     * Start a session outside the built-in login flows (SSO callbacks, MFA completion).
     * Records the refresh token so it can be rotated. An untracked refresh token is
     * refused at its first use. Use the returned familyId as the access token's `sid`.
     * @param {string|number} userId
     * @param {object} [req]
     * @returns {Promise<{ refreshToken: string, familyId: string }>}
     */
    async issueRefreshSession(userId, req) {
      const { token, familyId } = await issueRefreshToken({ db, tokenService, userId, req });
      return { refreshToken: token, familyId };
    },

    /** Issue a 1-hour RS256 token for a registered service account. */
    issueServiceToken(id) {
      const account = serviceAccounts.get(String(id));
      if (!account) {throw new Error("Service account not found");}
      return jwt.sign(
        { sub: String(id), scopes: account.scopes, type: "service" },
        account.privateKey,
        { algorithm: "RS256", expiresIn: SERVICE_TOKEN_TTL, issuer: SERVICE_TOKEN_ISSUER },
      );
    },

    /**
     * Verify a service token against the account's public key.
     * Checks algorithm, issuer and type, so a user token can never pass as a service token.
     * @param {string} token
     * @param {string} publicKey PEM
     */
    verifyServiceToken(token, publicKey) {
      const payload = jwt.verify(token, publicKey, {
        algorithms: ["RS256"],
        issuer: SERVICE_TOKEN_ISSUER,
      });
      if (payload?.type !== "service") {throw new Error("Invalid service token");}
      return payload;
    },

    rateLimiter,
    tokenService,
  };
}
