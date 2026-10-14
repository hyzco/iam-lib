import jwt from "jsonwebtoken";
import createError from "http-errors";
import { verifyWithKeys } from "../middleware/verifyAccessToken.js";

// A lifetime may be a duration string ("15m") or a function returning one, so a
// host can change it at runtime without rebuilding the token service.
const lifetime = (value) => (typeof value === "function" ? value() : value);

/**
 * Token kinds. Every token carries `type`, and each verifier accepts only the
 * kinds it is meant for:
 *
 *   access           session token, accepted by accessTokenMiddleware
 *   refresh          rotated through the refresh endpoint only
 *   mfa_pending      5-minute second-factor challenge, verifyMFAToken only
 *   mfa_setup_required  10-minute enrollment token, verifyMfaSetupToken only
 *
 * Tokens without a `type` (issued before the claim existed) are accepted where
 * a legacy token is still possible, so an upgrade does not sign everyone out.
 */
export const TOKEN_TYPES = Object.freeze({
  ACCESS: "access",
  REFRESH: "refresh",
  MFA_PENDING: "mfa_pending",
  MFA_SETUP: "mfa_setup_required",
});

function assertType(payload, expected, { allowLegacy = false, message = "Invalid or expired token" } = {}) {
  const type = payload?.type;
  if (type === expected) {return payload;}
  if (allowLegacy && type === undefined) {return payload;}
  throw createError.Unauthorized(message);
}

/**
 * @param {object} config
 * @param {'RS256'|'HS256'} [config.algorithm='RS256']
 * @param {string} [config.privateKey]   RS256 signing key (PEM)
 * @param {string} [config.publicKey]    RS256 verification key (PEM)
 * @param {string[]} [config.extraPublicKeys] retired public keys still accepted during rotation
 * @param {string} [config.accessSecret] HS256 access secret
 * @param {string} [config.refreshSecret] HS256 refresh secret (defaults to accessSecret)
 * @param {string|(() => string)} [config.accessExpiresIn='15m']
 * @param {string|(() => string)} [config.refreshExpiresIn='7d']
 */
export default function createTokenService({
  algorithm = "RS256",
  privateKey,
  publicKey,
  extraPublicKeys = [],
  accessSecret,
  refreshSecret,
  accessExpiresIn = process.env.ACCESS_TOKEN_LIFE || "15m",
  refreshExpiresIn = process.env.REFRESH_TOKEN_LIFE || "7d",
}) {
  if (algorithm !== "RS256" && algorithm !== "HS256") {
    throw new TypeError(`Unsupported algorithm: ${algorithm}`);
  }
  if (algorithm === "RS256" && (!privateKey || !publicKey)) {
    throw new TypeError("RS256 requires privateKey and publicKey");
  }
  if (algorithm === "HS256" && !accessSecret) {
    throw new TypeError("HS256 requires accessSecret");
  }

  const isRS = algorithm === "RS256";
  const accessKey = isRS ? privateKey : accessSecret;
  const refreshKey = isRS ? privateKey : (refreshSecret || accessSecret);

  // Verification keys per token kind. RS256 has one keypair, so access and
  // refresh share the list. HS256 keeps separate secrets, so a refresh token
  // must never verify under the access secret, and the reverse.
  const accessVerifyKeys = isRS
    ? [publicKey, ...(Array.isArray(extraPublicKeys) ? extraPublicKeys : [])].filter(Boolean)
    : [accessSecret];
  const refreshVerifyKeys = isRS
    ? accessVerifyKeys
    : [refreshSecret || accessSecret];

  return {
    /**
     * @param {string|number} userId
     * @param {object} [claims] extra claims (role, email, tenantId, sid, ...)
     */
    signAccessToken: (userId, claims = {}) =>
      new Promise((res, rej) =>
        jwt.sign(
          { ...claims, aud: userId, type: TOKEN_TYPES.ACCESS },
          accessKey,
          { algorithm, expiresIn: lifetime(accessExpiresIn) },
          (e, t) => (e ? rej(e) : res(t)),
        ),
      ),

    /**
     * @param {string|number} userId
     * @param {{ jti?: string, familyId?: string }} [opts]
     */
    signRefreshToken: (userId, opts = {}) =>
      new Promise((res, rej) => {
        const claims = { aud: userId, type: TOKEN_TYPES.REFRESH };
        if (opts.familyId) {claims.sid = opts.familyId;}
        const signOpts = { algorithm, expiresIn: lifetime(refreshExpiresIn) };
        if (opts.jti) {signOpts.jwtid = opts.jti;}
        jwt.sign(claims, refreshKey, signOpts, (e, t) => (e ? rej(e) : res(t)));
      }),

    /** Signature and expiry, then the access type check. */
    verifyAccessToken: (token) =>
      verifyWithKeys(token, accessVerifyKeys, algorithm).then((p) => assertType(p, TOKEN_TYPES.ACCESS, { allowLegacy: true })),

    /** Signature and expiry, then the refresh type check. */
    verifyRefreshToken: (token) =>
      verifyWithKeys(token, refreshVerifyKeys, algorithm).then((p) => assertType(p, TOKEN_TYPES.REFRESH, { allowLegacy: true })),

    /**
     * Short-lived (5 minute) challenge issued after a correct password for an
     * account with MFA enabled. Not a session token.
     * @param {{ userId: string|number, role?: string, email?: string, tenantId?: string }} claims
     */
    signMFAToken: (claims) =>
      new Promise((res, rej) =>
        jwt.sign(
          { ...claims, type: TOKEN_TYPES.MFA_PENDING },
          accessKey,
          { algorithm, expiresIn: "5m" },
          (e, t) => (e ? rej(e) : res(t)),
        ),
      ),

    /** @returns {Promise<object>} payload with type "mfa_pending" */
    verifyMFAToken: (token) =>
      verifyWithKeys(token, accessVerifyKeys, algorithm).then((p) => assertType(p, TOKEN_TYPES.MFA_PENDING, { message: "Invalid MFA token type" })),

    /**
     * Short-lived (10 minute) token issued when admin MFA enforcement blocks a
     * login because the account has no second factor yet. Usable only on the
     * enrollment endpoints.
     * @param {string|number} userId
     * @param {object} [claims]
     */
    signMfaSetupToken: (userId, claims = {}) =>
      new Promise((res, rej) =>
        jwt.sign(
          { ...claims, aud: userId, type: TOKEN_TYPES.MFA_SETUP },
          accessKey,
          { algorithm, expiresIn: "10m" },
          (e, t) => (e ? rej(e) : res(t)),
        ),
      ),

    /** @returns {Promise<object>} payload with type "mfa_setup_required" */
    verifyMfaSetupToken: (token) =>
      verifyWithKeys(token, accessVerifyKeys, algorithm).then((p) => assertType(p, TOKEN_TYPES.MFA_SETUP)),

    /** Decode without verifying. For logging and blacklist bookkeeping only. */
    decodeToken: (token) => jwt.decode(token),

    getArgs: () => ({
      // `key` is the primary access verification key, kept for middleware
      // configuration. `keys` is the full access verification set.
      key: accessVerifyKeys[0],
      keys: accessVerifyKeys,
      algorithm,
    }),
  };
}
