import createError from "http-errors";
import { rotateRefreshToken } from "../services/refreshTokenStore.js";

/**
 * Map a refresh failure to a short server-side reason for security telemetry.
 * Never sent to the client, where the response stays generic.
 * @param {unknown} err
 * @returns {string}
 */
export function refreshFailureReason(err) {
  if (err?.name === "TokenExpiredError") {return "refresh_expired";}
  if (err?.name === "JsonWebTokenError" || err?.name === "NotBeforeError") {return "refresh_forged";}
  if (err?.code === "REFRESH_SESSION_ENDED") {return "session_ended";}
  if (err?.code === "REFRESH_REPLAY") {return "refresh_reuse";}
  if (err?.code === "REFRESH_UNKNOWN") {return "refresh_unknown";}
  if (err?.code === "REFRESH_USER_MISMATCH") {return "refresh_user_mismatch";}
  if (err?.code === "REFRESH_MALFORMED") {return "refresh_malformed";}
  if (err?.code === "ACCOUNT_REFUSED") {return "account_refused";}
  return "unknown";
}

/**
 * @param {object} deps
 * @param {object} deps.tokenService
 * @param {import('knex').Knex} deps.db
 * @param {Function} [deps.checkAccountState] async (user, { audit, phase: 'refresh' }) => void; throw to refuse
 * @param {Function} [deps.audit]
 * @param {string} [deps.defaultTenantId='default']
 */
export default function refreshTokenHandler({ tokenService, db, checkAccountState, audit, defaultTenantId = "default" }) {
  return async (req, res, next) => {
    try {
      const { refreshToken } = req.body || {};
      if (typeof refreshToken !== "string" || !refreshToken) {
        throw createError.BadRequest("Refresh token is required");
      }

      // Signature, expiry and the `type` claim. An access token signed with the
      // same key is rejected here, so a short-lived access token cannot mint
      // unlimited new session pairs.
      const payload = await tokenService.verifyRefreshToken(refreshToken);
      const userId = payload?.aud;

      if (userId == null || Array.isArray(userId) || typeof userId === "object") {
        throw createError.Unauthorized("Invalid refresh token payload");
      }

      const user = await db("users").where({ id: userId }).first();
      if (!user) {throw createError.Unauthorized("User not found");}

      if (checkAccountState) {
        await checkAccountState(user, { audit, phase: "refresh" });
      }

      const rotated = await rotateRefreshToken({ db, tokenService, payload, req });

      // `sid` mirrors the refresh token's family id, so access-token-only requests
      // can identify their session.
      const newAccess = await tokenService.signAccessToken(userId, {
        role: user.role,
        email: user.email,
        tenantId: user.tenant_id || defaultTenantId,
        sid: rotated.familyId,
      });

      res.send({ accessToken: newAccess, refreshToken: rotated.token });
    } catch (err) {
      req.refreshFailureReason = req.refreshFailureReason || refreshFailureReason(err);
      if (err && err.status && !err.statusCode) {err.statusCode = err.status;}
      // Library JWT errors have no HTTP status. Map them to 401 with a generic
      // message instead of a 500 that leaks library internals.
      if (err && !err.status && !err.statusCode &&
          (err.name === "JsonWebTokenError" || err.name === "TokenExpiredError" || err.name === "NotBeforeError")) {
        return next(createError.Unauthorized("Invalid refresh token"));
      }
      next(err);
    }
  };
}
