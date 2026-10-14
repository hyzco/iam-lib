import createError from "http-errors";
import { revokeRefreshFamily, revokeAllRefreshTokensForUser } from "../services/refreshTokenStore.js";

function bearerToken(req) {
  const authHeader = req.headers["authorization"];
  return authHeader && authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
}

/**
 * @param {object} deps
 * @param {object} [deps.redis]          optional legacy session cache, keyed by user id
 * @param {object} deps.tokenService
 * @param {object} deps.logger
 * @param {import('knex').Knex} deps.db
 * @param {{ add: (entry: {token: string, userId: any, tokenType: 'access'|'refresh', expiresAt: Date, reason: string, ip?: string}) => Promise<void> }} [deps.tokenBlacklist]
 *   Optional denylist. Without it, a logged-out access token stays valid until its own expiry (ACCESS_TOKEN_LIFE).
 */
export default function logoutHandler({ redis, tokenService, logger, db, tokenBlacklist }) {
  const blacklist = async (token, userId, tokenType, reason, ip) => {
    if (!tokenBlacklist || !token) {return;}
    const decoded = tokenService.decodeToken ? tokenService.decodeToken(token) : null;
    if (!decoded?.exp) {return;}
    await tokenBlacklist.add({
      token,
      userId,
      tokenType,
      expiresAt: new Date(decoded.exp * 1000),
      reason,
      ip,
    });
  };

  return async (req, res, next) => {
    try {
      const rawRefreshToken = req.body && req.body.refreshToken;
      // Non-string values are treated as "missing" so library internals never leak through a 500.
      const refreshToken = typeof rawRefreshToken === "string" && rawRefreshToken ? rawRefreshToken : null;

      // No refresh token in the body, but a valid bearer access token is present:
      // log out everywhere. Clients that drop only local state cannot leave refresh
      // tokens replayable for their full lifetime.
      if (!refreshToken) {
        const userId = req.payload?.aud;
        if (userId == null) {
          throw createError.BadRequest("Refresh token required");
        }

        const revoked = await revokeAllRefreshTokensForUser(db, userId, "logout_all_no_body");
        logger?.info?.(`[iam-lib] logout-all for user ${userId}: ${revoked} refresh token(s) revoked`);

        try {
          await blacklist(bearerToken(req), userId, "access", "logout_all", req.ip);
        } catch (err) {
          logger?.error?.("[iam-lib] access-token blacklist on logout-all failed:", err?.message);
        }

        if (redis) {
          try { await redis.del(String(userId)); } catch (_e) { /* legacy cache, best effort */ }
        }
        return res.sendStatus(204);
      }

      // Verify the refresh token (signature, expiry, type) and get its session family.
      const payload = await tokenService.verifyRefreshToken(refreshToken);
      const userId = payload?.aud;
      const familyId = payload?.sid;

      if (redis && userId != null) {
        try { await redis.del(String(userId)); } catch (_e) { /* legacy cache, best effort */ }
      }

      if (familyId) {
        await revokeRefreshFamily(db, familyId, "logout");
      }

      try {
        await blacklist(bearerToken(req), userId, "access", "logout", req.ip);
        await blacklist(refreshToken, userId, "refresh", "logout", req.ip);
      } catch (err) {
        // Revocation above already ended the session. A denylist write failure is logged, not fatal.
        logger?.error?.("[iam-lib] token blacklist on logout failed:", err?.message);
      }

      res.sendStatus(204);
    } catch (err) {
      logger?.error?.("[iam-lib] logout failed:", err?.message);
      next(err);
    }
  };
}
