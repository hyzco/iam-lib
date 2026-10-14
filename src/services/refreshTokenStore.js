/**
 * Refresh-token rotation with replay detection.
 *
 *   - Every issued refresh token has a unique `jti` and a `family_id` (session id, `sid`).
 *   - rotate() marks the presented row as replaced and revoked, then inserts its successor.
 *   - Presenting an already-rotated or revoked token is treated as theft: the whole
 *     family is revoked.
 *   - Token lifetimes come from the JWT `exp` claim, so the expiry string is never parsed here.
 *
 * Table: `refresh_tokens` (jti, family_id, user_id, expires_at, last_used_at, ip,
 * user_agent, replaced_by_jti, revoked, revoked_reason, revoked_at).
 * See docs/DATABASE.md.
 */

import { randomUUID } from "node:crypto";
import { readSetting, parseDurationToMinutes } from "../config/runtime.js";

const TABLE = "refresh_tokens";
const DEFAULT_REFRESH_IDLE_TIMEOUT_MINUTES = 4320; // 3 days

function expFromPayload(payload) {
  if (!payload || typeof payload.exp !== "number") {return null;}
  return new Date(payload.exp * 1000);
}

function fallbackExpiry() {
  return new Date(Date.now() + 7 * 24 * 3600 * 1000);
}

/**
 * @param {object} args
 * @param {import('knex').Knex} args.db
 * @param {object} args.tokenService
 * @param {string|number} args.userId
 * @param {string} [args.familyId] reuse an existing family (rare; normally a fresh login starts one)
 * @param {object} [args.req]
 */
export async function issueRefreshToken({ db, tokenService, userId, familyId, req }) {
  const jti = randomUUID();
  const fam = familyId || randomUUID();
  const token = await tokenService.signRefreshToken(userId, { jti, familyId: fam });

  const decoded = await tokenService.verifyRefreshToken(token).catch(() => null);
  const expiresAt = expFromPayload(decoded) || fallbackExpiry();

  await db(TABLE).insert({
    jti,
    family_id: fam,
    user_id: userId,
    expires_at: expiresAt,
    last_used_at: db.fn.now(),
    ip: req?.ip || null,
    user_agent: (req?.headers?.["user-agent"] || "").slice(0, 255) || null,
  });

  return { token, jti, familyId: fam };
}

async function revokeFamily(db, familyId, reason) {
  await db(TABLE)
    .where({ family_id: familyId, revoked: false })
    .update({
      revoked: true,
      revoked_reason: reason ? String(reason).slice(0, 100) : "revoked",
      revoked_at: db.fn.now(),
    });
}

// revoked_reason values written when a session ends deliberately. A replay of
// one of these is a stale client, not an attack; the distinction is for logs only.
const SESSION_ENDED_REASONS = /^(logout|idle|access_changed|role_changed|password|admin_|user_revoke|account_)/i;

function httpError(message, code) {
  const err = new Error(message);
  err.status = 401;
  err.code = code;
  return err;
}

/**
 * Rotate a presented refresh token. Returns the successor bundle.
 * Throws an Error with `.status = 401` and a `.code` for reuse, revocation or an unknown jti.
 */
export async function rotateRefreshToken({ db, tokenService, payload, req }) {
  const userId = payload?.aud;
  const jti = payload?.jti;
  const familyId = payload?.sid;

  if (!userId || !jti || !familyId) {
    throw httpError("Refresh token missing rotation claims", "REFRESH_MALFORMED");
  }

  const row = await db(TABLE).where({ jti }).first();

  // Unknown jti: forged, or the family was already pruned. Revoke what we can.
  if (!row) {
    await revokeFamily(db, familyId, "unknown_jti_replay");
    throw httpError("Refresh token not recognized", "REFRESH_UNKNOWN");
  }

  if (String(row.user_id) !== String(userId)) {
    await revokeFamily(db, row.family_id, "user_mismatch");
    throw httpError("Refresh token user mismatch", "REFRESH_USER_MISMATCH");
  }

  if (row.replaced_by_jti || row.revoked) {
    await revokeFamily(db, row.family_id, "replay_detected");
    const code = !row.replaced_by_jti && SESSION_ENDED_REASONS.test(String(row.revoked_reason || ""))
      ? "REFRESH_SESSION_ENDED"
      : "REFRESH_REPLAY";
    throw httpError("Refresh token reuse detected; session revoked", code);
  }

  // Successor insert and predecessor update share one transaction, so a family
  // never holds two live tokens. The row lock serializes concurrent rotations.
  return db.transaction(async (trx) => {
    const locked = await trx(TABLE).where({ jti }).forUpdate().first();
    if (!locked || locked.replaced_by_jti || locked.revoked) {
      throw httpError("Refresh token reuse detected; session revoked", "REFRESH_REPLAY");
    }

    const newJti = randomUUID();
    const newToken = await tokenService.signRefreshToken(userId, {
      jti: newJti,
      familyId: row.family_id,
    });
    const decoded = await tokenService.verifyRefreshToken(newToken).catch(() => null);
    const expiresAt = expFromPayload(decoded) || fallbackExpiry();

    await trx(TABLE).insert({
      jti: newJti,
      family_id: row.family_id,
      user_id: userId,
      expires_at: expiresAt,
      last_used_at: trx.fn.now(),
      ip: req?.ip || null,
      user_agent: (req?.headers?.["user-agent"] || "").slice(0, 255) || null,
    });

    await trx(TABLE)
      .where({ jti })
      .update({
        replaced_by_jti: newJti,
        revoked: true,
        revoked_reason: "rotated",
        revoked_at: trx.fn.now(),
      });

    return { token: newToken, jti: newJti, familyId: row.family_id };
  });
}

/** Revoke every refresh token in one session family. */
export async function revokeRefreshFamily(db, familyId, reason = "logout") {
  if (!familyId) {return;}
  await revokeFamily(db, familyId, reason);
}

/** Revoke a single refresh token by jti. */
export async function revokeRefreshJti(db, jti, reason = "logout") {
  if (!jti) {return;}
  await db(TABLE)
    .where({ jti, revoked: false })
    .update({
      revoked: true,
      revoked_reason: String(reason).slice(0, 100),
      revoked_at: db.fn.now(),
    });
}

/**
 * Revoke every active refresh token for a user ("log out everywhere").
 * @returns {Promise<number>} rows revoked
 */
export async function revokeAllRefreshTokensForUser(db, userId, reason = "logout_all") {
  if (userId == null) {return 0;}
  return db(TABLE)
    .where({ user_id: userId, revoked: false })
    .update({
      revoked: true,
      revoked_reason: String(reason).slice(0, 100),
      revoked_at: db.fn.now(),
    });
}

/**
 * Minutes of inactivity after which a refresh token is considered idle.
 * Read from the `security.session_timeout` runtime setting, then the
 * REFRESH_TOKEN_IDLE_TIMEOUT_MINUTES env var, then a 3-day default.
 * A lookup failure falls through to the next source and never turns into an
 * immortal or instantly-expiring session.
 *
 * Enforcement is periodic (a sweeper calls this), so a change applies at the next sweep.
 *
 * @returns {Promise<number>}
 */
export async function getRefreshIdleTimeoutMinutes() {
  const fromSetting = parseDurationToMinutes(await readSetting("security", "session_timeout", null));
  if (fromSetting) {return fromSetting;}
  const configured = Number.parseInt(process.env.REFRESH_TOKEN_IDLE_TIMEOUT_MINUTES || "", 10);
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_REFRESH_IDLE_TIMEOUT_MINUTES;
}
