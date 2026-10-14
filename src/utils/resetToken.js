import crypto from "node:crypto";

/**
 * Password-reset tokens are random and single-use. Only a SHA-256 digest is
 * stored in the `token` column, so a database read cannot be turned into working reset links.
 */
export function generateResetToken() {
  return crypto.randomBytes(32).toString("hex");
}

/** @param {string} token @returns {string} hex digest for password_reset_tokens.token */
export function hashResetToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
