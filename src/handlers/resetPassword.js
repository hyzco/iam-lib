import createError from "http-errors";
import bcrypt from "bcrypt";
import { validatePasswordStrength } from "../utils/passwordPolicy.js";
import { hashResetToken } from "../utils/resetToken.js";
import { revokeAllRefreshTokensForUser } from "../services/refreshTokenStore.js";

/**
 * Complete a password reset with a token from the reset email.
 *
 * Steps: validate token (exists, unused, unexpired) → enforce MFA if enrolled →
 * update password and mark token used in one transaction → revoke every session.
 *
 * @param {object} deps
 * @param {import('knex').Knex} deps.db
 * @param {object} deps.logger
 * @param {Function} deps.audit
 * @param {Function} [deps.onPasswordReset]  async ({ email, userName }) => void
 * @param {Function} [deps.verifyMfa]        async (userId, code) => { verified: boolean }. Required
 *   when the account has `mfa_enabled`. The email link alone must not bypass the second factor.
 * @param {Function} [deps.extraPasswordUpdateFields] async (userId, trx) => object
 *   Extra columns to write with the new password (for example clearing a forced-reset flag).
 */
export default function resetPasswordHandler({
  db,
  logger,
  audit,
  onPasswordReset,
  verifyMfa,
  extraPasswordUpdateFields,
}) {
  return async (req, res, next) => {
    try {
      const { token, newPassword, mfaCode } = req.body || {};

      if (typeof token !== "string" || !token || typeof newPassword !== "string" || !newPassword) {
        throw createError.BadRequest("Token and new password are required");
      }

      const strength = await validatePasswordStrength(newPassword);
      if (!strength.valid) {
        throw createError.BadRequest(strength.errors.join(". "));
      }

      // Tokens are stored as digests (see utils/resetToken.js).
      const resetRecord = await db("password_reset_tokens")
        .select("id", "user_id", "expires_at", "used_at")
        .where({ token: hashResetToken(token) })
        .first();

      if (!resetRecord) {
        throw createError.BadRequest("Invalid or expired reset token");
      }
      if (resetRecord.used_at) {
        throw createError.BadRequest("This reset token has already been used");
      }
      if (new Date(resetRecord.expires_at) < new Date()) {
        throw createError.BadRequest("Reset token has expired");
      }

      const user = await db("users")
        .select("id", "email", "name", "surname", "mfa_enabled")
        .where({ id: resetRecord.user_id })
        .first();
      if (!user) {
        throw createError.NotFound("User not found");
      }

      // The reset email proves mailbox access, not identity. An account with a
      // second factor must present it too.
      if (user.mfa_enabled) {
        if (!verifyMfa) {
          // Refuse rather than silently skip the second factor.
          throw createError.Forbidden("Two-factor verification is not available for this account.");
        }
        if (typeof mfaCode !== "string" || !mfaCode.trim()) {
          const mfaError = createError.Forbidden(
            "This account has two-factor authentication enabled. Provide your authenticator code to reset the password.",
          );
          mfaError.code = "MFA_REQUIRED";
          throw mfaError;
        }
        const mfaResult = await verifyMfa(user.id, mfaCode.trim());
        if (!mfaResult?.verified) {
          audit({ action: "user.password.reset.mfa_failed", userId: user.id, status: "failure" });
          const invalidError = createError.Forbidden("Invalid two-factor authentication code");
          invalidError.code = "MFA_INVALID";
          throw invalidError;
        }
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      await db.transaction(async (trx) => {
        const extra = extraPasswordUpdateFields ? await extraPasswordUpdateFields(user.id, trx) : {};
        // Mark the token used inside the same transaction, guarded on used_at so two
        // concurrent submissions cannot both succeed.
        const claimed = await trx("password_reset_tokens")
          .where({ id: resetRecord.id })
          .whereNull("used_at")
          .update({ used_at: new Date() });
        if (!claimed) {
          throw createError.BadRequest("This reset token has already been used");
        }
        await trx("users")
          .where({ id: user.id })
          .update({ password: hashedPassword, updated_at: new Date(), ...extra });
      });

      // Every session must end with the old password. The password is already
      // changed, so a failure here is logged loudly rather than failing the request.
      try {
        await revokeAllRefreshTokensForUser(db, user.id, "password_reset");
      } catch (revokeError) {
        logger?.error?.(`[iam-lib] failed to revoke sessions after password reset for user ${user.id}:`, revokeError?.message);
      }

      logger?.info?.(`[iam-lib] password reset completed for user ${user.id}`);
      audit({ action: "user.password.reset.completed", userId: user.id, status: "success" });

      if (onPasswordReset) {
        try {
          await onPasswordReset({
            email: user.email,
            userName: [user.name, user.surname].filter(Boolean).join(" ") || user.email,
          });
        } catch (emailError) {
          logger?.error?.("[iam-lib] failed to send password reset confirmation:", emailError?.message);
        }
      }

      res.status(200).json({
        message: "Password has been reset successfully. You can now log in with your new password.",
      });
    } catch (err) {
      if (err.isJoi) {err.status = 422;}
      logger?.error?.("[iam-lib] reset password error:", err?.message);
      next(err);
    }
  };
}
