import createError from "http-errors";
import bcrypt from "bcrypt";
import { validatePasswordStrength } from "../utils/passwordPolicy.js";

/**
 * Change password for the authenticated user. Requires the current password.
 *
 * @param {object} deps
 * @param {import('knex').Knex} deps.db
 * @param {{ getById: (id: any) => Promise<object|null> }} deps.userRepo
 * @param {object} deps.logger
 * @param {Function} deps.audit
 * @param {Function} [deps.onPasswordChanged]  async (userId, { trx }) => void. Hosts revoke
 *   other sessions here if they want the change to end them.
 */
export default function changePwHandler({ db, userRepo, logger, audit, onPasswordChanged }) {
  return async (req, res, next) => {
    const userId = req.payload?.aud;
    const ip = req.ip || req.connection?.remoteAddress;
    const userAgent = req.get?.("user-agent");
    try {
      const { currentPassword, newPassword } = req.body || {};

      if (typeof currentPassword !== "string" || !currentPassword ||
          typeof newPassword !== "string" || !newPassword) {
        return res.status(400).json({ message: "Current and new passwords are required." });
      }

      const strength = await validatePasswordStrength(newPassword);
      if (!strength.valid) {
        return res.status(400).json({ message: strength.errors.join(". ") });
      }

      const user = await userRepo.getById(userId);
      if (!user) {
        throw createError.NotFound("User not found");
      }
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        audit({ action: "user.pw.change", userId, status: "failure", ip, meta: { userAgent, reason: "wrong_current_password" } });
        return res.status(400).json({ message: "Current password is incorrect." });
      }
      if (await bcrypt.compare(newPassword, user.password)) {
        return res.status(400).json({ message: "New password must be different from the current password." });
      }

      const hashed = await bcrypt.hash(newPassword, 10);
      await db.transaction(async (trx) => {
        await trx("users").where({ id: userId }).update({ password: hashed });
        if (onPasswordChanged) {
          await onPasswordChanged(userId, { trx });
        }
      });

      audit({ action: "user.pw.change", userId, status: "success", ip, meta: { userAgent } });
      return res.status(200).json({ message: "Password changed successfully." });
    } catch (err) {
      if (err.isJoi) {err.status = 422;}
      logger?.error?.("[iam-lib] change password error:", err?.message);
      audit({ action: "user.pw.change", userId, status: "failure", ip, meta: { userAgent } });
      next(err);
    }
  };
}
