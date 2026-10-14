import createError from "http-errors";
import { generateResetToken, hashResetToken } from "../utils/resetToken.js";

const RESET_TTL_MS = 60 * 60 * 1000; // 1 hour
const GENERIC_MESSAGE = "If an account with that email exists, a password reset link has been sent.";

const isDeadlock = (err) => {
  const code = err && (err.code || err.errno);
  return code === "ER_LOCK_DEADLOCK" || code === 1213 || code === "ER_LOCK_WAIT_TIMEOUT" || code === 1205;
};

/**
 * Forgot-password endpoint.
 *
 * Responses are the same for known and unknown emails, and every response is
 * padded to a uniform 350-400 ms. Without the pad, the account branch (DB write,
 * token mint, email enqueue) is much slower than the miss branch, which gives
 * an account-enumeration timing oracle.
 *
 * @param {object} deps
 * @param {import('knex').Knex} deps.db
 * @param {object} deps.logger
 * @param {Function} deps.audit
 * @param {Function} [deps.onTokenGenerated]  async ({ email, userName, resetToken, expiresIn }) => void
 */
export default function forgotPasswordHandler({ db, logger, audit, onTokenGenerated }) {
  return async (req, res, next) => {
    const padMs = 350 + Math.floor(Math.random() * 50);
    const padPromise = new Promise((resolve) => setTimeout(resolve, padMs));

    const work = (async () => {
      const { email } = req.body || {};
      // Non-string input is rejected before the query. Otherwise an object such as
      // {"$ne": null} reaches the query builder and yields a 500 with internals.
      if (typeof email !== "string" || !email) {
        throw createError.BadRequest("Email is required");
      }

      const user = await db("users").select("id", "email", "name").where({ email }).first();

      if (user) {
        const resetToken = generateResetToken();
        const expiresAt = new Date(Date.now() + RESET_TTL_MS);
        const storedToken = hashResetToken(resetToken);

        // Concurrent requests for one user must not race the delete+insert. Lock the
        // user's open tokens, replace them, and retry once on a deadlock.
        const writeToken = () => db.transaction(async (trx) => {
          await trx("password_reset_tokens")
            .where({ user_id: user.id })
            .whereNull("used_at")
            .forUpdate()
            .select("id");

          await trx("password_reset_tokens")
            .where({ user_id: user.id })
            .whereNull("used_at")
            .delete();

          await trx("password_reset_tokens").insert({
            user_id: user.id,
            token: storedToken,
            expires_at: expiresAt,
            created_at: new Date(),
          });
        });

        try {
          await writeToken();
        } catch (txErr) {
          if (!isDeadlock(txErr)) {throw txErr;}
          logger?.warn?.(`[iam-lib] forgot-password write deadlocked for user ${user.id}; retrying once`);
          await writeToken();
        }

        logger?.info?.(`[iam-lib] password reset token issued for user ${user.id}`);
        audit({ action: "user.password.reset.requested", userId: user.id, status: "success" });

        if (onTokenGenerated) {
          try {
            await onTokenGenerated({
              email: user.email,
              userName: user.name || user.email,
              resetToken,
              expiresIn: "1 hour",
            });
          } catch (emailError) {
            // Delivery failure must not reveal whether the account exists.
            logger?.error?.("[iam-lib] failed to send password reset email:", emailError?.message);
          }
        }
      } else {
        audit({ action: "user.password.reset.requested", status: "user_not_found" });
      }

      return { success: true, message: GENERIC_MESSAGE };
    })();

    try {
      const [body] = await Promise.all([work, padPromise]);
      res.status(200).json(body);
    } catch (err) {
      await padPromise;
      logger?.error?.("[iam-lib] forgot password error:", err?.message);
      next(err);
    }
  };
}
