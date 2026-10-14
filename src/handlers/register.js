import createError from "http-errors";
import bcrypt from "bcrypt";
import { buildRegisterSchema } from "../utils/validate.js";
import { validatePasswordStrength } from "../utils/passwordPolicy.js";
import { verifyCaptcha } from "../utils/captcha.js";
import { issueRefreshToken } from "../services/refreshTokenStore.js";
import { toBoolean } from "../config/runtime.js";

// Columns a registration may write. Anything else in the request body is ignored,
// so client input can never set role, status or other privileged columns.
const INSERT_COLUMNS = ["email", "name", "surname", "ext", "phone"];

const isDuplicateKeyError = (err) =>
  err?.code === "ER_DUP_ENTRY" || err?.code === "23505" || err?.errno === 1062;

/**
 * Resolve a boolean option that may be a static value or a resolver.
 * @param {boolean|(() => boolean|Promise<boolean>)|undefined} option
 * @param {boolean} fallback
 */
async function resolveFlag(option, fallback) {
  if (option === undefined) {return fallback;}
  return typeof option === "function" ? toBoolean(await option(), fallback) : Boolean(option);
}

/**
 * @param {object} deps
 * @param {import('knex').Knex} deps.db
 * @param {object} deps.tokenService
 * @param {object} deps.logger
 * @param {Function} deps.audit
 * @param {boolean|Function} [deps.allowRegistration=true]    static or resolver; false returns 403
 * @param {boolean|Function} [deps.requireAdminApproval=false] new accounts start inactive when true
 * @param {import('joi').ObjectSchema} [deps.registerSchema]   extra Joi rules merged onto the base schema
 * @param {(req) => string|null|Promise<string|null>} [deps.resolveTenantId]
 * @param {(data, req) => object|Promise<object>} [deps.extraUserFields] additional columns to insert
 * @param {(user, ctx) => void|Promise<void>} [deps.onUserCreated] e.g. onboarding, domain events
 * @param {string} [deps.defaultTenantId='default']
 */
export default function registerHandler({
  db,
  tokenService,
  logger,
  audit,
  allowRegistration,
  requireAdminApproval,
  registerSchema,
  resolveTenantId,
  extraUserFields,
  onUserCreated,
  defaultTenantId = "default",
}) {
  const schema = buildRegisterSchema(registerSchema);

  return async (req, res, next) => {
    try {
      if (!(await resolveFlag(allowRegistration, true))) {
        throw createError.Forbidden("New user registration is currently disabled.");
      }
      const approvalRequired = await resolveFlag(requireAdminApproval, false);

      const data = await schema.validateAsync(req.body);

      const strength = await validatePasswordStrength(data.password);
      if (!strength.valid) {
        throw createError.BadRequest(strength.errors.join(". "));
      }

      // Captcha is verified server-side. Failure is a generic 400 so the client
      // cannot tell a bad token from a configuration problem.
      const captchaValid = await verifyCaptcha(data.captchaToken, req.ip);
      if (!captchaValid) {
        throw createError.BadRequest("Captcha verification failed. Please try again.");
      }

      const existing = await db("users").select("id").where({ email: data.email }).first();
      if (existing) {throw createError.Conflict(`${data.email} already registered`);}

      const hashed = await bcrypt.hash(data.password, 10);

      const record = { password: hashed, role: "user" };
      for (const column of INSERT_COLUMNS) {
        if (data[column] !== undefined) {record[column] = data[column];}
      }
      if (resolveTenantId) {
        record.tenant_id = (await resolveTenantId(req)) || defaultTenantId;
      }
      // Written whenever the option is configured, so hosts that gate activation
      // always get an explicit value. Left out entirely when unconfigured.
      if (requireAdminApproval !== undefined) {
        record.is_active = !approvalRequired;
      }
      if (extraUserFields) {
        Object.assign(record, await extraUserFields(data, req));
      }

      let id;
      try {
        [id] = await db("users").insert(record);
      } catch (err) {
        if (isDuplicateKeyError(err)) {
          throw createError.Conflict(`${data.email} already registered`);
        }
        throw err;
      }

      const tenantId = record.tenant_id || defaultTenantId;
      const user = { id, email: data.email, role: "user", tenant_id: tenantId };

      // Issue a tracked refresh token. An untracked one would fail at the first refresh.
      const { token: refreshToken, familyId } = await issueRefreshToken({ db, tokenService, userId: id, req });
      const accessToken = await tokenService.signAccessToken(id, {
        role: "user",
        email: data.email,
        tenantId,
        sid: familyId,
      });

      audit({ action: "user.register", userId: id, status: "success", ip: req.ip || req.connection?.remoteAddress });

      if (onUserCreated) {
        try {
          await onUserCreated(user, { data, req });
        } catch (hookErr) {
          // The account exists; a failing side effect must not turn into a failed registration.
          logger?.error?.("[iam-lib] onUserCreated hook failed:", hookErr?.message);
        }
      }

      res.status(201).send({ accessToken, refreshToken });
    } catch (err) {
      if (err.isJoi) {err.status = 422;}
      next(err);
    }
  };
}
