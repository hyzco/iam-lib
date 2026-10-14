import Joi from "joi";
import { passwordJoi } from "./passwordPolicy.js";

/**
 * Registration body. Unknown keys are tolerated here but never written to the
 * database: the register handler inserts an explicit whitelist only.
 *
 * Hosts that need extra required fields (for example consent flags) pass their
 * own schema via `registerSchema` in createIamHandlers, which is concatenated
 * onto this base.
 */
export const registerBaseSchema = Joi.object({
  email: Joi.string().email().required(),
  password: passwordJoi,
  name: Joi.string().max(255).optional(),
  surname: Joi.string().max(255).optional(),
  ext: Joi.string().max(32).optional(),
  phone: Joi.string().max(64).optional(),
  captchaToken: Joi.string().allow("").optional(),
}).unknown(true);

/**
 * Login is intentionally lax on password strength: accounts may predate the policy.
 */
export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  captchaToken: Joi.string().optional(),
}).unknown(true);

/**
 * @param {Joi.ObjectSchema} [extra]
 * @returns {Joi.ObjectSchema}
 */
export function buildRegisterSchema(extra) {
  return extra ? registerBaseSchema.concat(extra) : registerBaseSchema;
}
