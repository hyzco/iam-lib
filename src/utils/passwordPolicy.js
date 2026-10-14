/**
 * Password strength policy.
 *
 * One definition shared by register, change-password and reset-password.
 * The fixed floor below is always enforced. Optional runtime settings
 * (security.password_min_length, security.password_require_special_chars)
 * can only tighten it, never relax it.
 */

import Joi from "joi";
import { readSetting, toBoolean } from "../config/runtime.js";

export const PASSWORD_MIN_LENGTH = 8;

export const PASSWORD_REQUIREMENTS = [
  `At least ${PASSWORD_MIN_LENGTH} characters`,
  "At least one uppercase letter",
  "At least one lowercase letter",
  "At least one number",
];

async function getPolicy() {
  const [minLengthSetting, requireSpecialSetting] = await Promise.all([
    readSetting("security", "password_min_length", PASSWORD_MIN_LENGTH),
    readSetting("security", "password_require_special_chars", false),
  ]);
  const configuredMinLength = Number.parseInt(String(minLengthSetting), 10);
  return {
    minLength: Number.isFinite(configuredMinLength) && configuredMinLength > PASSWORD_MIN_LENGTH
      ? configuredMinLength
      : PASSWORD_MIN_LENGTH,
    requireSpecialChars: toBoolean(requireSpecialSetting, false),
  };
}

/**
 * @param {string} password
 * @returns {Promise<{ valid: boolean, errors: string[] }>}
 */
export async function validatePasswordStrength(password) {
  const errors = [];
  const { minLength, requireSpecialChars } = await getPolicy();
  const value = typeof password === "string" ? password : "";

  if (value.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }
  if (!/[A-Z]/.test(value)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  if (!/[a-z]/.test(value)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  if (!/\d/.test(value)) {
    errors.push("Password must contain at least one number");
  }
  if (requireSpecialChars && !/[^A-Za-z0-9]/.test(value)) {
    errors.push("Password must contain at least one special character");
  }
  return { valid: errors.length === 0, errors };
}

/**
 * Joi rule for the fixed floor, for schema-based validation at register time.
 */
export const passwordJoi = Joi.string()
  .min(PASSWORD_MIN_LENGTH)
  .pattern(/[A-Z]/, "uppercase")
  .pattern(/[a-z]/, "lowercase")
  .pattern(/\d/, "number")
  .required()
  .messages({
    "string.min": `Password must be at least ${PASSWORD_MIN_LENGTH} characters long`,
    "string.pattern.name": "Password must contain at least one {#name} character",
    "any.required": "Password is required",
    "string.empty": "Password is required",
  });
