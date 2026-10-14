import createError from "http-errors";

// Fields returned by GET /me by default. Anything not listed is dropped, so
// secrets (password, MFA secret, reset tokens, OAuth ids) can never leak through
// this endpoint. Hosts extend the list with `meFields`.
export const DEFAULT_ME_FIELDS = Object.freeze([
  "id",
  "email",
  "name",
  "surname",
  "username",
  "display_name",
  "avatar_url",
  "role",
  "status",
  "phone",
  "country",
  "timezone",
  "language",
  "email_verified_at",
  "mfa_enabled",
  "created_at",
  "updated_at",
  "last_login_at",
]);

/**
 * @param {Record<string, unknown>} user
 * @param {Set<string>} allowed
 */
export function pickFields(user, allowed) {
  if (!user || typeof user !== "object") {return user;}
  const out = {};
  for (const key of Object.keys(user)) {
    if (allowed.has(key)) {out[key] = user[key];}
  }
  return out;
}

/**
 * @param {object} deps
 * @param {{ getById: (id: any) => Promise<object|null> }} deps.userRepo
 * @param {string[]} [deps.meFields]
 */
export default function meHandler({ userRepo, meFields = DEFAULT_ME_FIELDS }) {
  const allowed = new Set(meFields);
  return async (req, res, next) => {
    try {
      const userId = req.payload?.aud;
      const user = await userRepo.getById(userId);
      if (!user) {throw createError.NotFound("User not found");}
      res.send({ userData: pickFields(user, allowed) });
    } catch (err) {
      next(err);
    }
  };
}
