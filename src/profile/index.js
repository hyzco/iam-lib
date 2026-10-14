import createError from "http-errors";

export const DEFAULT_UPDATABLE_FIELDS = Object.freeze(["name", "surname", "ext", "phone"]);

// Keys stripped from any profile response, whatever the repository returns.
const SECRET_KEY = /password|secret|mfa|reset_token|token_hash/i;

function stripSecrets(user) {
  const out = {};
  for (const key of Object.keys(user)) {
    if (!SECRET_KEY.test(key)) {out[key] = user[key];}
  }
  return out;
}

/**
 * Profile CRUD for the authenticated user.
 *
 * Authorization:
 *   - Read, update and delete always act on the caller (`req.payload.aud`) by default.
 *   - Reading another user (GET /:id) requires `canAccessOtherUsers(req, targetId)`
 *     to resolve true. Without it, the request is refused. Wire this to a role check.
 *
 * @param {object} deps
 * @param {(id: any) => Promise<object|null>} deps.getUserById
 * @param {(id: any, data: object) => Promise<unknown>} deps.updateUser
 * @param {(id: any) => Promise<unknown>} deps.deleteUser
 * @param {object} [deps.logger]
 * @param {string[]} [deps.updatableFields]           allowlist for updateProfile
 * @param {(req: object, targetId: any) => boolean|Promise<boolean>} [deps.canAccessOtherUsers]
 */
export default function createProfileHandlers({
  getUserById,
  updateUser,
  deleteUser,
  logger = console,
  updatableFields = DEFAULT_UPDATABLE_FIELDS,
  canAccessOtherUsers,
}) {
  const allowedUpdates = new Set(updatableFields);

  const requireCaller = (req) => {
    const self = req.payload?.aud;
    if (self == null) {throw createError.Unauthorized("Authentication required");}
    return self;
  };

  return {
    getProfile: async (req, res, next) => {
      try {
        const self = requireCaller(req);
        const targetId = req.params?.id ?? self;

        if (String(targetId) !== String(self)) {
          const allowed = canAccessOtherUsers
            ? await canAccessOtherUsers(req, targetId)
            : false;
          if (!allowed) {throw createError.Forbidden("Not allowed to view this profile");}
        }

        const user = await getUserById(targetId);
        if (!user) {throw createError.NotFound("User not found");}
        res.send({ user: stripSecrets(user) });
      } catch (err) {
        logger?.error?.("[iam-lib] getProfile error:", err?.message);
        next(err);
      }
    },

    updateProfile: async (req, res, next) => {
      try {
        const self = requireCaller(req);
        const body = req.body && typeof req.body === "object" ? req.body : {};
        const changes = {};
        for (const key of Object.keys(body)) {
          if (allowedUpdates.has(key)) {changes[key] = body[key];}
        }
        if (Object.keys(changes).length === 0) {
          throw createError.BadRequest("No updatable fields provided");
        }
        await updateUser(self, changes);
        res.send({ message: "Profile updated" });
      } catch (err) {
        logger?.error?.("[iam-lib] updateProfile error:", err?.message);
        next(err);
      }
    },

    deleteProfile: async (req, res, next) => {
      try {
        const self = requireCaller(req);
        await deleteUser(self);
        res.send({ message: "Profile deleted" });
      } catch (err) {
        logger?.error?.("[iam-lib] deleteProfile error:", err?.message);
        next(err);
      }
    },
  };
}
