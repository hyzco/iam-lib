import createError from "http-errors";
import { normalizeRole } from "../roles.js";

/**
 * Returns a role-based middleware.
 *
 * `roles` is an ordered privilege ladder (lowest first), e.g. ["user", "admin", "support"].
 * A caller satisfies the guard when its role ranks at or above the required role.
 *
 * `requiredRole` accepts either a single role or a list of roles. A list means OR:
 * the caller passes if it satisfies ANY of the listed roles. Unknown role names in
 * the list are ignored (they are not part of the ladder); if NONE of the listed roles
 * is known, the guard denies rather than degrading to "any authenticated user".
 *
 * @returns {(requiredRole: string | string[]) => Middleware}
 */
export default function requireRole({ roles, getRole }) {
  return (requiredRole) => {
    const required = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    const requiredIndexes = required
      .map((role) => roles.indexOf(normalizeRole(role) ?? ""))
      .filter((index) => index >= 0);

    return async (req, res, next) => {
      try {
        const userId = req.payload?.aud;
        if (!userId) {return next(createError.Forbidden());}

        // No recognised role was requested — deny instead of letting everyone through.
        if (requiredIndexes.length === 0) {
          return next(createError.Forbidden("Insufficient role"));
        }

        const userRole = await getRole(userId);
        if (userRole === null) {return (next(createError.NotFound("User not found.")));}
        if (!userRole) {return next(createError.Forbidden("No role assigned"));}

        const userIndex = roles.indexOf(normalizeRole(userRole) ?? "");
        const minRequiredIndex = Math.min(...requiredIndexes);

        if (userIndex < 0 || userIndex < minRequiredIndex) {
          return next(createError.Forbidden("Insufficient role"));
        }

        next();
      } catch (err) {
        next(createError.InternalServerError());
      }
    };
  };
}
