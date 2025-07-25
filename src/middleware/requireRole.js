import createError from 'http-errors';

/**
 * Returns a role-based middleware
 * @returns {(requiredRole: string) => Middleware}
 */
export default function requireRole({ roles, getRole }) {
  return (requiredRole) => {
    return async (req, res, next) => {
      try {
        const userId = req.payload?.aud;
        if (!userId) return next(createError.Forbidden());

        const userRole = await getRole(userId);
        if (userRole === null) return (next(createError.NotFound("User not found.")))
        if (!userRole) return next(createError.Forbidden('No role assigned'));

        const userIndex = roles.indexOf(userRole);
        const requiredIndex = roles.indexOf(requiredRole);

        if (userIndex < 0 || userIndex < requiredIndex) {
          return next(createError.Forbidden('Insufficient role'));
        }

        next();
      } catch (err) {
        next(createError.InternalServerError());
      }
    };
  };
}
