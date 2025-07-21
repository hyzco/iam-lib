export default function requireRole(roles = []) {
  return (requiredRole) => {
    return (req, res, next) => {
      const userRole = req.payload?.role;
      if (!userRole || roles.indexOf(userRole) < roles.indexOf(requiredRole)) {
        return res.status(403).send('Forbidden');
      }
      next();
    };
  };
}
