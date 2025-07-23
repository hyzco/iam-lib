import UserModel from "@classes/DB/models/User.js";

export default function requireRole(roles = []) {
  return (requiredRole) => {
    return (req, res, next) => {
      const user = new UserModel(req.payload.aud);
      if (!user) {
        return res.status(403).send('Forbidden');
      };
      user.getRole().then((role) => {
        if (!role || roles.indexOf(role) < roles.indexOf(requiredRole)) {
          return res.status(403).send('Forbidden');
        }
      })

      next();
    };
  };
}
