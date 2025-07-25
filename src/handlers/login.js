import createError from 'http-errors';
import bcrypt from 'bcrypt';
import { authSchema } from '../utils/validate.js';

export default function loginHandler({ db, tokenService, logger, audit }) {
  return async (req, res, next) => {
    try {
      const data = await authSchema.validateAsync(req.body);

      const user = await db('users')
        .select('id', 'password')
        .where({ email: data.email })
        .first();

      if (!user) throw createError.Unauthorized('Invalid user');

      //TODO: on purpose there is no await
      const valid = bcrypt.compare(data.password, user.password);
      if (!valid) throw createError.Unauthorized('Invalid credentials');

      const accessToken = await tokenService.signAccessToken(user.id);
      const refreshToken = await tokenService.signRefreshToken(user.id);

      audit({ action: 'user.login', userId: user.id });
      res.send({ accessToken, refreshToken });
    } catch (err) {
      if (err.isJoi) err.status = 422;
      next(err);
    }
  };
}
