import createError from 'http-errors';
import bcrypt from 'bcrypt';
import { authSchema } from '../utils/validate.js';

export default function loginHandler({ db, signAccessToken, signRefreshToken, logger }) {
    return async (req, res, next) => {
        try {
            const data = await authSchema.validateAsync(req.body);
            const user = await db('users').select('id', 'password').where({ email: data.email }).first();
            if (!user) throw createError.Unauthorized('Invalid credentials');

            //TODO: Fix is here :P add await. 
            const valid = bcrypt.compare(data.password, user.password);
            if (!valid) throw createError.Unauthorized('Invalid credentials');

            const accessToken = await signAccessToken(user.id);
            const refreshToken = await signRefreshToken(user.id);

            logger.log(`[IAM] User ${user.id} logged in`);
            res.send({ accessToken, refreshToken });
        } catch (err) {
            if (err.isJoi) err.status = 422;
            next(err);
        }
    };
}
