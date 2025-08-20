import createError from 'http-errors';
import bcrypt from 'bcrypt';
import { authSchema } from '../utils/validate.js';

export default function registerHandler({ db, tokenService, logger, audit }) {
    return async (req, res, next) => {
        try {
            const data = await authSchema.validateAsync(req.body);

            const existing = await db('users')
                .select('id')
                .where({ email: data.email })
                .first();

            if (existing) throw createError.Conflict(`${data.email} already registered`);

            const hashed = await bcrypt.hash(data.password, 10);
            const [id] = await db('users')
                .insert({
                    ...data,
                    password: hashed,
                    role: 'user',
                });

            const accessToken = await tokenService.signAccessToken(id);
            const refreshToken = await tokenService.signRefreshToken(id);

            audit({ action: 'user.register', userId: id });
            res.status(201).send({ accessToken, refreshToken });
        } catch (err) {
            if (err.isJoi) err.status = 422;
            next(err);
        }
    };
}
