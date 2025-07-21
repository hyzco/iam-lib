import createError from 'http-errors';
import bcrypt from 'bcrypt';
import { authSchema } from '../utils/validate.js';

export default function registerHandler({ db, signAccessToken, signRefreshToken, logger }) {
    return async (req, res, next) => {
        try {
            const data = await authSchema.validateAsync(req.body);

            const existing = await db('users').select('id').where({ email: data.email }).first();
            if (existing) throw createError.Conflict(`${data.email} already registered`);

            const hashed = await bcrypt.hash(data.password, 10);
            const [id] = await db('users').insert({
                ...data,
                password: hashed,
                role: 'user'
            }).returning('id');

            const accessToken = await signAccessToken(id);
            const refreshToken = await signRefreshToken(id);

            logger.log(`[IAM] User registered with ID ${id}`);
            res.status(201).send({ accessToken, refreshToken });
        } catch (err) {
            if (err.isJoi) err.status = 422;
            next(err);
        }
    };
}
