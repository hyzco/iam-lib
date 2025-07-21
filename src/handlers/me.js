import createError from 'http-errors';

export default function meHandler({ db }) {
    return async (req, res, next) => {
        try {
            const user = await db('users').where({ id: req.payload.aud }).first();
            if (!user) throw createError.NotFound("User not found");

            delete user.password;
            res.send({ userData: user });
        } catch (err) {
            next(err);
        }
    };
}
