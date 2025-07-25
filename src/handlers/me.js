import createError from 'http-errors';

export default function meHandler({ userRepo }) {
    return async (req, res, next) => {
        try {
            const userId = req.payload?.aud;
            const user = await userRepo.getById(userId);

            if (!user) throw createError.NotFound('User not found');

            delete user.password;
            res.send({ userData: user });
        } catch (err) {
            next(err);
        }
    };
}
