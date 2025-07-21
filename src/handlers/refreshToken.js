import createError from 'http-errors';

export default function refreshTokenHandler({ verifyRefreshToken, signAccessToken, signRefreshToken }) {
    return async (req, res, next) => {
        try {
            const { refreshToken } = req.body;
            if (!refreshToken) throw createError.BadRequest();

            const userId = await verifyRefreshToken(refreshToken);
            const newAccess = await signAccessToken(userId);
            const newRefresh = await signRefreshToken(userId);

            res.send({ accessToken: newAccess, refreshToken: newRefresh });
        } catch (err) {
            next(err);
        }
    };
}
