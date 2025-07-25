import createError from 'http-errors';

export default function refreshTokenHandler({ tokenService }) {
    return async (req, res, next) => {
        try {
            const { refreshToken } = req.body;
            if (!refreshToken) throw createError.BadRequest();

            const userId = await tokenService.verifyRefreshToken(refreshToken);
            const newAccess = await tokenService.signAccessToken(userId);
            const newRefresh = await tokenService.signRefreshToken(userId);

            res.send({ accessToken: newAccess, refreshToken: newRefresh });
        } catch (err) {
            next(err);
        }
    };
}
