import createError from 'http-errors';

export default function logoutHandler({ verifyRefreshToken, redis, logger }) {
    return async (req, res, next) => {
        try {
            const { refreshToken } = req.body;
            if (!refreshToken) throw createError.BadRequest();

            const userId = await verifyRefreshToken(refreshToken);
            if (redis) await redis.del(userId);

            logger.log(`[IAM] User ${userId} logged out`);
            res.sendStatus(204);
        } catch (err) {
            logger.error('[IAM] Logout failed', err);
            next(err);
        }
    };
}
