import createError from 'http-errors';
import jwt from 'jsonwebtoken';

export default function verifyAccessToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) return next(createError.Unauthorized());
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
        if (err) return next(createError.Unauthorized());
        req.payload = payload;
        next();
    });
}
