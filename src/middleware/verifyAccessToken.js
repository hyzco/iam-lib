import jwt from 'jsonwebtoken';
import createError from 'http-errors';

/**
 * Express middleware to extract and verify the Authorization header.
 * Injects `req.payload` with the decoded JWT payload.
 * Uses HS256 or RS256 depending on config.
 *
 * @param {{ key: string, algorithm: 'HS256' | 'RS256' }} config
 */
export function accessTokenMiddleware({ key, algorithm = 'RS256' }) {
  return function (req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    if (!token) return next(createError.Unauthorized());

    jwt.verify(token, key, { algorithms: [algorithm] }, (err, payload) => {
      if (err) return next(createError.Unauthorized());
      req.payload = payload;
      next();
    });
  };
}


/**
 * Creates a token verifier using the specified public key and algorithm.
 * @param {{ key: string, algorithm: 'HS256' | 'RS256' }} config
 */
export function createAccessTokenVerifier({ key, algorithm = 'RS256' }) {
  return function verifyAccessToken(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, key, { algorithms: [algorithm] }, (err, payload) => {
        if (err) {
          const message =
            err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message;
          return reject(createError.Unauthorized(message));
        }
        resolve(payload);
      });
    });
  };
}