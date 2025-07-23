import jwt from 'jsonwebtoken';
import createError from 'http-errors';

const accessTokenLife = process.env.ACCESS_TOKEN_LIFE || '15m';
const refreshTokenLife = process.env.REFRESH_TOKEN_LIFE || '7d';

/**
 * Sign an access token for a given user ID.
 * @param {string|number} userId
 * @returns {Promise<string>}
 */
export function signAccessToken(userId) {
  return new Promise((resolve, reject) => {
    const payload = {};
    const options = {
      expiresIn: accessTokenLife,
      audience: userId.toString(),
    };

    console.log("=================")
    console.log("access token   ", process.env)
    jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, options, (err, token) => {
      if (err) {
        console.log(err);
        reject(createError.InternalServerError('Failed to sign access token'));
      }
      resolve(token);
    });
  });
}

/**
 * Sign a refresh token for a given user ID.
 * @param {string|number} userId
 * @returns {Promise<string>}
 */
export function signRefreshToken(userId) {
  return new Promise((resolve, reject) => {
    const payload = {};
    const options = {
      expiresIn: refreshTokenLife,
      audience: userId.toString(),
    };

    jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, options, (err, token) => {
      if (err) {
        reject(createError.Internal('Failed to sign refresh token'));
      }
      resolve(token);
    });
  });
}

/**
 * Verify an access token and extract the payload.
 * @param {string} token
 * @returns {Promise<object>}
 */
export function verifyAccessToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
      console.log("==========================", err)
      if (err) {
        const message =
          err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message;
        return reject(createError.Unauthorized(message));
      }
      resolve(payload);
    });
  });
}
  // jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
  //       if (err) return next(createError.Unauthorized());
  //       req.payload = payload;
  //       next();
  //   });
/**
 * Verify a refresh token and return the user ID.
 * @param {string} token
 * @returns {Promise<string>} userId
 */
export function verifyRefreshToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
      if (err) return reject(createError.Unauthorized());

      const userId = payload.aud;
      resolve(userId);
    });
  });
}
