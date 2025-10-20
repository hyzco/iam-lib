import jwt from 'jsonwebtoken';

/**
 * Creates a token service for handling JWT tokens
 * @param {Object} options - The configuration options
 * @param {string} [options.algorithm='RS256'] - The JWT signing algorithm
 * @param {string} [options.privateKey] - Private key for RS256 algorithm
 * @param {string} [options.publicKey] - Public key for RS256 algorithm verification
 * @param {string} [options.accessSecret] - Secret for HS256 access token
 * @param {string} [options.refreshSecret] - Secret for HS256 refresh token
 * @param {string} [options.accessExpiresIn='15m'] - Access token expiration time
 * @param {string} [options.refreshExpiresIn='7d'] - Refresh token expiration time
 * @returns {Object} Token service object
 * @returns {Function} service.signAccessToken - Signs access token with user ID and optional claims
 * @returns {Function} service.signRefreshToken - Signs refresh token with user ID
 * @returns {Function} service.verifyAccessToken - Verifies access token
 * @returns {Function} service.verifyRefreshToken - Verifies refresh token
 * @returns {Function} service.getArgs - Returns verification key and algorithm
 * @throws {Error} When token signing or verification fails
 */
export default function createTokenService({
  algorithm = 'RS256',
  privateKey,
  publicKey,
  accessSecret,
  refreshSecret,
  accessExpiresIn = '15m',
  refreshExpiresIn = '7d',
}) {
  const accessKey = algorithm === 'RS256' ? privateKey : accessSecret;
  const refreshKey = algorithm === 'RS256' ? privateKey : refreshSecret;
  const verifyKey = algorithm === 'RS256' ? publicKey : accessSecret;

  return {
    signAccessToken: (userId, claims = {}) =>
      new Promise((res, rej) =>
        jwt.sign(
          { ...claims, aud: userId },
          accessKey,
          { algorithm, expiresIn: accessExpiresIn },
          (e, t) => (e ? rej(e) : res(t))
        )
      ),
    signRefreshToken: (userId) =>
      new Promise((res, rej) =>
        jwt.sign(
          { aud: userId },
          refreshKey,
          { algorithm, expiresIn: refreshExpiresIn },
          (e, t) => (e ? rej(e) : res(t))
        )
      ),
    verifyAccessToken: (token) =>
      new Promise((res, rej) =>
        jwt.verify(token, verifyKey, { algorithms: [algorithm] }, (e, p) => (e ? rej(e) : res(p)))
      ),
    verifyRefreshToken: (token) =>
      new Promise((res, rej) =>
        jwt.verify(token, verifyKey, { algorithms: [algorithm] }, (e, p) => (e ? rej(e) : res(p)))
      ),
    getArgs: () => ({
      key: verifyKey,
      algorithm
    })
  };
}