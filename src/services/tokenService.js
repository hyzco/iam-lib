import jwt from 'jsonwebtoken';

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