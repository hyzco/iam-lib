import jwt from 'jsonwebtoken';
import loginHandler from './handlers/login.js';
import registerHandler from './handlers/register.js';
import refreshTokenHandler from './handlers/refreshToken.js';
import logoutHandler from './handlers/logout.js';
import meHandler from './handlers/me.js';
import { accessTokenMiddleware, createAccessTokenVerifier } from './middleware/verifyAccessToken.js';
import requireRole from './middleware/requireRole.js';
import createRateLimiter from './middleware/rateLimiter.js'
import createProfileHandlers from './profile/index.js';
import auditLogger from './events/auditLogger.js';
import changePwHandler from './handlers/changePw.js';


/**
 * Verifies a JWT from a service account
 */
function verifyServiceToken(token, publicKey) {
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

/**
 * Issues a JWT for a service account
 */
function issueServiceToken(id) {
  const account = serviceAccounts.get(id);
  if (!account) throw new Error('Service account not found');

  const token = jwt.sign(
    {
      sub: id,
      scopes: account.scopes,
      type: 'service',
    },
    account.secret,
    {
      algorithm: 'RS256',
      expiresIn: '1h',
      issuer: 'iam-lib'
    }
  );

  return token;
}

/**
 * @returns {import('iam-lib').IamHandlers}
 */
export function createIamHandlers({
  db,
  redis,
  logger = console,
  roles = [],
  rbacMiddleware,
  userRepo,
  tokenService,
  getRole,
  overrides = {}
}) {
  const audit = auditLogger({ logger });
  const rateLimiter = createRateLimiter({ windowMs: 60000, max: 60 });

  const { key, algorithm } = tokenService.getArgs();
  const verifyAccessToken = createAccessTokenVerifier({ key, algorithm });
  const accessToken = accessTokenMiddleware({ key, algorithm });
  const requireRoleMiddleware = requireRole({ roles, getRole });

  const wrap = (override, fallback) => {
    if (Array.isArray(override)) return override;
    if (typeof override === 'function') return [override];
    if (!override) return [fallback];
    return [fallback];
  };

  const fallbacks = {
    me: [rateLimiter, meHandler({ userRepo })],
    login: [rateLimiter, loginHandler({ db, tokenService, logger, audit })],
    register: [rateLimiter, registerHandler({ db, tokenService, logger, audit })],
    logout: [rateLimiter, logoutHandler({ redis, tokenService, logger })],
    refreshToken: [rateLimiter, refreshTokenHandler({ tokenService })],
    changePw: [rateLimiter, changePwHandler({ db, userRepo, logger, audit })],
  }


  return {
    me: wrap(overrides.me, fallbacks.me),
    login: wrap(overrides.login, fallbacks.login),
    register: wrap(overrides.register, fallbacks.register),
    logout: wrap(overrides.logout, fallbacks.logout),
    changePw: wrap(overrides.changePw, fallbacks.changePw),
    refreshToken: wrap(overrides.refreshToken, fallbacks.refreshToken),
    requireRole: rbacMiddleware || requireRoleMiddleware,
    profile: createProfileHandlers({
      db,
      getUserById: userRepo.getById,
      updateUser: userRepo.update,
      deleteUser: userRepo.delete,
      logger
    }),
    verifyAccessToken,              // for tokenService-style verification
    accessTokenMiddleware: accessToken, // for route protection
    issueServiceToken,
    verifyServiceToken,
    rateLimiter,
    tokenService
  };

}
