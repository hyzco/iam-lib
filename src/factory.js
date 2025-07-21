import loginHandler from './handlers/login.js';
import registerHandler from './handlers/register.js';
import refreshTokenHandler from './handlers/refreshToken.js';
import logoutHandler from './handlers/logout.js';
import meHandler from './handlers/me.js';
import verifyAccessToken from './middleware/verifyAccessToken.js';
import requireRole from './middleware/requireRole.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from './utils/jwt.js';

/**
 * @returns {import('iam-lib').IamHandlers}
 */
export function createIamHandlers({ db, redis, logger = console, roles = [], rbacMiddleware }) {
  return {
    login: loginHandler({ db, signAccessToken, signRefreshToken, logger }),
    register: registerHandler({ db, signAccessToken, signRefreshToken, logger }),
    refreshToken: refreshTokenHandler({ verifyRefreshToken, signAccessToken, signRefreshToken }),
    logout: logoutHandler({ verifyRefreshToken, redis, logger }),
    me: meHandler({ db }),
    verifyAccessToken,
    requireRole: rbacMiddleware || requireRole(roles)
  };
}
