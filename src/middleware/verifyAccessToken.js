import jwt from "jsonwebtoken";
import createError from "http-errors";

/**
 * Token types accepted by the general access-token middleware.
 *
 * Tokens carry a `type` claim so one signing key can safely serve several token
 * kinds. Only "access" is a session token. Every other type (refresh, MFA
 * challenge, MFA enrollment, service) must be rejected here, otherwise a
 * short-lived partial credential becomes a full session.
 *
 * Tokens minted before the `type` claim existed carry no type. They are still
 * accepted so existing sessions survive an upgrade. Set `strictTokenType: true`
 * once every outstanding token has expired.
 */
const SESSION_TOKEN_TYPES = new Set(["access"]);

/**
 * Normalize a single key or {key, keys} config into a non-empty key array.
 * `keys` takes precedence; the first key is the primary (signing counterpart).
 */
export function resolveVerifyKeys({ key, keys } = {}) {
  const list = (Array.isArray(keys) ? keys : keys ? [keys] : [])
    .concat(key ? [key] : [])
    .filter(Boolean);
  return [...new Set(list)];
}

/**
 * Verify a token against a list of keys. The first key that verifies wins.
 * Used to accept retired keys during a rotation overlap.
 *
 * Only signature mismatches advance to the next key. Expiry and not-before
 * failures are key-independent and reject immediately.
 *
 * @param {string} token
 * @param {string|string[]} keys
 * @param {'HS256'|'RS256'} algorithm
 * @returns {Promise<object>} decoded payload
 */
export function verifyWithKeys(token, keys, algorithm = "RS256") {
  const list = Array.isArray(keys) ? keys.filter(Boolean) : [keys].filter(Boolean);
  return new Promise((resolve, reject) => {
    if (list.length === 0) {
      return reject(createError.Unauthorized("No verification key configured"));
    }
    let i = 0;
    const tryNext = () => {
      if (i >= list.length) {
        return reject(createError.Unauthorized("Invalid token"));
      }
      jwt.verify(token, list[i++], { algorithms: [algorithm] }, (err, payload) => {
        if (!err) {return resolve(payload);}
        if (err.name === "TokenExpiredError" || err.name === "NotBeforeError") {
          const expired = createError.Unauthorized("Invalid or expired token");
          expired.tokenReason = err.name === "TokenExpiredError" ? "expired" : "not_yet_valid";
          return reject(expired);
        }
        tryNext();
      });
    };
    tryNext();
  });
}

/**
 * Is this decoded payload acceptable as a session access token?
 * @param {object} payload
 * @param {{ strictTokenType?: boolean }} [opts]
 * @returns {boolean}
 */
export function isSessionTokenType(payload, opts = {}) {
  if (payload?.type === undefined) {return !opts.strictTokenType;}
  return SESSION_TOKEN_TYPES.has(payload.type);
}

/**
 * Express middleware: verifies `Authorization: Bearer <token>` and sets `req.payload`.
 *
 * Client-facing errors are deliberately generic. The specific reason is recorded
 * on `req.authFailureReason` for server-side telemetry only, so an attacker
 * cannot learn which check a forged token failed.
 *
 * @param {{ key?: string, keys?: string[], algorithm?: 'HS256'|'RS256', strictTokenType?: boolean }} config
 */
export function accessTokenMiddleware({ key, keys, algorithm = "RS256", strictTokenType = false }) {
  const verifyKeys = resolveVerifyKeys({ key, keys });
  return function (req, res, next) {
    const reject = (err, reason, token) => {
      req.authFailureReason = reason;
      if (token) {
        try {
          req.authFailureTokenPayload = jwt.decode(token) || null;
        } catch {
          req.authFailureTokenPayload = null;
        }
      }
      return next(err);
    };

    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return reject(createError.Unauthorized("No authorization header"), "missing_header");
    }
    if (!authHeader.startsWith("Bearer ")) {
      return reject(createError.Unauthorized("Invalid authorization format. Expected: Bearer <token>"), "malformed_header");
    }
    const token = authHeader.slice(7).trim();
    if (!token) {
      return reject(createError.Unauthorized("No token provided"), "empty_token");
    }

    verifyWithKeys(token, verifyKeys, algorithm).then(
      (payload) => {
        if (!isSessionTokenType(payload, { strictTokenType })) {
          return reject(createError.Unauthorized("Invalid or expired token"), `wrong_token_type:${payload.type}`, token);
        }
        req.payload = payload;
        next();
      },
      (err) => reject(err, err?.tokenReason || "invalid_signature", token),
    );
  };
}

/**
 * Standalone verifier for callers that need the decoded payload without Express.
 * Performs signature and expiry checks only. Callers must check `type` themselves.
 *
 * @param {{ key?: string, keys?: string[], algorithm?: 'HS256'|'RS256' }} config
 */
export function createAccessTokenVerifier({ key, keys, algorithm = "RS256" }) {
  const verifyKeys = resolveVerifyKeys({ key, keys });
  return function verifyAccessToken(token) {
    return verifyWithKeys(token, verifyKeys, algorithm);
  };
}
