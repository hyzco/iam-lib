import rateLimit from "express-rate-limit";

/**
 * Per-route request limiter. Defaults to 5 requests per minute.
 *
 * Keyed by req.ip. Behind a reverse proxy, set Express's `trust proxy` so the
 * client address is real. Otherwise every client shares the proxy's limit.
 *
 * @param {{ windowMs?: number, max?: number }} [options]
 */
export default function createRateLimiter({ windowMs = 60 * 1000, max = 5 } = {}) {
  return rateLimit({
    windowMs,
    limit: max,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  });
}
