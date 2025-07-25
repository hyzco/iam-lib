import rateLimit from 'express-rate-limit';

/**
 * Creates a rate limiter middleware (e.g., 5 requests per minute)
 */
export default function createRateLimiter({ windowMs = 60 * 1000, max = 5 }) {
  return rateLimit({ windowMs, max });
}
