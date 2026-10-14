/**
 * hCaptcha server-side verification.
 *
 * The client widget alone proves nothing: a bot can submit any token string.
 * The token must be checked against hCaptcha's verify endpoint.
 *
 * Fails closed: a missing secret or an unreachable verifier returns false.
 * There is no environment-based bypass.
 */

const HCAPTCHA_VERIFY_URL = "https://hcaptcha.com/siteverify";
const VERIFY_TIMEOUT_MS = 5000;

/**
 * @param {string} token - token produced by the client-side widget
 * @param {string} [remoteIp] - client IP, improves hCaptcha scoring
 * @param {{ secret?: string, fetchImpl?: typeof fetch }} [opts]
 * @returns {Promise<boolean>}
 */
export async function verifyHcaptchaToken(token, remoteIp, opts = {}) {
  const secret = opts.secret ?? process.env.HCAPTCHA_SECRET_KEY;
  if (!secret) {
    // Misconfiguration refuses the request. It never passes.
    return false;
  }
  if (!token) {return false;}

  const params = new URLSearchParams({ secret, response: token });
  if (remoteIp) {params.set("remoteip", remoteIp);}

  const doFetch = opts.fetchImpl ?? fetch;
  try {
    const res = await doFetch(HCAPTCHA_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (!res.ok) {return false;}
    const result = await res.json();
    return result?.success === true;
  } catch {
    // Network or parse failure: treat as a failed check, never as a pass.
    return false;
  }
}

export default verifyHcaptchaToken;
