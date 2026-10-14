/**
 * Captcha verification, provider selected by CAPTCHA_PROVIDER.
 *
 *   none     - no captcha (default)
 *   hcaptcha - hCaptcha server-side verification (HCAPTCHA_SECRET_KEY)
 *
 * Adding a provider means one more case here plus its client widget.
 * Registration only calls verifyCaptcha().
 */

import { verifyHcaptchaToken } from "./hcaptcha.js";

export const captchaProvider = () => String(process.env.CAPTCHA_PROVIDER || "none").trim().toLowerCase();

/**
 * @param {string|undefined} token - widget response token (ignored for "none")
 * @param {string} [remoteIp]
 * @returns {Promise<boolean>}
 */
export async function verifyCaptcha(token, remoteIp) {
  switch (captchaProvider()) {
    case "none":
      return true;
    case "hcaptcha":
      return verifyHcaptchaToken(token, remoteIp);
    default:
      // Unknown provider: refuse rather than silently accept.
      return false;
  }
}

export default verifyCaptcha;
