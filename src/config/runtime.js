/**
 * Process-wide settings provider.
 *
 * Some policies (password strength, login lockout, registration toggles, session
 * idle timeout) are operator-tunable at runtime. Instead of importing a host
 * application's settings service, the host registers a reader once:
 *
 *   import { setSettingsProvider } from "iam-lib";
 *   setSettingsProvider((scope, key, fallback) => settings.get(`${scope}.${key}`, fallback));
 *
 * The provider may be sync or async. When none is registered, every lookup
 * returns its fallback, so the library behaves like a fixed-policy install.
 */

let provider = null;

/**
 * @param {((scope: string, key: string, fallback: unknown) => unknown | Promise<unknown>) | null} fn
 */
export function setSettingsProvider(fn) {
  if (fn !== null && typeof fn !== "function") {
    throw new TypeError("setSettingsProvider expects a function or null");
  }
  provider = fn;
}

/**
 * Read a setting. Never throws: a failing provider yields the fallback, so a
 * settings outage cannot turn into a login or registration outage.
 *
 * @param {string} scope
 * @param {string} key
 * @param {unknown} fallback
 * @param {{ logger?: { error?: Function } }} [opts]
 * @returns {Promise<unknown>}
 */
export async function readSetting(scope, key, fallback, opts = {}) {
  if (!provider) {return fallback;}
  try {
    const value = await provider(scope, key, fallback);
    return value === undefined ? fallback : value;
  } catch (err) {
    opts.logger?.error?.(`[iam-lib] settings read failed for ${scope}.${key}; using fallback:`, err?.message);
    return fallback;
  }
}

/**
 * Parse "15m", "2h", "7d", "30s" or a bare number of minutes.
 * Returns null for anything unparseable so callers can apply their own default.
 *
 * @param {unknown} value
 * @returns {number | null} minutes
 */
export function parseDurationToMinutes(value) {
  if (value === null || value === undefined) {return null;}
  const str = String(value).trim();
  if (/^\d+$/.test(str)) {
    const n = Number.parseInt(str, 10);
    return n > 0 ? n : null;
  }
  const match = /^(\d+)\s*(s|m|h|d)$/i.exec(str);
  if (!match) {return null;}
  const perMinute = { s: 1 / 60, m: 1, h: 60, d: 1440 };
  const minutes = Number.parseInt(match[1], 10) * perMinute[match[2].toLowerCase()];
  return minutes > 0 ? minutes : null;
}

/**
 * Coerce the mixed shapes booleans arrive in ("true", 1, "1", true) to a boolean.
 *
 * @param {unknown} value
 * @param {boolean} fallback
 * @returns {boolean}
 */
export function toBoolean(value, fallback) {
  if (value === null || value === undefined) {return fallback;}
  return value === true || value === 1 || value === "1" || String(value).toLowerCase() === "true";
}
