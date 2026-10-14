/**
 * Drives an Express-style handler without a server. Resolves with the first
 * outcome: { status, body, headers } from res, or { error } from next(err).
 */
export function invoke(handler, { body, headers = {}, payload, ip = "203.0.113.7", params } = {}) {
  return new Promise((resolve, reject) => {
    const outcome = { status: 200, headers: {} };
    let req;
    req = {
      body,
      headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
      payload,
      params: params || {},
      ip,
      get(name) { return this.headers[name.toLowerCase()]; },
    };
    let settled = false;
    const finish = () => { if (!settled) { settled = true; outcome.req = req; resolve(outcome); } };
    const res = {
      status(code) { outcome.status = code; return this; },
      set(name, value) { outcome.headers[name] = value; return this; },
      json(payloadOut) { outcome.body = payloadOut; finish(); return this; },
      send(payloadOut) { outcome.body = payloadOut; finish(); return this; },
      sendStatus(code) { outcome.status = code; finish(); return this; },
    };
    const next = (err) => {
      if (err) {
        outcome.error = err;
        outcome.status = err.status || err.statusCode || 500;
        outcome.body = err.message;
        outcome.code = err.code;
      }
      finish();
    };
    try {
      Promise.resolve(handler(req, res, next)).then(finish, reject);
    } catch (err) {
      reject(err);
    }
  });
}

export const silentLogger = { info() {}, warn() {}, error() {}, debug() {}, log() {} };
