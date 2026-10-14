import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { setSettingsProvider, parseDurationToMinutes, toBoolean } from "../src/config/runtime.js";
import { validatePasswordStrength } from "../src/utils/passwordPolicy.js";
import { verifyHcaptchaToken } from "../src/utils/hcaptcha.js";
import { verifyCaptcha } from "../src/utils/captcha.js";
import requireRole from "../src/middleware/requireRole.js";
import { normalizeRole, highestRole } from "../src/roles.js";
import { createIamHandlers } from "../src/factory.js";
import createTokenService from "../src/services/tokenService.js";
import { createFakeDb } from "./helpers/fakeDb.js";
import { invoke } from "./helpers/http.js";

afterEach(() => { setSettingsProvider(null); delete process.env.CAPTCHA_PROVIDER; });

describe("settings provider", () => {
  test("without a provider every lookup returns its fallback", async () => {
    const { readSetting } = await import("../src/config/runtime.js");
    assert.equal(await readSetting("security", "x", "fallback"), "fallback");
  });

  test("a throwing provider degrades to the fallback instead of failing the caller", async () => {
    const { readSetting } = await import("../src/config/runtime.js");
    setSettingsProvider(() => { throw new Error("db down"); });
    assert.equal(await readSetting("security", "x", 7), 7);
  });

  test("setSettingsProvider rejects non-functions", () => {
    assert.throws(() => setSettingsProvider("nope"), TypeError);
  });

  test("duration parsing accepts units and bare minutes, rejects garbage", () => {
    assert.equal(parseDurationToMinutes("15m"), 15);
    assert.equal(parseDurationToMinutes("2h"), 120);
    assert.equal(parseDurationToMinutes("1d"), 1440);
    assert.equal(parseDurationToMinutes("90"), 90);
    assert.equal(parseDurationToMinutes("soon"), null);
    assert.equal(parseDurationToMinutes("0m"), null);
  });

  test("toBoolean coerces the mixed shapes settings arrive in", () => {
    assert.equal(toBoolean("true", false), true);
    assert.equal(toBoolean(1, false), true);
    assert.equal(toBoolean("0", true), false);
    assert.equal(toBoolean(undefined, true), true);
  });
});

describe("password policy", () => {
  test("fixed floor applies with no settings", async () => {
    const r = await validatePasswordStrength("abcdefgh");
    assert.equal(r.valid, false);
    assert.ok(r.errors.some((e) => /uppercase/.test(e)));
    assert.ok(r.errors.some((e) => /number/.test(e)));
  });

  test("a settings provider can raise the minimum length", async () => {
    setSettingsProvider((scope, key, fb) => (key === "password_min_length" ? 14 : fb));
    const r = await validatePasswordStrength("Abcdefgh1234");
    assert.equal(r.valid, false);
    assert.match(r.errors[0], /at least 14/);
  });

  test("a settings provider can never lower the floor", async () => {
    setSettingsProvider((scope, key, fb) => (key === "password_min_length" ? 3 : fb));
    const r = await validatePasswordStrength("Ab1");
    assert.equal(r.valid, false);
  });

  test("special characters are required when the setting is on", async () => {
    setSettingsProvider((scope, key, fb) => (key === "password_require_special_chars" ? "true" : fb));
    assert.equal((await validatePasswordStrength("Abcdefg12")).valid, false);
    assert.equal((await validatePasswordStrength("Abcdefg1!")).valid, true);
  });
});

describe("captcha", () => {
  test("provider defaults to none and accepts", async () => {
    assert.equal(await verifyCaptcha(undefined), true);
  });

  test("unknown provider refuses rather than accepts", async () => {
    process.env.CAPTCHA_PROVIDER = "mystery";
    assert.equal(await verifyCaptcha("tok"), false);
  });

  test("hcaptcha without a secret refuses (no environment-based bypass)", async () => {
    delete process.env.HCAPTCHA_SECRET_KEY;
    assert.equal(await verifyHcaptchaToken("tok", "1.2.3.4"), false);
  });

  test("hcaptcha success is true only for an explicit success flag", async () => {
    const ok = async () => new globalThis.Response(JSON.stringify({ success: true }), { status: 200 });
    const no = async () => new globalThis.Response(JSON.stringify({ success: false }), { status: 200 });
    assert.equal(await verifyHcaptchaToken("t", undefined, { secret: "s", fetchImpl: ok }), true);
    assert.equal(await verifyHcaptchaToken("t", undefined, { secret: "s", fetchImpl: no }), false);
  });

  test("hcaptcha network failure is a failed check, never a pass", async () => {
    const boom = async () => { throw new Error("ECONNRESET"); };
    assert.equal(await verifyHcaptchaToken("t", undefined, { secret: "s", fetchImpl: boom }), false);
  });
});

describe("roles and requireRole", () => {
  const roles = ["user", "support", "admin", "super_admin"];
  const run = (required, role, { getRole } = {}) => {
    const mw = requireRole({ roles, getRole: getRole ?? (async () => role) })(required);
    return invoke(mw, { payload: { aud: 1 } });
  };

  test("ladder: higher role satisfies lower requirement", async () => {
    assert.equal((await run("support", "admin")).error, undefined);
    assert.equal((await run("admin", "support")).status, 403);
  });

  test("alias spellings normalize to the same tier", async () => {
    assert.equal(normalizeRole("superadmin"), "super_admin");
    assert.equal((await run("admin", "super-admin")).error, undefined);
  });

  test("list means OR; unknown names are ignored", async () => {
    assert.equal((await run(["ghost", "admin"], "admin")).error, undefined);
  });

  test("no known role in the requirement denies", async () => {
    assert.equal((await run("ghost", "super_admin")).status, 403);
  });

  test("unknown user role denies", async () => {
    assert.equal((await run("user", "ghost")).status, 403);
  });

  test("getRole returning null is 404, missing role is 403", async () => {
    assert.equal((await run("user", null, { getRole: async () => null })).status, 404);
    assert.equal((await run("user", "", { getRole: async () => "" })).status, 403);
  });

  test("highestRole picks the higher of two known roles", () => {
    assert.equal(highestRole(roles, "user", "admin"), "admin");
  });
});

describe("service accounts", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const make = () => createIamHandlers({
    db: createFakeDb(),
    tokenService: createTokenService({ algorithm: "RS256", privateKey, publicKey }),
    userRepo: { getById: async () => null, update: async () => {}, delete: async () => {} },
    logger: { info() {}, warn() {}, error() {} },
  });

  test("issues and verifies a token for a registered account", () => {
    const iam = make();
    iam.registerServiceAccount({ id: "billing-worker", privateKey, scopes: ["read"] });
    const token = iam.issueServiceToken("billing-worker");
    const payload = iam.verifyServiceToken(token, publicKey);
    assert.equal(payload.sub, "billing-worker");
    assert.equal(payload.type, "service");
  });

  test("unknown service account cannot be issued a token", () => {
    assert.throws(() => make().issueServiceToken("nobody"), /not found/);
  });

  test("a user access token is not accepted as a service token", async () => {
    const iam = make();
    const user = await iam.tokenService.signAccessToken(1);
    assert.throws(() => iam.verifyServiceToken(user, publicKey));
  });

  test("registries are per instance", () => {
    const a = make();
    const b = make();
    a.registerServiceAccount({ id: "svc", privateKey });
    assert.throws(() => b.issueServiceToken("svc"), /not found/);
  });
});

describe("factory configuration checks", () => {
  test("missing db, tokenService or userRepo.getById fails at construction", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const tokenService = createTokenService({ algorithm: "RS256", privateKey, publicKey });
    const userRepo = { getById: async () => null };
    assert.throws(() => createIamHandlers({ tokenService, userRepo }), /db/);
    assert.throws(() => createIamHandlers({ db: createFakeDb(), userRepo }), /tokenService/);
    assert.throws(() => createIamHandlers({ db: createFakeDb(), tokenService }), /userRepo/);
  });
});
