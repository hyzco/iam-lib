import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import createTokenService from "../src/services/tokenService.js";
import { accessTokenMiddleware, isSessionTokenType } from "../src/middleware/verifyAccessToken.js";
import { invoke } from "./helpers/http.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const rsa = () => createTokenService({ algorithm: "RS256", privateKey, publicKey });
const hs = () => createTokenService({
  algorithm: "HS256",
  accessSecret: "access-secret-for-tests-0000000000000000",
  refreshSecret: "refresh-secret-for-tests-000000000000000",
});

const gate = accessTokenMiddleware({ key: publicKey, algorithm: "RS256" });

describe("token types", () => {
  test("access token passes the session gate", async () => {
    const svc = rsa();
    const token = await svc.signAccessToken(42, { role: "user" });
    const out = await invoke(gate, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(out.error, undefined);
  });

  for (const [label, sign] of [
    ["refresh", (s) => s.signRefreshToken(42, { jti: "j1", familyId: "f1" })],
    ["mfa_pending", (s) => s.signMFAToken({ userId: 42, role: "user" })],
    ["mfa_setup_required", (s) => s.signMfaSetupToken(42, { role: "user" })],
  ]) {
    test(`${label} token is refused as a session token`, async () => {
      const token = await sign(rsa());
      const out = await invoke(gate, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(out.status, 401);
      assert.equal(out.body, "Invalid or expired token", "client message must be generic");
    });
  }

  test("untyped legacy token is accepted unless strictTokenType is set", async () => {
    const jwt = (await import("jsonwebtoken")).default;
    const legacy = jwt.sign({ aud: 42 }, privateKey, { algorithm: "RS256", expiresIn: "5m" });
    const lenient = await invoke(gate, { headers: { authorization: `Bearer ${legacy}` } });
    assert.equal(lenient.error, undefined);
    const strict = accessTokenMiddleware({ key: publicKey, algorithm: "RS256", strictTokenType: true });
    const strictOut = await invoke(strict, { headers: { authorization: `Bearer ${legacy}` } });
    assert.equal(strictOut.status, 401);
  });

  test("isSessionTokenType allowlists access only", () => {
    assert.equal(isSessionTokenType({ type: "access" }), true);
    assert.equal(isSessionTokenType({ type: "mfa_pending" }), false);
    assert.equal(isSessionTokenType({}), true);
    assert.equal(isSessionTokenType({}, { strictTokenType: true }), false);
  });

  test("access token is refused at the refresh verifier", async () => {
    const svc = rsa();
    const access = await svc.signAccessToken(42);
    await assert.rejects(svc.verifyRefreshToken(access), { status: 401 });
  });

  test("refresh token is refused at the access verifier", async () => {
    const svc = rsa();
    const refresh = await svc.signRefreshToken(42, { jti: "j", familyId: "f" });
    await assert.rejects(svc.verifyAccessToken(refresh), { status: 401 });
  });
});

describe("HS256 with separate secrets", () => {
  test("refresh token verifies with the refresh secret (regression: was verified with the access secret)", async () => {
    const svc = hs();
    const refresh = await svc.signRefreshToken(7, { jti: "j", familyId: "f" });
    const payload = await svc.verifyRefreshToken(refresh);
    assert.equal(payload.aud, 7);
    assert.equal(payload.type, "refresh");
  });

  test("refresh token is not accepted as an access token, and access tokens are not refresh tokens", async () => {
    const svc = hs();
    const refresh = await svc.signRefreshToken(7, { jti: "j", familyId: "f" });
    await assert.rejects(svc.verifyAccessToken(refresh));
    const access = await svc.signAccessToken(7);
    await assert.rejects(svc.verifyRefreshToken(access));
  });

  test("algorithm is pinned: a token signed with a different alg is rejected", async () => {
    const jwt = (await import("jsonwebtoken")).default;
    const forged = jwt.sign({ aud: 7, type: "access" }, "anything", { algorithm: "HS512" });
    await assert.rejects(hs().verifyAccessToken(forged));
  });
});

describe("factory validation", () => {
  test("RS256 without keys is rejected at construction", () => {
    assert.throws(() => createTokenService({ algorithm: "RS256" }), TypeError);
  });
  test("unsupported algorithm is rejected", () => {
    assert.throws(() => createTokenService({ algorithm: "none", accessSecret: "x" }), TypeError);
  });
});

describe("failure telemetry", () => {
  test("expired token is reported server-side as 'expired' while the client sees a generic 401", async () => {
    const jwt = (await import("jsonwebtoken")).default;
    const expired = jwt.sign({ aud: 42, type: "access", exp: Math.floor(Date.now() / 1000) - 60 }, privateKey, { algorithm: "RS256" });
    const req = { headers: { authorization: `Bearer ${expired}` } };
    const out = await invoke(gate, { headers: req.headers });
    assert.equal(out.status, 401);
    assert.equal(out.body, "Invalid or expired token");
    assert.equal(out.req.authFailureReason, "expired");
  });
});
