import { test, describe } from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcrypt";
import { generateKeyPairSync } from "node:crypto";
import { createIamHandlers } from "../src/factory.js";
import createTokenService from "../src/services/tokenService.js";
import { createFakeDb } from "./helpers/fakeDb.js";
import { invoke, silentLogger } from "./helpers/http.js";
import { hashResetToken } from "../src/utils/resetToken.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const PASSWORD = "Correct-Horse-1";
const HASH = bcrypt.hashSync(PASSWORD, 4);
const noAudit = () => {};

function setup({ users = [], db: existingDb, ...hooks } = {}) {
  const db = existingDb || createFakeDb({
    users: users.length ? users : [
      { id: 1, email: "ada@example.com", password: HASH, role: "user", mfa_enabled: false, failed_login_attempts: 0, locked_until: null },
    ],
  });
  const tokenService = createTokenService({ algorithm: "RS256", privateKey, publicKey });
  const iam = createIamHandlers({
    db,
    tokenService,
    logger: silentLogger,
    roles: ["user", "admin"],
    getRole: async (id) => (await db("users").where({ id }).first())?.role,
    userRepo: {
      getById: (id) => db("users").where({ id }).first(),
      update: (id, data) => db("users").where({ id }).update(data),
      delete: (id) => db("users").where({ id }).delete(),
    },
    ...hooks,
  });
  return { db, iam, tokenService };
}

describe("login", () => {
  test("correct password returns a bearer access token and a refresh token", async () => {
    const { iam } = setup();
    const out = await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(out.status, 200);
    assert.match(out.body.accessToken, /^Bearer /);
    assert.ok(out.body.refreshToken);
  });

  test("wrong password and unknown email give the same status and message", async () => {
    const { iam } = setup();
    const wrong = await invoke(iam.login[1], { body: { email: "ada@example.com", password: "nope-nope-1A" } });
    const unknown = await invoke(iam.login[1], { body: { email: "nobody@example.com", password: "nope-nope-1A" } });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal(wrong.body, unknown.body);
  });

  test("lockout after maxAttempts blocks even the correct password", async () => {
    const { iam, db } = setup({ lockout: { maxAttempts: 2, duration: "15m" } });
    const bad = { email: "ada@example.com", password: "wrong-Password-9" };
    await invoke(iam.login[1], { body: bad });
    await invoke(iam.login[1], { body: bad });
    assert.ok(db.tables.users[0].locked_until instanceof Date, "locked_until must be set");

    const good = await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(good.status, 429);
    assert.equal(good.body, "Too many failed login attempts. Try again later.");
  });

  test("a successful login clears the failure counter", async () => {
    const { iam, db } = setup({ lockout: { maxAttempts: 5, duration: "15m" } });
    await invoke(iam.login[1], { body: { email: "ada@example.com", password: "wrong-Password-9" } });
    assert.equal(db.tables.users[0].failed_login_attempts, 1);
    await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(db.tables.users[0].failed_login_attempts, 0);
  });

  test("checkAccountState can refuse a correct password (host account states)", async () => {
    const refusal = Object.assign(new Error("suspended"), { status: 403, code: "ACCOUNT_SUSPENDED" });
    const { iam } = setup({ checkAccountState: async () => { throw refusal; } });
    const out = await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(out.status, 403);
    assert.equal(out.code, "ACCOUNT_SUSPENDED");
  });

  test("MFA-enabled account gets an mfa_pending challenge, never a session", async () => {
    const { iam, db } = setup();
    db.tables.users[0].mfa_enabled = true;
    const out = await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(out.body.mfaRequired, true);
    assert.equal(out.body.accessToken, undefined);
    assert.equal(db.tables.refresh_tokens.length, 0, "no refresh family may be created before MFA");
  });

  test("requireMfaForAdmins blocks an un-enrolled admin with a setup token", async () => {
    const { iam } = setup({ requireMfaForAdmins: async () => true });
    const out = await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.equal(out.status, 403);
    assert.equal(out.body.code, "MFA_SETUP_REQUIRED");
    assert.ok(out.body.setupToken);
  });

  test("onLoginSuccess is called only after a real session is issued", async () => {
    const seen = [];
    const { iam } = setup({ onLoginSuccess: async (user) => { seen.push(user.id); } });
    await invoke(iam.login[1], { body: { email: "ada@example.com", password: "wrong-Password-9" } });
    assert.deepEqual(seen, []);
    await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    assert.deepEqual(seen, [1]);
  });
});

describe("register", () => {
  const body = (over = {}) => ({ email: "new@example.com", password: "Brand-New-1", ...over });

  test("creates a user with role forced to user, ignoring client-supplied privilege fields", async () => {
    const { iam, db } = setup();
    const out = await invoke(iam.register[1], { body: body({ role: "admin", is_active: true }) });
    assert.equal(out.status, 201);
    const created = db.tables.users.find((u) => u.email === "new@example.com");
    assert.equal(created.role, "user");
    assert.equal(created.is_active, undefined);
  });

  test("the refresh token issued at registration is tracked, so it can be rotated", async () => {
    const { iam } = setup();
    const reg = await invoke(iam.register[1], { body: body() });
    const refresh = await invoke(iam.refreshToken[1], { body: { refreshToken: reg.body.refreshToken } });
    assert.equal(refresh.status, 200, "first refresh after registration must succeed");
    assert.ok(refresh.body.refreshToken);
  });

  test("duplicate email is a 409", async () => {
    const { iam } = setup();
    const out = await invoke(iam.register[1], { body: body({ email: "ada@example.com" }) });
    assert.equal(out.status, 409);
  });

  test("allowRegistration=false refuses with 403", async () => {
    const { iam } = setup({ allowRegistration: () => false });
    const out = await invoke(iam.register[1], { body: body() });
    assert.equal(out.status, 403);
  });

  test("requireAdminApproval starts the account inactive", async () => {
    const { iam, db } = setup({ requireAdminApproval: true });
    await invoke(iam.register[1], { body: body() });
    assert.equal(db.tables.users.find((u) => u.email === "new@example.com").is_active, false);
  });

  test("extraUserFields are written and resolveTenantId is applied", async () => {
    const { iam, db } = setup({
      extraUserFields: (data) => ({ terms_version: "v3" }),
      resolveTenantId: () => "tenant-b",
    });
    await invoke(iam.register[1], { body: body() });
    const row = db.tables.users.find((u) => u.email === "new@example.com");
    assert.equal(row.terms_version, "v3");
    assert.equal(row.tenant_id, "tenant-b");
  });

  test("a failing onUserCreated hook does not fail a completed registration", async () => {
    const { iam } = setup({ onUserCreated: async () => { throw new Error("onboarding down"); } });
    const out = await invoke(iam.register[1], { body: body() });
    assert.equal(out.status, 201);
  });

  test("weak password is refused before any write", async () => {
    const { iam, db } = setup();
    const out = await invoke(iam.register[1], { body: body({ password: "short" }) });
    assert.equal(out.status, 422);
    assert.equal(db.tables.users.length, 1);
  });
});

describe("refresh and logout", () => {
  async function loggedIn() {
    const ctx = setup();
    const out = await invoke(ctx.iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    return { ...ctx, refresh: out.body.refreshToken };
  }

  test("rotation returns a new pair and retires the old refresh token", async () => {
    const { iam, refresh } = await loggedIn();
    const first = await invoke(iam.refreshToken[1], { body: { refreshToken: refresh } });
    assert.equal(first.status, 200);
    assert.notEqual(first.body.refreshToken, refresh);
  });

  test("replaying a rotated refresh token revokes the whole family", async () => {
    const { iam, db, refresh } = await loggedIn();
    const first = await invoke(iam.refreshToken[1], { body: { refreshToken: refresh } });
    const replay = await invoke(iam.refreshToken[1], { body: { refreshToken: refresh } });
    assert.equal(replay.status, 401);
    const live = db.tables.refresh_tokens.filter((r) => r.revoked === false);
    assert.equal(live.length, 0, "successor must be revoked as well");
    const successor = await invoke(iam.refreshToken[1], { body: { refreshToken: first.body.refreshToken } });
    assert.equal(successor.status, 401);
  });

  test("an access token presented to the refresh endpoint is refused", async () => {
    const { iam, tokenService } = await loggedIn();
    const access = await tokenService.signAccessToken(1, { sid: "x" });
    const out = await invoke(iam.refreshToken[1], { body: { refreshToken: access } });
    assert.equal(out.status, 401);
  });

  test("refresh is refused for a suspended account, and the token is not rotated", async () => {
    const { iam, db, refresh } = await loggedIn();
    const suspendedIam = setup({
      db,
      checkAccountState: async () => { throw Object.assign(new Error("suspended"), { status: 403, code: "ACCOUNT_SUSPENDED" }); },
    }).iam;
    const out = await invoke(suspendedIam.refreshToken[1], { body: { refreshToken: refresh } });
    assert.equal(out.status, 403);
    assert.equal(db.tables.refresh_tokens.filter((r) => !r.revoked).length, 1, "refresh row must stay unrotated");
    assert.ok(iam);
  });

  test("logout revokes the refresh family", async () => {
    const { iam, db, refresh } = await loggedIn();
    const out = await invoke(iam.logout[1], { body: { refreshToken: refresh } });
    assert.equal(out.status, 204);
    assert.equal(db.tables.refresh_tokens.every((r) => r.revoked), true);
  });

  test("logout without a body revokes all sessions for the bearer's user", async () => {
    const { iam, db } = await loggedIn();
    await invoke(iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    const out = await invoke(iam.logout[1], { body: {}, payload: { aud: 1 } });
    assert.equal(out.status, 204);
    assert.equal(db.tables.refresh_tokens.filter((r) => !r.revoked).length, 0);
  });

  test("tokenBlacklist receives the access and refresh tokens on logout", async () => {
    const entries = [];
    const { iam, refresh } = await loggedIn();
    const withBlacklist = setup({ tokenBlacklist: { add: async (e) => { entries.push(e.tokenType); } } });
    const login = await invoke(withBlacklist.iam.login[1], { body: { email: "ada@example.com", password: PASSWORD } });
    await invoke(withBlacklist.iam.logout[1], {
      body: { refreshToken: login.body.refreshToken },
      headers: { authorization: login.body.accessToken },
    });
    assert.deepEqual(entries.sort(), ["access", "refresh"]);
    assert.ok(iam && refresh);
  });
});

describe("profile", () => {
  test("a user cannot read another user's profile by default", async () => {
    const { iam } = setup({ users: [
      { id: 1, email: "a@x.com", password: HASH, role: "user" },
      { id: 2, email: "b@x.com", password: HASH, role: "user" },
    ] });
    const out = await invoke(iam.profile.getProfile, { params: { id: "2" }, payload: { aud: 1 } });
    assert.equal(out.status, 403);
  });

  test("canAccessOtherUsers grants the read and password fields are stripped", async () => {
    const { iam } = setup({
      profile: { canAccessOtherUsers: async (req) => req.payload.role === "admin" },
      users: [{ id: 2, email: "b@x.com", password: HASH, mfa_secret: "s", role: "user", name: "B" }],
    });
    const out = await invoke(iam.profile.getProfile, { params: { id: "2" }, payload: { aud: 1, role: "admin" } });
    assert.equal(out.status, 200);
    assert.equal(out.body.user.password, undefined);
    assert.equal(out.body.user.mfa_secret, undefined);
    assert.equal(out.body.user.name, "B");
  });

  test("updateProfile ignores non-allowlisted fields such as role", async () => {
    const { iam, db } = setup();
    const out = await invoke(iam.profile.updateProfile, { body: { name: "Ada", role: "admin" }, payload: { aud: 1 } });
    assert.equal(out.status, 200);
    assert.equal(db.tables.users[0].name, "Ada");
    assert.equal(db.tables.users[0].role, "user");
  });

  test("updateProfile with no allowed fields is a 400", async () => {
    const { iam } = setup();
    const out = await invoke(iam.profile.updateProfile, { body: { role: "admin" }, payload: { aud: 1 } });
    assert.equal(out.status, 400);
  });

  test("getProfile with a non-string error passes an Error to next (not a bare message)", async () => {
    const { iam } = setup();
    const out = await invoke(iam.profile.getProfile, { payload: undefined });
    assert.equal(out.status, 401);
  });
});

describe("password reset and change", () => {
  test("reset token is stored as a digest and works once", async () => {
    const { iam, db } = setup();
    const raw = "a".repeat(64);
    db.tables.password_reset_tokens.push({ id: 1, user_id: 1, token: hashResetToken(raw), expires_at: new Date(Date.now() + 60000), used_at: null });
    const first = await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-22" } });
    assert.equal(first.status, 200);
    assert.equal(db.tables.password_reset_tokens[0].token, hashResetToken(raw));
    const second = await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-33" } });
    assert.equal(second.status, 400);
  });

  test("reset with a plaintext-stored token no longer matches (existing rows expire naturally)", async () => {
    const { iam, db } = setup();
    db.tables.password_reset_tokens.push({ id: 1, user_id: 1, token: "legacy-plaintext", expires_at: new Date(Date.now() + 60000), used_at: null });
    const out = await invoke(iam.resetPassword[1], { body: { token: "legacy-plaintext", newPassword: "Fresh-Pass-22" } });
    assert.equal(out.status, 400);
  });

  test("reset is refused for an MFA account when no verifyMfa hook is configured", async () => {
    const { iam, db } = setup({ users: [{ id: 1, email: "a@x.com", password: HASH, role: "user", mfa_enabled: true }] });
    const raw = "b".repeat(64);
    db.tables.password_reset_tokens.push({ id: 1, user_id: 1, token: hashResetToken(raw), expires_at: new Date(Date.now() + 60000), used_at: null });
    const out = await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-22" } });
    assert.equal(out.status, 403);
  });

  test("reset requires a valid MFA code when verifyMfa is configured", async () => {
    const { iam, db } = setup({
      users: [{ id: 1, email: "a@x.com", password: HASH, role: "user", mfa_enabled: true }],
      verifyMfa: async (id, code) => ({ verified: code === "123456" }),
    });
    const raw = "c".repeat(64);
    db.tables.password_reset_tokens.push({ id: 1, user_id: 1, token: hashResetToken(raw), expires_at: new Date(Date.now() + 60000), used_at: null });
    const bad = await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-22", mfaCode: "000000" } });
    assert.equal(bad.status, 403);
    const good = await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-22", mfaCode: "123456" } });
    assert.equal(good.status, 200);
  });

  test("reset revokes existing sessions", async () => {
    const { iam, db } = setup();
    db.tables.refresh_tokens.push({ jti: "x", family_id: "f", user_id: 1, revoked: false });
    const raw = "d".repeat(64);
    db.tables.password_reset_tokens.push({ id: 1, user_id: 1, token: hashResetToken(raw), expires_at: new Date(Date.now() + 60000), used_at: null });
    await invoke(iam.resetPassword[1], { body: { token: raw, newPassword: "Fresh-Pass-22" } });
    assert.equal(db.tables.refresh_tokens[0].revoked, true);
  });

  test("forgot-password answers generically and never 500s on object input", async () => {
    const { iam } = setup();
    const unknown = await invoke(iam.forgotPassword[1], { body: { email: "nobody@x.com" } });
    assert.equal(unknown.status, 200);
    const object = await invoke(iam.forgotPassword[1], { body: { email: { $ne: null } } });
    assert.equal(object.status, 400);
  });

  test("forgot-password for a known account stores only the digest of the token", async () => {
    let sent;
    const { iam, db } = setup({ onPasswordResetRequested: async (args) => { sent = args; } });
    await invoke(iam.forgotPassword[1], { body: { email: "ada@example.com" } });
    assert.ok(sent.resetToken);
    assert.equal(db.tables.password_reset_tokens[0].token, hashResetToken(sent.resetToken));
  });

  test("change password refuses reuse of the current password", async () => {
    const { iam } = setup();
    const out = await invoke(iam.changePw[1], { body: { currentPassword: PASSWORD, newPassword: PASSWORD }, payload: { aud: 1 } });
    assert.equal(out.status, 400);
  });
});

describe("issueRefreshSession", () => {
  test("a session started outside login is tracked, so its refresh token rotates", async () => {
    const { iam, db } = setup();
    const { refreshToken, familyId } = await iam.issueRefreshSession(1, { ip: "203.0.113.9", headers: {} });
    assert.ok(familyId);
    assert.equal(db.tables.refresh_tokens.length, 1);
    const out = await invoke(iam.refreshToken[1], { body: { refreshToken } });
    assert.equal(out.status, 200);
  });
});
