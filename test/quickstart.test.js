// Executes the README quick-start shape end to end against the in-memory db,
// so the documented example cannot drift from the real API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createIamHandlers, createTokenService } from "../index.js";
import { createFakeDb } from "./helpers/fakeDb.js";
import { invoke, silentLogger } from "./helpers/http.js";

test("README quick-start: register, login, authenticated /me, admin-only route", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const db = createFakeDb({ users: [{ id: 1, email: "admin@example.com", password: "x", role: "admin" }] });

  const tokenService = createTokenService({ algorithm: "RS256", privateKey, publicKey });
  const iam = createIamHandlers({
    db,
    tokenService,
    logger: silentLogger,
    roles: ["user", "admin"],
    getRole: async (userId) => (await db("users").where({ id: userId }).first())?.role,
    userRepo: {
      getById: (id) => db("users").where({ id }).first(),
      update: (id, data) => db("users").where({ id }).update(data),
      delete: (id) => db("users").where({ id }).delete(),
    },
  });

  const registered = await invoke(iam.register[1], { body: { email: "new@example.com", password: "Sturdy-Pass-1" } });
  assert.equal(registered.status, 201);

  const login = await invoke(iam.login[1], { body: { email: "new@example.com", password: "Sturdy-Pass-1" } });
  assert.equal(login.status, 200);
  const bearer = login.body.accessToken;
  assert.match(bearer, /^Bearer /);

  // A registered user is authenticated, but is not an admin.
  const me = await invoke(iam.accessTokenMiddleware, { headers: { authorization: bearer } });
  assert.equal(me.error, undefined);
  const newUserId = db.tables.users.find((u) => u.email === "new@example.com").id;
  assert.notEqual(newUserId, 1, "new user must not reuse the seeded admin id");
  const userCheck = await invoke(iam.requireRole("admin"), { payload: { aud: newUserId } });
  assert.equal(userCheck.status, 403);

  const adminCheck = await invoke(iam.requireRole("admin"), { payload: { aud: 1 } });
  assert.equal(adminCheck.error, undefined);
});
