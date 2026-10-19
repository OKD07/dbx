import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createGateway, tenantKey } from "./oidc-multitenant.mjs";

test("one DBX Web process keeps two OIDC accounts in separate databases", { skip: !process.env.DBX_TEST_WEB_BIN }, async () => {
  const issuer = "https://identity.example.test";
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "smoke", alg: "RS256", use: "sig" };
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "dbx-oidc-shared-"));
  const realFetch = globalThis.fetch;
  let subject = "alice";
  let nonce = "";
  globalThis.fetch = async (input, options) => {
    const url = String(input);
    if (url.startsWith("http://127.0.0.1:")) return realFetch(input, options);
    if (url.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }), { status: 200 });
    if (url.endsWith("/jwks")) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    if (url.endsWith("/token")) {
      const head = Buffer.from(JSON.stringify({ alg: "RS256", kid: "smoke" })).toString("base64url");
      const body = Buffer.from(JSON.stringify({ iss: issuer, sub: subject, aud: "dbx-smoke", nonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 })).toString("base64url");
      return new Response(JSON.stringify({ id_token: `${head}.${body}.${sign("sha256", Buffer.from(`${head}.${body}`), privateKey).toString("base64url")}` }), { status: 200 });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };
  let server;
  try {
    server = await createGateway({ issuer, clientId: "dbx-smoke", clientSecret: "smoke", redirectUri: "http://127.0.0.1/api/auth/oidc/callback", dataDir, staticDir: path.resolve("dist"), isolation: "shared", webBinary: process.env.DBX_TEST_WEB_BIN });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    assert.equal((await realFetch(`${base}/api/migration/status`)).status, 401);
    for (subject of ["alice", "bob"]) {
      const begin = await realFetch(`${base}/api/auth/oidc/start`, { redirect: "manual" });
      const redirect = new URL(begin.headers.get("location"));
      nonce = redirect.searchParams.get("nonce");
      const stateCookie = begin.headers.get("set-cookie").split(";")[0];
      const callback = await realFetch(`${base}/api/auth/oidc/callback?state=${redirect.searchParams.get("state")}&code=smoke`, { headers: { cookie: stateCookie, "sec-fetch-site": "cross-site" }, redirect: "manual" });
      assert.equal(callback.status, 302);
      const cookie = callback.headers.get("set-cookie").match(/dbx_mt_session=[^;]+/)[0];
      const result = await realFetch(`${base}/api/migration/status`, { headers: { cookie } });
      assert.equal(result.status, 200, await result.text());
      const forbidden = await realFetch(`${base}/api/plugins`, { headers: { cookie } });
      assert.equal(forbidden.status, 403);
      const localFile = await realFetch(`${base}/api/connection/save`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ configs: [{ db_type: "sqlite", host: "/etc/passwd" }] }) });
      assert.equal(localFile.status, 403);
      const migration = await realFetch(`${base}/api/migration/start`, { method: "POST", headers: { cookie } });
      assert.equal(migration.status, 200, await migration.text());
      const config = { id: `connection-${subject}`, name: subject, db_type: "postgres", host: "db.example.test", port: 5432, username: subject, password: "", database: null };
      const saved = await realFetch(`${base}/api/connection/save`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: JSON.stringify({ configs: [config] }) });
      assert.equal(saved.status, 200, await saved.text());
      const listed = await realFetch(`${base}/api/connection/list`, { headers: { cookie } });
      assert.equal(listed.status, 200);
      const connections = await listed.json();
      assert.match(JSON.stringify(connections), new RegExp(`connection-${subject}`));
      assert.doesNotMatch(JSON.stringify(connections), new RegExp(`connection-${subject === "alice" ? "bob" : "alice"}`));
      await stat(path.join(dataDir, "tenants", tenantKey(issuer, subject), "dbx.db"));
    }
    assert.notEqual(tenantKey(issuer, "alice"), tenantKey(issuer, "bob"));
  } finally {
    globalThis.fetch = realFetch;
    if (server) await new Promise((resolve) => server.close(resolve));
  }
});
