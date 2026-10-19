import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createGateway, tenantKey, verifyIdToken } from "./oidc-multitenant.mjs";

const issuer = "https://identity.example.test";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test", alg: "RS256", use: "sig" };

function idToken(subject, nonce) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ iss: issuer, sub: subject, aud: "dbx-client", nonce, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 })).toString("base64url");
  return `${header}.${payload}.${sign("sha256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url")}`;
}

test("OIDC identity uses a verified issuer and subject, not an email claim", () => {
  assert.notEqual(tenantKey(issuer, "alice"), tenantKey(issuer, "bob"));
  assert.notEqual(tenantKey(issuer, "alice"), tenantKey("https://other.example", "alice"));
  const token = idToken("alice", "nonce");
  assert.deepEqual(verifyIdToken(token, { keys: [jwk] }, { issuer, clientId: "dbx-client", nonce: "nonce" }), { issuer, subject: "alice" });
  assert.throws(() => verifyIdToken(token, { keys: [jwk] }, { issuer, clientId: "dbx-client", nonce: "other" }));
  assert.throws(() => verifyIdToken(token, { keys: [jwk] }, { issuer: "https://other.example", clientId: "dbx-client", nonce: "nonce" }));
  const broken = `${token.slice(0, -2)}xx`;
  assert.throws(() => verifyIdToken(broken, { keys: [jwk] }, { issuer, clientId: "dbx-client", nonce: "nonce" }));
});

test("gateway authenticates two accounts and forwards only verified tenant keys", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "dbx-oidc-test-"));
  const staticDir = path.join(root, "dist");
  await mkdir(staticDir);
  await writeFile(path.join(staticDir, "index.html"), "<title>DBX</title>");
  const fakeBackend = path.join(root, "backend.mjs");
  await writeFile(fakeBackend, `#!/usr/bin/env node
import http from 'node:http';
http.createServer((req, res) => {
  if (req.headers['x-dbx-internal-secret'] !== process.env.DBX_MULTITENANT_SECRET) { res.writeHead(401).end(); return; }
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ tenant: req.headers['x-dbx-tenant-key'], path: req.url, cookie: req.headers.cookie }));
}).listen(Number(process.env.DBX_PORT), '127.0.0.1');
`);
  await chmod(fakeBackend, 0o700);
  const originalFetch = globalThis.fetch;
  let currentSubject = "alice";
  let activeNonce;
  globalThis.fetch = async (input, options) => {
    const url = String(input);
    if (url.startsWith("http://127.0.0.1:")) return originalFetch(input, options);
    if (url.endsWith("/.well-known/openid-configuration")) return new Response(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` }), { status: 200 });
    if (url.endsWith("/jwks")) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    if (url.endsWith("/token")) {
      assert.equal(options.body.get("grant_type"), "authorization_code");
      assert.ok(options.body.get("code_verifier"));
      return new Response(JSON.stringify({ id_token: idToken(currentSubject, activeNonce) }), { status: 200 });
    }
    throw new Error(`Unexpected fetch ${url}`);
  };
  let server;
  try {
    server = await createGateway({ issuer, clientId: "dbx-client", clientSecret: "test", redirectUri: "http://127.0.0.1/api/auth/oidc/callback", dataDir: root, staticDir, webBinary: fakeBackend });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    assert.equal((await originalFetch(`${base}/api/connection/list`)).status, 401);
    assert.equal((await originalFetch(`${base}/api/auth/check`, { headers: { origin: "https://other.example" } })).status, 403);
    assert.equal((await originalFetch(base, { headers: { "sec-fetch-site": "cross-site" } })).status, 200);
    for (const subject of ["alice", "bob"]) {
      currentSubject = subject;
      const start = await originalFetch(`${base}/api/auth/oidc/start`, { redirect: "manual" });
      const authorize = new URL(start.headers.get("location"));
      activeNonce = authorize.searchParams.get("nonce");
      assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
      const stateCookie = start.headers.get("set-cookie").split(";")[0];
      const callback = await originalFetch(`${base}/api/auth/oidc/callback?state=${authorize.searchParams.get("state")}&code=mock-code`, { headers: { cookie: stateCookie, "sec-fetch-site": "cross-site" }, redirect: "manual" });
      assert.equal(callback.status, 302);
      assert.equal((await originalFetch(`${base}/api/auth/oidc/callback?state=${authorize.searchParams.get("state")}&code=mock-code`, { headers: { cookie: stateCookie }, redirect: "manual" })).status, 401);
      const sessionCookie = callback.headers.get("set-cookie").match(/dbx_mt_session=[^;]+/)[0];
      const response = await originalFetch(`${base}/api/connection/list`, { headers: { cookie: `${sessionCookie}; dbx_session=attacker`, "x-dbx-tenant-key": "attacker", "x-dbx-internal-secret": "attacker" } });
      assert.equal(response.status, 200);
      const result = await response.json();
      assert.equal(result.tenant, tenantKey(issuer, subject));
      assert.equal(result.cookie, undefined);
      const check = await originalFetch(`${base}/api/auth/check`, { headers: { cookie: sessionCookie } });
      assert.equal((await check.json()).tenant_id, tenantKey(issuer, subject));
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (server) await new Promise((resolve) => server.close(resolve));
  }
});
