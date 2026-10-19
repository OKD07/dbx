#!/usr/bin/env node
// OIDC edge service for account-scoped DBX Web state in one backend process. No third-party
// middleware can supply an account name: only a verified ID token can.
import http from "node:http";
import net from "node:net";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, realpath, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ownPath = fileURLToPath(import.meta.url);
const projectRoot = path.resolve(path.dirname(ownPath), "..");
const SESSION_AGE_MS = 8 * 60 * 60 * 1000;
const LOGIN_AGE_MS = 5 * 60 * 1000;
const jsonHeaders = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export function tenantKey(issuer, subject) {
  if (!issuer || !subject) throw new Error("OIDC issuer and subject are required");
  return createHash("sha256").update(issuer).update("\0").update(subject).digest("hex");
}

function decodeJwtPart(value) {
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
}

export function verifyIdToken(jwt, jwks, expected) {
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid ID token");
  const header = decodeJwtPart(parts[0]);
  const claims = decodeJwtPart(parts[1]);
  const alg = header.alg;
  if (!["RS256", "PS256", "ES256"].includes(alg)) throw new Error("Unsupported ID token algorithm");
  const keys = jwks.keys?.filter((key) => key.kid === header.kid && key.kty !== "oct" && (!key.use || key.use === "sig") && (!key.alg || key.alg === alg));
  if (keys?.length !== 1) throw new Error("ID token signing key is unavailable or ambiguous");
  const key = createPublicKey({ key: keys[0], format: "jwk" });
  const options = alg === "PS256" ? { key, padding: 6, saltLength: 32 } : alg === "ES256" ? { key, dsaEncoding: "ieee-p1363" } : key;
  if (!verify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`), options, Buffer.from(parts[2], "base64url"))) throw new Error("Invalid ID token signature");
  const now = Math.floor(Date.now() / 1000);
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.iss !== expected.issuer || !audience.includes(expected.clientId) || (claims.azp !== undefined && claims.azp !== expected.clientId) || (audience.length > 1 && claims.azp !== expected.clientId)) throw new Error("ID token issuer or audience mismatch");
  if (typeof claims.exp !== "number" || claims.exp <= now || typeof claims.iat !== "number" || claims.iat > now + 60) throw new Error("ID token expired or issued in the future");
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf > now + 60)) throw new Error("ID token is not valid yet");
  if (claims.nonce !== expected.nonce || typeof claims.sub !== "string" || !claims.sub.trim()) throw new Error("ID token nonce or subject mismatch");
  return { issuer: claims.iss, subject: claims.sub };
}

function cookie(req, name) {
  return req.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
}

function reply(res, status, body, headers = {}) {
  res.writeHead(status, { ...jsonHeaders, ...headers });
  res.end(JSON.stringify(body));
}

async function fetchJson(url, options) {
  const response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error(`OIDC endpoint returned HTTP ${response.status}`);
  return response.json();
}

function httpsEndpoint(value) {
  const url = new URL(value);
  if (url.protocol !== "https:") throw new Error(`OIDC endpoint must use HTTPS: ${url.hostname}`);
  return url;
}

function oauthBasicPart(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

async function freeLoopbackPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.once("error", reject).listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForBackend(port, child, headers = {}) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (child.startupError) throw child.startupError;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`DBX Web exited before becoming ready (status ${child.exitCode ?? child.signalCode})`);
    try {
      const result = await fetch(`http://127.0.0.1:${port}/api/auth/check`, { headers, signal: AbortSignal.timeout(1000) });
      if (result.ok) return;
    } catch { /* still starting */ }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  child.kill();
  throw new Error("DBX Web did not become ready within 90 seconds");
}

async function serveStatic(req, res, directory) {
  if (req.method !== "GET" && req.method !== "HEAD") return reply(res, 405, { error: "method_not_allowed" });
  const url = new URL(req.url, "http://localhost");
  const decoded = decodeURIComponent(url.pathname);
  if (decoded.split("/").some((part) => part.startsWith("."))) return reply(res, 404, { error: "not_found" });
  const requested = path.resolve(directory, `.${decoded}`);
  if (requested !== directory && !requested.startsWith(`${directory}${path.sep}`)) return reply(res, 404, { error: "not_found" });
  let file = requested;
  try {
    if (!(await stat(file)).isFile()) file = path.join(directory, "index.html");
  } catch {
    file = path.join(directory, "index.html");
  }
  const resolved = await realpath(file);
  if (resolved !== directory && !resolved.startsWith(`${directory}${path.sep}`)) return reply(res, 404, { error: "not_found" });
  const extensions = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".woff2": "font/woff2" };
  res.writeHead(200, { "content-type": extensions[path.extname(file)] || "application/octet-stream", "cache-control": file.endsWith("index.html") ? "no-store" : "public, max-age=3600" });
  if (req.method === "HEAD") return res.end();
  createReadStream(file).pipe(res);
}

export async function createGateway(config) {
  const issuer = config.issuer.trim();
  const issuerUrl = httpsEndpoint(issuer);
  if (issuerUrl.search || issuerUrl.hash || issuerUrl.username || issuerUrl.password) throw new Error("OIDC issuer URL must not contain credentials, a query or a fragment");
  const redirectUri = new URL(config.redirectUri);
  if (redirectUri.pathname !== "/api/auth/oidc/callback" || redirectUri.search || redirectUri.hash || redirectUri.username || redirectUri.password || (redirectUri.protocol !== "https:" && !(redirectUri.protocol === "http:" && redirectUri.hostname === "127.0.0.1"))) {
    throw new Error("OIDC redirect URI must be an HTTPS /api/auth/oidc/callback URL (HTTP is allowed for 127.0.0.1 development)");
  }
  const cookieFlags = `Path=/; HttpOnly; SameSite=Lax${redirectUri.protocol === "https:" ? "; Secure" : ""}`;
  const directory = await realpath(config.staticDir);
  const discovery = await fetchJson(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (discovery.issuer !== issuer) throw new Error("OIDC discovery issuer mismatch");
  for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) httpsEndpoint(discovery[key]);
  if (discovery.token_endpoint_auth_methods_supported && !discovery.token_endpoint_auth_methods_supported.includes("client_secret_basic")) {
    throw new Error("OIDC provider does not support client_secret_basic");
  }
  const sessions = new Map();
  const pending = new Map();
  const publicOrigin = redirectUri.origin;
  let sharedBackend;

  function allowedOrigin(req) {
    const origin = req.headers.origin;
    const fetchSite = req.headers["sec-fetch-site"];
    return (!origin || origin === publicOrigin) && (!fetchSite || fetchSite === "same-origin" || fetchSite === "none");
  }

  async function backendFor(identity) {
    if (!sharedBackend) {
      sharedBackend = (async () => {
        const port = await freeLoopbackPort();
        const internalSecret = randomBytes(32).toString("hex");
        const childEnv = { ...process.env, DBX_DATA_DIR: config.dataDir, DBX_PORT: String(port), DBX_BIND_ADDR: "127.0.0.1", DBX_MULTITENANT_SECRET: internalSecret, DBX_MAX_ACTIVE_TENANTS: String(config.maxActiveTenants ?? 32) };
        for (const name of Object.keys(childEnv)) {
          if (name.startsWith("DBX_OIDC_") || ["DBX_PASSWORD", "DBX_DISABLE_PASSWORD", "DBX_SECRET_KEY", "DBX_SECRET_KEY_FILE", "DBX_DOCS_NOTES_ROOTS", "DBX_WEB_MCP_TOKEN", "DBX_WEB_MCP_TOKEN_FILE"].includes(name)) delete childEnv[name];
        }
        const child = spawn(config.webBinary, [], { env: childEnv, stdio: ["ignore", "inherit", "inherit"] });
        child.on("error", (error) => { child.startupError = error; });
        child.once("exit", () => { sharedBackend = undefined; });
        await waitForBackend(port, child, { "x-dbx-internal-secret": internalSecret, "x-dbx-tenant-key": tenantKey(identity.issuer, identity.subject) });
        return { port, child, internalSecret };
      })();
      sharedBackend.catch(() => { sharedBackend = undefined; });
    }
    return sharedBackend;
  }

  async function requestHandler(req, res) {
    try {
      const url = new URL(req.url, "http://localhost");
      // The identity provider's top-level redirect is necessarily cross-site;
      // its state cookie, PKCE verifier and ID-token nonce protect that path.
      const servicePath = url.pathname.startsWith("/api/") || url.pathname === "/mcp" || url.pathname.startsWith("/mcp/");
      if (servicePath && url.pathname !== "/api/auth/oidc/callback" && !allowedOrigin(req)) return reply(res, 403, { error: "origin_mismatch" });
      if (url.pathname === "/api/auth/oidc/start") {
        if (req.method !== "GET") return reply(res, 405, { error: "method_not_allowed" });
        for (const [key, value] of pending) if (value.expires <= Date.now()) pending.delete(key);
        if (pending.size >= 2048) return reply(res, 429, { error: "too_many_pending_logins" });
        const state = randomBytes(32).toString("base64url");
        const nonce = randomBytes(32).toString("base64url");
        const verifier = randomBytes(32).toString("base64url");
        pending.set(state, { nonce, verifier, expires: Date.now() + LOGIN_AGE_MS });
        const destination = new URL(discovery.authorization_endpoint);
        for (const [key, value] of Object.entries({ response_type: "code", client_id: config.clientId, redirect_uri: config.redirectUri, scope: "openid profile email", state, nonce, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" })) destination.searchParams.set(key, value);
        res.writeHead(302, { location: destination.href, "set-cookie": `dbx_oidc_state=${state}; ${cookieFlags}; Max-Age=300`, "cache-control": "no-store" });
        return res.end();
      }
      if (url.pathname === "/api/auth/oidc/callback") {
        if (req.method !== "GET") return reply(res, 405, { error: "method_not_allowed" });
        const state = url.searchParams.get("state");
        const login = pending.get(state);
        pending.delete(state);
        if (!login || login.expires < Date.now() || state !== cookie(req, "dbx_oidc_state") || !url.searchParams.get("code") || url.searchParams.has("error")) return reply(res, 401, { error: "invalid_oidc_response" });
        const body = new URLSearchParams({ grant_type: "authorization_code", code: url.searchParams.get("code"), redirect_uri: config.redirectUri, code_verifier: login.verifier });
        const basic = Buffer.from(`${oauthBasicPart(config.clientId)}:${oauthBasicPart(config.clientSecret)}`).toString("base64");
        const tokens = await fetchJson(discovery.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${basic}` }, body });
        if (typeof tokens.id_token !== "string") throw new Error("OIDC token response has no ID token");
        const identity = verifyIdToken(tokens.id_token, await fetchJson(discovery.jwks_uri), { issuer, clientId: config.clientId, nonce: login.nonce });
        for (const [key, value] of sessions) if (value.expires <= Date.now()) sessions.delete(key);
        if (sessions.size >= 10000) return reply(res, 503, { error: "session_capacity_reached" });
        const sid = randomBytes(32).toString("base64url");
        sessions.set(sid, { identity, expires: Date.now() + SESSION_AGE_MS });
        res.writeHead(302, { location: "/", "set-cookie": [`dbx_oidc_state=; ${cookieFlags}; Max-Age=0`, `dbx_mt_session=${sid}; ${cookieFlags}; Max-Age=${SESSION_AGE_MS / 1000}`], "cache-control": "no-store" });
        return res.end();
      }
      const sid = cookie(req, "dbx_mt_session");
      const session = sessions.get(sid);
      if (session && session.expires < Date.now()) sessions.delete(sid);
      const identity = session?.expires > Date.now() ? session.identity : null;
      if (url.pathname === "/api/auth/check") return reply(res, 200, { required: true, authenticated: !!identity, setup_required: false, provider: "oidc", ...(identity ? { tenant_id: tenantKey(identity.issuer, identity.subject) } : {}) });
      if (url.pathname === "/api/auth/logout") {
        if (req.method !== "POST") return reply(res, 405, { error: "method_not_allowed" });
        sessions.delete(sid);
        res.setHeader("set-cookie", `dbx_mt_session=; ${cookieFlags}; Max-Age=0`);
        return reply(res, 200, { ok: true });
      }
      if (url.pathname.startsWith("/api/") || url.pathname === "/mcp" || url.pathname.startsWith("/mcp/")) {
        if (!identity) return reply(res, 401, { error: "unauthorized" });
        const { port, internalSecret } = await backendFor(identity);
        const headers = { ...req.headers, host: `127.0.0.1:${port}` };
        delete headers.cookie;
        headers["x-dbx-internal-secret"] = internalSecret;
        headers["x-dbx-tenant-key"] = tenantKey(identity.issuer, identity.subject);
        const upstream = http.request({ hostname: "127.0.0.1", port, path: req.url, method: req.method, headers }, (response) => {
          const responseHeaders = { ...response.headers };
          delete responseHeaders["set-cookie"];
          res.writeHead(response.statusCode, responseHeaders);
          response.pipe(res);
        });
        upstream.on("error", () => reply(res, 502, { error: "backend_unavailable" }));
        req.pipe(upstream);
        return;
      }
      await serveStatic(req, res, directory);
    } catch (error) {
      console.error("OIDC gateway request failed:", error);
      if (!res.headersSent) reply(res, 502, { error: "gateway_error" });
      else res.destroy();
    }
  }

  const server = http.createServer(requestHandler);
  server.on("upgrade", async (req, socket, head) => {
    if (!allowedOrigin(req)) return socket.destroy();
    const sid = cookie(req, "dbx_mt_session");
    const session = sessions.get(sid);
    if (!session || session.expires <= Date.now()) return socket.destroy();
    try {
      const { port, internalSecret } = await backendFor(session.identity);
      const headers = { ...req.headers, host: `127.0.0.1:${port}` };
      delete headers.cookie;
      headers["x-dbx-internal-secret"] = internalSecret;
      headers["x-dbx-tenant-key"] = tenantKey(session.identity.issuer, session.identity.subject);
      const upstream = http.request({ hostname: "127.0.0.1", port, path: req.url, method: req.method, headers });
      upstream.on("response", () => socket.destroy());
      upstream.on("upgrade", (response, backendSocket, backendHead) => {
        socket.write(`HTTP/1.1 ${response.statusCode} Switching Protocols\r\n${Object.entries(response.headers).map(([key, value]) => `${key}: ${value}`).join("\r\n")}\r\n\r\n`);
        if (head.length) backendSocket.write(head);
        if (backendHead.length) socket.write(backendHead);
        socket.pipe(backendSocket).pipe(socket);
      });
      upstream.on("error", () => socket.destroy());
      upstream.end();
    } catch { socket.destroy(); }
  });
  server.on("close", () => {
    sharedBackend?.then(({ child }) => child.kill()).catch(() => {});
  });
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === ownPath) {
  const required = ["DBX_OIDC_ISSUER", "DBX_OIDC_CLIENT_ID", "DBX_OIDC_CLIENT_SECRET", "DBX_OIDC_REDIRECT_URI"];
  const missing = required.filter((name) => !process.env[name]);
  if (missing.length) throw new Error(`Missing configuration: ${missing.join(", ")}`);
  const dataDir = path.resolve(process.env.DBX_DATA_DIR || path.join(process.cwd(), "dbx-multitenant-data"));
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const maxActiveTenants = Number(process.env.DBX_MAX_ACTIVE_TENANTS || 32);
  if (!Number.isInteger(maxActiveTenants) || maxActiveTenants < 1) throw new Error("DBX_MAX_ACTIVE_TENANTS must be a positive integer");
  const server = await createGateway({ issuer: process.env.DBX_OIDC_ISSUER, clientId: process.env.DBX_OIDC_CLIENT_ID, clientSecret: process.env.DBX_OIDC_CLIENT_SECRET, redirectUri: process.env.DBX_OIDC_REDIRECT_URI, dataDir, staticDir: process.env.DBX_STATIC_DIR || path.join(projectRoot, "dist"), webBinary: process.env.DBX_WEB_BIN || path.join(projectRoot, "target", "release", "dbx-web"), maxActiveTenants });
  const port = Number(process.env.DBX_PORT || 4224);
  server.listen(port, process.env.DBX_BIND_ADDR || "127.0.0.1", () => console.log(`DBX OIDC gateway listening on port ${port}`));
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => server.close());
}
