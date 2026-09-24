/**
 * Local Test Console (development only) - one page to test oidc_mfa_auth in a browser.
 *
 *   npm run console          -> http://localhost:5170
 *
 * Plays three Business Unit apps (RMS Admin :5173, AMS Admin :5174, RMS Mumin :5175) that sign in
 * through Core with Authorization Code + PKCE, verify the ID token with JWKS and call /me. The page
 * also shows the dev outbox (OTP codes), test members (with passwords, dev only), Core sessions,
 * the audit trail and service status - refreshed live.
 * Client secrets are read from .e2e-<app>.txt (printed by npm run client:register).
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { Pool } from 'pg';
import { loadDotEnv } from '../src/config/env';
import { decryptString, toKey32 } from '../src/common/crypto.util';
import { decrypt } from '../src/modules/identity/legacy-password-cipher';
import { base32Decode, hotp } from '../src/modules/mfa/totp';
import { isAllowedPath, normalizeRelativePath } from '../src/modules/handoff/handoff-path';

loadDotEnv();
if (process.env.NODE_ENV === 'production') throw new Error('the test console is for local development only');

const ISSUER = (process.env.ISSUER ?? 'http://localhost:4000').replace(/\/+$/, '');
const CONSOLE_PORT = Number(process.env.CONSOLE_PORT ?? 5170);
const OUTBOX = resolve(process.env.OUTBOX_DIR ?? './.outbox');
const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));

interface App {
  key: string;
  clientId: string;
  label: string;
  port: number;
  secretFile: string;
  secret: string | null;
  realm: string | null;
  session: { claims: Record<string, unknown>; me: unknown; kid: string | undefined; at: string; idToken: string } | null;
  lastError: string | null;
  /** Local-only events: logout steps and received back-channel logout messages. */
  events: { at: string; text: string; ok: boolean }[];
  /** Simulates an unavailable back-channel endpoint (answers 503) to watch Core retry. */
  backchannelDown: boolean;
}

function event(app: App, text: string, ok = true) {
  app.events.unshift({ at: new Date().toISOString(), text, ok });
  app.events.length = Math.min(app.events.length, 6);
}

/** Back-channel logout jti values already processed (replay protection, BU spec §18). */
const seenLogoutJti = new Map<string, number>();
const pendingLogout = new Map<string, App>();

const apps: App[] = [
  { key: 'rms-admin', clientId: 'rms-admin-dev', label: 'RMS Admin', port: 5173 },
  { key: 'ams-admin', clientId: 'ams-admin-dev', label: 'AMS Admin', port: 5174 },
  { key: 'rms-mumin', clientId: 'rms-mumin-dev', label: 'RMS Mumin', port: 5175 },
].map((a) => ({ ...a, secretFile: `.e2e-${a.key}.txt`, secret: null, realm: null, session: null, lastError: null, events: [], backchannelDown: false }));

const pending = new Map<string, { app: App; verifier: string; nonce: string; acr: string }>();

const db = new Pool({
  max: 4,
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: `-c search_path=${process.env.DB_SCHEMA}`,
});

async function loadSecrets() {
  for (const app of apps) {
    const text = await readFile(app.secretFile, 'utf8').catch(() => '');
    app.secret = text.match(/shown once[^:]*: (\S+)/)?.[1] ?? null;
    const [row] = (await db.query('SELECT auth_realm FROM auth_clients WHERE client_id = $1', [app.clientId])).rows;
    app.realm = row?.auth_realm ?? null;
  }
}

// ---- data for the page --------------------------------------------------------------------------

async function outbox() {
  const files = await readdir(OUTBOX).catch(() => [] as string[]);
  const items = await Promise.all(
    files.map(async (f) => {
      const body = await readFile(join(OUTBOX, f), 'utf8');
      return {
        at: (await stat(join(OUTBOX, f))).mtime.toISOString(),
        channel: f.includes('_sms_') ? 'SMS' : 'Email',
        to: body.match(/^To: (.*)$/m)?.[1] ?? '',
        code: body.match(/\b(\d{6})\b/)?.[1] ?? '',
      };
    }),
  );
  return items.sort((a, b) => b.at.localeCompare(a.at)).slice(0, 8);
}

async function members() {
  const rows = (
    await db.query(`
      SELECT u.mumin_id, mm.fullname, mm.status_id, COALESCE(u.allow_login, true) AS allow_login, u.password,
             EXISTS (SELECT 1 FROM user_eligible e WHERE e.mumin_id = u.mumin_id AND NOT e.is_source_deleted) AS eligible,
             (SELECT string_agg(f.method || CASE WHEN f.is_default THEN '*' ELSE '' END, ', ' ORDER BY f.is_default DESC)
                FROM user_mfa_factors f WHERE f.its_id = u.mumin_id::text AND f.status = 'ACTIVE') AS factors,
             (mm.email IS NOT NULL) AS has_email,
             (SELECT f.totp_secret_enc FROM user_mfa_factors f WHERE f.its_id = u.mumin_id::text AND f.method = 'TOTP' AND f.status = 'ACTIVE' ORDER BY f.created_at LIMIT 1) AS totp_enc
        FROM users u JOIN mumin_master mm ON mm.mumin_id = u.mumin_id
       WHERE NOT u.is_source_deleted ORDER BY u.mumin_id`)
  ).rows;
  const locked = (
    await db.query(`SELECT its_id, count(*)::int AS n FROM auth_login_attempts
                     WHERE failure_reason = 'INVALID_PASSWORD' AND created_at > now() - interval '15 minutes' GROUP BY its_id`)
  ).rows as { its_id: string; n: number }[];
  return rows.map((r) => ({
    itsId: String(r.mumin_id),
    name: r.fullname,
    active: r.status_id === Number(process.env.ACTIVE_STATUS_ID ?? 3),
    allowLogin: r.allow_login,
    eligible: r.eligible,
    factors: r.factors ?? (r.has_email ? 'EMAIL_OTP (mumin_master)' : '—'),
    password: r.password ? decrypt(r.password) : '',
    recentWrong: locked.find((l) => l.its_id === String(r.mumin_id))?.n ?? 0,
    totpNow: r.totp_enc ? totpNow(r.totp_enc) : null,
  }));
}

/** Dev only: the authenticator-app code a TOTP member would see right now (so no phone is needed). */
function totpNow(enc: string): { code: string; secondsLeft: number } | null {
  try {
    const secret = decryptString(toKey32(process.env.DATA_ENCRYPTION_KEY ?? ''), enc);
    const now = Date.now() / 1000;
    return { code: hotp(base32Decode(secret), Math.floor(now / 30)), secondsLeft: 30 - Math.floor(now % 30) };
  } catch {
    return null;
  }
}

async function coreSessions() {
  return (
    await db.query(`SELECT sid, its_id, auth_realm, status, aal, amr, mfa_method, created_at, expires_at,
                           (SELECT string_agg(client_id, ', ') FROM auth_session_clients c WHERE c.sid = s.sid) AS apps
                      FROM auth_sessions s WHERE auth_realm IS NOT NULL ORDER BY created_at DESC LIMIT 8`)
  ).rows;
}

async function audit() {
  return (await db.query(`SELECT event_type, outcome, its_id, client_id, metadata, created_at FROM auth_audit_events ORDER BY id DESC LIMIT 14`)).rows;
}

async function service() {
  const health = await fetch(`${ISSUER}/health/ready`).then((r) => r.json()).catch(() => null);
  const keys = await fetch(`${ISSUER}/.well-known/jwks.json`).then((r) => r.json() as Promise<{ keys: { kid: string }[] }>).catch(() => null);
  return { issuer: ISSUER, health, kids: keys?.keys.map((k) => k.kid) ?? [] };
}

// ---- BU app behaviour (per port) --------------------------------------------------------------

async function appRoute(app: App, req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${app.port}`);
  const back = (hash = app.key) => res.writeHead(303, { location: `http://localhost:${CONSOLE_PORT}/#${hash}` }).end();

  if (url.pathname === '/login') {
    if (!app.secret) {
      app.lastError = `no client secret in ${app.secretFile}`;
      return back();
    }
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const acr = url.searchParams.get('acr') === 'aal2' ? 'urn:miqaat:aal:2' : '';
    pending.set(state, { app, verifier, nonce, acr });
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: app.clientId,
      redirect_uri: `http://localhost:${app.port}/auth/callback`,
      scope: 'openid profile',
      state,
      nonce,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      ...(acr ? { acr_values: acr } : {}),
      ...(url.searchParams.get('max_age') ? { mfa_max_age: url.searchParams.get('max_age')! } : {}),
    });
    res.writeHead(302, { location: `${ISSUER}/auth?${q}` }).end();
    return;
  }

  if (url.pathname === '/auth/callback') {
    const flow = pending.get(url.searchParams.get('state') ?? '');
    pending.delete(url.searchParams.get('state') ?? '');
    if (url.searchParams.get('error')) {
      app.lastError = `${url.searchParams.get('error')}: ${url.searchParams.get('error_description') ?? ''}`;
      return back();
    }
    if (!flow || flow.app !== app) {
      app.lastError = 'unknown or reused state';
      return back();
    }
    const tokenRes = await fetch(`${ISSUER}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${app.clientId}:${app.secret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: url.searchParams.get('code') ?? '',
        redirect_uri: `http://localhost:${app.port}/auth/callback`,
        code_verifier: flow.verifier,
      }),
    });
    const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string; error?: string; error_description?: string };
    if (!tokens.id_token) {
      app.lastError = `/token: ${tokens.error} ${tokens.error_description ?? ''}`;
      return back();
    }
    const { payload } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: app.clientId, algorithms: ['RS256'] });
    if (payload.nonce !== flow.nonce) {
      app.lastError = 'nonce mismatch';
      return back();
    }
    const me = await fetch(`${ISSUER}/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } }).then((r) => r.json());
    app.session = { claims: payload as Record<string, unknown>, me, kid: decodeProtectedHeader(tokens.id_token).kid, at: new Date().toISOString(), idToken: tokens.id_token };
    app.lastError = flow.acr && payload.acr !== flow.acr ? `asked for ${flow.acr}, got ${String(payload.acr)}` : null;
    return back();
  }

  // BU-initiated logout (BU spec §15): end the local session first, then send the browser to Core.
  if (url.pathname === '/logout') {
    const state = randomBytes(16).toString('base64url');
    pendingLogout.set(state, app);
    const q = new URLSearchParams({ client_id: app.clientId, post_logout_redirect_uri: `http://localhost:${app.port}/logged-out`, state });
    if (app.session) q.set('id_token_hint', app.session.idToken);
    event(app, app.session ? 'Logout clicked: local session ended, sent to Core /logout (with id_token_hint)' : 'Logout clicked without a local session: Core asks to confirm');
    app.session = null;
    app.lastError = null;
    res.writeHead(302, { location: `${ISSUER}/logout?${q}` }).end();
    return;
  }

  // Core sends the browser back here after logout.
  if (url.pathname === '/logged-out') {
    const state = url.searchParams.get('state') ?? '';
    const ok = pendingLogout.get(state) === app;
    pendingLogout.delete(state);
    event(app, ok ? `Back from Core: whole ${app.realm} realm signed out` : 'Back from Core with an unknown state', ok);
    return back();
  }

  // Back-channel logout endpoint (BU spec §16): server-to-server, no browser cookie needed.
  if (url.pathname === '/auth/core/logout' && req.method === 'POST') {
    if (app.backchannelDown) {
      event(app, 'Back-channel logout received while "endpoint down" -> answered 503 (Core will retry)', false);
      res.writeHead(503, { 'content-type': 'application/json' }).end('{"error":"unavailable"}');
      return;
    }
    const body = new URLSearchParams(await readBody(req));
    try {
      const { payload } = await jwtVerify(body.get('logout_token') ?? '', jwks, {
        issuer: ISSUER,
        audience: app.clientId,
        algorithms: ['RS256'],
        typ: 'miqaat-logout+jwt',
        clockTolerance: 30,
      });
      if (payload.auth_realm !== app.realm || typeof payload.sid !== 'string' || typeof payload.jti !== 'string') throw new Error('wrong realm / missing sid or jti');
      const replay = seenLogoutJti.has(payload.jti);
      seenLogoutJti.set(payload.jti, Date.now());
      const hadSession = app.session?.claims.sid === payload.sid;
      if (hadSession) app.session = null;
      event(
        app,
        replay
          ? `Back-channel logout replayed (jti ${payload.jti.slice(0, 8)}) - ignored, answered 200`
          : `Back-channel logout from Core verified (sid ${payload.sid.slice(0, 8)}, ${String(payload.reason)}) -> ${hadSession ? 'local session ended' : 'no local session for that sid'}`,
      );
      res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
    } catch (error) {
      event(app, `Back-channel logout REJECTED: ${error instanceof Error ? error.message : String(error)}`, false);
      res.writeHead(400, { 'content-type': 'application/json' }).end('{"error":"invalid_logout_token"}');
    }
    return;
  }

  // ---- trusted handoff: SOURCE side (Handoff spec §22) ----------------------------------------
  // The source app's backend asks Core for a handoff as itself (client_secret_basic) - it never sends
  // the ITS ID - then redirects the browser to the one-time Core URL.
  if (url.pathname === '/handoff') {
    const target = apps.find((a) => a.key === url.searchParams.get('target'));
    const path = url.searchParams.get('path') ?? '/dashboard';
    if (!app.session) {
      event(app, 'Handoff refused: sign in to this app first (source must have a local session)', false);
      return back();
    }
    if (!target) return back();
    const r = await fetch(`${ISSUER}/v1/handoff/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Basic ${Buffer.from(`${app.clientId}:${app.secret}`).toString('base64')}` },
      body: JSON.stringify({ target_client_id: target.clientId, requested_path: path }),
    });
    const body = (await r.json()) as { browser_redirect_url?: string; error?: string; error_description?: string };
    if (r.status !== 201 || !body.browser_redirect_url) {
      event(app, `Handoff to ${target.label} ${path} refused by Core: ${body.error} (${body.error_description ?? ''})`, false);
      return back();
    }
    event(app, `Handoff to ${target.label} ${path}: Core request created, browser sent to Core`);
    res.writeHead(303, { location: body.browser_redirect_url }).end();
    return;
  }

  // ---- trusted handoff: TARGET side (Handoff spec §13-20) -----------------------------------
  if (url.pathname === '/auth/core/handoff' && req.method === 'POST') {
    const assertion = new URLSearchParams(await readBody(req)).get('assertion') ?? '';
    const result = await verifyHandoff(app, assertion);
    if (!result.ok) {
      event(app, `Handoff REJECTED: ${result.code}`, false);
      return page(res, 400, app, `<h2>Could not open this page</h2><p class="err">${esc(result.code)}</p>`);
    }
    const c = result.claims;
    if (result.denied) {
      event(app, `Handoff verified for ITS ${String(c.sub)} but ${String(c.requested_path)} DENIED by ${app.label} authorization (no local session created)`, false);
      return page(res, 403, app, `<h2>Access denied</h2><p>You are signed in as ITS ${esc(c.sub)}, but you do not have permission for <code>${esc(c.requested_path)}</code> in ${esc(app.label)}.</p>`);
    }
    app.session = { claims: c, me: { note: 'signed in by trusted handoff (no token exchange)', source: c.source_client_id }, kid: result.kid, at: new Date().toISOString(), idToken: '' };
    app.lastError = null;
    event(app, `Handoff from ${String(c.source_client_id)} verified (JWKS, one-time jti) -> local session for ITS ${String(c.sub)} -> ${String(c.requested_path)}`);
    res.writeHead(303, { location: `http://localhost:${app.port}${String(c.requested_path)}`, 'cache-control': 'no-store' }).end();
    return;
  }

  // Landing pages of the demo apps (what a handoff opens).
  if (req.method === 'GET' && /^\/(dashboard|events|bookings|admin)(\/|$)/.test(url.pathname)) {
    if (!app.session) return back();
    const c = app.session.claims;
    return page(
      res,
      200,
      app,
      `<h2>${esc(url.pathname)}${url.search ? esc(url.search) : ''}</h2>
       <p>Signed in to <b>${esc(app.label)}</b> as <b>${esc(c.name ?? 'ITS ' + String(c.sub))}</b> (ITS ${esc(c.sub)}), realm ${esc(c.auth_realm)}, ${esc(c.acr)}.</p>
       ${c.source_client_id ? `<p>Arrived by <b>trusted handoff</b> from <code>${esc(c.source_client_id)}</code> - no second login, no token exchange. Core session sid <code>${esc(String(c.sid).slice(0, 8))}</code>.</p>` : ''}`,
    );
  }

  res.writeHead(303, { location: `http://localhost:${CONSOLE_PORT}/` }).end();
}

/** Target-local rules: what this demo app lets a handoff open, and who may open it. */
const TARGET_PATHS = ['/dashboard', '/events/*', '/events/*/details', '/bookings/*', '/admin/*'];
const handoffJti = new Map<string, number>();

/** Handoff spec §14, in order. Any failure: no local session, no redirect to the requested path. */
async function verifyHandoff(app: App, assertion: string): Promise<
  { ok: true; claims: Record<string, unknown>; kid: string | undefined; denied: boolean } | { ok: false; code: string }
> {
  if (!assertion) return { ok: false, code: 'HANDOFF_MISSING' };
  if (assertion.length > 8192) return { ok: false, code: 'HANDOFF_MALFORMED' };
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(assertion);
  } catch {
    return { ok: false, code: 'HANDOFF_MALFORMED' };
  }
  if (header.typ !== 'miqaat-handoff+jwt') return { ok: false, code: 'HANDOFF_TYP_INVALID' };
  if (header.alg !== 'RS256') return { ok: false, code: 'HANDOFF_ALG_INVALID' };
  if (!header.kid) return { ok: false, code: 'HANDOFF_KID_UNKNOWN' };
  let claims: Record<string, unknown>;
  try {
    // createRemoteJWKSet: trusted Core JWKS URL, cached, refreshed once for an unknown kid.
    ({ payload: claims } = await jwtVerify(assertion, jwks, {
      issuer: ISSUER,
      audience: app.clientId,
      algorithms: ['RS256'],
      typ: 'miqaat-handoff+jwt',
      clockTolerance: 30,
      requiredClaims: ['sub', 'sid', 'jti', 'iat', 'exp', 'auth_time', 'acr', 'amr', 'requested_path', 'source_client_id', 'target_client_id', 'auth_realm'],
    }));
  } catch (error) {
    const code = (error as { code?: string }).code ?? '';
    return {
      ok: false,
      code: code === 'ERR_JWT_EXPIRED' ? 'HANDOFF_EXPIRED' : code === 'ERR_JWKS_NO_MATCHING_KEY' ? 'HANDOFF_KID_UNKNOWN' : code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' ? 'HANDOFF_SIGNATURE_INVALID' : code.includes('CLAIM') ? 'HANDOFF_CLAIMS_INVALID' : 'HANDOFF_SIGNATURE_INVALID',
    };
  }
  if (claims.target_client_id !== app.clientId) return { ok: false, code: 'HANDOFF_TARGET_MISMATCH' };
  if (claims.auth_realm !== app.realm) return { ok: false, code: 'HANDOFF_REALM_MISMATCH' };
  if (!/^[0-9]{1,10}$/.test(String(claims.sub))) return { ok: false, code: 'HANDOFF_MALFORMED' };
  // One-time jti (in memory here; a real BU uses SET handoff:jti:<jti> 1 NX EX 120 in Redis).
  const now = Date.now();
  for (const [k, t] of handoffJti) if (now - t > 120_000) handoffJti.delete(k);
  if (handoffJti.has(String(claims.jti))) return { ok: false, code: 'HANDOFF_REPLAYED' };
  handoffJti.set(String(claims.jti), now);
  // The target validates the signed path again with its own rules.
  const path = normalizeRelativePath(claims.requested_path);
  if (!path || path !== claims.requested_path || !isAllowedPath(path, TARGET_PATHS)) return { ok: false, code: 'HANDOFF_PATH_INVALID' };
  // Target-local authorization (demo policy): nobody has the admin role in these demo apps.
  const denied = path.startsWith('/admin/');
  return { ok: true, claims, kid: header.kid, denied };
}

function page(res: ServerResponse, status: number, app: App, body: string) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(`<!doctype html><html><head><meta charset="utf-8"><title>${esc(app.label)}</title>
<style>body{font-family:Mulish,system-ui,sans-serif;background:#fbf9f5;color:#1d2b33;margin:0}header{background:linear-gradient(90deg,#10232a,#215f60);color:#fff;padding:16px 24px;font-size:20px}
main{max-width:760px;margin:28px auto;padding:0 16px}h2{color:#1c5a5c;font-weight:600}code{background:#f4f1ea;padding:2px 6px;border-radius:4px}.err{color:#9b2c1f;font-weight:700}a{color:#1c5a5c}</style></head>
<body><header>${esc(app.label)} <small style="opacity:.7">· demo BU app · :${app.port}</small></header><main>${body}<p><a href="http://localhost:${CONSOLE_PORT}/#${app.key}">Back to the Test Console</a></p></main></body></html>`);
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

async function handoffRequests() {
  return (
    await db.query(`SELECT id, source_client_id, target_client_id, auth_realm, requested_path, status, its_id, sid, created_at, completed_at
                      FROM handoff_requests ORDER BY created_at DESC LIMIT 8`)
  ).rows;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((done, fail) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 64 * 1024) req.destroy();
    });
    req.on('end', () => done(data));
    req.on('error', fail);
  });
}

/**
 * The cookies THIS browser holds for localhost. In local development every localhost port shares one
 * cookie jar, so the console receives Core's cookies (set by :4000) and can explain them. Core's SSO
 * cookies are matched to their server-side session through the SHA-256 of the value (only the hash is
 * stored). In production Core runs on its own domain and no application can see these cookies.
 */
const COOKIE_PURPOSE: Record<string, string> = {
  _session: 'oidc-provider session (protocol only - the realm cookies decide SSO)',
  '_session.sig': 'signature of _session',
  _interaction: 'sign-in in progress (login / MFA page)',
  '_interaction.sig': 'signature of _interaction',
  _interaction_resume: 'resumes the authorization after login / MFA',
  '_interaction_resume.sig': 'signature of _interaction_resume',
  oidc_csrf: 'CSRF secret for the login / MFA / sign-out forms',
};

async function browserCookies(req: IncomingMessage) {
  const jar = new Map<string, string>();
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) jar.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  const realmCookies: Record<string, 'ADMIN' | 'MUMIN'> = {
    [process.env.SSO_COOKIE_ADMIN ?? 'miqaat-admin-sso']: 'ADMIN',
    [process.env.SSO_COOKIE_MUMIN ?? 'miqaat-mumin-sso']: 'MUMIN',
  };
  const out: { name: string; preview: string; purpose: string; realm?: string; session?: Record<string, unknown> | null }[] = [];
  for (const [name, realm] of Object.entries(realmCookies)) {
    const value = jar.get(name);
    if (!value) {
      out.push({ name, preview: '', purpose: `Core ${realm} realm session (SSO) - not set: next ${realm} app asks for the password`, realm, session: null });
      continue;
    }
    const hash = createHash('sha256').update(value).digest('hex');
    const [s] = (
      await db.query(
        `SELECT sid, its_id, status, aal, amr, mfa_method, expires_at, absolute_expires_at,
                (SELECT string_agg(client_id, ', ') FROM auth_session_clients c WHERE c.sid = s.sid) AS apps
           FROM auth_sessions s WHERE session_secret_hash = $1`,
        [hash],
      )
    ).rows;
    out.push({ name, preview: `${value.slice(0, 6)}…${value.slice(-4)}`, purpose: `Core ${realm} realm session (SSO)`, realm, session: s ?? null });
  }
  for (const [name, value] of jar) {
    if (name in realmCookies || !(name in COOKIE_PURPOSE)) continue;
    out.push({ name, preview: `${value.slice(0, 6)}…`, purpose: COOKIE_PURPOSE[name] });
  }
  return out;
}

async function logoutDeliveries() {
  return (
    await db.query(`SELECT j.created_at, j.its_id, j.auth_realm, j.initiated_by_client, d.client_id, d.status, d.attempt_count,
                           d.last_http_status, d.last_error_code, d.next_attempt_at
                      FROM logout_deliveries d JOIN logout_jobs j ON j.id = d.job_id
                     ORDER BY j.created_at DESC, d.client_id LIMIT 10`)
  ).rows;
}

// ---- console -----------------------------------------------------------------------------------

async function consoleRoute(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${CONSOLE_PORT}`);
  if (url.pathname === '/api/state') {
    const [o, m, s, a, svc, lo, ck, ho] = await Promise.all([outbox(), members(), coreSessions(), audit(), service(), logoutDeliveries(), browserCookies(req), handoffRequests()]);
    const body = {
      apps: apps.map(({ key, clientId, label, port, realm, secret, session, lastError, events, backchannelDown }) => ({
        key,
        clientId,
        label,
        port,
        realm,
        configured: Boolean(secret),
        session: session ? { claims: session.claims, me: session.me, kid: session.kid, at: session.at } : null,
        lastError,
        events,
        backchannelDown,
      })),
      logout: lo,
      cookies: ck,
      handoffs: ho,
      outbox: o,
      members: m,
      sessions: s,
      audit: a,
      service: svc,
    };
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(body));
    return;
  }
  if (url.pathname === '/api/clear') {
    const app = apps.find((a) => a.key === url.searchParams.get('app'));
    if (app) {
      app.session = null;
      app.lastError = null;
      app.events = [];
    }
    res.writeHead(204).end();
    return;
  }
  if (url.pathname === '/api/backchannel') {
    const app = apps.find((a) => a.key === url.searchParams.get('app'));
    if (app) {
      app.backchannelDown = url.searchParams.get('down') === '1';
      event(app, `Back-channel endpoint set ${app.backchannelDown ? 'DOWN (answers 503)' : 'UP'}`, !app.backchannelDown);
    }
    res.writeHead(204).end();
    return;
  }
  if (url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }).end(PAGE);
    return;
  }
  res.writeHead(404).end();
}

const PAGE = /* html */ `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Miqaat Auth · Test Console</title>
<link href="https://fonts.googleapis.com/css2?family=Marcellus&family=Mulish:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--teal:#1c5a5c;--teal2:#2a7272;--gold:#d2a55a;--cream:#fbf9f5;--ink:#1d2b33;--muted:#5b6770;--line:#e4ded3;--ok:#15803d;--bad:#b91c1c;--card:#fff}
*{box-sizing:border-box}body{margin:0;font-family:Mulish,system-ui,sans-serif;background:var(--cream);color:var(--ink)}
header{background:linear-gradient(90deg,#10232a,#215f60);color:#fff;padding:18px 24px;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
header h1{font-family:Marcellus,serif;font-weight:400;margin:0;font-size:24px}header .gold{color:var(--gold)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;background:rgba(255,255,255,.12)}
.dot{width:8px;height:8px;border-radius:50%;background:#94a3b8}.dot.up{background:#4ade80}.dot.down{background:#f87171}
main{padding:20px 24px;display:grid;gap:18px;max-width:1500px;margin:0 auto}
h2{font-family:Marcellus,serif;font-weight:400;color:var(--teal);margin:0 0 10px;font-size:20px}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);gap:16px}
@media(max-width:1100px){.grid3,.grid2{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.app h3{margin:0;font-size:18px}.app .meta{color:var(--muted);font-size:12.5px;margin:2px 0 10px}
.realm{font-size:11px;font-weight:800;padding:2px 8px;border-radius:999px;margin-left:6px}.realm.ADMIN{background:#fde68a;color:#78350f}.realm.MUMIN{background:#bbf7d0;color:#14532d}
.btns{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
a.btn,button.btn{border:0;cursor:pointer;font:inherit;font-size:13px;font-weight:700;padding:8px 14px;border-radius:999px;background:var(--teal);color:#fff;text-decoration:none}
a.btn.gold{background:#8a6a45}a.btn.red{background:#9b2c1f}a.btn.light,button.btn.light{background:#e8efee;color:var(--teal)}
.status{padding:10px 12px;border-radius:10px;font-size:13.5px;margin-top:8px}.status.in{background:#f0fdf4;border:1px solid #bbf7d0}.status.out{background:#f8fafc;border:1px dashed var(--line);color:var(--muted)}.status.err{background:#fef2f2;border:1px solid #fecaca;color:var(--bad)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 10px;font-size:12.5px;margin-top:6px}.kv b{color:var(--muted);font-weight:600}
code,.mono{font-family:Consolas,monospace;font-size:12px}
details{margin-top:8px}summary{cursor:pointer;color:var(--teal);font-size:12.5px;font-weight:700}pre{background:#f4f1ea;border-radius:8px;padding:10px;font-size:11.5px;overflow:auto;max-height:260px}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{text-align:left;color:var(--muted);font-weight:700;border-bottom:1px solid var(--line);padding:6px}td{padding:6px;border-bottom:1px solid #f1ede5;vertical-align:top}
.code{font-family:Consolas,monospace;font-size:20px;font-weight:800;letter-spacing:3px;color:var(--teal)}
.yes{color:var(--ok);font-weight:700}.no{color:var(--bad);font-weight:700}.muted{color:var(--muted)}
.copy{border:1px solid var(--line);background:#fff;border-radius:6px;font-size:11px;padding:2px 6px;cursor:pointer}
.check td:first-child{width:28px}.check input{width:16px;height:16px}
.handoff{margin-top:10px;font-size:12.5px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}.handoff select{font:inherit;font-size:12.5px;padding:4px 6px;border:1px solid var(--line);border-radius:6px}.bc{margin-top:8px;font-size:12px;color:var(--muted)}.events{margin:8px 0 0;padding:8px 10px 8px 22px;background:#f8fafc;border-radius:8px;font-size:12px}.events li{margin:2px 0}.events li.no{color:var(--bad)}
.new{animation:flash 1.2s ease}@keyframes flash{from{background:#fef3c7}to{background:transparent}}
</style></head>
<body>
<header><h1>Miqaat Auth <span class="gold">·</span> Test Console</h1>
<span class="pill"><span class="dot" id="hdot"></span><span id="htext">checking…</span></span>
<span class="pill mono" id="issuer"></span><span class="pill mono" id="kids"></span>
<a class="btn light" id="disco" target="_blank">Discovery</a><a class="btn light" id="jwks" target="_blank">JWKS</a></header>
<main>
<section><h2>Applications (Business Units)</h2><div class="grid3" id="apps"></div>
<p class="muted" style="font-size:12.5px;margin:8px 2px 0">Each app runs on its own port and signs in through Core. "Clear" forgets only the app's local session - the Core session stays, so signing in again is silent (SSO). Use a private window to start without any Core session.</p></section>
<section class="card"><h2>Your browser’s cookies (set by Core on localhost:4000)</h2><table><thead><tr><th>Cookie</th><th>Value</th><th>What it is</th><th>Core session behind it</th></tr></thead><tbody id="cookies"></tbody></table>
<p class="muted" style="font-size:12.5px;margin:8px 2px 0">Signing in to one ADMIN app sets <b>miqaat-admin-sso</b>; every other ADMIN app is then signed in without a password (SSO). MUMIN has its own cookie, so ADMIN never signs you in to MUMIN. The cookies are HttpOnly (page scripts cannot read them) and hold only a random secret - Core stores just its SHA-256. The console can list them only because all localhost ports share cookies in development.</p></section>
<section class="grid2">
 <div class="card"><h2>Latest codes (dev outbox)</h2><table><thead><tr><th>Code</th><th>Channel</th><th>To</th><th>Sent</th></tr></thead><tbody id="outbox"></tbody></table></div>
 <div class="card"><h2>Test members</h2><table><thead><tr><th>ITS ID</th><th>Name</th><th>Active</th><th>Allow</th><th>Eligible</th><th>MFA</th><th>Password</th></tr></thead><tbody id="members"></tbody></table></div>
</section>
<section class="grid2">
 <div class="card"><h2>Core sessions</h2><table><thead><tr><th>sid</th><th>ITS</th><th>Realm</th><th>AAL</th><th>Apps</th><th>Status</th></tr></thead><tbody id="sessions"></tbody></table></div>
 <div class="card"><h2>Audit trail</h2><table><thead><tr><th>Time</th><th>Event</th><th>ITS</th><th>App</th><th>Details</th></tr></thead><tbody id="audit"></tbody></table></div>
</section>
<section class="card"><h2>Handoff requests (trusted handoff)</h2><table><thead><tr><th>Created</th><th>From</th><th>To</th><th>Path</th><th>Realm</th><th>Status</th><th>ITS (bound by Core)</th><th>sid</th></tr></thead><tbody id="handoffs"></tbody></table></section>
<section class="card"><h2>Logout deliveries (back-channel)</h2><table><thead><tr><th>Logout at</th><th>ITS</th><th>Realm</th><th>Started by</th><th>Delivered to</th><th>Status</th><th>Attempts</th><th>Last result</th></tr></thead><tbody id="logout"></tbody></table></section>
<section class="card"><h2>Test scenarios</h2><table class="check"><tbody id="scenarios"></tbody></table></section>
</main>
<script>
const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]);
const time=(t)=>new Date(t).toLocaleTimeString();
const short=(s)=>s?String(s).slice(0,8):'';
let seenCodes=new Set(),first=true;
const SCENARIOS=[
 ['RMS Admin → "Sign in + MFA", member 10110101','Login page, then code page; card shows realm ADMIN, aal:2, amr pwd+otp'],
 ['AMS Admin → "Sign in + MFA"','No pages at all (SSO + MFA reuse); same sid as RMS Admin'],
 ['RMS Mumin → "Sign in + MFA"','Login AND code again; realm MUMIN, different sid'],
 ['Private window: RMS Admin "Sign in (AAL1)", then "Sign in + MFA"','First password only (aal:1), then only the code page (step-up)'],
 ['Wait > 60 s, then "AAL2 · MFA ≤ 60 s"','Only the code page again (stale MFA re-challenged)'],
 ['On the code page enter 000000','"Incorrect code. 4 attempts left."'],
 ['Click "Send a new code" twice quickly','New code in the table, then "Please wait … seconds"'],
 ['On the code page "Use SMS instead"','Code arrives as SMS in the table'],
 ['Member 10110103 (TOTP)','Code page asks for the authenticator app (no code sent)'],
 ['Wrong password','"Incorrect ITS ID or password."'],
 ['Member 10110106','"You are not eligible…" (turn LOGIN_ELIGIBILITY_CHECK_ENABLED=false to allow)'],
 ['Member 10110108','"Your account cannot sign in at the moment…"'],
 ['Member 10110102 with "Sign in + MFA"','Explains no verification method is registered'],
 ['"Cancel" on the login page','App card shows access_denied'],
 ['Sign in to RMS Admin + AMS Admin + RMS Mumin, then "Logout" on RMS Admin','Back on console; RMS + AMS cards signed out (AMS by back-channel), MUMIN still signed in; ADMIN session REVOKED'],
 ['After that logout, "Sign in" on AMS Admin','Login page again (no SSO - the ADMIN session is gone)'],
 ['After the ADMIN logout, "Sign in" on RMS Mumin','Silent - MUMIN session untouched'],
 ['"Logout" on a card that is not signed in (while Core session exists)','Core shows "Sign out?" confirmation first'],
 ['Set AMS "endpoint down", sign in RMS+AMS, Logout on RMS','AMS delivery shows RETRY; set endpoint up -> SUCCEEDED on the next retry'],
];
function scen(){const done=JSON.parse(localStorage.getItem('scen')||'[]');
 document.getElementById('scenarios').innerHTML='<tr><th></th><th>Do this</th><th>Expected</th></tr>'+SCENARIOS.map((s,i)=>'<tr><td><input type="checkbox" data-i="'+i+'" '+(done.includes(i)?'checked':'')+'></td><td>'+esc(s[0])+'</td><td class="muted">'+esc(s[1])+'</td></tr>').join('');
 document.querySelectorAll('#scenarios input').forEach(c=>c.onchange=()=>{const d=[...document.querySelectorAll('#scenarios input:checked')].map(x=>+x.dataset.i);localStorage.setItem('scen',JSON.stringify(d))});}
function appCard(a){
 const base='http://localhost:'+a.port;
 const s=a.session,c=s?.claims||{};
 const state=!a.configured?'<div class="status err">No client secret found in .e2e-'+esc(a.key)+'.txt</div>'
  :a.lastError?'<div class="status err">'+esc(a.lastError)+'</div>':'';
 const body=s?'<div class="status in"><b>'+esc(c.name)+'</b> · ITS '+esc(c.sub)+'<div class="kv"><b>acr</b><span class="mono">'+esc(c.acr)+'</span><b>amr</b><span class="mono">'+esc((c.amr||[]).join(', '))+'</span><b>sid</b><span class="mono">'+esc(c.sid)+'</span><b>aud</b><span class="mono">'+esc(c.aud)+'</span><b>auth_time</b><span>'+esc(new Date(c.auth_time*1000).toLocaleTimeString())+'</span><b>signed by</b><span class="mono">'+esc(s.kid)+'</span></div></div><details><summary>ID token claims · /me</summary><pre>'+esc(JSON.stringify(c,null,2))+'</pre><pre>'+esc(JSON.stringify(s.me,null,2))+'</pre></details>'
  :'<div class="status out">Not signed in to this app</div>';
 return '<div class="card app" id="'+a.key+'"><h3>'+esc(a.label)+'<span class="realm '+esc(a.realm)+'">'+esc(a.realm||'no realm')+'</span></h3><div class="meta mono">'+esc(a.clientId)+' · :'+a.port+'</div>'
  +'<div class="btns"><a class="btn" href="'+base+'/login">Sign in (AAL1)</a><a class="btn gold" href="'+base+'/login?acr=aal2">Sign in + MFA (AAL2)</a><a class="btn light" href="'+base+'/login?acr=aal2&max_age=60">AAL2 · MFA ≤ 60 s</a><a class="btn red" href="'+base+'/logout">Logout (all '+esc(a.realm||'')+' apps)</a>'+(s||a.lastError?'<button class="btn light" onclick="clearApp(\\''+a.key+'\\')">Clear</button>':'')+'</div>'+state+body
  +handoffForm(a)
  +'<div class="bc"><label><input type="checkbox" '+(a.backchannelDown?'checked':'')+' onchange="setDown(\\''+a.key+'\\',this.checked)"> back-channel endpoint down (503)</label></div>'
  +(a.events.length?'<ul class="events">'+a.events.map(e=>'<li class="'+(e.ok?'':'no')+'"><span class="muted">'+time(e.at)+'</span> '+esc(e.text)+'</li>').join('')+'</ul>':'')+'</div>';
}
let APPS=[];
function handoffForm(a){const others=APPS.filter(o=>o.key!==a.key);
 return '<form class="handoff" method="get" action="http://localhost:'+a.port+'/handoff"><span class="muted">Open another app via handoff:</span> <select name="target">'+others.map(o=>'<option value="'+o.key+'">'+esc(o.label)+' ('+esc(o.realm)+')</option>').join('')+'</select> <select name="path"><option>/events/123</option><option>/events/123/details</option><option>/bookings/ABC</option><option>/dashboard</option><option>/admin/users</option></select> <button class="btn light" type="submit">Open via handoff</button></form>';}
async function setDown(k,down){await fetch('/api/backchannel?app='+k+'&down='+(down?1:0));load();}
function cookieRow(c){const s=c.session;let sess='';
 if(c.realm){sess=!c.preview?'<span class="muted">—</span>':!s?'<span class="no">no matching session (already revoked or unknown)</span>':'<span class="'+(s.status==='ACTIVE'?'yes':'no')+'">'+esc(s.status)+'</span> · sid <span class="mono">'+short(s.sid)+'</span> · ITS '+esc(s.its_id)+' · AAL '+esc(s.aal)+(s.mfa_method?' ('+esc(s.mfa_method)+')':'')+'<br><span class="muted">apps: '+esc(s.apps||'—')+' · idle expiry '+time(s.expires_at)+'</span>';}
 return '<tr><td class="mono"><b>'+esc(c.name)+'</b>'+(c.realm?' <span class="realm '+esc(c.realm)+'">'+esc(c.realm)+'</span>':'')+'</td><td class="mono">'+(c.preview?esc(c.preview):'<span class="muted">not set</span>')+'</td><td>'+esc(c.purpose)+(c.realm?'<br><span class="muted">HttpOnly · SameSite=Lax · Path=/'+(c.preview?'':'')+'</span>':'')+'</td><td>'+sess+'</td></tr>';}
function logoutRow(l){const cls=l.status==='SUCCEEDED'?'yes':l.status==='RETRY'||l.status==='PENDING'?'':'no';
 return '<tr><td>'+time(l.created_at)+'</td><td class="mono">'+esc(l.its_id)+'</td><td><span class="realm '+esc(l.auth_realm)+'">'+esc(l.auth_realm)+'</span></td><td class="mono">'+esc(l.initiated_by_client||'')+'</td><td class="mono">'+esc(l.client_id)+'</td><td class="'+cls+'">'+esc(l.status)+'</td><td>'+esc(l.attempt_count)+'</td><td class="mono muted">'+esc(l.last_http_status?('HTTP '+l.last_http_status):'')+' '+esc(l.last_error_code||'')+(l.status==='RETRY'?' · next '+time(l.next_attempt_at):'')+'</td></tr>';}
async function clearApp(k){await fetch('/api/clear?app='+k);load();}
async function load(){
 const d=await fetch('/api/state').then(r=>r.json());
 const h=d.service.health;document.getElementById('hdot').className='dot '+(h&&h.status==='ok'?'up':'down');
 document.getElementById('htext').textContent=h?('Core '+h.status+' · db '+h.checks.database+' · redis '+h.checks.redis):'Core not reachable - start the service (npm start)';
 document.getElementById('issuer').textContent=d.service.issuer;document.getElementById('kids').textContent='kid: '+(d.service.kids.join(', ')||'—');
 document.getElementById('disco').href=d.service.issuer+'/.well-known/openid-configuration';document.getElementById('jwks').href=d.service.issuer+'/.well-known/jwks.json';
 APPS=d.apps;
 document.getElementById('apps').innerHTML=d.apps.map(appCard).join('');
 document.getElementById('outbox').innerHTML=d.outbox.map(o=>{const n=!first&&!seenCodes.has(o.at+o.code);seenCodes.add(o.at+o.code);return '<tr class="'+(n?'new':'')+'"><td class="code">'+esc(o.code)+' <button class="copy" onclick="navigator.clipboard.writeText(\\''+esc(o.code)+'\\')">copy</button></td><td>'+esc(o.channel)+'</td><td class="mono">'+esc(o.to)+'</td><td>'+time(o.at)+'</td></tr>'}).join('')||'<tr><td colspan="4" class="muted">No codes yet - sign in with MFA</td></tr>';
 first=false;
 document.getElementById('members').innerHTML=d.members.map(m=>'<tr><td class="mono">'+esc(m.itsId)+'</td><td>'+esc(m.name)+'</td><td class="'+(m.active?'yes':'no')+'">'+(m.active?'yes':'no')+'</td><td class="'+(m.allowLogin?'yes':'no')+'">'+(m.allowLogin?'yes':'no')+'</td><td class="'+(m.eligible?'yes':'no')+'">'+(m.eligible?'yes':'no')+'</td><td class="mono">'+esc(m.factors)+(m.totpNow?'<br><span class="code" style="font-size:15px">'+esc(m.totpNow.code)+'</span> <span class="muted">app code · '+m.totpNow.secondsLeft+'s</span>':'')+(m.recentWrong>=5?' <span class="no">locked</span>':'')+'</td><td><span class="mono pw" data-p="'+esc(m.password)+'">••••••</span> <button class="copy" onclick="this.previousElementSibling.textContent=this.previousElementSibling.dataset.p">show</button> <button class="copy" onclick="navigator.clipboard.writeText(this.parentNode.querySelector(\\'.pw\\').dataset.p)">copy</button></td></tr>').join('');
 document.getElementById('sessions').innerHTML=d.sessions.map(s=>'<tr><td class="mono">'+short(s.sid)+'</td><td class="mono">'+esc(s.its_id)+'</td><td><span class="realm '+esc(s.auth_realm)+'">'+esc(s.auth_realm)+'</span></td><td>'+esc(s.aal)+(s.mfa_method?' <span class="muted">'+esc(s.mfa_method)+'</span>':'')+'</td><td class="mono">'+esc(s.apps||'')+'</td><td class="'+(s.status==='ACTIVE'?'yes':'no')+'">'+esc(s.status)+'</td></tr>').join('');
 document.getElementById('cookies').innerHTML=d.cookies.map(cookieRow).join('');
 document.getElementById('handoffs').innerHTML=d.handoffs.map(h=>'<tr><td>'+time(h.created_at)+'</td><td class="mono">'+esc(h.source_client_id)+'</td><td class="mono">'+esc(h.target_client_id)+'</td><td class="mono">'+esc(h.requested_path)+'</td><td><span class="realm '+esc(h.auth_realm)+'">'+esc(h.auth_realm)+'</span></td><td class="'+(h.status==='COMPLETED'?'yes':h.status==='PENDING'?'':'no')+'">'+esc(h.status)+'</td><td class="mono">'+esc(h.its_id||'')+'</td><td class="mono">'+short(h.sid)+'</td></tr>').join('')||'<tr><td colspan="8" class="muted">No handoff yet - use "Open via handoff" on a signed-in card</td></tr>';
 document.getElementById('logout').innerHTML=d.logout.map(logoutRow).join('')||'<tr><td colspan="8" class="muted">No logout yet - use a Logout button</td></tr>';
 document.getElementById('audit').innerHTML=d.audit.map(a=>'<tr><td>'+time(a.created_at)+'</td><td class="'+(a.outcome==='FAILURE'?'no':a.outcome==='SUCCESS'?'yes':'')+'">'+esc(a.event_type)+'</td><td class="mono">'+esc(a.its_id||'')+'</td><td class="mono">'+esc(a.client_id||'')+'</td><td class="mono muted">'+esc(a.metadata?JSON.stringify(a.metadata):'')+'</td></tr>').join('');
}
scen();load();setInterval(load,3000);
</script></body></html>`;

// ---- start -------------------------------------------------------------------------------------

async function main() {
  await db.query('SELECT 1');
  await loadSecrets();
  const wrap = (fn: (req: IncomingMessage, res: ServerResponse) => Promise<void>) => (req: IncomingMessage, res: ServerResponse) =>
    fn(req, res).catch((e: unknown) => {
      res.writeHead(500, { 'content-type': 'text/plain' }).end(e instanceof Error ? e.message : String(e));
    });
  createServer(wrap(consoleRoute)).listen(CONSOLE_PORT, '127.0.0.1');
  for (const app of apps) {
    createServer(
      wrap(async (req, res) => {
        await appRoute(app, req, res).catch((e: unknown) => {
          app.lastError = e instanceof Error ? e.message : String(e);
          res.writeHead(303, { location: `http://localhost:${CONSOLE_PORT}/#${app.key}` }).end();
        });
      }),
    ).listen(app.port, '127.0.0.1');
  }
  console.log(`Test Console: http://localhost:${CONSOLE_PORT}   (apps on :${apps.map((a) => a.port).join(', :')}; Core ${ISSUER})`);
  for (const a of apps) console.log(`  ${a.label.padEnd(10)} ${a.clientId}  realm ${a.realm ?? '-'}  ${a.secret ? 'secret loaded' : `NO SECRET (${a.secretFile})`}`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
