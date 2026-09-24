/**
 * Demo Business Unit application for manual browser testing (development only).
 *
 *   DEMO_CLIENT_ID=rms-admin-dev DEMO_CLIENT_SECRET=<secret> DEMO_PORT=5173 npm run demo:client
 *   -> open http://localhost:5173
 *
 * It does exactly what a real BU backend does: Authorization Code + PKCE S256 redirect to Core,
 * callback with state check, code exchange at /token (client_secret_basic), ID token verification
 * with the published JWKS (iss, aud, exp, nonce, RS256), a /me call, and a local session.
 * The registered redirect URI must be http://localhost:<DEMO_PORT>/auth/callback.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { loadDotEnv } from '../src/config/env';

loadDotEnv();
if (process.env.NODE_ENV === 'production') throw new Error('demo client is for local testing only');

const ISSUER = (process.env.ISSUER ?? 'http://localhost:4000').replace(/\/+$/, '');
const CLIENT_ID = process.env.DEMO_CLIENT_ID ?? 'rms-admin-dev';
const CLIENT_SECRET = process.env.DEMO_CLIENT_SECRET ?? '';
const PORT = Number(process.env.DEMO_PORT ?? 5173);
const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;
const COOKIE = `demo_session_${PORT}`;
if (!CLIENT_SECRET) throw new Error('set DEMO_CLIENT_SECRET (printed once by npm run client:register)');

const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));
const pending = new Map<string, { verifier: string; nonce: string; acr: string }>();
const sessions = new Map<string, { claims: Record<string, unknown>; me: unknown; idToken: string }>();

const esc = (v: unknown) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function page(res: ServerResponse, body: string, status = 200, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>${esc(CLIENT_ID)} (demo)</title>
<style>body{font-family:system-ui,sans-serif;max-width:860px;margin:32px auto;padding:0 16px;color:#1d2b33}
h1{color:#1c5a5c;font-weight:600}a.btn{display:inline-block;margin:6px 8px 6px 0;padding:10px 18px;border-radius:999px;background:#1c5a5c;color:#fff;text-decoration:none}
a.alt{background:#8a6a45}pre{background:#f4f1ea;padding:14px;border-radius:8px;overflow:auto}.err{color:#9b2c1f}.muted{color:#5b6770}</style></head>
<body><h1>${esc(CLIENT_ID)} <span class="muted">— demo BU app</span></h1>${body}</body></html>`);
}

function cookieOf(req: IncomingMessage): string | undefined {
  return req.headers.cookie?.split(';').map((c) => c.trim().split('=')).find(([k]) => k === COOKIE)?.[1];
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  if (url.pathname === '/') {
    const s = sessions.get(cookieOf(req) ?? '');
    const status = s
      ? `<p>Signed in as <b>${esc(s.claims.name)}</b> (ITS ${esc(s.claims.sub)}) · realm <b>${esc(s.claims.auth_realm)}</b> · <b>${esc(s.claims.acr)}</b></p>
         <h3>ID token claims (verified with JWKS)</h3><pre>${esc(JSON.stringify(s.claims, null, 2))}</pre>
         <h3>GET ${esc(ISSUER)}/me</h3><pre>${esc(JSON.stringify(s.me, null, 2))}</pre>`
      : '<p class="muted">Not signed in to this application.</p>';
    return page(
      res,
      `${status}
      <p><a class="btn" href="/login">Sign in (AAL1 - password)</a><a class="btn alt" href="/login?acr=aal2">Sign in / step-up with MFA (AAL2)</a>
      <a class="btn alt" href="/login?acr=aal2&max_age=60">AAL2, MFA not older than 60 s</a>${s ? '<a class="btn" href="/local-logout">Clear local session</a>' : ''}</p>
      <p class="muted">Clearing the local session keeps the Core session: signing in again is silent (SSO).</p>`,
    );
  }

  if (url.pathname === '/login') {
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(16).toString('base64url');
    const nonce = randomBytes(16).toString('base64url');
    const acr = url.searchParams.get('acr') === 'aal2' ? 'urn:miqaat:aal:2' : '';
    pending.set(state, { verifier, nonce, acr });
    const auth = new URL(`${ISSUER}/auth`);
    auth.search = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile',
      state,
      nonce,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
      ...(acr ? { acr_values: acr } : {}),
      ...(url.searchParams.get('max_age') ? { mfa_max_age: url.searchParams.get('max_age')! } : {}),
    }).toString();
    res.writeHead(302, { location: auth.toString() }).end();
    return;
  }

  if (url.pathname === '/auth/callback') {
    const error = url.searchParams.get('error');
    if (error) return page(res, `<p class="err">Core returned <b>${esc(error)}</b>: ${esc(url.searchParams.get('error_description'))}</p><a class="btn" href="/">Back</a>`, 400);
    const flow = pending.get(url.searchParams.get('state') ?? '');
    if (!flow) return page(res, '<p class="err">Unknown or reused state.</p><a class="btn" href="/">Back</a>', 400);
    pending.delete(url.searchParams.get('state')!);

    const tokenRes = await fetch(`${ISSUER}/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64')}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: url.searchParams.get('code') ?? '', redirect_uri: REDIRECT_URI, code_verifier: flow.verifier }).toString(),
    });
    const tokens = (await tokenRes.json()) as { id_token?: string; access_token?: string; error?: string; error_description?: string };
    if (!tokens.id_token) return page(res, `<p class="err">/token failed: ${esc(tokens.error)} ${esc(tokens.error_description)}</p><a class="btn" href="/">Back</a>`, 502);

    const { payload } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: CLIENT_ID, algorithms: ['RS256'] });
    if (payload.nonce !== flow.nonce) return page(res, '<p class="err">nonce mismatch</p>', 400);
    if (flow.acr && payload.acr !== flow.acr) return page(res, `<p class="err">asked for ${esc(flow.acr)}, got ${esc(payload.acr)}</p>`, 403);
    const me = await fetch(`${ISSUER}/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } }).then((r) => r.json());

    const sid = randomBytes(24).toString('base64url');
    sessions.set(sid, { claims: payload as Record<string, unknown>, me, idToken: tokens.id_token });
    res.writeHead(303, { location: '/', 'set-cookie': `${COOKIE}=${sid}; HttpOnly; SameSite=Lax; Path=/` }).end();
    return;
  }

  if (url.pathname === '/local-logout') {
    sessions.delete(cookieOf(req) ?? '');
    res.writeHead(303, { location: '/', 'set-cookie': `${COOKIE}=; Max-Age=0; Path=/` }).end();
    return;
  }

  page(res, '<p>Not found</p>', 404);
}

createServer((req, res) => {
  handle(req, res).catch((e: unknown) => page(res, `<p class="err">${esc(e instanceof Error ? e.message : e)}</p><a class="btn" href="/">Back</a>`, 500));
}).listen(PORT, () => {
  console.log(`demo BU app "${CLIENT_ID}" on http://localhost:${PORT}  (Core: ${ISSUER}, redirect ${REDIRECT_URI})`);
});
