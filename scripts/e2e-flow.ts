/**
 * End-to-end check against a RUNNING service, playing both the browser and a BU backend:
 *   /auth (PKCE S256) -> login page -> password -> [MFA: code from the dev outbox] -> callback
 *   -> /token (client_secret_basic) -> ID token verified with the published JWKS.
 *
 *   npm run e2e:flow -- --client-id rms-mumin-dev --client-secret <secret> \
 *     --redirect http://localhost:5173/auth/callback --its 10110101 --password <pw> \
 *     [--acr urn:miqaat:aal:2] [--jar .e2e/browser.json] [--expect login|sso|mfa-only]
 *
 * --jar keeps the "browser" cookies between runs, to test SSO and realm isolation.
 * --password-from-db (development only) reads the member's legacy password from the local database.
 */
import 'reflect-metadata';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { loadDotEnv } from '../src/config/env';
import { one, parseArgs } from './cli-args';

loadDotEnv();
const args = parseArgs();
const ISSUER = (process.env.ISSUER ?? 'http://localhost:4000').replace(/\/+$/, '');

type Jar = Record<string, string>;

async function loadJar(path: string | undefined): Promise<Jar> {
  if (!path) return {};
  return readFile(path, 'utf8').then((s) => JSON.parse(s) as Jar).catch(() => ({}));
}

async function saveJar(path: string | undefined, jar: Jar) {
  if (!path) return;
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, JSON.stringify(jar, null, 2));
}

/** fetch with a cookie jar and manual redirects (every hop is visible to the test). */
async function request(jar: Jar, url: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  if (cookie) headers.set('cookie', cookie);
  const res = await fetch(url, { ...init, headers, redirect: 'manual' });
  for (const line of res.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(';');
    const i = pair.indexOf('=');
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1).trim();
    const expired = attrs.some((a) => /^\s*max-age=0/i.test(a) || /expires=Thu, 01 Jan 1970/i.test(a));
    if (expired || value === '') delete jar[name];
    else jar[name] = value;
  }
  return res;
}

const abs = (location: string) => new URL(location, ISSUER).toString();
const field = (html: string, name: string) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? '';
const alertText = (html: string) => html.match(/class="alert alert-(?:error|info)"[^>]*>([^<]*)</)?.[1]?.trim();

async function latestOutboxCode(since: number): Promise<string> {
  const dir = resolve(process.env.OUTBOX_DIR ?? './.outbox');
  for (let i = 0; i < 20; i++) {
    const files = await readdir(dir).catch(() => [] as string[]);
    const fresh: { f: string; t: number }[] = [];
    for (const f of files) {
      const t = (await stat(join(dir, f))).mtimeMs;
      if (t >= since) fresh.push({ f, t });
    }
    fresh.sort((a, b) => b.t - a.t);
    if (fresh.length) {
      const body = await readFile(join(dir, fresh[0].f), 'utf8');
      const code = body.match(/\b(\d{6})\b/)?.[1];
      if (code) return code;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('no OTP found in the outbox (is EMAIL_TRANSPORT=outbox?)');
}

async function passwordFromDb(itsId: string): Promise<string> {
  if (process.env.NODE_ENV === 'production') throw new Error('--password-from-db is for local development only');
  const { default: AppDataSource } = await import('../src/database/data-source');
  const { decrypt } = await import('../src/modules/identity/legacy-password-cipher');
  await AppDataSource.initialize();
  try {
    const [row] = await AppDataSource.query('SELECT password FROM users WHERE mumin_id = $1 LIMIT 1', [Number(itsId)]);
    if (!row?.password) throw new Error(`no password for ${itsId}`);
    return decrypt(row.password);
  } finally {
    await AppDataSource.destroy();
  }
}

async function main() {
  const clientId = one(args, 'client-id');
  const clientSecret = one(args, 'client-secret', process.env.E2E_CLIENT_SECRET);
  const redirectUri = one(args, 'redirect');
  const itsId = one(args, 'its');
  const acr = args.get('acr')?.[0];
  const jarPath = args.get('jar')?.[0];
  const expect = args.get('expect')?.[0];
  const wrongCodeFirst = args.has('wrong-code-first');
  const password = args.has('password-from-db') ? await passwordFromDb(itsId) : one(args, 'password', process.env.E2E_PASSWORD);
  const jar = await loadJar(jarPath);
  const seen: string[] = [];

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(16).toString('base64url');
  const nonce = randomBytes(16).toString('base64url');
  const auth = new URL(`${ISSUER}/auth`);
  auth.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(acr ? { acr_values: acr } : {}),
  }).toString();

  let res = await request(jar, auth.toString());
  let callback: URL | null = null;

  for (let hop = 0; hop < 20 && !callback; hop++) {
    if (res.status >= 300 && res.status < 400) {
      const location = abs(res.headers.get('location') ?? '');
      if (location.startsWith(redirectUri)) {
        callback = new URL(location);
        break;
      }
      res = await request(jar, location);
      continue;
    }
    const html = await res.text();
    if (res.status >= 400 && !html.includes('/login"') && !html.includes('/mfa"')) {
      throw new Error(`HTTP ${res.status}: ${alertText(html) ?? html.slice(0, 300)}`);
    }
    const uid = html.match(/action="\/interaction\/([^/"]+)\//)?.[1];
    if (!uid) throw new Error(`unexpected page (HTTP ${res.status}): ${html.slice(0, 300)}`);
    const csrf = field(html, 'csrf');
    const post = (path: string, body: Record<string, string>) =>
      request(jar, `${ISSUER}/interaction/${uid}/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', origin: new URL(ISSUER).origin },
        body: new URLSearchParams({ csrf, ...body }).toString(),
      });

    if (html.includes(`/interaction/${uid}/login"`)) {
      if (seen.includes('login')) throw new Error(`login rejected: ${alertText(html)}`);
      seen.push('login');
      console.log('  page: LOGIN  -> submitting ITS ID + password');
      res = await post('login', { its_id: itsId, password });
    } else if (html.includes(`/interaction/${uid}/mfa"`)) {
      const mfaVisits = seen.filter((s) => s === 'mfa').length;
      if (mfaVisits > (wrongCodeFirst ? 1 : 0)) {
        if (!(wrongCodeFirst && mfaVisits === 1)) throw new Error(`MFA rejected: ${alertText(html)}`);
        console.log(`  wrong code answer: ${alertText(html)}`);
      }
      seen.push('mfa');
      const method = field(html, 'method');
      const challengeId = field(html, 'challenge_id');
      console.log(`  page: MFA (${method}) -> ${alertText(html) ?? 'code sent'}`);
      const code = wrongCodeFirst && mfaVisits === 0 ? '000000' : await latestOutboxCode(Date.now() - 15_000);
      console.log('  MFA: code read from dev outbox, submitting');
      res = await post('mfa', { code, challenge_id: challengeId, method });
    } else {
      throw new Error(`unexpected page: ${alertText(html) ?? html.slice(0, 200)}`);
    }
  }
  if (!callback) throw new Error('never reached the client callback');
  await saveJar(jarPath, jar);

  if (callback.searchParams.get('error')) throw new Error(`authorization error: ${callback.searchParams.get('error')} ${callback.searchParams.get('error_description') ?? ''}`);
  if (callback.searchParams.get('state') !== state) throw new Error('state mismatch');
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('no code in callback');
  console.log(`  callback: code received (pages shown: ${seen.length ? seen.join(' -> ') : 'none, silent SSO'})`);

  const tokenRes = await fetch(`${ISSUER}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
  });
  const tokens = (await tokenRes.json()) as { id_token?: string; error?: string; error_description?: string };
  if (!tokenRes.ok || !tokens.id_token) throw new Error(`token endpoint: ${tokens.error} ${tokens.error_description ?? ''}`);

  const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));
  const { payload, protectedHeader } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: clientId, algorithms: ['RS256'] });
  if (payload.nonce !== nonce) throw new Error('nonce mismatch');
  console.log(`  id_token verified via JWKS (alg ${protectedHeader.alg}, kid ${protectedHeader.kid})`);
  console.log(JSON.stringify({ sub: payload.sub, aud: payload.aud, auth_realm: payload.auth_realm, sid: payload.sid, acr: payload.acr, amr: payload.amr ?? "(missing)", name: payload.name, auth_time: payload.auth_time }, null, 2));

  // Replay: the same code must be refused.
  const replay = await fetch(`${ISSUER}/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: verifier }).toString(),
  });
  console.log(`  code replay refused: ${replay.status === 400 ? 'yes' : `NO (HTTP ${replay.status})`}`);

  if (expect === 'sso' && seen.length) throw new Error(`expected silent SSO but saw: ${seen.join(', ')}`);
  if (expect === 'login' && !seen.includes('login')) throw new Error('expected a login page');
  if (expect === 'mfa-only' && (seen.includes('login') || !seen.includes('mfa'))) throw new Error(`expected MFA only, saw: ${seen.join(', ')}`);
  if (acr === 'urn:miqaat:aal:2' && payload.acr !== acr) throw new Error(`expected acr ${acr}, got ${String(payload.acr)}`);
  console.log('RESULT: OK');
}

main().catch((e) => {
  console.error(`RESULT: FAILED - ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
