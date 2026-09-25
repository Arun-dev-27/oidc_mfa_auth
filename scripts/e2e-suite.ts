/**
 * Full end-to-end suite for oidc_mfa_auth (development / test databases only).
 *
 *   npm run build && npm run test:e2e
 *
 * Starts the built service several times with different settings, prepares its own test clients
 * (e2e-*) and MFA factors, and walks every use case of the authentication diagrams 00-05:
 * discovery/JWKS, login rules, SSO, realm isolation, MFA (Email / SMS / TOTP, reuse, step-up,
 * resend, switch, limits, expiry), tokens (/token, /me, replay, client auth incl. private_key_jwt),
 * sessions (idle / absolute expiry, cookie rotation, Redis loss), CSRF / headers / rate limits,
 * key rotation + emergency revoke (file) and KMS signing (LocalStack).
 *
 * Only e2e-* clients, the suite's own factors and the auth_* rows of the fixed test ITS IDs are
 * reset. The synced identity tables are only read. Refuses to run when NODE_ENV=production.
 */
import 'reflect-metadata';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { readdir, readFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import Redis from 'ioredis';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify, type JWK } from 'jose';
import { encryptString, toKey32 } from '../src/common/crypto.util';
import { loadDotEnv } from '../src/config/env';
import AppDataSource from '../src/database/data-source';
import { AuthClient, HandoffPath, HandoffRequest, UserMfaFactor } from '../src/database/entities';
import { HandoffRepository } from '../src/database/repositories/handoff.repository';
import { ClientRepository } from '../src/database/repositories/client.repository';
import { MfaFactorRepository } from '../src/database/repositories/mfa.repository';
import { decrypt } from '../src/modules/identity/legacy-password-cipher';
import { base32Decode, base32Encode, hotp } from '../src/modules/mfa/totp';
import {
  abort,
  authorizeUrl,
  Browser,
  clientAssertion,
  exchange,
  fetchJwks,
  follow,
  ISSUER,
  isServerUp,
  outboxCode,
  resend,
  sleep,
  start,
  startServer,
  submitLogin,
  submitMfa,
  switchMethod,
  verifyIdToken,
  type AuthorizeParams,
  type Page,
  type RunningServer,
  type Step,
  type TestClient,
} from './lib/test-kit';

loadDotEnv();
if (process.env.NODE_ENV === 'production') throw new Error('the e2e suite never runs against production');

const AAL1 = 'urn:miqaat:aal:1';
const AAL2 = 'urn:miqaat:aal:2';
const ADMIN_COOKIE = process.env.SSO_COOKIE_ADMIN ?? 'miqaat-admin-sso';
const PREFIX = process.env.REDIS_KEY_PREFIX ?? 'oidcmfa:';

/** Fixed members of the local identity test data. */
const M = {
  main: '10110101', // active, eligible, email + sms factors
  noEmail: '10110102', // active, eligible, no email -> MFA impossible
  totp: '10110103', // allow_login NULL (= allowed), TOTP factor
  sms: '10110104', // SMS factor (default)
  mfaAll: '10110105', // email factor, used by MFA-policy / expiry / cap tests
  notEligible: '10110106',
  inactive: '10110107', // status_id 2
  notAllowed: '10110108', // allow_login false
  lockout: '10110109',
  plain: '10110110',
};
const TEST_IDS = Object.values(M);

/** Mock BU back-channel logout endpoints: POST {BC_BASE}/{client_id}. */
const BC_PORT = 5190;
const BC_BASE = `http://127.0.0.1:${BC_PORT}/bc`;
interface BcReceived {
  clientId: string;
  token: string;
  at: number;
  status: number;
}
const bc = {
  received: [] as BcReceived[],
  /** per client: 'ok' | '503' | '400', and how many requests to fail before answering ok. */
  mode: new Map<string, { mode: 'ok' | '503' | '400'; failFirst?: number }>(),
  server: null as Server | null,
};

async function startBackchannelMock(): Promise<void> {
  bc.server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const clientId = (req.url ?? '').split('/').pop() ?? '';
      const token = new URLSearchParams(body).get('logout_token') ?? '';
      const m = bc.mode.get(clientId) ?? { mode: 'ok' as const };
      let status = 200;
      if (m.failFirst && m.failFirst > 0) {
        m.failFirst--;
        status = 503;
      } else if (m.mode === '503') status = 503;
      else if (m.mode === '400') status = 400;
      bc.received.push({ clientId, token, at: Date.now(), status });
      res.writeHead(status, { 'content-type': 'application/json' }).end(status === 200 ? '{"ok":true}' : '{"error":"x"}');
    });
  });
  await new Promise<void>((r) => bc.server!.listen(BC_PORT, '127.0.0.1', () => r()));
}

// ---- results ---------------------------------------------------------------------------------

interface Result {
  group: string;
  name: string;
  ok: boolean;
  detail: string;
}
const results: Result[] = [];
let group = '';
const usedCodes = new Set<string>();

function check(name: string, ok: boolean, detail = ''): boolean {
  results.push({ group, name, ok, detail });
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `  -> ${detail}` : ''}`);
  return ok;
}

async function scenario(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (error) {
    check(`${name} (unexpected error)`, false, error instanceof Error ? error.message : String(error));
  }
}

// ---- test data ---------------------------------------------------------------------------------

const passwords = new Map<string, string>();
const totpSecrets = new Map<string, string>();
let clients: Record<'admin' | 'admin2' | 'mumin' | 'pkjwt' | 'aal2', TestClient>;

const HANDOFF_PATHS = ['/dashboard', '/events/*', '/events/*/details', '/bookings/*'];
const handoffRepo = () => new HandoffRepository(AppDataSource.getRepository(HandoffPath), AppDataSource.getRepository(HandoffRequest), AppDataSource);

async function prepareData(): Promise<void> {
  await AppDataSource.initialize();
  const rows: { mumin_id: number; password: string }[] = await AppDataSource.query(
    'SELECT mumin_id, password FROM users WHERE mumin_id = ANY($1::int[]) AND password IS NOT NULL',
    [TEST_IDS.map(Number)],
  );
  for (const r of rows) passwords.set(String(r.mumin_id), decrypt(r.password));

  // Reset only this suite's own state (never the synced tables).
  await AppDataSource.query('DELETE FROM auth_login_attempts WHERE its_id = ANY($1)', [TEST_IDS]);
  await AppDataSource.query('DELETE FROM auth_otp_challenges WHERE its_id = ANY($1)', [TEST_IDS]);
  await AppDataSource.query('DELETE FROM user_mfa_factors WHERE its_id = ANY($1)', [TEST_IDS]);

  const key = toKey32(process.env.DATA_ENCRYPTION_KEY ?? '');
  const factors = new MfaFactorRepository(AppDataSource.getRepository(UserMfaFactor));
  const add = (itsId: string, method: 'EMAIL_OTP' | 'SMS_OTP' | 'TOTP', isDefault: boolean, destination?: string, secret?: string) =>
    factors.create({
      itsId,
      method,
      isDefault,
      destinationEnc: destination ? encryptString(key, destination) : null,
      totpSecretEnc: secret ? encryptString(key, secret) : null,
    });
  await add(M.main, 'EMAIL_OTP', true, 'main.10110101@example.test');
  await add(M.main, 'SMS_OTP', false, '+919800000101');
  await add(M.sms, 'SMS_OTP', true, '+919800000104');
  await add(M.mfaAll, 'EMAIL_OTP', true, 'mfa.10110105@example.test');
  await add(M.plain, 'EMAIL_OTP', true, 'plain.10110110@example.test');
  const secret = base32Encode(randomBytes(20));
  totpSecrets.set(M.totp, secret);
  await add(M.totp, 'TOTP', true, undefined, secret);

  // Suite clients (recreated every run so their secrets are known).
  const repo = new ClientRepository(AppDataSource.getRepository(AuthClient), AppDataSource);
  const ids = ['e2e-rms-admin', 'e2e-ams-admin', 'e2e-rms-mumin', 'e2e-pkjwt-admin', 'e2e-aal2-admin'];
  await repo.deleteByClientIds(ids);
  const secretFor = async (clientId: string, realm: 'ADMIN' | 'MUMIN', port: number, defaultAcr: string | null = null, backchannel = true): Promise<TestClient> => {
    const s = randomBytes(32).toString('hex');
    const redirectUri = `http://localhost:${port}/auth/callback`;
    const logoutReturn = `http://localhost:${port}/logged-out`;
    await repo.create({
      clientId,
      name: clientId,
      applicationCode: clientId,
      businessUnit: 'E2E',
      environment: 'DEV',
      authRealm: realm,
      tokenEndpointAuthMethod: 'client_secret_basic',
      clientSecretEnc: encryptString(key, s),
      clientJwksUri: null,
      allowedScopes: 'openid profile',
      defaultAcr,
      redirectUris: [redirectUri],
      postLogoutRedirectUris: [logoutReturn],
      backchannelLogoutUri: backchannel ? `${BC_BASE}/${clientId}` : null,
    });
    return { clientId, redirectUri, secret: s };
  };
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = { ...(await exportJWK(privateKey)), kid: 'e2e-bu-key-1', alg: 'RS256', use: 'sig' } as JWK & { kid: string };
  const { d, p, q, dp, dq, qi, ...publicJwk } = privateJwk;
  void d, p, q, dp, dq, qi;
  await repo.create({
    clientId: 'e2e-pkjwt-admin',
    name: 'e2e-pkjwt-admin',
    applicationCode: 'e2e-pkjwt-admin',
    businessUnit: 'E2E',
    environment: 'DEV',
    authRealm: 'ADMIN',
    tokenEndpointAuthMethod: 'private_key_jwt',
    clientSecretEnc: null,
    clientJwksUri: null,
    clientJwks: { keys: [publicJwk as Record<string, unknown>] },
    allowedScopes: 'openid profile',
    defaultAcr: null,
    redirectUris: ['http://localhost:5184/auth/callback'],
    postLogoutRedirectUris: [],
  });
  clients = {
    admin: await secretFor('e2e-rms-admin', 'ADMIN', 5181),
    admin2: await secretFor('e2e-ams-admin', 'ADMIN', 5182),
    mumin: await secretFor('e2e-rms-mumin', 'MUMIN', 5183),
    // No back-channel URI on purpose: logout reports NO_ENDPOINT for it.
    aal2: await secretFor('e2e-aal2-admin', 'ADMIN', 5185, AAL2, false),
    pkjwt: { clientId: 'e2e-pkjwt-admin', redirectUri: 'http://localhost:5184/auth/callback', privateJwk },
  };
  // Trusted handoff between the suite's ADMIN apps (the MUMIN app too, to prove the realm check).
  for (const [c, port] of [[clients.admin, 5181], [clients.admin2, 5182], [clients.mumin, 5183], [clients.aal2, 5185], [clients.pkjwt, 5184]] as const) {
    await handoffRepo().configure(c.clientId, { callbackUri: `http://localhost:${port}/auth/core/handoff`, inbound: true, outbound: true, patterns: HANDOFF_PATHS });
  }
}

async function resetRedisCounters(): Promise<void> {
  const redis = new Redis(process.env.REDIS_URL ?? '');
  try {
    for (const pattern of [`${PREFIX}ratelimit:*`, `${PREFIX}cooldown:*`]) {
      let cursor = '0';
      do {
        const [next, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
        if (keys.length) await redis.del(...keys);
        cursor = next;
      } while (cursor !== '0');
    }
  } finally {
    redis.disconnect();
  }
}

async function deleteRedis(pattern: string): Promise<number> {
  const redis = new Redis(process.env.REDIS_URL ?? '');
  let n = 0;
  try {
    let cursor = '0';
    do {
      const [next, keys] = await redis.scan(cursor, 'MATCH', `${PREFIX}${pattern}`, 'COUNT', 500);
      if (keys.length) n += await redis.del(...keys);
      cursor = next;
    } while (cursor !== '0');
  } finally {
    redis.disconnect();
  }
  return n;
}

// ---- flow helpers -----------------------------------------------------------------------------

/** SMS source: dev outbox by default, or the mock gateway in the SMS-http profile. */
let smsSource: (since: number) => Promise<string> = async (since) => (await outboxCode('sms', since)).code;

function totpCode(itsId: string, offsetSteps = 0): string {
  return hotp(base32Decode(totpSecrets.get(itsId)!), Math.floor(Date.now() / 30_000) + offsetSteps);
}

async function codeFor(page: Page, itsId: string, since: number): Promise<string> {
  const code = page.method === 'TOTP' ? totpCode(itsId) : page.method === 'SMS_OTP' ? await smsSource(since) : (await outboxCode('email', since)).code;
  usedCodes.add(code);
  return code;
}

interface LoginOutcome {
  pages: string[];
  step: Step;
  flow: ReturnType<typeof authorizeUrl>;
  cookieBeforeMfa?: string;
}

/** Drives a whole authorization: password (from the local DB) and MFA (from outbox / SMS / TOTP). */
async function runFlow(browser: Browser, client: TestClient, itsId: string, params: AuthorizeParams = {}): Promise<LoginOutcome> {
  let since = Date.now();
  const { flow, step: first } = await start(browser, client, params);
  const pages: string[] = [];
  let step = first;
  let cookieBeforeMfa: string | undefined;
  for (let i = 0; i < 6 && step.page; i++) {
    const page = step.page;
    if (page.kind === 'login') {
      if (pages.includes('login')) break;
      pages.push('login');
      since = Date.now();
      step = await submitLogin(browser, page, client, itsId, passwords.get(itsId) ?? '');
    } else if (page.kind === 'mfa') {
      if (pages.includes('mfa')) break;
      pages.push('mfa');
      cookieBeforeMfa = browser.cookie(ADMIN_COOKIE);
      step = await submitMfa(browser, page, client, await codeFor(page, itsId, since));
    } else break;
  }
  return { pages, step, flow, cookieBeforeMfa };
}

interface Tokens {
  idToken: string;
  accessToken: string;
  claims: Record<string, unknown>;
  kid: string | undefined;
  code: string;
}

async function tokensFrom(outcome: LoginOutcome, client: TestClient): Promise<Tokens> {
  const cb = outcome.step.callback;
  if (!cb) throw new Error(`no callback (pages: ${outcome.pages.join(' -> ') || 'none'}; last page: ${outcome.step.page?.alert ?? outcome.step.page?.status ?? ''})`);
  if (cb.searchParams.get('error')) throw new Error(`authorization error ${cb.searchParams.get('error')}`);
  if (cb.searchParams.get('state') !== outcome.flow.state) throw new Error('state mismatch');
  const code = cb.searchParams.get('code') ?? '';
  const t = await exchange(client, code, outcome.flow.verifier);
  if (t.status !== 200 || !t.body.id_token) throw new Error(`token endpoint ${t.status} ${t.body.error ?? ''} ${t.body.error_description ?? ''}`);
  const { payload, kid } = await verifyIdToken(t.body.id_token, client, outcome.flow.nonce);
  return { idToken: t.body.id_token, accessToken: t.body.access_token ?? '', claims: payload, kid, code };
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// ---- mock SMS gateway ---------------------------------------------------------------------------

interface SmsMock {
  server: Server;
  fail: boolean;
  messages: { to: string; from: string; message: string; auth: string }[];
}

async function startSmsMock(port: number): Promise<SmsMock> {
  const mock: SmsMock = { server: undefined as unknown as Server, fail: false, messages: [] };
  mock.server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (mock.fail) {
        res.writeHead(500).end('gateway down');
        return;
      }
      const json = JSON.parse(body || '{}');
      mock.messages.push({ ...json, auth: req.headers.authorization ?? '' });
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id: `mock-${mock.messages.length}` }));
    });
  });
  await new Promise<void>((r) => mock.server.listen(port, '127.0.0.1', () => r()));
  return mock;
}

// ---- keys CLI -------------------------------------------------------------------------------------

function keysCli(env: Record<string, string>, ...argv: string[]): string {
  const out = spawnSync(process.execPath, ['-r', 'ts-node/register/transpile-only', '-r', 'tsconfig-paths/register', 'scripts/keys.ts', ...argv], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
  if (out.status !== 0) throw new Error(`keys ${argv.join(' ')} failed: ${out.stderr || out.stdout}`);
  return out.stdout;
}

function rotateSecret(clientId: string): string {
  const out = spawnSync(process.execPath, ['-r', 'ts-node/register/transpile-only', '-r', 'tsconfig-paths/register', 'scripts/client-rotate-secret.ts', '--client-id', clientId], {
    env: process.env,
    encoding: 'utf8',
  });
  if (out.status !== 0) throw new Error(out.stderr || out.stdout);
  return out.stdout;
}

const basicAuth = (c: TestClient) => `Basic ${Buffer.from(`${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.secret ?? '')}`).toString('base64')}`;

/** POST /token with exactly the given form and headers (no client authentication added). */
async function rawToken(form: Record<string, string>, headers: Record<string, string>) {
  const res = await fetch(`${ISSUER}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(form).toString() });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, string> };
}

// ---- profiles -------------------------------------------------------------------------------------

/** Settings shared by every run: dev outboxes and no incidental throttling. */
const BASE: Record<string, string> = {
  EMAIL_TRANSPORT: 'outbox',
  SMS_TRANSPORT: 'outbox',
  LOGIN_MAX_ATTEMPTS_PER_IP: '1000',
  OTP_MAX_SENDS_PER_HOUR: '1000',
  OTP_RESEND_COOLDOWN_SECONDS: '2',
  LOGIN_ELIGIBILITY_CHECK_ENABLED: 'true',
  MFA_REQUIRED_FOR_ALL: 'false',
  // A local .env may enable the testing static OTP; the suite switches it on only in its own profile.
  MFA_STATIC_OTP: '',
  // Deterministic key source: a developer machine may have AWS credentials (KEY_PROVIDER=auto -> SSM).
  KEY_PROVIDER: 'file',
};

let server: RunningServer | null = null;

async function profile(name: string, overrides: Record<string, string>, body: () => Promise<void>): Promise<void> {
  group = name;
  console.log(`\n=== ${name}`);
  await resetRedisCounters();
  try {
    server = await startServer(name.replace(/[^a-z0-9]+/gi, '-').toLowerCase(), { ...BASE, ...overrides });
  } catch (error) {
    check('service starts', false, error instanceof Error ? error.message : String(error));
    return;
  }
  try {
    await body();
  } finally {
    await server.stop();
    server = null;
  }
}

// ====================================================================================================

async function main() {
  if (await isServerUp()) throw new Error(`something already listens on ${ISSUER}; stop it first`);
  await prepareData();
  await startBackchannelMock();
  await rm(resolve(process.env.OUTBOX_DIR ?? './.outbox'), { recursive: true, force: true });
  await rm(resolve('.e2e/logs'), { recursive: true, force: true });
  const startedAt = new Date();

  // ------------------------------------------------------------------------------------------------
  await profile('1. Discovery, JWKS, health', {}, async () => {
    await scenario('health', async () => {
      check('GET /health/live = 200', (await fetch(`${ISSUER}/health/live`)).status === 200);
      const ready = await fetch(`${ISSUER}/health/ready`);
      const body = (await ready.json()) as { checks: Record<string, string> };
      check('GET /health/ready = 200 with database + redis up', ready.status === 200 && body.checks.database === 'up' && body.checks.redis === 'up');
    });
    await scenario('discovery', async () => {
      const d = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
      check('issuer matches ISSUER', d.issuer === ISSUER);
      check('only response_type=code (no implicit / hybrid)', same(d.response_types_supported, ['code']));
      check('PKCE: S256 only', same(d.code_challenge_methods_supported, ['S256']));
      check('ID token alg: RS256 only', same(d.id_token_signing_alg_values_supported, ['RS256']));
      check('acr values: aal:1 and aal:2', same(d.acr_values_supported, [AAL1, AAL2]));
      check('jwks_uri is /.well-known/jwks.json', d.jwks_uri === `${ISSUER}/.well-known/jwks.json`);
      check('userinfo endpoint /me advertised', d.userinfo_endpoint === `${ISSUER}/me`);
      const methods = d.token_endpoint_auth_methods_supported as string[];
      check('client auth: client_secret_basic only (standard), never "none"', same(methods, ['client_secret_basic']), JSON.stringify(methods));
      for (const c of ['sub', 'auth_realm', 'sid', 'acr', 'amr']) check(`claim "${c}" supported`, (d.claims_supported as string[]).includes(c));
    });
    await scenario('search engines and legacy logout paths', async () => {
      for (const p of ['/.well-known/openid-configuration', '/logout?client_id=e2e-rms-admin', '/health/live']) {
        const r = await fetch(`${ISSUER}${p}`, { redirect: 'manual' });
        check(`X-Robots-Tag noindex on ${p.split('?')[0]}`, r.headers.get('x-robots-tag') === 'noindex, nofollow');
      }
      const legacy = await fetch(`${ISSUER}/session/end/confirm?client_id=e2e-rms-admin&state=s1&other=x`, { redirect: 'manual' });
      check('/session/end/confirm -> 303 /logout with the logout parameters only', legacy.status === 303 && legacy.headers.get('location') === '/logout?client_id=e2e-rms-admin&state=s1', legacy.headers.get('location') ?? '');
      const bare = await fetch(`${ISSUER}/session/end`, { redirect: 'manual' });
      check('/session/end -> 303 /logout', bare.status === 303 && bare.headers.get('location') === '/logout');
    });
    await scenario('jwks', async () => {
      const jwks = await fetchJwks();
      check('JWKS has at least one RS256 signing key', jwks.keys.length > 0 && jwks.keys.every((k) => k.alg === 'RS256' && k.use === 'sig' && typeof k.kid === 'string'));
      check('JWKS contains no private key material', jwks.keys.every((k) => !['d', 'p', 'q', 'dp', 'dq', 'qi'].some((m) => m in k)));
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('2. Login, SSO, realms, tokens, /me, MFA', {}, async () => {
    const { admin, admin2, mumin, pkjwt, aal2 } = clients;
    const browser = new Browser();
    let adminTokens: Tokens | undefined;

    await scenario('first ADMIN login with AAL2', async () => {
      const out = await runFlow(browser, admin, M.main, { acr: AAL2 });
      check('pages: login -> MFA (Email OTP)', same(out.pages, ['login', 'mfa']), out.pages.join(','));
      adminTokens = await tokensFrom(out, admin);
      const c = adminTokens.claims;
      check('sub = ITS ID (mumin_id)', c.sub === M.main);
      check('aud = this client only', c.aud === admin.clientId);
      check('auth_realm = ADMIN', c.auth_realm === 'ADMIN');
      check('acr = aal:2, amr = [pwd, otp]', c.acr === AAL2 && same(c.amr, ['pwd', 'otp']));
      check('sid = Core session id (uuid)', typeof c.sid === 'string' && /^[0-9a-f-]{36}$/.test(c.sid as string));
      check('auth_time and name present', typeof c.auth_time === 'number' && typeof c.name === 'string');
      check('ID token lifetime <= 5 minutes', Number(c.exp) - Number(c.iat) <= 300);
      check('session cookie rotated after MFA', Boolean(out.cookieBeforeMfa) && out.cookieBeforeMfa !== browser.cookie(ADMIN_COOKIE));

      const bearer = { headers: { authorization: `Bearer ${adminTokens.accessToken}` } };
      const me = await fetch(`${ISSUER}/me`, bearer);
      const meBody = (await me.json()) as Record<string, unknown>;
      check('/me with access token = 200', me.status === 200, JSON.stringify(meBody));
      check('/me: sub, auth_realm, sid, name', meBody.sub === M.main && meBody.auth_realm === 'ADMIN' && meBody.sid === adminTokens.claims.sid && typeof meBody.name === 'string', JSON.stringify(meBody));

      const replay = await exchange(admin, adminTokens.code, out.flow.verifier);
      check('authorization code is one-time (replay -> invalid_grant)', replay.status === 400 && replay.body.error === 'invalid_grant');
      const afterReplay = await fetch(`${ISSUER}/me`, bearer);
      check('code replay revokes the tokens already issued from that code', afterReplay.status === 401);

      const old = new Browser();
      old.setCookie(ADMIN_COOKIE, out.cookieBeforeMfa ?? '');
      const reuse = await start(old, admin, {});
      check('pre-MFA cookie no longer works (session fixation)', reuse.step.page?.kind === 'login');
    });

    await scenario('/me userinfo', async () => {
      const none = await fetch(`${ISSUER}/me`);
      check('/me without token = 401', none.status === 401);
      const bad = await fetch(`${ISSUER}/me`, { headers: { authorization: 'Bearer not-a-token' } });
      check('/me with a bogus token = 401', bad.status === 401);
    });

    await scenario('SSO to a second ADMIN app', async () => {
      const out = await runFlow(browser, admin2, M.main, { acr: AAL2 });
      check('no password, no MFA (silent SSO + MFA reuse)', out.pages.length === 0, out.pages.join(','));
      const t = await tokensFrom(out, admin2);
      check('same Core sid, aud = second app, acr = aal:2', t.claims.sid === adminTokens?.claims.sid && t.claims.aud === admin2.clientId && t.claims.acr === AAL2);
      const cross = await exchange(admin2, adminTokens!.code, 'x'.repeat(43));
      check('a code of app A is useless to app B', cross.status === 400);
    });

    await scenario('MUMIN realm is isolated from ADMIN', async () => {
      const out = await runFlow(browser, mumin, M.main, { acr: AAL2 });
      check('MUMIN asks for password AND MFA again', same(out.pages, ['login', 'mfa']), out.pages.join(','));
      const t = await tokensFrom(out, mumin);
      check('auth_realm = MUMIN, different sid', t.claims.auth_realm === 'MUMIN' && t.claims.sid !== adminTokens?.claims.sid);
    });

    await scenario('AAL1 request while AAL2 is fresh', async () => {
      const out = await runFlow(browser, admin, M.main, {});
      const t = await tokensFrom(out, admin);
      check('silent SSO, acr still reports aal:2', out.pages.length === 0 && t.claims.acr === AAL2);
    });

    await scenario('step-up: AAL1 first, then AAL2', async () => {
      const b = new Browser();
      const first = await runFlow(b, admin, M.main, {});
      const t1 = await tokensFrom(first, admin);
      check('AAL1 login: password only, acr aal:1, amr [pwd]', same(first.pages, ['login']) && t1.claims.acr === AAL1 && same(t1.claims.amr, ['pwd']));
      const second = await runFlow(b, admin, M.main, { acr: AAL2 });
      const t2 = await tokensFrom(second, admin);
      check('step-up asks MFA only (password skipped)', same(second.pages, ['mfa']), second.pages.join(','));
      check('step-up keeps the same session and returns aal:2', t2.claims.sid === t1.claims.sid && t2.claims.acr === AAL2);
      await sleep(2100);
      const stale = await runFlow(b, admin, M.main, { acr: AAL2, mfaMaxAge: 1 });
      check('stale MFA (older than mfa_max_age) -> MFA again, no password', same(stale.pages, ['mfa']), stale.pages.join(','));
    });

    await scenario('client default_acr forces MFA', async () => {
      const out = await runFlow(new Browser(), aal2, M.main, {});
      const t = await tokensFrom(out, aal2);
      check('client registered with default_acr aal:2 gets login + MFA', same(out.pages, ['login', 'mfa']) && t.claims.acr === AAL2);
    });

    await scenario('wrong codes and attempt limit', async () => {
      const b = new Browser();
      const { step } = await start(b, admin, { acr: AAL2 });
      const since = Date.now();
      const mfa = await submitLogin(b, step.page!, admin, M.main, passwords.get(M.main)!);
      const page = mfa.page!;
      const code = await codeFor(page, M.main, since);
      let s = await submitMfa(b, page, admin, '000000');
      check('wrong code -> "Incorrect code. 4 attempts left."', s.page?.alert === 'Incorrect code. 4 attempts left.', s.page?.alert);
      for (let i = 0; i < 3; i++) s = await submitMfa(b, page, admin, '000000');
      check('4th wrong code -> "1 attempt left"', s.page?.alert === 'Incorrect code. 1 attempt left.', s.page?.alert);
      s = await submitMfa(b, page, admin, '000000');
      check('5th wrong code -> too many attempts', s.page?.alert === 'Too many incorrect codes. Request a new code.', s.page?.alert);
      s = await submitMfa(b, page, admin, code);
      check('even the right code is refused after the limit', Boolean(s.page) && !s.callback, s.page?.alert);
    });

    await scenario('resend with cooldown', async () => {
      const b = new Browser();
      const { step } = await start(b, admin, { acr: AAL2 });
      const t0 = Date.now();
      const p1 = (await submitLogin(b, step.page!, admin, M.main, passwords.get(M.main)!)).page!;
      const code1 = await codeFor(p1, M.main, t0);
      await sleep(50);
      const t1 = Date.now();
      const r1 = await resend(b, p1, admin);
      check('resend -> "A new code has been sent."', r1.page?.alert === 'A new code has been sent.', r1.page?.alert);
      const code2 = await codeFor(r1.page!, M.main, t1);
      const r2 = await resend(b, r1.page!, admin);
      check('immediate second resend -> cooldown message', /^Please wait \d+ seconds/.test(r2.page?.alert ?? ''), r2.page?.alert);
      const old = await submitMfa(b, r1.page!, admin, code1);
      check('the previous code does not work for the new challenge', Boolean(old.page) && /Incorrect code/.test(old.page?.alert ?? ''), old.page?.alert);
      const ok = await submitMfa(b, r1.page!, admin, code2);
      check('the new code works', Boolean(ok.callback));
    });

    await scenario('switch method Email -> SMS', async () => {
      const b = new Browser();
      const { step } = await start(b, admin, { acr: AAL2 });
      const p1 = (await submitLogin(b, step.page!, admin, M.main, passwords.get(M.main)!)).page!;
      check('MFA page offers SMS as an alternative', p1.method === 'EMAIL_OTP' && p1.html.includes('Use SMS'));
      const t = Date.now();
      const sw = await switchMethod(b, p1, admin, 'SMS_OTP');
      check('after switch the page shows SMS', sw.page?.method === 'SMS_OTP' && sw.page.html.includes('by SMS'));
      const done = await submitMfa(b, sw.page!, admin, await codeFor(sw.page!, M.main, t));
      check('SMS code completes the login', Boolean(done.callback));
      const [row] = await AppDataSource.query(`SELECT mfa_method FROM auth_sessions WHERE its_id = $1 AND aal = 2 ORDER BY mfa_verified_at DESC LIMIT 1`, [M.main]);
      check('session records mfa_method = SMS_OTP', row?.mfa_method === 'SMS_OTP', row?.mfa_method);
    });

    await scenario('SMS as the default method', async () => {
      const out = await runFlow(new Browser(), admin, M.sms, { acr: AAL2 });
      const t = await tokensFrom(out, admin);
      check('SMS OTP login -> acr aal:2', same(out.pages, ['login', 'mfa']) && t.claims.acr === AAL2);
    });

    await scenario('TOTP (authenticator app)', async () => {
      const b = new Browser();
      const { step } = await start(b, admin, { acr: AAL2 });
      const page = (await submitLogin(b, step.page!, admin, M.totp, passwords.get(M.totp)!)).page!;
      check('MFA page asks for the authenticator code (nothing sent)', page.method === 'TOTP' && page.html.includes('authenticator app'));
      const code = totpCode(M.totp);
      const done = await submitMfa(b, page, admin, code);
      check('valid TOTP completes the login', Boolean(done.callback));
      const b2 = new Browser();
      const s2 = await start(b2, admin, { acr: AAL2 });
      const page2 = (await submitLogin(b2, s2.step.page!, admin, M.totp, passwords.get(M.totp)!)).page!;
      const replay = await submitMfa(b2, page2, admin, code);
      check('the same TOTP code cannot be used twice', Boolean(replay.page) && /Incorrect code/.test(replay.page?.alert ?? ''), replay.page?.alert);
    });

    await scenario('no MFA method available', async () => {
      const out = await runFlow(new Browser(), admin, M.noEmail, { acr: AAL2 });
      const p = out.step.page;
      check('AAL2 for a member without email/factor -> 403 explanation page', p?.status === 403 && /no email address/.test(p.alert), p?.alert);
      const aal1 = await runFlow(new Browser(), admin, M.noEmail, {});
      check('the same member can still sign in at AAL1', Boolean(aal1.step.callback));
    });

    await scenario('cancel', async () => {
      const b = new Browser();
      const { step, flow } = await start(b, admin, { acr: AAL2 });
      const c1 = await abort(b, step.page!, admin);
      check('cancel on the login page -> access_denied to the app', c1.callback?.searchParams.get('error') === 'access_denied' && c1.callback.searchParams.get('state') === flow.state);
      const b2 = new Browser();
      const s2 = await start(b2, admin, { acr: AAL2 });
      const mfa = (await submitLogin(b2, s2.step.page!, admin, M.main, passwords.get(M.main)!)).page!;
      const c2 = await abort(b2, mfa, admin);
      check('cancel on the MFA page -> access_denied', c2.callback?.searchParams.get('error') === 'access_denied');
    });

    await scenario('login rules on the existing identity tables', async () => {
      const attempt = async (its: string, password: string) => {
        const b = new Browser();
        const { step } = await start(b, admin, {});
        return (await submitLogin(b, step.page!, admin, its, password)).page;
      };
      check('wrong password -> generic message', (await attempt(M.plain, 'wrong-password'))?.alert === 'Incorrect ITS ID or password.');
      check('inactive member (status_id 2) -> same generic message', (await attempt(M.inactive, passwords.get(M.inactive)!))?.alert === 'Incorrect ITS ID or password.');
      check('unknown ITS ID -> same generic message', (await attempt('99999999', 'x'))?.alert === 'Incorrect ITS ID or password.');
      check('malformed ITS ID -> same generic message', (await attempt('abc', 'x'))?.alert === 'Incorrect ITS ID or password.');
      check('allow_login = false -> account unavailable', /cannot sign in at the moment/.test((await attempt(M.notAllowed, passwords.get(M.notAllowed)!))?.alert ?? ''));
      check('not in user_eligible -> eligibility message', /not eligible/.test((await attempt(M.notEligible, passwords.get(M.notEligible)!))?.alert ?? ''));
      check('not eligible but WRONG password -> generic (eligibility not revealed)', (await attempt(M.notEligible, 'wrong'))?.alert === 'Incorrect ITS ID or password.');
      check('empty form -> asks for ITS ID and password', (await attempt('', ''))?.alert === 'Enter your ITS ID and password.');
    });

    await scenario('account lockout', async () => {
      const b = new Browser();
      let last: Page | undefined;
      for (let i = 0; i < 6; i++) {
        const { step } = await start(b, admin, {});
        last = (await submitLogin(b, step.page!, admin, M.lockout, `wrong-${i}`)).page;
      }
      check('6th attempt after 5 wrong passwords -> locked', /Too many incorrect attempts/.test(last?.alert ?? ''), last?.alert);
      const { step } = await start(b, admin, {});
      const right = await submitLogin(b, step.page!, admin, M.lockout, passwords.get(M.lockout)!);
      check('correct password is refused while locked', /Too many incorrect attempts/.test(right.page?.alert ?? ''), right.page?.alert);
    });

    await scenario('authorization request validation', async () => {
      const b = new Browser();
      const bad = async (overrides: Record<string, string | null>, client: TestClient = admin) => {
        const f = authorizeUrl(client, {}, overrides);
        return follow(b, await b.fetch(f.url), client.redirectUri);
      };
      const unknown = await bad({ client_id: 'nope-client' });
      check('unknown client -> 400 page, no redirect', unknown.page?.status === 400 && !unknown.callback);
      const noRealm = await bad({ client_id: 'rms-web-dev' });
      check('existing client without auth_realm -> rejected (400)', noRealm.page?.status === 400 && !noRealm.callback);
      const evil = await bad({ redirect_uri: 'https://evil.example/cb' });
      check('unregistered redirect_uri -> 400 page, never redirected', evil.page?.status === 400 && !evil.callback);
      const noPkce = await bad({ code_challenge: null, code_challenge_method: null });
      check('missing PKCE -> invalid_request', noPkce.callback?.searchParams.get('error') === 'invalid_request');
      const plain = await bad({ code_challenge_method: 'plain' });
      check('PKCE plain -> refused', Boolean(plain.callback?.searchParams.get('error')));
      const implicit = await bad({ response_type: 'id_token token' });
      const implicitError = implicit.callback?.searchParams.get('error') ?? new URLSearchParams(implicit.callback?.hash.slice(1) ?? '').get('error');
      check('implicit flow -> unsupported_response_type', implicitError === 'unsupported_response_type', implicitError ?? String(implicit.page?.status));
      const none = await bad({ prompt: 'none' });
      check('prompt=none -> login_required (every request passes the realm gate)', none.callback?.searchParams.get('error') === 'login_required');
    });

    await scenario('token endpoint validation', async () => {
      const b = new Browser();
      const run = async () => {
        const out = await runFlow(b, admin, M.main, {});
        return { code: out.step.callback!.searchParams.get('code')!, verifier: out.flow.verifier };
      };
      let x = await run();
      const wrongSecret = await exchange(admin, x.code, x.verifier, { secret: 'wrong' });
      check('wrong client secret -> 401 invalid_client', wrongSecret.status === 401 && wrongSecret.body.error === 'invalid_client');
      x = await run();
      const wrongVerifier = await exchange(admin, x.code, randomBytes(32).toString('base64url'));
      check('wrong code_verifier (PKCE) -> invalid_grant', wrongVerifier.body.error === 'invalid_grant');
      x = await run();
      const wrongRedirect = await exchange(admin, x.code, x.verifier, { redirectUri: 'http://localhost:5999/other' });
      check('different redirect_uri -> refused', wrongRedirect.status >= 400);
    });

    await scenario('client_secret_basic is the standard client authentication', async () => {
      const b = new Browser();
      const out = await runFlow(b, admin, M.main, {});
      const code = out.step.callback!.searchParams.get('code')!;
      const form = { grant_type: 'authorization_code', code, redirect_uri: admin.redirectUri, code_verifier: out.flow.verifier };
      const none = await rawToken(form, {});
      check('/token without client credentials -> refused (400 invalid_request), no token', none.status === 400 && none.body.error === 'invalid_request' && !none.body.id_token, JSON.stringify(none));
      const post = await rawToken({ ...form, client_id: admin.clientId, client_secret: admin.secret! }, {});
      check('client_secret_post (secret in the body) -> 401 invalid_client', post.status === 401 && post.body.error === 'invalid_client', `${post.status} ${post.body.error}`);
      const basic = await rawToken(form, { authorization: basicAuth(admin) });
      check('the same code with Authorization: Basic -> 200', basic.status === 200 && typeof basic.body.id_token === 'string', `${basic.status} ${basic.body.error ?? ''}`);
      const pk = await start(new Browser(), pkjwt, {});
      check('a client registered for private_key_jwt is unusable while the method is disabled (400, no redirect)', pk.step.page?.status === 400 && !pk.step.callback);
    });

    await scenario('CSRF and security headers', async () => {
      const b = new Browser();
      const { step } = await start(b, admin, {});
      const p = step.page!;
      const csp = p.headers.get('content-security-policy') ?? '';
      check("CSP frame-ancestors 'none' (no iframes)", csp.includes("frame-ancestors 'none'"));
      check('Cache-Control: no-store on login page', (p.headers.get('cache-control') ?? '').includes('no-store'));
      check('X-Content-Type-Options: nosniff', p.headers.get('x-content-type-options') === 'nosniff');
      // no-referrer would make real browsers send "Origin: null" on the login POST (CSRF rejects it).
      check('Referrer-Policy: same-origin (browsers keep the real Origin on form POSTs)', p.headers.get('referrer-policy') === 'same-origin');
      const nullOrigin = await b.post(`/signin/${p.uid}/password`, { csrf: p.csrf, its_id: M.main, password: 'x' }, 'null');
      check('POST with "Origin: null" is still refused', nullOrigin.status === 403);
      const noToken = await b.fetch(`/signin/${p.uid}/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', origin: new URL(ISSUER).origin },
        body: new URLSearchParams({ its_id: M.main, password: passwords.get(M.main)! }).toString(),
      });
      check('POST without CSRF token -> 403', noToken.status === 403);
      const crossSite = await b.post(`/signin/${p.uid}/password`, { csrf: p.csrf, its_id: M.main, password: passwords.get(M.main)! }, 'https://evil.example');
      check('POST from another Origin -> 403', crossSite.status === 403);
      const login = await b.post(`/signin/${p.uid}/password`, { csrf: p.csrf, its_id: M.main, password: passwords.get(M.main)! });
      const setCookies = login.headers.getSetCookie().join('\n');
      check('realm cookie is HttpOnly + SameSite=Lax', new RegExp(`${ADMIN_COOKIE}=[^;]+;.*HttpOnly`, 'i').test(setCookies) && /SameSite=Lax/i.test(setCookies));
    });

    await scenario('Redis loss: session rebuilt from PostgreSQL', async () => {
      const deleted = await deleteRedis('sso:*');
      const out = await runFlow(browser, admin2, M.main, {});
      check(`after deleting ${deleted} Redis session copies, SSO still works (durable auth_sessions)`, out.pages.length === 0 && Boolean(out.step.callback));
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('3. Per-IP login rate limit', { LOGIN_MAX_ATTEMPTS_PER_IP: '3' }, async () => {
    await scenario('ip limit', async () => {
      const statuses: number[] = [];
      let last: Page | undefined;
      for (let i = 0; i < 4; i++) {
        const b = new Browser();
        const { step } = await start(b, clients.admin, {});
        const res = await submitLogin(b, step.page!, clients.admin, M.plain, passwords.get(M.plain)!);
        statuses.push(res.page?.status ?? 303);
        last = res.page;
      }
      check('4th login from the same IP within the window -> 429', statuses[3] === 429 && /Too many attempts/.test(last?.alert ?? ''), statuses.join(','));
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('4. Eligibility check switched off', { LOGIN_ELIGIBILITY_CHECK_ENABLED: 'false' }, async () => {
    await scenario('eligibility off', async () => {
      const out = await runFlow(new Browser(), clients.admin, M.notEligible, {});
      const t = await tokensFrom(out, clients.admin);
      check('member missing from user_eligible can sign in', t.claims.sub === M.notEligible);
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('5. MFA for everyone + OTP expiry', { MFA_REQUIRED_FOR_ALL: 'true', OTP_TTL_SECONDS: '30' }, async () => {
    await scenario('MFA_REQUIRED_FOR_ALL', async () => {
      const out = await runFlow(new Browser(), clients.admin, M.mfaAll, {});
      const t = await tokensFrom(out, clients.admin);
      check('no acr_values requested, still login + MFA, acr aal:2', same(out.pages, ['login', 'mfa']) && t.claims.acr === AAL2);
    });
    await scenario('OTP expiry', async () => {
      const b = new Browser();
      const { step } = await start(b, clients.admin, {});
      const since = Date.now();
      const page = (await submitLogin(b, step.page!, clients.admin, M.mfaAll, passwords.get(M.mfaAll)!)).page!;
      const code = await codeFor(page, M.mfaAll, since);
      console.log('    waiting 32 s for the OTP to expire...');
      await sleep(32_000);
      const s = await submitMfa(b, page, clients.admin, code);
      check('correct code after OTP_TTL -> "This code has expired"', s.page?.alert === 'This code has expired. Request a new one.', s.page?.alert);
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('6b. Static test OTP (MFA_STATIC_OTP=123456)', { MFA_STATIC_OTP: '123456', OTP_MAX_SENDS_PER_HOUR: '1' }, async () => {
    const { admin } = clients;
    const STATIC = '123456';
    /** Password, then the given MFA code; returns the MFA page seen and the final step. */
    const loginWith = async (itsId: string, code: string) => {
      const b = new Browser();
      const { flow, step } = await start(b, admin, { acr: AAL2 });
      const afterLogin = await submitLogin(b, step.page!, admin, itsId, passwords.get(itsId) ?? '');
      const mfaPage = afterLogin.page;
      const done = mfaPage?.kind === 'mfa' ? await submitMfa(b, mfaPage, admin, code) : afterLogin;
      return { b, flow, mfaPage, done };
    };
    const tokensOf = (r: Awaited<ReturnType<typeof loginWith>>) => tokensFrom({ pages: ['login', 'mfa'], step: r.done, flow: r.flow }, admin);

    await scenario('static code accepted for every method', async () => {
      const email = await loginWith(M.main, STATIC);
      check('Email OTP member: 123456 completes MFA', email.mfaPage?.method === 'EMAIL_OTP' && Boolean(email.done.callback), email.done.page?.alert);
      const t = await tokensOf(email);
      check('ID token: acr aal:2, amr [pwd, otp]', t.claims.acr === AAL2 && same(t.claims.amr, ['pwd', 'otp']));
      const sms = await loginWith(M.sms, STATIC);
      check('SMS OTP member: 123456 completes MFA', sms.mfaPage?.method === 'SMS_OTP' && Boolean(sms.done.callback), sms.done.page?.alert);
      const totp = await loginWith(M.totp, STATIC);
      check('TOTP member: 123456 completes MFA', totp.mfaPage?.method === 'TOTP' && Boolean(totp.done.callback), totp.done.page?.alert);
      const none = await loginWith(M.noEmail, STATIC);
      check('member without any method: gets an MFA step and 123456 completes it', none.mfaPage?.kind === 'mfa' && Boolean(none.done.callback), none.mfaPage?.alert ?? none.done.page?.alert);
      const plain = await loginWith(M.plain, STATIC);
      check('another Email member: 123456 completes MFA (all users)', Boolean(plain.done.callback));
    });

    await scenario('real codes and limits still apply', async () => {
      const wrong = await loginWith(M.main, '000001');
      check('a wrong code is still refused ("Incorrect code")', Boolean(wrong.done.page) && /Incorrect code/.test(wrong.done.page?.alert ?? ''), wrong.done.page?.alert);
      const b = new Browser();
      const since = Date.now();
      const { flow, step } = await start(b, admin, { acr: AAL2 });
      const mfa = (await submitLogin(b, step.page!, admin, M.mfaAll, passwords.get(M.mfaAll)!)).page!;
      const real = await submitMfa(b, mfa, admin, await codeFor(mfa, M.mfaAll, since));
      check('the real emailed code still works', Boolean(real.callback) && Boolean((await tokensFrom({ pages: ['login', 'mfa'], step: real, flow }, admin)).idToken));
      const again = await loginWith(M.mfaAll, STATIC);
      check('hourly OTP cap (1 here) not applied while testing -> MFA page again, 123456 works', again.mfaPage?.kind === 'mfa' && Boolean(again.done.callback), again.mfaPage?.alert);
      const totpBad = await loginWith(M.totp, '000001');
      check('TOTP: a wrong code is still refused', Boolean(totpBad.done.page) && !totpBad.done.callback);
    });

    await scenario('audit', async () => {
      const rows: { n: number }[] = await AppDataSource.query(
        `SELECT count(*)::int AS n FROM auth_audit_events WHERE event_type = 'MFA_SUCCESS' AND metadata->>'staticOtp' = 'true' AND created_at >= $1`,
        [startedAt],
      );
      check('MFA_SUCCESS by the static code is audited with staticOtp: true', rows[0].n >= 5, String(rows[0].n));
      const [real] = await AppDataSource.query(
        `SELECT count(*)::int AS n FROM auth_audit_events WHERE event_type = 'MFA_SUCCESS' AND its_id = $1 AND metadata->>'staticOtp' IS NULL AND created_at >= $2`,
        [M.mfaAll, startedAt],
      );
      check('a real code is audited without the flag', real.n >= 1);
    });
  });

  await profile('6. OTP hourly cap', { OTP_MAX_SENDS_PER_HOUR: '3', OTP_RESEND_COOLDOWN_SECONDS: '0' }, async () => {
    await AppDataSource.query('DELETE FROM auth_otp_challenges WHERE its_id = $1', [M.plain]);
    await scenario('hourly cap', async () => {
      const b = new Browser();
      const { step } = await start(b, clients.admin, { acr: AAL2 });
      let s = await submitLogin(b, step.page!, clients.admin, M.plain, passwords.get(M.plain)!);
      s = await resend(b, s.page!, clients.admin);
      s = await resend(b, s.page!, clients.admin);
      check('3 codes sent', s.page?.alert === 'A new code has been sent.', s.page?.alert);
      s = await resend(b, s.page!, clients.admin);
      check('4th code in the hour -> refused', s.page?.alert === 'Too many codes were requested. Please try again later.', s.page?.alert);
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('7. Session idle timeout', { SESSION_IDLE_TTL_SECONDS: '30' }, async () => {
    await scenario('idle expiry', async () => {
      const b = new Browser();
      await tokensFrom(await runFlow(b, clients.admin, M.plain, {}), clients.admin);
      const early = await runFlow(b, clients.admin2, M.plain, {});
      check('within the idle window: SSO', early.pages.length === 0);
      console.log('    waiting 32 s without activity...');
      await sleep(32_000);
      const late = await start(b, clients.admin2, {});
      check('after SESSION_IDLE_TTL of inactivity: login required', late.step.page?.kind === 'login');
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('8. Session absolute lifetime', { SESSION_IDLE_TTL_SECONDS: '1800', SESSION_ABSOLUTE_TTL_SECONDS: '30' }, async () => {
    await scenario('absolute expiry', async () => {
      const b = new Browser();
      await tokensFrom(await runFlow(b, clients.admin, M.plain, {}), clients.admin);
      await sleep(15_000);
      const mid = await runFlow(b, clients.admin2, M.plain, {});
      check('activity at 15 s: SSO (idle is refreshed)', mid.pages.length === 0);
      console.log('    waiting until the absolute lifetime has passed...');
      await sleep(17_000);
      const late = await start(b, clients.admin2, {});
      check('after SESSION_ABSOLUTE_TTL even an active session ends: login required', late.step.page?.kind === 'login');
    });
  });

  // ------------------------------------------------------------------------------------------------
  const sms = await startSmsMock(4999);
  smsSource = async () => {
    for (let i = 0; i < 40 && !sms.messages.length; i++) await sleep(100);
    const m = sms.messages.shift();
    if (!m) throw new Error('mock SMS gateway received nothing');
    return m.message.match(/\b(\d{6})\b/)?.[1] ?? '';
  };
  await profile('9. SMS gateway adapter (http)', { SMS_TRANSPORT: 'http', SMS_HTTP_URL: 'http://127.0.0.1:4999/sms', SMS_HTTP_TOKEN: 'e2e-sms-token', SMS_SENDER_ID: 'MIQAAT' }, async () => {
    await scenario('sms http', async () => {
      sms.fail = true;
      const b = new Browser();
      const { step } = await start(b, clients.admin, { acr: AAL2 });
      const down = (await submitLogin(b, step.page!, clients.admin, M.sms, passwords.get(M.sms)!)).page!;
      check('gateway error -> "We could not send the code"', down.alert === 'We could not send the code. Please try again.', down.alert);
      sms.fail = false;
      const sent = await resend(b, down, clients.admin);
      const captured = sms.messages[0];
      check('gateway got JSON {to, from, message} with Bearer token', Boolean(captured) && captured.to === '+919800000104' && captured.from === 'MIQAAT' && captured.auth === 'Bearer e2e-sms-token');
      const done = await submitMfa(b, sent.page!, clients.admin, await smsSource(Date.now()));
      check('code delivered through the gateway completes the login', Boolean(done.callback));
    });
  });
  sms.server.close();
  smsSource = async (since) => (await outboxCode('sms', since)).code;

  // ------------------------------------------------------------------------------------------------
  const rotation = { KEY_PROVIDER: 'file', SIGNING_KEYS_FILE: './.e2e/rotation-keys.json' };
  await rm(resolve(rotation.SIGNING_KEYS_FILE), { force: true });
  const kidsOf = (text: string) => [...text.matchAll(/^(\S+)\t(\w+)/gm)].map((m) => ({ kid: m[1], status: m[2] }));
  const loginKid = async (client: TestClient, b = new Browser()) => {
    const out = await runFlow(b, client, M.plain, {});
    return tokensFrom(out, client);
  };
  let k1 = '';
  let k2 = '';
  let tokenK1: Tokens | undefined;
  const k1Browser = new Browser();
  keysCli(rotation, 'generate');
  k1 = kidsOf(keysCli(rotation, 'list'))[0]?.kid ?? '';
  await profile('10a. Key rotation - one ACTIVE key', rotation, async () => {
    await scenario('k1', async () => {
      tokenK1 = await loginKid(clients.admin, k1Browser);
      check('tokens are signed with the ACTIVE key', tokenK1.kid === k1);
    });
  });
  keysCli(rotation, 'generate');
  k2 = kidsOf(keysCli(rotation, 'list')).find((k) => k.status === 'NEXT')?.kid ?? '';
  await profile('10b. Key rotation - NEXT key prepublished', rotation, async () => {
    await scenario('prepublish', async () => {
      const kids = (await fetchJwks()).keys.map((k) => k.kid);
      check('JWKS publishes ACTIVE + NEXT before the switch', kids.includes(k1) && kids.includes(k2));
      const t = await loginKid(clients.admin);
      check('still signed by the old ACTIVE key', t.kid === k1);
    });
  });
  keysCli(rotation, 'activate', k2);
  await profile('10c. Key rotation - activated', rotation, async () => {
    await scenario('activate', async () => {
      const t = await loginKid(clients.admin);
      check('new tokens signed by the new key', t.kid === k2);
      const jwks = await fetchJwks();
      check('old key stays published as RETIRING', jwks.keys.some((k) => k.kid === k1));
      await verifyIdToken(tokenK1!.idToken, clients.admin, String(tokenK1!.claims.nonce), jwks)
        .then(() => check('a token signed before the switch still verifies', true))
        .catch((e) => check('a token signed before the switch still verifies', false, String(e)));
    });
  });
  keysCli(rotation, 'retire', k1);
  await profile('10d. Key rotation - old key retired', rotation, async () => {
    await scenario('retire', async () => {
      const jwks = await fetchJwks();
      check('retired key removed from JWKS', !jwks.keys.some((k) => k.kid === k1) && jwks.keys.some((k) => k.kid === k2));
      await verifyIdToken(tokenK1!.idToken, clients.admin, String(tokenK1!.claims.nonce), jwks)
        .then(() => check('tokens of the retired key no longer verify', false))
        .catch(() => check('tokens of the retired key no longer verify', true));
    });
  });
  const revokeOut = keysCli(rotation, 'revoke', k2, '--revoke-sessions');
  const k3 = kidsOf(keysCli(rotation, 'list')).find((k) => k.status === 'ACTIVE')?.kid ?? '';
  await profile('10e. Emergency revoke of the ACTIVE key', rotation, async () => {
    await scenario('revoke', async () => {
      check('revoke created an emergency ACTIVE key', /created emergency key/.test(revokeOut) && Boolean(k3) && k3 !== k2);
      const jwks = await fetchJwks();
      check('revoked key is gone from JWKS immediately', !jwks.keys.some((k) => k.kid === k2) && jwks.keys.some((k) => k.kid === k3));
      const [meta] = await AppDataSource.query('SELECT status, revoked_at FROM signing_key_metadata WHERE kid = $1', [k2]);
      check('signing_key_metadata: RETIRED + revoked_at', meta?.status === 'RETIRED' && Boolean(meta?.revoked_at));
      const relogin = await start(k1Browser, clients.admin, {});
      check('--revoke-sessions ended existing Core sessions (login required)', relogin.step.page?.kind === 'login');
      const t = await loginKid(clients.admin);
      check('new tokens signed by the emergency key', t.kid === k3);
    });
  });

  // ------------------------------------------------------------------------------------------------
  const kmsEnv = {
    KEY_PROVIDER: 'kms',
    AWS_ENDPOINT_URL: process.env.E2E_KMS_ENDPOINT ?? 'http://localhost:4566',
    AWS_ACCESS_KEY_ID: 'test',
    AWS_SECRET_ACCESS_KEY: 'test',
    AWS_REGION: process.env.AWS_REGION ?? 'ap-south-1',
  };
  const kmsUp = await fetch(`${kmsEnv.AWS_ENDPOINT_URL}/_localstack/health`).then((r) => r.ok).catch(() => false);
  group = '11. KMS signing (LocalStack)';
  if (!kmsUp) {
    console.log(`\n=== ${group}`);
    check('LocalStack KMS reachable', false, `${kmsEnv.AWS_ENDPOINT_URL} is not reachable (docker start miqaat-authn-localstack)`);
  } else {
    await AppDataSource.query(`UPDATE signing_key_metadata SET status = 'RETIRED' WHERE key_provider_ref LIKE 'kms:%' AND status <> 'RETIRED'`);
    const created = keysCli(kmsEnv, 'generate');
    const kmsKid1 = created.match(/generated (\S+)/)?.[1] ?? '';
    await profile('11a. KMS signing (LocalStack)', kmsEnv, async () => {
      await scenario('kms', async () => {
        const [meta] = await AppDataSource.query('SELECT key_provider_ref, public_jwk FROM signing_key_metadata WHERE kid = $1', [kmsKid1]);
        check('key created in KMS, only public JWK stored', String(meta?.key_provider_ref).startsWith('kms:') && !('d' in (meta?.public_jwk ?? {})));
        const t = await loginKid(clients.admin);
        check('ID token signed by KMS verifies with the published JWKS', t.kid === kmsKid1);
      });
    });
    keysCli(kmsEnv, 'generate');
    const next = kidsOf(keysCli(kmsEnv, 'list')).find((k) => k.status === 'NEXT')?.kid ?? '';
    keysCli(kmsEnv, 'activate', next);
    await profile('11b. KMS key rotation', kmsEnv, async () => {
      await scenario('kms rotate', async () => {
        const t = await loginKid(clients.admin);
        const jwks = await fetchJwks();
        check('after activate, tokens signed by the new KMS key; old one still published', t.kid === next && jwks.keys.some((k) => k.kid === kmsKid1));
      });
    });
    const revoked = keysCli(kmsEnv, 'revoke', next);
    const emergency = kidsOf(keysCli(kmsEnv, 'list')).find((k) => k.status === 'ACTIVE')?.kid ?? '';
    await profile('11c. KMS emergency revoke', kmsEnv, async () => {
      await scenario('kms revoke', async () => {
        const jwks = await fetchJwks();
        check('revoked KMS key removed, emergency KMS key active', /created emergency key/.test(revoked) && !jwks.keys.some((k) => k.kid === next) && (await loginKid(clients.admin)).kid === emergency);
      });
    });
  }

  // ------------------------------------------------------------------------------------------------
  // Key-set providers: SSM Parameter Store (LocalStack) and KEY_PROVIDER=auto in both directions.
  const ssmParam = `/miqaatcoredev/test/auth/jwks-private-key-e2e-${Date.now()}`;
  const ssmEnv = {
    KEY_PROVIDER: 'ssm',
    SSM_SIGNING_KEYS_PARAMETER: ssmParam,
    AWS_ENDPOINT_URL: kmsEnv.AWS_ENDPOINT_URL,
    AWS_ACCESS_KEY_ID: 'test',
    AWS_SECRET_ACCESS_KEY: 'test',
    AWS_REGION: kmsEnv.AWS_REGION,
    SIGNING_KEYS_FILE: './.e2e/ssm-must-not-use-this-file.json',
  };
  if (!kmsUp) {
    group = '11d. SSM key provider (LocalStack)';
    console.log(`\n=== ${group}`);
    check('LocalStack SSM reachable', false, `${kmsEnv.AWS_ENDPOINT_URL} is not reachable (docker start miqaat-authn-localstack)`);
  } else {
    await rm(resolve(ssmEnv.SIGNING_KEYS_FILE), { force: true });
    const ssm = new SSMClient({ region: ssmEnv.AWS_REGION, endpoint: ssmEnv.AWS_ENDPOINT_URL, credentials: { accessKeyId: 'test', secretAccessKey: 'test' } });
    const storedSet = async () => {
      const out = await ssm.send(new GetParameterCommand({ Name: ssmParam, WithDecryption: true }));
      return { type: out.Parameter?.Type, set: JSON.parse(out.Parameter?.Value ?? '{"keys":[]}') as { keys: { status: string; jwk: Record<string, unknown> }[] } };
    };
    const genOut = keysCli(ssmEnv, 'generate');
    const ssmKid1 = genOut.match(/generated (\S+)/)?.[1] ?? '';
    await profile('11d. SSM key provider (LocalStack)', ssmEnv, async () => {
      await scenario('ssm generate + sign', async () => {
        check('keys generate (KEY_PROVIDER=ssm) wrote the key set to the SSM parameter', genOut.includes(`key provider: ssm:${ssmParam}`) && Boolean(ssmKid1), genOut.slice(0, 200));
        const { type, set } = await storedSet();
        check('parameter is a SecureString holding the private JWK + status', type === 'SecureString' && set.keys.length === 1 && set.keys[0].status === 'ACTIVE' && 'd' in set.keys[0].jwk);
        const onDisk = await readFile(resolve(ssmEnv.SIGNING_KEYS_FILE), 'utf8').then(() => true).catch(() => false);
        check('no local key file was created', !onDisk);
        const jwks = await fetchJwks();
        check('JWKS publishes the SSM key, public members only', jwks.keys.some((k) => k.kid === ssmKid1) && jwks.keys.every((k) => !('d' in k)));
        const t = await loginKid(clients.admin);
        check('ID token signed (RS256, in process) with the key loaded from SSM', t.kid === ssmKid1);
        const [meta] = await AppDataSource.query('SELECT key_provider_ref FROM signing_key_metadata WHERE kid = $1', [ssmKid1]);
        check('signing_key_metadata.key_provider_ref = ssm:<parameter>', meta?.key_provider_ref === `ssm:${ssmParam}`, meta?.key_provider_ref);
      });
    });
    keysCli(ssmEnv, 'generate');
    const ssmKid2 = kidsOf(keysCli(ssmEnv, 'list')).find((k) => k.status === 'NEXT')?.kid ?? '';
    keysCli(ssmEnv, 'activate', ssmKid2);
    await profile('11e. SSM key rotation', ssmEnv, async () => {
      await scenario('ssm rotate', async () => {
        const t = await loginKid(clients.admin);
        const jwks = await fetchJwks();
        check('after activate, tokens signed by the new SSM key; old one still published (RETIRING)', t.kid === ssmKid2 && jwks.keys.some((k) => k.kid === ssmKid1));
      });
    });
    keysCli(ssmEnv, 'retire', ssmKid1);
    const afterRetire = (await storedSet()).set.keys;
    const retired = afterRetire.find((k) => k.jwk.kid === ssmKid1);
    const activeNow = afterRetire.find((k) => k.jwk.kid === ssmKid2);
    await profile('11f. KEY_PROVIDER=auto with AWS credentials -> SSM', { ...ssmEnv, KEY_PROVIDER: 'auto' }, async () => {
      await scenario('auto -> ssm', async () => {
        check('retired key kept in SSM without private material; ACTIVE key keeps it', retired?.status === 'RETIRED' && !('d' in (retired?.jwk ?? {})) && Boolean(activeNow && 'd' in activeNow.jwk));
        const jwks = await fetchJwks();
        check('auto picked SSM: JWKS = the SSM key set (retired key gone)', jwks.keys.some((k) => k.kid === ssmKid2) && !jwks.keys.some((k) => k.kid === ssmKid1));
        check('auto picked SSM: tokens signed by the SSM ACTIVE key', (await loginKid(clients.admin)).kid === ssmKid2);
        const log = await readFile(resolve('.e2e/logs/11f-key-provider-auto-with-aws-credentials-ssm.log'), 'utf8').catch(() => '');
        check('start-up log says AWS credentials found -> ssm', /KEY_PROVIDER=auto: AWS credentials found -> ssm:/.test(log));
      });
    });
    // No credentials at all: env, profile files, metadata service all unavailable.
    const noAws = {
      ...rotation,
      KEY_PROVIDER: 'auto',
      AWS_ENDPOINT_URL: '',
      AWS_ACCESS_KEY_ID: '',
      AWS_SECRET_ACCESS_KEY: '',
      AWS_SESSION_TOKEN: '',
      AWS_PROFILE: '',
      AWS_SHARED_CREDENTIALS_FILE: resolve('.e2e/no-aws-credentials'),
      AWS_CONFIG_FILE: resolve('.e2e/no-aws-config'),
      AWS_EC2_METADATA_DISABLED: 'true',
      KEY_PROVIDER_DETECT_TIMEOUT_MS: '1500',
    };
    const fileActive = kidsOf(keysCli(rotation, 'list')).find((k) => k.status === 'ACTIVE')?.kid ?? '';
    const autoList = keysCli(noAws, 'list');
    await profile('11g. KEY_PROVIDER=auto without AWS credentials -> local file', noAws, async () => {
      await scenario('auto -> file', async () => {
        check('keys CLI with auto and no credentials uses the local file', autoList.includes(`key provider: file:${rotation.SIGNING_KEYS_FILE}`), autoList.slice(0, 200));
        check('service starts without AWS credentials and signs with the file key', (await loginKid(clients.admin)).kid === fileActive && Boolean(fileActive));
        const log = await readFile(resolve('.e2e/logs/11g-key-provider-auto-without-aws-credentials-local-file.log'), 'utf8').catch(() => '');
        check('start-up log says no AWS credentials -> file', /KEY_PROVIDER=auto: no AWS credentials .*-> file:/.test(log));
      });
    });
  }

  // ------------------------------------------------------------------------------------------------
  // ------------------------------------------------------------------------------------------------
  await profile('12. Realm-wide logout + back-channel', { LOGOUT_RETRY_SCHEDULE_SECONDS: '0,1,1', LOGOUT_WORKER_INTERVAL_MS: '250' }, async () => {
    const { admin, admin2, mumin, aal2 } = clients;
    const LOGOUT_TYP = 'miqaat-logout+jwt';
    const logoutUrl = (client: TestClient, p: Record<string, string>) => `${ISSUER}/logout?${new URLSearchParams({ client_id: client.clientId, ...p })}`;
    const waitDeliveries = async (sid: string, done: (rows: { client_id: string; status: string; attempt_count: number }[]) => boolean, ms = 8000) => {
      const end = Date.now() + ms;
      let rows: { client_id: string; status: string; attempt_count: number; job_status: string }[] = [];
      while (Date.now() < end) {
        rows = await AppDataSource.query(
          `SELECT d.client_id, d.status, d.attempt_count, j.status AS job_status FROM logout_deliveries d JOIN logout_jobs j ON j.id = d.job_id WHERE j.sid = $1`,
          [sid],
        );
        if (done(rows)) break;
        await sleep(200);
      }
      return rows;
    };

    await scenario('logout with id_token_hint', async () => {
      bc.received.length = 0;
      const b = new Browser();
      const t1 = await tokensFrom(await runFlow(b, admin, M.main, { acr: AAL2 }), admin);
      const t2 = await tokensFrom(await runFlow(b, admin2, M.main, {}), admin2);
      const tm = await tokensFrom(await runFlow(b, mumin, M.main, {}), mumin);
      const sid = String(t1.claims.sid);
      check('ADMIN apps share one sid; MUMIN has its own', t2.claims.sid === sid && tm.claims.sid !== sid);

      const res = await b.fetch(logoutUrl(admin, { id_token_hint: t1.idToken, post_logout_redirect_uri: 'http://localhost:5181/logged-out', state: 'st-123' }));
      check('GET /logout -> 303 to the exact registered post-logout URI with state', res.status === 303 && res.headers.get('location') === 'http://localhost:5181/logged-out?state=st-123', `${res.status} ${res.headers.get('location')}`);
      check('realm cookie cleared in the browser', !b.cookie(ADMIN_COOKIE));
      const [row] = await AppDataSource.query('SELECT status, revoke_reason FROM auth_sessions WHERE sid = $1', [sid]);
      check('auth_sessions: REVOKED / USER_LOGOUT', row?.status === 'REVOKED' && row?.revoke_reason === 'USER_LOGOUT');
      const me = await fetch(`${ISSUER}/me`, { headers: { authorization: `Bearer ${t1.accessToken}` } });
      const me2 = await fetch(`${ISSUER}/me`, { headers: { authorization: `Bearer ${t2.accessToken}` } });
      check('access tokens issued in the session are revoked (/me = 401 for both apps)', me.status === 401 && me2.status === 401);
      const meMumin = await fetch(`${ISSUER}/me`, { headers: { authorization: `Bearer ${tm.accessToken}` } });
      check('MUMIN access token still valid', meMumin.status === 200);

      const rows = await waitDeliveries(sid, (r) => r.length === 2 && r.every((x) => x.status === 'SUCCEEDED'));
      check('back-channel delivered to both ADMIN participants (SUCCEEDED), job COMPLETED',
        rows.length === 2 && rows.every((r) => r.status === 'SUCCEEDED' && r.job_status === 'COMPLETED'), JSON.stringify(rows));
      check('nothing delivered to the MUMIN app', !bc.received.some((r) => r.clientId === mumin.clientId));

      const jwks = createLocalJWKSet(await fetchJwks());
      const jtis = new Set<string>();
      for (const client of [admin, admin2]) {
        const msg = bc.received.find((r) => r.clientId === client.clientId);
        if (!msg) {
          check(`logout JWS for ${client.clientId} received`, false);
          continue;
        }
        const { payload, protectedHeader } = await jwtVerify(msg.token, jwks, { issuer: ISSUER, audience: client.clientId, algorithms: ['RS256'], typ: LOGOUT_TYP });
        jtis.add(String(payload.jti));
        check(`logout JWS for ${client.clientId}: signature (JWKS), typ, aud, sub, sid, realm, reason, 120 s`,
          protectedHeader.typ === LOGOUT_TYP && payload.sub === M.main && payload.sid === sid && payload.auth_realm === 'ADMIN' &&
            payload.reason === 'USER_LOGOUT' && Number(payload.exp) - Number(payload.iat) === 120 &&
            typeof payload.events === 'object' && payload.events !== null && 'http://schemas.openid.net/event/backchannel-logout' in payload.events);
      }
      check('each client gets its own jti', jtis.size === 2);

      const again = await start(b, admin2, {});
      check('after logout the other ADMIN app requires login', again.step.page?.kind === 'login');
      const stillMumin = await runFlow(b, mumin, M.main, {});
      check('MUMIN SSO still silent after ADMIN logout', stillMumin.pages.length === 0 && Boolean(stillMumin.step.callback));

      const repeat = await b.fetch(logoutUrl(admin, { id_token_hint: t1.idToken, post_logout_redirect_uri: 'http://localhost:5181/logged-out', state: 'st-2' }));
      const [{ n }] = await AppDataSource.query('SELECT count(*)::int AS n FROM logout_jobs WHERE sid = $1', [sid]);
      check('repeating the logout is idempotent (303, no second job)', repeat.status === 303 && n === 1);
    });

    await scenario('logout request validation', async () => {
      const b = new Browser();
      const t1 = await tokensFrom(await runFlow(b, admin, M.plain, {}), admin);
      const t2 = await tokensFrom(await runFlow(b, admin2, M.plain, {}), admin2);
      const unknown = await b.fetch(logoutUrl({ ...admin, clientId: 'nope-client' }, {}));
      check('unknown client -> 400 page', unknown.status === 400);
      const evil = await b.fetch(logoutUrl(admin, { post_logout_redirect_uri: 'https://evil.example/out' }));
      check('unregistered post_logout_redirect_uri -> 400, never redirected', evil.status === 400 && !evil.headers.get('location'));
      const wrongAud = await b.fetch(logoutUrl(admin, { id_token_hint: t2.idToken }));
      check('id_token_hint issued to another client -> 400', wrongAud.status === 400);
      const tampered = await b.fetch(logoutUrl(admin, { id_token_hint: t1.idToken.slice(0, -4) + 'AAAA' }));
      check('tampered id_token_hint -> 400', tampered.status === 400);
      const [row] = await AppDataSource.query('SELECT status FROM auth_sessions WHERE sid = $1', [t1.claims.sid]);
      check('rejected logout requests leave the session ACTIVE', row?.status === 'ACTIVE');
    });

    await scenario('logout confirmation (no hint)', async () => {
      const b = new Browser();
      const t1 = await tokensFrom(await runFlow(b, admin, M.plain, {}), admin);
      const page = await b.fetch(logoutUrl(admin, { post_logout_redirect_uri: 'http://localhost:5181/logged-out', state: 's3' }));
      const html = await page.text();
      const csrf = html.match(/name="csrf" value="([^"]*)"/)?.[1] ?? '';
      check('without id_token_hint Core shows a "Sign out?" page (200) instead of logging out', page.status === 200 && html.includes('Sign out?'));
      const [before] = await AppDataSource.query('SELECT status FROM auth_sessions WHERE sid = $1', [t1.claims.sid]);
      check('showing the page does not end the session', before?.status === 'ACTIVE');
      const form = { client_id: admin.clientId, post_logout_redirect_uri: 'http://localhost:5181/logged-out', state: 's3' };
      const noCsrf = await b.post('/logout/confirm', form);
      check('confirm without CSRF token -> 403', noCsrf.status === 403);
      const crossSite = await b.post('/logout/confirm', { ...form, csrf }, 'https://evil.example');
      check('confirm from another Origin -> 403', crossSite.status === 403);
      const ok = await b.post('/logout/confirm', { ...form, csrf });
      check('confirm with CSRF token -> 303 to the post-logout URI', ok.status === 303 && ok.headers.get('location') === 'http://localhost:5181/logged-out?state=s3');
      const [after] = await AppDataSource.query('SELECT status FROM auth_sessions WHERE sid = $1', [t1.claims.sid]);
      check('session REVOKED after confirmation', after?.status === 'REVOKED');
    });

    await scenario('delivery outcomes: retry, dead letter, permanent failure, no endpoint', async () => {
      const b = new Browser();
      // Let deliveries from earlier scenarios finish first, so the mock's failure budget is not
      // consumed by an unrelated delivery.
      for (let i = 0; i < 40; i++) {
        const [{ n }] = await AppDataSource.query(`SELECT count(*)::int AS n FROM logout_deliveries WHERE status IN ('PENDING', 'RETRY')`);
        if (n === 0) break;
        await sleep(250);
      }
      bc.mode.set(admin.clientId, { mode: 'ok', failFirst: 2 });
      bc.mode.set(admin2.clientId, { mode: '503' });
      bc.received.length = 0;
      const t1 = await tokensFrom(await runFlow(b, admin, M.main, { acr: AAL2 }), admin);
      await tokensFrom(await runFlow(b, admin2, M.main, {}), admin2);
      await tokensFrom(await runFlow(b, aal2, M.main, {}), aal2);
      await b.fetch(logoutUrl(admin, { id_token_hint: t1.idToken }));
      const rows = await waitDeliveries(String(t1.claims.sid), (r) => r.length === 3 && r.every((x) => !['PENDING', 'RETRY'].includes(x.status)), 15_000);
      const by = (c: string) => rows.find((r) => r.client_id === c);
      check('503, 503, then 200 -> SUCCEEDED on attempt 3', by(admin.clientId)?.status === 'SUCCEEDED' && by(admin.clientId)?.attempt_count === 3, JSON.stringify(by(admin.clientId)));
      check('always 503 -> DEAD after the whole retry schedule (3 attempts)', by(admin2.clientId)?.status === 'DEAD' && by(admin2.clientId)?.attempt_count === 3, JSON.stringify(by(admin2.clientId)));
      check('client without a back-channel URI -> NO_ENDPOINT', by(aal2.clientId)?.status === 'NO_ENDPOINT', JSON.stringify(by(aal2.clientId)));
      const [job] = await AppDataSource.query('SELECT status FROM logout_jobs WHERE sid = $1', [t1.claims.sid]);
      check('job COMPLETED_WITH_FAILURES when a delivery is DEAD', job?.status === 'COMPLETED_WITH_FAILURES');
      const retried = bc.received
        .filter((r) => r.clientId === admin.clientId && decodeJwt(r.token).sid === t1.claims.sid)
        .map((r) => String(decodeJwt(r.token).jti));
      check('the jti stays the same across retries (BU can de-duplicate)', retried.length === 3 && new Set(retried).size === 1);
      const relogin = await start(b, admin, {});
      check('a failed delivery never restores the Core session (login required)', relogin.step.page?.kind === 'login');

      bc.mode.set(admin.clientId, { mode: '400' });
      const b2 = new Browser();
      const t3 = await tokensFrom(await runFlow(b2, admin, M.main, {}), admin);
      bc.received.length = 0;
      await b2.fetch(logoutUrl(admin, { id_token_hint: t3.idToken }));
      const r2 = await waitDeliveries(String(t3.claims.sid), (r) => r.length === 1 && r[0].status !== 'PENDING' && r[0].status !== 'RETRY');
      check('HTTP 400 from the BU -> FAILED after 1 attempt, no retry', r2[0]?.status === 'FAILED' && r2[0]?.attempt_count === 1, JSON.stringify(r2));
      bc.mode.clear();
    });

    await scenario('audit', async () => {
      const rows: { event_type: string }[] = await AppDataSource.query(`SELECT DISTINCT event_type FROM auth_audit_events WHERE created_at >= $1`, [startedAt]);
      const types = new Set(rows.map((r) => r.event_type));
      for (const t of ['LOGOUT', 'LOGOUT_DELIVERY_SUCCEEDED', 'LOGOUT_DELIVERY_RETRY', 'LOGOUT_DELIVERY_DEAD', 'LOGOUT_DELIVERY_FAILED', 'LOGOUT_DELIVERY_NO_ENDPOINT']) {
        check(`audit event ${t} recorded`, types.has(t));
      }
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('12b. Optional client auth methods + secret rotation', { CLIENT_AUTH_METHODS: 'client_secret_basic,private_key_jwt,client_secret_post' }, async () => {
    const { admin, admin2, pkjwt } = clients;
    await scenario('methods enabled through CLIENT_AUTH_METHODS', async () => {
      const d = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
      check('discovery lists the three enabled methods', same([...(d.token_endpoint_auth_methods_supported as string[])].sort(), ['client_secret_basic', 'client_secret_post', 'private_key_jwt']));
      // At /token oidc-provider treats the two secret methods as equivalent once both are enabled;
      // Core's own handoff API holds the client to its registered method.
      const post = await fetch(`${ISSUER}/v1/handoff/requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ target_client_id: admin2.clientId, requested_path: '/dashboard', client_id: admin.clientId, client_secret: admin.secret }),
      });
      check('handoff API: a client_secret_basic client cannot use client_secret_post (401)', post.status === 401);
      const assertion = await clientAssertion(pkjwt, { aud: `${ISSUER}/v1/handoff/requests` });
      const body = { target_client_id: admin2.clientId, requested_path: '/dashboard', client_id: pkjwt.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion };
      const send = async () => (await fetch(`${ISSUER}/v1/handoff/requests`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).status;
      check('handoff request with a client assertion (private_key_jwt) -> 201', (await send()) === 201);
      check('replayed handoff client assertion (same jti) -> 401', (await send()) === 401);
    });

    await scenario('private_key_jwt client authentication (when enabled)', async () => {
      const b = new Browser();
      const out = await runFlow(b, pkjwt, M.main, {});
      const assertion = await clientAssertion(pkjwt);
      const code1 = out.step.callback!.searchParams.get('code')!;
      const ok = await exchange(pkjwt, code1, out.flow.verifier, { assertion });
      check('token with a signed client assertion = 200', ok.status === 200 && Boolean(ok.body.id_token), `${ok.status} ${ok.body.error_description ?? ''}`);
      const again = await runFlow(b, pkjwt, M.main, {});
      const replay = await exchange(pkjwt, again.step.callback!.searchParams.get('code')!, again.flow.verifier, { assertion });
      check('replayed assertion (same jti) -> invalid_client', replay.status === 401 && replay.body.error === 'invalid_client', `${replay.status} ${replay.body.error}`);
      const third = await runFlow(b, pkjwt, M.main, {});
      const { privateKey: wrongKey } = await generateKeyPair('RS256');
      const forged = await clientAssertion(pkjwt, { key: wrongKey });
      const bad = await exchange(pkjwt, third.step.callback!.searchParams.get('code')!, third.flow.verifier, { assertion: forged });
      check('assertion signed with another key -> invalid_client', bad.status === 401 && bad.body.error === 'invalid_client');
    });

    await scenario('client secret rotation', async () => {
      const b = new Browser();
      const old = admin2.secret!;
      const out = rotateSecret(admin2.clientId);
      const fresh = out.match(/shown once[^:]*: (\S+)/)?.[1] ?? '';
      check('client:rotate-secret prints a new 64-hex secret once', /^[0-9a-f]{64}$/.test(fresh) && fresh !== old);
      const [row] = await AppDataSource.query('SELECT client_secret_enc, token_endpoint_auth_method FROM auth_clients WHERE client_id = $1', [admin2.clientId]);
      check('stored encrypted, never in clear', typeof row?.client_secret_enc === 'string' && !row.client_secret_enc.includes(fresh) && row.token_endpoint_auth_method === 'client_secret_basic');
      let x = await runFlow(b, admin2, M.main, {});
      const withOld = await exchange(admin2, x.step.callback!.searchParams.get('code')!, x.flow.verifier, { secret: old });
      check('the old secret stops working immediately -> 401 invalid_client', withOld.status === 401 && withOld.body.error === 'invalid_client', `${withOld.status}`);
      admin2.secret = fresh;
      x = await runFlow(b, admin2, M.main, {});
      const withNew = await exchange(admin2, x.step.callback!.searchParams.get('code')!, x.flow.verifier);
      check('the new secret works at /token', withNew.status === 200 && Boolean(withNew.body.id_token));
      let err = '';
      try {
        rotateSecret('no-such-client');
      } catch (e) {
        err = e instanceof Error ? e.message : String(e);
      }
      check('rotating an unknown client fails', /unknown client/.test(err));
    });
  });

  // ------------------------------------------------------------------------------------------------
  await profile('13. Trusted handoff', { HANDOFF_REQUEST_TTL_SECONDS: '5', LOGOUT_WORKER_INTERVAL_MS: '250' }, async () => {
    const { admin, admin2, mumin, aal2, pkjwt } = clients;
    const TYP = 'miqaat-handoff+jwt';
    const basic = (c: TestClient) => `Basic ${Buffer.from(`${c.clientId}:${c.secret}`).toString('base64')}`;
    const request = async (body: Record<string, unknown>, authorization?: string) => {
      const r = await fetch(`${ISSUER}/v1/handoff/requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) },
        body: JSON.stringify(body),
      });
      return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, string> };
    };
    const hand = (from: TestClient, target: TestClient, requested_path: string) => request({ target_client_id: target.clientId, requested_path }, basic(from));
    const jwks = createLocalJWKSet(await fetchJwks());
    /** The target BU's verification (Handoff spec §14). */
    const verify = (assertion: string, target: TestClient) => jwtVerify(assertion, jwks, { issuer: ISSUER, audience: target.clientId, algorithms: ['RS256'], typ: TYP, clockTolerance: 30 });
    /** Browser opens the Core URL; login / MFA pages are completed as a member would. */
    const openHandoff = async (b: Browser, url: string, itsId: string, pages: string[] = []) => {
      let since = Date.now();
      let step = await follow(b, await b.fetch(url), 'http://never/');
      for (let i = 0; i < 4 && step.page && step.page.kind !== 'handoff'; i++) {
        const p = step.page;
        if (p.kind === 'login') {
          pages.push('login');
          since = Date.now();
          step = await submitLogin(b, p, { clientId: '', redirectUri: 'http://never/' }, itsId, passwords.get(itsId) ?? '');
        } else if (p.kind === 'mfa') {
          pages.push('mfa');
          step = await submitMfa(b, p, { clientId: '', redirectUri: 'http://never/' }, await codeFor(p, itsId, since));
        } else break;
      }
      return step;
    };

    const b = new Browser();
    const source = await tokensFrom(await runFlow(b, admin, M.plain, {}), admin);
    let delivered: { assertion: string; callback: string } | null = null;

    await scenario('handoff request (source backend)', async () => {
      const r = await hand(admin, admin2, '/events/123');
      check('POST /v1/handoff/requests (client_secret_basic) -> 201', r.status === 201, JSON.stringify(r.body));
      check('response: id, browser_redirect_url on Core, expires_in', /^[0-9a-f-]{36}$/.test(r.body.handoff_request_id) && r.body.browser_redirect_url === `${ISSUER}/v1/handoff/${r.body.handoff_request_id}` && Number(r.body.expires_in) === 5);
      const [row] = await AppDataSource.query('SELECT status, its_id, sid FROM handoff_requests WHERE id = $1', [r.body.handoff_request_id]);
      check('stored PENDING, not yet bound to a member (source never sends the ITS ID)', row?.status === 'PENDING' && row.its_id === null && row.sid === null);

      const step = await openHandoff(b, r.body.browser_redirect_url, M.plain);
      check('existing ADMIN session: no login page, auto-POST page to the target callback', step.page?.kind === 'handoff' && step.page.callback === 'http://localhost:5182/auth/core/handoff');
      check('delivery page: no-store, no-referrer', step.page?.headers.get('cache-control')?.includes('no-store') === true && step.page.headers.get('referrer-policy') === 'no-referrer');
      delivered = { assertion: step.page?.assertion ?? '', callback: step.page?.callback ?? '' };
      const header = decodeProtectedHeader(delivered.assertion);
      check('assertion header: typ miqaat-handoff+jwt, RS256, kid from JWKS', header.typ === TYP && header.alg === 'RS256' && typeof header.kid === 'string');
      const { payload: c } = await verify(delivered.assertion, admin2);
      check('verifies with the Core JWKS (iss, aud = target)', c.iss === ISSUER && c.aud === admin2.clientId);
      check('sub = ITS ID of the Core session, sid = source sid', c.sub === M.plain && c.sid === source.claims.sid);
      check('source/target/realm/path claims', c.source_client_id === admin.clientId && c.target_client_id === admin2.clientId && c.auth_realm === 'ADMIN' && c.requested_path === '/events/123');
      check('acr/amr/auth_time carried from the session', c.acr === source.claims.acr && same(c.amr, source.claims.amr) && c.auth_time === source.claims.auth_time);
      check('assertion lifetime 60 seconds, unique jti', Number(c.exp) - Number(c.iat) === 60 && typeof c.jti === 'string' && (c.jti as string).length >= 16);
      check('assertion signed for the target is refused by any other audience', await verify(delivered.assertion, admin).then(() => false, () => true));
      const [done] = await AppDataSource.query('SELECT status, its_id, sid, jti FROM handoff_requests WHERE id = $1', [r.body.handoff_request_id]);
      check('request COMPLETED and bound to ITS ID, sid and jti', done?.status === 'COMPLETED' && done.its_id === M.plain && done.sid === source.claims.sid && done.jti === c.jti);
      const [part] = await AppDataSource.query('SELECT established_by FROM auth_session_clients WHERE sid = $1 AND client_id = $2', [source.claims.sid, admin2.clientId]);
      check('target recorded as a session participant (HANDOFF)', part?.established_by === 'HANDOFF', part?.established_by);

      const again = await follow(b, await b.fetch(r.body.browser_redirect_url), 'http://never/');
      check('the handoff URL is one-time (second open -> 400, no assertion)', again.page?.status === 400 && again.page.kind !== 'handoff');
      const other = await follow(new Browser(), await new Browser().fetch(r.body.browser_redirect_url), 'http://never/');
      check('a used URL opened in another browser gets no assertion either', other.page?.kind !== 'handoff');
    });

    await scenario('source authentication: client_secret_basic only', async () => {
      const bad = await request({ target_client_id: admin2.clientId, requested_path: '/dashboard' });
      check('no client authentication -> 401 SOURCE_CLIENT_INVALID', bad.status === 401 && bad.body.error === 'SOURCE_CLIENT_INVALID');
      const post = await request({ target_client_id: admin2.clientId, requested_path: '/dashboard', client_id: admin.clientId, client_secret: admin.secret });
      check('client_secret_post body credentials -> 401 (method not enabled)', post.status === 401);
      const assertion = await clientAssertion(pkjwt, { aud: `${ISSUER}/v1/handoff/requests` });
      const pk = await request({ target_client_id: admin2.clientId, requested_path: '/dashboard', client_id: pkjwt.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion });
      check('private_key_jwt client assertion -> 401 (method not enabled)', pk.status === 401);
    });

    await scenario('request validation', async () => {
      const wrong = await request({ target_client_id: admin2.clientId, requested_path: '/dashboard' }, `Basic ${Buffer.from(`${admin.clientId}:wrong`).toString('base64')}`);
      check('wrong client secret -> 401', wrong.status === 401 && wrong.body.error === 'SOURCE_CLIENT_INVALID');
      const unknown = await request({ target_client_id: 'no-such-app', requested_path: '/dashboard' }, basic(admin));
      check('unknown target -> 400 TARGET_CLIENT_NOT_FOUND', unknown.status === 400 && unknown.body.error === 'TARGET_CLIENT_NOT_FOUND');
      const self = await hand(admin, admin, '/dashboard');
      check('target = source -> 400', self.status === 400);
      const cross = await hand(admin, mumin, '/events/1');
      check('ADMIN -> MUMIN app -> 400 REALM_MISMATCH', cross.status === 400 && cross.body.error === 'REALM_MISMATCH');
      for (const p of ['https://evil.example/x', '//evil.example', '/../admin', '/%2e%2e/admin', '/events/1/../../admin', '/not-listed', '/events', '/events/1/2/3', 'events/1', '/events/1#frag', '/a\\b', ' /dashboard']) {
        const r = await hand(admin, admin2, p);
        check(`path ${JSON.stringify(p)} -> 400 HANDOFF_PATH_INVALID`, r.status === 400 && r.body.error === 'HANDOFF_PATH_INVALID', `${r.status} ${r.body.error}`);
      }
      const q = await hand(admin, admin2, '/events/9/details?tab=seats');
      check('allowed path with query string -> 201 ("*" = one segment)', q.status === 201);

      const repo = handoffRepo();
      await repo.configure(admin2.clientId, { callbackUri: 'http://localhost:5182/auth/core/handoff', inbound: false, outbound: true, patterns: HANDOFF_PATHS });
      const disabled = await hand(admin, admin2, '/dashboard');
      check('target with inbound handoff disabled -> 400 TARGET_CLIENT_DISABLED', disabled.status === 400 && disabled.body.error === 'TARGET_CLIENT_DISABLED');
      await repo.configure(admin2.clientId, { callbackUri: 'http://localhost:5182/auth/core/handoff', inbound: true, outbound: true, patterns: HANDOFF_PATHS });
      await repo.configure(admin.clientId, { callbackUri: 'http://localhost:5181/auth/core/handoff', inbound: true, outbound: false, patterns: HANDOFF_PATHS });
      const noOut = await hand(admin, admin2, '/dashboard');
      check('source with outbound handoff disabled -> 403', noOut.status === 403);
      await repo.configure(admin.clientId, { callbackUri: 'http://localhost:5181/auth/core/handoff', inbound: true, outbound: true, patterns: HANDOFF_PATHS });
    });

    await scenario('no Core session / step-up / expiry', async () => {
      const r = await hand(admin, admin2, '/bookings/B-7');
      const fresh = new Browser();
      const pages: string[] = [];
      const step = await openHandoff(fresh, r.body.browser_redirect_url, M.plain, pages);
      check('no ADMIN session -> Core login page on /v1/handoff/<id>, then delivery', same(pages, ['login']) && step.page?.kind === 'handoff', pages.join(','));
      const { payload } = await verify(step.page!.assertion, admin2);
      check('assertion carries the newly created session', payload.sub === M.plain && payload.sid !== source.claims.sid);

      const up = await hand(admin, aal2, '/events/5');
      check('handoff to an app requiring aal:2 is accepted', up.status === 201, JSON.stringify(up.body));
      const p2: string[] = [];
      const s2 = await openHandoff(b, up.body.browser_redirect_url, M.plain, p2);
      check('target requires aal:2 -> MFA only (no password), then delivery', same(p2, ['mfa']) && s2.page?.kind === 'handoff', p2.join(','));
      const { payload: c2 } = await verify(s2.page!.assertion, aal2);
      check('stepped-up assertion: acr aal:2, amr contains otp, mfa_time', c2.acr === AAL2 && (c2.amr as string[]).includes('otp') && typeof c2.mfa_time === 'number');

      const late = await hand(admin, admin2, '/dashboard');
      await sleep(6000);
      const expired = await follow(b, await b.fetch(late.body.browser_redirect_url), 'http://never/');
      check('request older than its TTL -> 400, no assertion', expired.page?.status === 400 && expired.page.kind !== 'handoff');
      const [row] = await AppDataSource.query('SELECT status FROM handoff_requests WHERE id = $1', [late.body.handoff_request_id]);
      check('expired request marked EXPIRED', row?.status === 'EXPIRED', row?.status);

      const cancel = await hand(admin, admin2, '/dashboard');
      const cb = new Browser();
      const login = await follow(cb, await cb.fetch(cancel.body.browser_redirect_url), 'http://never/');
      const ab = await cb.post(login.page!.actions.cancel, { csrf: login.page!.csrf });
      const [crow] = await AppDataSource.query('SELECT status FROM handoff_requests WHERE id = $1', [cancel.body.handoff_request_id]);
      check('cancel on the handoff login page -> CANCELLED, no assertion', crow?.status === 'CANCELLED' && ab.status < 500, `${crow?.status} ${ab.status}`);
    });

    await scenario('logout after handoff', async () => {
      bc.received.length = 0;
      await b.fetch(`${ISSUER}/logout?${new URLSearchParams({ client_id: admin.clientId, id_token_hint: source.idToken })}`);
      const end = Date.now() + 8000;
      while (Date.now() < end && !bc.received.some((r) => r.clientId === admin2.clientId && decodeJwt(r.token).sid === source.claims.sid)) await sleep(200);
      check('the handoff target receives the back-channel logout for the shared sid', bc.received.some((r) => r.clientId === admin2.clientId && decodeJwt(r.token).sid === source.claims.sid));
      const r = await hand(admin, admin2, '/dashboard');
      const after = await follow(b, await b.fetch(r.body.browser_redirect_url), 'http://never/');
      check('after logout the handoff asks for login again', after.page?.kind === 'login');
    });

    await scenario('audit', async () => {
      const rows: { event_type: string }[] = await AppDataSource.query(`SELECT DISTINCT event_type FROM auth_audit_events WHERE created_at >= $1`, [startedAt]);
      const types = new Set(rows.map((r) => r.event_type));
      for (const t of ['HANDOFF_REQUESTED', 'HANDOFF_REJECTED', 'HANDOFF_COMPLETED', 'HANDOFF_CANCELLED']) check(`audit event ${t} recorded`, types.has(t));
    });
    void delivered;
  });

  group = '14. Data and logs';
  console.log(`\n=== ${group}`);
  await scenario('audit and secrets', async () => {
    const rows: { event_type: string }[] = await AppDataSource.query('SELECT DISTINCT event_type FROM auth_audit_events WHERE created_at >= $1', [startedAt]);
    const types = new Set(rows.map((r) => r.event_type));
    for (const t of ['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'SESSION_REUSED', 'MFA_CHALLENGE_SENT', 'MFA_CHALLENGE_FAILED', 'MFA_SUCCESS', 'MFA_FAILURE', 'MFA_UNAVAILABLE', 'AUTHORIZATION_COMPLETED']) {
      check(`audit event ${t} recorded`, types.has(t));
    }
    const [otp] = await AppDataSource.query(
      `SELECT count(*)::int AS total, count(*) FILTER (WHERE code_hash ~ '^[0-9a-f]{64}$')::int AS hashed FROM auth_otp_challenges WHERE created_at >= $1`,
      [startedAt],
    );
    check('every OTP stored only as a 64-hex HMAC', otp.total > 0 && otp.total === otp.hashed);
    const attempts: { t: string }[] = await AppDataSource.query(`SELECT DISTINCT attempt_type AS t FROM auth_login_attempts WHERE created_at >= $1`, [startedAt]);
    check('login attempts split into LOGIN and MFA', attempts.some((a) => a.t === 'LOGIN') && attempts.some((a) => a.t === 'MFA'));
    const logs = await Promise.all((await readdir(resolve('.e2e/logs'))).map((f) => readFile(resolve('.e2e/logs', f), 'utf8')));
    const joined = logs.join('\n');
    const leaked = [...usedCodes].filter((c) => joined.includes(c));
    check(`none of the ${usedCodes.size} OTP codes appears in the service logs`, leaked.length === 0, leaked.join(','));
    const pw = [...passwords.values()].filter((p) => p.length >= 6 && joined.includes(p));
    check('no password appears in the service logs', pw.length === 0);
  });

  // ------------------------------------------------------------------------------------------------
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${'='.repeat(70)}\nRESULT: ${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`  FAILED [${f.group}] ${f.name} ${f.detail ? `-> ${f.detail}` : ''}`);
  await AppDataSource.destroy();
  bc.server?.close();
  process.exit(failed.length ? 1 : 0);
}

main().catch(async (e) => {
  console.error(`suite aborted: ${e instanceof Error ? e.stack : String(e)}`);
  if (server) await server.stop();
  process.exit(2);
});
