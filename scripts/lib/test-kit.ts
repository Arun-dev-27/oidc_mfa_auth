/**
 * Building blocks for the end-to-end suite: a cookie-keeping "browser", SSR page parsing, a BU-side
 * OIDC client (PKCE, token exchange with client_secret_basic or private_key_jwt, JWKS verification)
 * and a launcher that runs the built service with per-scenario environment overrides.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createLocalJWKSet, jwtVerify, SignJWT, type JWK, type JWTPayload } from 'jose';
import type { FormActions } from '../../src/modules/oidc/auth-pages.service';
import { signinActions } from '../../src/modules/oidc/signin-paths';

export const ISSUER = (process.env.ISSUER ?? 'http://localhost:4000').replace(/\/+$/, '');
export const ORIGIN = new URL(ISSUER).origin;

// ---- browser ---------------------------------------------------------------------------------

export class Browser {
  readonly jar = new Map<string, string>();

  cookie(name: string): string | undefined {
    return this.jar.get(name);
  }

  setCookie(name: string, value: string): void {
    this.jar.set(name, value);
  }

  async fetch(url: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.jar.size) headers.set('cookie', [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '));
    const res = await fetch(new URL(url, ISSUER), { ...init, headers, redirect: 'manual' });
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      const expired = value === '' || attrs.some((a) => /^\s*max-age=0/i.test(a) || /expires=Thu, 01 Jan 1970/i.test(a));
      if (expired) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }

  post(url: string, form: Record<string, string>, origin = ORIGIN): Promise<Response> {
    return this.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin },
      body: new URLSearchParams(form).toString(),
    });
  }
}

// ---- pages -----------------------------------------------------------------------------------

export type PageKind = 'login' | 'mfa' | 'handoff' | 'error';

export interface Page {
  kind: PageKind;
  status: number;
  html: string;
  uid: string;
  /** Form base path: /signin/<uid> (OIDC) or /v1/handoff/<id> (trusted handoff). */
  base: string;
  /** Where each form posts (the endings differ between the two flows). */
  actions: FormActions;
  /** Handoff delivery page: the signed assertion and the target callback it auto-POSTs to. */
  assertion: string;
  callback: string;
  csrf: string;
  method: string;
  challengeId: string;
  alert: string;
  headers: Headers;
}

/** Form endings per flow: sign-in /signin/<uid>/password | /verify | /cancel, handoff /v1/handoff/<id>/login | /mfa | /abort. */
function actionsFor(base: string): FormActions {
  if (base.startsWith('/signin/')) return signinActions(base.split('/').pop() ?? '');
  return { login: `${base}/login`, verify: `${base}/mfa`, resend: `${base}/mfa/resend`, switch: `${base}/mfa/switch`, cancel: `${base}/abort` };
}

const fieldOf = (html: string, name: string) => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1] ?? '';

export function parsePage(status: number, html: string, headers: Headers): Page {
  const base = html.match(/action="(\/(?:signin|v1\/handoff)\/[^/"]+)\//)?.[1] ?? '';
  const actions = actionsFor(base);
  const uid = base.split('/').pop() ?? '';
  const assertion = fieldOf(html, 'assertion');
  const callback = assertion ? (html.match(/<form[^>]*action="([^"]+)"[^>]*data-autosubmit/)?.[1] ?? '').replace(/&amp;/g, '&') : '';
  const kind: PageKind = assertion
    ? 'handoff'
    : base && html.includes(`action="${actions.login}"`)
      ? 'login'
      : base && (html.includes(`action="${actions.verify}"`) || html.includes(`action="${actions.resend}"`))
        ? 'mfa'
        : 'error';
  const alert = html.match(/class="alert alert-(?:error|info)"[^>]*>([^<]*)</)?.[1]?.trim() ?? '';
  return { kind, status, html, uid, base, actions, assertion, callback, csrf: fieldOf(html, 'csrf'), method: fieldOf(html, 'method'), challengeId: fieldOf(html, 'challenge_id'), alert, headers };
}

// ---- authorization flow ------------------------------------------------------------------------

export interface TestClient {
  clientId: string;
  redirectUri: string;
  secret?: string;
  /** private_key_jwt signing key (private JWK). */
  privateJwk?: JWK & { kid: string };
}

export interface AuthorizeParams {
  acr?: string;
  mfaMaxAge?: number;
  scope?: string;
  prompt?: string;
  extra?: Record<string, string>;
}

export interface FlowStart {
  verifier: string;
  state: string;
  nonce: string;
  url: string;
}

export function authorizeUrl(client: TestClient, p: AuthorizeParams = {}, overrides: Record<string, string | null> = {}): FlowStart {
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(12).toString('base64url');
  const nonce = randomBytes(12).toString('base64url');
  const params: Record<string, string | null> = {
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    scope: p.scope ?? 'openid profile',
    state,
    nonce,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    ...(p.acr ? { acr_values: p.acr } : {}),
    ...(p.mfaMaxAge !== undefined ? { mfa_max_age: String(p.mfaMaxAge) } : {}),
    ...(p.prompt ? { prompt: p.prompt } : {}),
    ...(p.extra ?? {}),
    ...overrides,
  };
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== null) q.set(k, v);
  return { verifier, state, nonce, url: `${ISSUER}/auth?${q.toString()}` };
}

export interface Step {
  /** A page was shown. */
  page?: Page;
  /** The browser reached the client's redirect_uri. */
  callback?: URL;
  /** Any other non-page response (e.g. a 4xx without a form). */
  response?: Response;
}

/** Follows redirects until a page, the client callback, or a non-redirect response. */
export async function follow(browser: Browser, first: Response, redirectUri: string): Promise<Step> {
  let res = first;
  for (let hop = 0; hop < 15; hop++) {
    if (res.status >= 300 && res.status < 400) {
      const location = new URL(res.headers.get('location') ?? '', ISSUER).toString();
      if (location.startsWith(redirectUri)) return { callback: new URL(location) };
      res = await browser.fetch(location);
      continue;
    }
    const type = res.headers.get('content-type') ?? '';
    if (type.includes('text/html')) return { page: parsePage(res.status, await res.text(), res.headers) };
    return { response: res };
  }
  throw new Error('too many redirects');
}

export async function start(browser: Browser, client: TestClient, p: AuthorizeParams = {}) {
  const flow = authorizeUrl(client, p);
  const step = await follow(browser, await browser.fetch(flow.url), client.redirectUri);
  return { flow, step };
}

export async function submitLogin(browser: Browser, page: Page, client: TestClient, itsId: string, password: string, form: Record<string, string> = {}) {
  return follow(browser, await browser.post(page.actions.login, { csrf: page.csrf, its_id: itsId, password, ...form }), client.redirectUri);
}

export async function submitMfa(browser: Browser, page: Page, client: TestClient, code: string) {
  return follow(browser, await browser.post(page.actions.verify, { csrf: page.csrf, code, challenge_id: page.challengeId, method: page.method }), client.redirectUri);
}

export async function resend(browser: Browser, page: Page, client: TestClient) {
  return follow(browser, await browser.post(page.actions.resend, { csrf: page.csrf, method: page.method }), client.redirectUri);
}

export async function switchMethod(browser: Browser, page: Page, client: TestClient, method: string) {
  return follow(browser, await browser.post(page.actions.switch, { csrf: page.csrf, method }), client.redirectUri);
}

export async function abort(browser: Browser, page: Page, client: TestClient) {
  return follow(browser, await browser.post(page.actions.cancel, { csrf: page.csrf }), client.redirectUri);
}

// ---- token endpoint --------------------------------------------------------------------------

export interface TokenResult {
  status: number;
  body: { id_token?: string; access_token?: string; error?: string; error_description?: string; token_type?: string };
}

type SigningKey = Parameters<SignJWT['sign']>[0];

export async function clientAssertion(client: TestClient, overrides: { jti?: string; key?: SigningKey; kid?: string; aud?: string } = {}): Promise<string> {
  const { importJWK } = await import('jose');
  const key = overrides.key ?? ((await importJWK(client.privateJwk!, 'RS256')) as SigningKey);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: overrides.kid ?? client.privateJwk!.kid })
    .setIssuer(client.clientId)
    .setSubject(client.clientId)
    .setAudience(overrides.aud ?? ISSUER)
    .setJti(overrides.jti ?? randomUUID())
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(key);
}

export async function exchange(
  client: TestClient,
  code: string,
  verifier: string,
  opts: { redirectUri?: string; assertion?: string; secret?: string } = {},
): Promise<TokenResult> {
  const form: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: opts.redirectUri ?? client.redirectUri, code_verifier: verifier };
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (client.privateJwk) {
    form.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    form.client_assertion = opts.assertion ?? (await clientAssertion(client));
    form.client_id = client.clientId;
  } else {
    const secret = opts.secret ?? client.secret ?? '';
    headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(secret)}`).toString('base64')}`;
  }
  const res = await fetch(`${ISSUER}/token`, { method: 'POST', headers, body: new URLSearchParams(form).toString() });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as TokenResult['body'] };
}

export async function fetchJwks(): Promise<{ keys: JWK[] }> {
  const res = await fetch(`${ISSUER}/.well-known/jwks.json`);
  return (await res.json()) as { keys: JWK[] };
}

export async function verifyIdToken(idToken: string, client: TestClient, nonce: string, jwks?: { keys: JWK[] }) {
  const set = createLocalJWKSet(jwks ?? (await fetchJwks()));
  const { payload, protectedHeader } = await jwtVerify(idToken, set, { issuer: ISSUER, audience: client.clientId, algorithms: ['RS256'] });
  if (payload.nonce !== nonce) throw new Error('nonce mismatch');
  return { payload: payload as JWTPayload & Record<string, unknown>, kid: protectedHeader.kid };
}

// ---- dev outbox ------------------------------------------------------------------------------

/** Newest Email/SMS written by the outbox adapters after `sinceMs`; returns the 6-digit code. */
export async function outboxCode(channel: 'email' | 'sms', sinceMs: number, dir = resolve(process.env.OUTBOX_DIR ?? './.outbox')): Promise<{ code: string; to: string }> {
  for (let i = 0; i < 40; i++) {
    const files = (await readdir(dir).catch(() => [] as string[])).filter((f) => f.includes(`_${channel}_`));
    const fresh: { f: string; t: number }[] = [];
    for (const f of files) {
      const t = (await stat(join(dir, f))).mtimeMs;
      if (t >= sinceMs - 50) fresh.push({ f, t });
    }
    fresh.sort((a, b) => b.t - a.t);
    if (fresh.length) {
      const body = await readFile(join(dir, fresh[0].f), 'utf8');
      const code = body.match(/\b(\d{6})\b/)?.[1];
      const to = body.match(/^To: (.*)$/m)?.[1] ?? '';
      if (code) return { code, to };
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`no ${channel} OTP in the outbox`);
}

// ---- server ------------------------------------------------------------------------------------

export interface RunningServer {
  proc: ChildProcess;
  stop(): Promise<void>;
}

export async function startServer(name: string, overrides: Record<string, string>): Promise<RunningServer> {
  const logDir = resolve('.e2e/logs');
  await mkdir(logDir, { recursive: true });
  const log = createWriteStream(join(logDir, `${name}.log`));
  const proc = spawn(process.execPath, ['dist/main.js'], { env: { ...process.env, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] });
  proc.stdout?.pipe(log);
  proc.stderr?.pipe(log);
  let exited = false;
  proc.on('exit', () => (exited = true));
  const deadline = Date.now() + 40_000;
  while (Date.now() < deadline) {
    if (exited) throw new Error(`server "${name}" exited during start-up - see .e2e/logs/${name}.log`);
    const ok = await fetch(`${ISSUER}/health/ready`).then((r) => r.ok).catch(() => false);
    if (ok) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  if (Date.now() >= deadline) throw new Error(`server "${name}" did not become ready`);
  return {
    proc,
    stop: () =>
      new Promise<void>((done) => {
        if (exited) return done();
        proc.once('exit', () => done());
        proc.kill();
      }),
  };
}

export async function isServerUp(): Promise<boolean> {
  return fetch(`${ISSUER}/health/live`).then((r) => r.ok).catch(() => false);
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
