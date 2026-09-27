import { GOOGLE_TEST_SITE_KEY, parseEnv } from '../src/config/env';
import type { AppConfig } from '../src/config/config.module';
import { CaptchaService } from '../src/modules/identity/captcha.service';
import { captchaInfo, loginFailureMessage } from '../src/modules/oidc/auth-pages.service';

const BASE_ENV = {
  ISSUER: 'http://localhost:4000',
  DB_HOST: 'localhost',
  DB_NAME: 'identity_db',
  DB_SCHEMA: 'miqaat_core',
  DB_USER: 'u',
  DB_PASSWORD: 'p',
  REDIS_URL: 'redis://localhost:6379',
  OIDC_COOKIE_KEYS: 'k'.repeat(32),
  CSRF_SECRET: 'c'.repeat(32),
  DATA_ENCRYPTION_KEY: 'd'.repeat(32),
  OTP_HMAC_KEY: 'o'.repeat(32),
  EMAIL_TRANSPORT: 'outbox',
  SSO_COOKIE_ADMIN: 'miqaat-admin-sso',
  SSO_COOKIE_MUMIN: 'miqaat-mumin-sso',
  COOKIE_SECURE: 'false',
};
const CAPTCHA_ENV = { ...BASE_ENV, LOGIN_CAPTCHA_ENABLED: 'true', RECAPTCHA_SITE_KEY: 'site', RECAPTCHA_SECRET_KEY: 'secret' };
const PROD_ENV = {
  ...CAPTCHA_ENV,
  NODE_ENV: 'production',
  ISSUER: 'https://auth.example.com',
  COOKIE_SECURE: 'true',
  SSO_COOKIE_ADMIN: '__Host-a',
  SSO_COOKIE_MUMIN: '__Host-m',
  EMAIL_TRANSPORT: 'smtp',
  SMTP_HOST: 'smtp.example.com',
  KEY_PROVIDER: 'ssm',
};

type Reply = { ok: boolean; status: number; body?: unknown; hang?: boolean; throws?: boolean };

/** CaptchaService with the HTTP call to Google replaced. */
class TestCaptcha extends CaptchaService {
  calls: { url: string; body: URLSearchParams }[] = [];
  constructor(env: Record<string, string>, private readonly reply: Reply) {
    super({ env: parseEnv(env) } as unknown as AppConfig);
  }
  protected override post(url: string, body: string, signal: AbortSignal) {
    this.calls.push({ url, body: new URLSearchParams(body) });
    if (this.reply.throws) return Promise.reject(new Error('ECONNREFUSED'));
    if (this.reply.hang) {
      return new Promise<never>((_, reject) => signal.addEventListener('abort', () => reject(new Error('aborted'))));
    }
    return Promise.resolve({ ok: this.reply.ok, status: this.reply.status, json: async () => this.reply.body });
  }
}

describe('captcha configuration', () => {
  it('is off by default; threshold 3, window 3600 s; account lock on', () => {
    const env = parseEnv({ ...BASE_ENV });
    expect([env.LOGIN_CAPTCHA_ENABLED, env.LOGIN_CAPTCHA_AFTER_FAILURES, env.LOGIN_CAPTCHA_WINDOW_SECONDS, env.LOGIN_ACCOUNT_LOCK_ENABLED]).toEqual([false, 3, 3600, true]);
    expect(env.RECAPTCHA_VERIFY_URL).toBe('https://www.google.com/recaptcha/api/siteverify');
  });
  it('enabled needs the site and secret keys', () => {
    expect(() => parseEnv({ ...BASE_ENV, LOGIN_CAPTCHA_ENABLED: 'true' })).toThrow(/RECAPTCHA_SITE_KEY/);
    expect(parseEnv(CAPTCHA_ENV).LOGIN_CAPTCHA_ENABLED).toBe(true);
  });
  it('threshold from config, including 0 (always); lock can be switched off', () => {
    expect(parseEnv({ ...CAPTCHA_ENV, LOGIN_CAPTCHA_AFTER_FAILURES: '5' }).LOGIN_CAPTCHA_AFTER_FAILURES).toBe(5);
    expect(parseEnv({ ...CAPTCHA_ENV, LOGIN_CAPTCHA_AFTER_FAILURES: '0' }).LOGIN_CAPTCHA_AFTER_FAILURES).toBe(0);
    expect(parseEnv({ ...BASE_ENV, LOGIN_ACCOUNT_LOCK_ENABLED: 'false' }).LOGIN_ACCOUNT_LOCK_ENABLED).toBe(false);
  });
  it("production refuses Google's always-pass test key and an http verify URL", () => {
    expect(parseEnv(PROD_ENV).LOGIN_CAPTCHA_ENABLED).toBe(true);
    expect(() => parseEnv({ ...PROD_ENV, RECAPTCHA_SITE_KEY: GOOGLE_TEST_SITE_KEY })).toThrow(/test key/);
    expect(() => parseEnv({ ...PROD_ENV, RECAPTCHA_VERIFY_URL: 'http://verify.local/siteverify' })).toThrow(/https/);
  });
});

describe('CaptchaService.verify', () => {
  it('no token -> CAPTCHA_REQUIRED without calling Google', async () => {
    const c = new TestCaptcha(CAPTCHA_ENV, { ok: true, status: 200, body: { success: true } });
    await expect(c.verify('', '1.2.3.4')).resolves.toEqual({ ok: false, code: 'CAPTCHA_REQUIRED' });
    await expect(c.verify(undefined, '1.2.3.4')).resolves.toEqual({ ok: false, code: 'CAPTCHA_REQUIRED' });
    expect(c.calls).toHaveLength(0);
  });
  it('posts secret, response and remoteip to the verify URL; success passes', async () => {
    const c = new TestCaptcha(CAPTCHA_ENV, { ok: true, status: 200, body: { success: true, hostname: 'auth.example.com' } });
    await expect(c.verify('tok', '1.2.3.4')).resolves.toEqual({ ok: true });
    expect(c.calls[0].url).toBe('https://www.google.com/recaptcha/api/siteverify');
    expect(Object.fromEntries(c.calls[0].body)).toEqual({ secret: 'secret', response: 'tok', remoteip: '1.2.3.4' });
  });
  it('success=false -> CAPTCHA_INVALID with Google error codes', async () => {
    const c = new TestCaptcha(CAPTCHA_ENV, { ok: true, status: 200, body: { success: false, 'error-codes': ['timeout-or-duplicate'] } });
    await expect(c.verify('tok', '')).resolves.toEqual({ ok: false, code: 'CAPTCHA_INVALID', detail: 'timeout-or-duplicate' });
  });
  it('expected hostnames: another host -> CAPTCHA_INVALID, listed host passes', async () => {
    const env = { ...CAPTCHA_ENV, RECAPTCHA_EXPECTED_HOSTNAMES: 'auth.example.com' };
    await expect(new TestCaptcha(env, { ok: true, status: 200, body: { success: true, hostname: 'evil.example' } }).verify('t', '')).resolves.toMatchObject({ ok: false, code: 'CAPTCHA_INVALID' });
    await expect(new TestCaptcha(env, { ok: true, status: 200, body: { success: true, hostname: 'auth.example.com' } }).verify('t', '')).resolves.toEqual({ ok: true });
  });
  it('fails closed: HTTP error, network error or timeout -> CAPTCHA_UNAVAILABLE', async () => {
    await expect(new TestCaptcha(CAPTCHA_ENV, { ok: false, status: 503 }).verify('t', '')).resolves.toEqual({ ok: false, code: 'CAPTCHA_UNAVAILABLE' });
    await expect(new TestCaptcha(CAPTCHA_ENV, { ok: true, status: 200, throws: true }).verify('t', '')).resolves.toEqual({ ok: false, code: 'CAPTCHA_UNAVAILABLE' });
    const slow = new TestCaptcha({ ...CAPTCHA_ENV, RECAPTCHA_TIMEOUT_MS: '500' }, { ok: true, status: 200, hang: true });
    await expect(slow.verify('t', '')).resolves.toEqual({ ok: false, code: 'CAPTCHA_UNAVAILABLE' });
  });
  it('rejects an oversized token without calling Google', async () => {
    const c = new TestCaptcha(CAPTCHA_ENV, { ok: true, status: 200, body: { success: true } });
    await expect(c.verify('x'.repeat(5000), '')).resolves.toMatchObject({ ok: false, code: 'CAPTCHA_INVALID' });
    expect(c.calls).toHaveLength(0);
  });
});

describe('captcha messages', () => {
  it('clear message per refusal; explanation only when the captcha newly appears', () => {
    expect(loginFailureMessage({ code: 'CAPTCHA_REQUIRED' })).toMatch(/not a robot/);
    expect(loginFailureMessage({ code: 'CAPTCHA_INVALID' })).toMatch(/failed or expired/);
    expect(loginFailureMessage({ code: 'CAPTCHA_UNAVAILABLE' })).toMatch(/not available/);
    expect(captchaInfo({ captcha: true, failure: { code: 'INVALID_CREDENTIALS' } })).toMatch(/not a robot/);
    expect(captchaInfo({ captcha: true, failure: { code: 'CAPTCHA_REQUIRED' } })).toBeUndefined();
    expect(captchaInfo({ captcha: false, failure: { code: 'INVALID_CREDENTIALS' } })).toBeUndefined();
  });
});
