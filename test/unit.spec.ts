import { decryptString, encryptString, maskEmail, maskPhone, safeEqual, toKey32 } from '../src/common/crypto.util';
import { parseEnv } from '../src/config/env';
import { decrypt, encrypt } from '../src/modules/identity/legacy-password-cipher';
import { toMuminId } from '../src/modules/identity/credential.service';
import { ACR_AAL2, MfaService } from '../src/modules/mfa/mfa.service';
import { base32Decode, base32Encode, hotp, verifyTotp } from '../src/modules/mfa/totp';
import type { RealmSession } from '../src/modules/sessions/global-session.service';
import { escapeHtml, ViewService } from '../src/modules/views/view.service';

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

describe('TOTP (RFC 4226 / 6238)', () => {
  // RFC 4226 appendix D test secret "12345678901234567890".
  const secret = Buffer.from('12345678901234567890');

  it('matches the RFC 4226 HOTP vectors', () => {
    expect(['755224', '287082', '359152', '969429', '338314'].map((_, i) => hotp(secret, i))).toEqual([
      '755224',
      '287082',
      '359152',
      '969429',
      '338314',
    ]);
  });

  it('accepts the current step and +/-1, rejects others', () => {
    const b32 = base32Encode(secret);
    expect(base32Decode(b32).equals(secret)).toBe(true);
    const now = 1_790_000_000_000;
    const step = Math.floor(now / 30_000);
    expect(verifyTotp(b32, hotp(secret, step), now)).toBe(step);
    expect(verifyTotp(b32, hotp(secret, step - 1), now)).toBe(step - 1);
    expect(verifyTotp(b32, hotp(secret, step + 3), now)).toBeNull();
    expect(verifyTotp(b32, 'abcdef', now)).toBeNull();
  });
});

describe('crypto helpers', () => {
  it('round-trips AES-GCM and rejects tampering', () => {
    const key = toKey32('x'.repeat(40));
    const sealed = encryptString(key, 'member@example.com');
    expect(decryptString(key, sealed)).toBe('member@example.com');
    const parts = sealed.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    expect(() => decryptString(key, parts.join('.'))).toThrow();
  });

  it('masks destinations and compares safely', () => {
    expect(maskEmail('member@example.com')).toBe('m*****@example.com');
    expect(maskPhone('+91 98000 04321')).toBe('********4321');
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('identity helpers', () => {
  it('accepts only integer ITS IDs', () => {
    expect(toMuminId(' 10110101 ')).toBe(10110101);
    expect(toMuminId('0')).toBeNull();
    expect(toMuminId('1011x')).toBeNull();
    expect(toMuminId('99999999999')).toBeNull();
  });

  it('legacy decrypt handles empty and odd-length input like the C# original', () => {
    expect(decrypt('')).toBe('');
    expect(decrypt('abc')).toBe('');
    expect(decrypt(null)).toBe('');
  });

  it('legacy encrypt is the exact inverse of decrypt, with printable random ciphertext', () => {
    for (const plain of ['a', 'Test@Pass#123', ' spaces and ~!{}|', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']) {
      const a = encrypt(plain);
      const b = encrypt(plain);
      expect(decrypt(a)).toBe(plain);
      expect(decrypt(b)).toBe(plain);
      expect(a).toHaveLength(plain.length * 2);
      expect(/^[!-~]+$/.test(a)).toBe(true);
      if (plain.length > 3) expect(a).not.toBe(b);
    }
    expect(() => encrypt('')).toThrow();
    expect(() => encrypt('é')).toThrow(/cannot store/);
  });
});

describe('SSR view rendering', () => {
  const views = new ViewService({ env: { BRAND_TAGLINE: 'Tagline' }, isProduction: false } as never);

  it('escapes values and never re-scans inserted text', () => {
    const html = views.render('error', { title: '<script>x</script>', message: '{{tagline}}', code: 'C1' });
    expect(html).toContain('&lt;script&gt;x&lt;/script&gt;');
    expect(html).not.toContain('<script>x</script>');
    expect(html).toContain('{{tagline}}');
    expect(escapeHtml(`"'&`)).toBe('&quot;&#39;&amp;');
  });

  it('keeps or drops conditional blocks', () => {
    const shown = views.render('login', { uid: 'u1', csrf: 't', error: 'Bad', clientName: 'RMS', realmLabel: 'Admin', forgotUrl: '' });
    expect(shown).toContain('alert-error');
    expect(shown).not.toContain('Forgot password?');
    const hidden = views.render('login', { uid: 'u1', csrf: 't', clientName: 'RMS', realmLabel: 'Admin' });
    expect(hidden).not.toContain('alert-error');
  });
});

describe('configuration rules', () => {
  it('parses a valid development configuration', () => {
    const env = parseEnv({ ...BASE_ENV });
    expect(env.LOGIN_ELIGIBILITY_CHECK_ENABLED).toBe(true);
    expect(parseEnv({ ...BASE_ENV, LOGIN_ELIGIBILITY_CHECK_ENABLED: 'false' }).LOGIN_ELIGIBILITY_CHECK_ENABLED).toBe(false);
  });

  it('refuses __Host- cookies without Secure and unsafe production settings', () => {
    expect(() => parseEnv({ ...BASE_ENV, SSO_COOKIE_ADMIN: '__Host-x' })).toThrow(/__Host-/);
    expect(() => parseEnv({ ...BASE_ENV, SSO_COOKIE_MUMIN: 'miqaat-admin-sso' })).toThrow(/different cookies/);
    expect(() => parseEnv({ ...BASE_ENV, NODE_ENV: 'production' })).toThrow(/production/);
  });

  it('client authentication: client_secret_basic by default, others only when listed', () => {
    expect(parseEnv({ ...BASE_ENV }).CLIENT_AUTH_METHODS).toEqual(['client_secret_basic']);
    expect(parseEnv({ ...BASE_ENV, CLIENT_AUTH_METHODS: ' client_secret_basic , private_key_jwt,client_secret_basic' }).CLIENT_AUTH_METHODS).toEqual(['client_secret_basic', 'private_key_jwt']);
    expect(() => parseEnv({ ...BASE_ENV, CLIENT_AUTH_METHODS: 'none' })).toThrow(/CLIENT_AUTH_METHODS/);
    expect(() => parseEnv({ ...BASE_ENV, CLIENT_AUTH_METHODS: ',' })).toThrow(/CLIENT_AUTH_METHODS/);
  });
});

describe('MFA policy', () => {
  const config = { env: { ...parseEnv({ ...BASE_ENV }), MFA_MAX_AGE_SECONDS: 1800 } };
  const mfa = new MfaService(config as never, {} as never, {} as never, {} as never, {} as never, {} as never);
  const member = { itsId: '1', displayName: null, email: null, otpRequired: false };
  const session = (aal: 1 | 2, mfaAgoSeconds: number | null): RealmSession => ({
    sid: 's',
    itsId: '1',
    realm: 'ADMIN',
    aal,
    amr: aal === 2 ? ['pwd', 'otp'] : ['pwd'],
    authTime: Date.now(),
    mfaVerifiedAt: mfaAgoSeconds === null ? null : Date.now() - mfaAgoSeconds * 1000,
    mfaMethod: aal === 2 ? 'EMAIL_OTP' : null,
    idleExpiresAt: Date.now() + 1e6,
    absoluteExpiresAt: Date.now() + 1e7,
  });

  it('requires AAL2 when asked, or when the member flag says so', () => {
    expect(mfa.isRequired(member, [])).toBe(false);
    expect(mfa.isRequired(member, [ACR_AAL2])).toBe(true);
    expect(mfa.isRequired({ ...member, otpRequired: true }, [])).toBe(true);
  });

  it('reuses a fresh AAL2 only, and caps the requested max age', () => {
    expect(mfa.isFresh(session(2, 60), 1800)).toBe(true);
    expect(mfa.isFresh(session(2, 3600), 1800)).toBe(false);
    expect(mfa.isFresh(session(1, null), 1800)).toBe(false);
    expect(mfa.effectiveMaxAge(600)).toBe(600);
    expect(mfa.effectiveMaxAge(999_999)).toBe(1800);
    expect(mfa.effectiveMaxAge(null)).toBe(1800);
  });
});
