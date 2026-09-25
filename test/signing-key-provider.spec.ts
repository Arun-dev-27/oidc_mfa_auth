import { GetParameterCommand, ParameterNotFound, PutParameterCommand } from '@aws-sdk/client-ssm';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { parseEnv } from '../src/config/env';
import { AutoSigningKeyProvider } from '../src/modules/keys/auto-signing-key-provider';
import { detectAwsCredentials } from '../src/modules/keys/aws-credentials';
import { createSigningKeyProvider } from '../src/modules/keys/create-signing-key-provider';
import { FileSigningKeyProvider } from '../src/modules/keys/file-signing-key-provider';
import type { StoredSigningKey } from '../src/modules/keys/key-file';
import type { SigningKeyProvider, SigningKeySet } from '../src/modules/keys/signing-key-provider';
import { createSsmClient, envOnlyCredentials, SsmSigningKeyProvider } from '../src/modules/keys/ssm-signing-key-provider';

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
const PROD_ENV = {
  ...BASE_ENV,
  NODE_ENV: 'production',
  ISSUER: 'https://auth.example.com',
  COOKIE_SECURE: 'true',
  SSO_COOKIE_ADMIN: '__Host-a',
  SSO_COOKIE_MUMIN: '__Host-m',
  EMAIL_TRANSPORT: 'smtp',
  SMTP_HOST: 'smtp.example.com',
};

async function key(kid: string, status: StoredSigningKey['status'], revokedAt?: string): Promise<StoredSigningKey> {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { status, ...(revokedAt ? { revokedAt } : {}), jwk: { ...privateKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' } as StoredSigningKey['jwk'] };
}

/** In-memory SSM with the two commands the provider uses. */
function fakeSsm(initial?: string, fail?: Error) {
  const store = new Map<string, { value: string; input: Record<string, unknown> }>();
  if (initial !== undefined) store.set('/p', { value: initial, input: {} });
  const calls: string[] = [];
  return {
    store,
    calls,
    client: {
      async send(command: unknown) {
        if (fail) throw fail;
        if (command instanceof GetParameterCommand) {
          calls.push('get');
          const hit = store.get(command.input.Name!);
          if (!hit) throw new ParameterNotFound({ message: 'not found', $metadata: {} });
          return { Parameter: { Value: hit.value } };
        }
        if (command instanceof PutParameterCommand) {
          calls.push('put');
          store.set(command.input.Name!, { value: command.input.Value!, input: command.input as unknown as Record<string, unknown> });
          return {};
        }
        throw new Error('unexpected command');
      },
    } as never,
  };
}

describe('KEY_PROVIDER configuration', () => {
  it('defaults to auto with the stage-based SSM parameter path', () => {
    const env = parseEnv({ ...BASE_ENV });
    expect(env.KEY_PROVIDER).toBe('auto');
    expect(env.SSM_SIGNING_KEYS_PARAMETER).toBe('/miqaatcoredev/dev/auth/jwks-private-key');
    expect(parseEnv({ ...BASE_ENV, NODE_ENV: 'test' }).SSM_SIGNING_KEYS_PARAMETER).toBe('/miqaatcoredev/test/auth/jwks-private-key');
  });
  it('keeps honouring the legacy SIGNING_KEY_PROVIDER; KEY_PROVIDER wins', () => {
    expect(parseEnv({ ...BASE_ENV, SIGNING_KEY_PROVIDER: 'file' }).KEY_PROVIDER).toBe('file');
    expect(parseEnv({ ...BASE_ENV, SIGNING_KEY_PROVIDER: 'kms' }).KEY_PROVIDER).toBe('kms');
    expect(parseEnv({ ...BASE_ENV, SIGNING_KEY_PROVIDER: 'file', KEY_PROVIDER: 'ssm' }).KEY_PROVIDER).toBe('ssm');
  });
  it('accepts an explicit parameter path and rejects a relative one', () => {
    expect(parseEnv({ ...BASE_ENV, SSM_SIGNING_KEYS_PARAMETER: '/miqaatcoredev/prod/auth/jwks-private-key' }).SSM_SIGNING_KEYS_PARAMETER).toBe('/miqaatcoredev/prod/auth/jwks-private-key');
    expect(() => parseEnv({ ...BASE_ENV, SSM_SIGNING_KEYS_PARAMETER: 'miqaat/x' })).toThrow(/SSM_SIGNING_KEYS_PARAMETER/);
  });
  it('production: file refused; auto, ssm and kms accepted; path defaults to /miqaatcoredev/prod/...', () => {
    expect(() => parseEnv({ ...PROD_ENV, KEY_PROVIDER: 'file' })).toThrow(/local file/);
    expect(() => parseEnv({ ...PROD_ENV, SIGNING_KEY_PROVIDER: 'file' })).toThrow(/local file/);
    expect(parseEnv({ ...PROD_ENV, KEY_PROVIDER: 'ssm' }).KEY_PROVIDER).toBe('ssm');
    expect(parseEnv({ ...PROD_ENV, KEY_PROVIDER: 'kms' }).KEY_PROVIDER).toBe('kms');
    const auto = parseEnv({ ...PROD_ENV });
    expect(auto.KEY_PROVIDER).toBe('auto');
    expect(auto.SSM_SIGNING_KEYS_PARAMETER).toBe('/miqaatcoredev/prod/auth/jwks-private-key');
  });
});

describe('FileSigningKeyProvider', () => {
  let dir = '';
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'keys-'));
  });
  afterAll(() => rm(dir, { recursive: true, force: true }));

  it('missing file: empty set with allowMissing, otherwise a clear error', async () => {
    const p = new FileSigningKeyProvider(join(dir, 'none.json'));
    await expect(p.getSigningKeys({ allowMissing: true })).resolves.toEqual({ keys: [] });
    await expect(p.getSigningKeys()).rejects.toThrow(/npm run keys -- generate/);
  });
  it('round-trips the key set and returns the ACTIVE key', async () => {
    const p = new FileSigningKeyProvider(join(dir, 'sub', 'signing-keys.json'));
    const set = { keys: [await key('k-active', 'ACTIVE'), await key('k-next', 'NEXT')] };
    await p.saveSigningKeys(set);
    expect((await p.getSigningKeys()).keys.map((k) => k.jwk.kid)).toEqual(['k-active', 'k-next']);
    expect((await p.getSigningKey()).jwk.kid).toBe('k-active');
    expect(p.describe()).toBe(`file:${join(dir, 'sub', 'signing-keys.json')}`);
  });
});

describe('SsmSigningKeyProvider', () => {
  it('missing parameter: empty set with allowMissing, otherwise a clear error', async () => {
    const p = new SsmSigningKeyProvider(fakeSsm().client, '/p');
    await expect(p.getSigningKeys({ allowMissing: true })).resolves.toEqual({ keys: [] });
    await expect(p.getSigningKeys()).rejects.toThrow(/not found in SSM/);
  });
  it('stores one SecureString (overwrite, intelligent tier, optional KMS key) and reads it back', async () => {
    const ssm = fakeSsm();
    const p = new SsmSigningKeyProvider(ssm.client, '/p', 'alias/miqaat-auth');
    await p.saveSigningKeys({ keys: [await key('k1', 'ACTIVE'), await key('k0', 'NEXT')] });
    const put = ssm.store.get('/p')!.input;
    expect(put).toMatchObject({ Type: 'SecureString', Overwrite: true, Tier: 'Intelligent-Tiering', KeyId: 'alias/miqaat-auth' });
    expect((await p.getSigningKey()).jwk.kid).toBe('k1');
    expect('d' in (await p.getSigningKey()).jwk).toBe(true);
  });
  it('keeps private material only for keys that can still sign', async () => {
    const ssm = fakeSsm();
    const p = new SsmSigningKeyProvider(ssm.client, '/p');
    await p.saveSigningKeys({ keys: [await key('a', 'ACTIVE'), await key('r', 'RETIRING'), await key('x', 'RETIRED'), await key('v', 'RETIRED', '2026-01-01T00:00:00Z')] });
    const saved = JSON.parse(ssm.store.get('/p')!.value) as SigningKeySet;
    const priv = Object.fromEntries(saved.keys.map((k) => [k.jwk.kid, 'd' in k.jwk]));
    expect(priv).toEqual({ a: true, r: true, x: false, v: false });
  });
  it('refuses a key set larger than an SSM parameter', async () => {
    const p = new SsmSigningKeyProvider(fakeSsm().client, '/p');
    const many = await Promise.all(Array.from({ length: 6 }, (_, i) => key(`k${i}`, i === 0 ? 'ACTIVE' : 'NEXT')));
    await expect(p.saveSigningKeys({ keys: many })).rejects.toThrow(/SSM allows 8192/);
  });
  it('rejects a corrupt value', async () => {
    const p = new SsmSigningKeyProvider(fakeSsm('not json').client, '/p');
    await expect(p.getSigningKeys()).rejects.toThrow(/not valid JSON/);
  });
});

describe('AutoSigningKeyProvider', () => {
  const stub = (storage: 'ssm' | 'file', set: SigningKeySet | Error): SigningKeyProvider & { reads: number } => {
    const s = {
      storage,
      reads: 0,
      describe: () => `${storage}:x`,
      async getSigningKeys() {
        s.reads++;
        if (set instanceof Error) throw set;
        return set;
      },
      async getSigningKey() {
        return (set as SigningKeySet).keys[0];
      },
      async saveSigningKeys() {},
    };
    return s;
  };
  const ssmSet = { keys: [{ status: 'ACTIVE' as const, jwk: { kid: 'from-ssm', alg: 'RS256' } }] };
  const fileSet = { keys: [{ status: 'ACTIVE' as const, jwk: { kid: 'from-file', alg: 'RS256' } }] };

  it('AWS credentials available -> SSM', async () => {
    const p = new AutoSigningKeyProvider(async () => ({ available: true }), stub('ssm', ssmSet), stub('file', fileSet), { fallbackOnSsmError: true });
    expect((await p.getSigningKeys()).keys[0].jwk.kid).toBe('from-ssm');
    expect(p.storage).toBe('ssm');
  });
  it('no AWS credentials -> local file, without touching SSM', async () => {
    const ssm = stub('ssm', ssmSet);
    const p = new AutoSigningKeyProvider(async () => ({ available: false, reason: 'none' }), ssm, stub('file', fileSet), { fallbackOnSsmError: true });
    expect((await p.getSigningKeys()).keys[0].jwk.kid).toBe('from-file');
    expect(p.storage).toBe('file');
    expect(ssm.reads).toBe(0);
  });
  it('detects once and keeps the choice', async () => {
    let detections = 0;
    const p = new AutoSigningKeyProvider(async () => (detections++, { available: true }), stub('ssm', ssmSet), stub('file', fileSet), { fallbackOnSsmError: true });
    await Promise.all([p.getSigningKeys(), p.getSigningKeys(), p.resolve()]);
    expect(detections).toBe(1);
  });
  it('credentials but SSM unreadable: falls back to the file only when allowed (outside production)', async () => {
    const denied = new Error('AccessDeniedException');
    const logs: string[] = [];
    const dev = new AutoSigningKeyProvider(async () => ({ available: true }), stub('ssm', denied), stub('file', fileSet), { fallbackOnSsmError: true, log: (m) => logs.push(m) });
    expect((await dev.getSigningKeys()).keys[0].jwk.kid).toBe('from-file');
    expect(dev.storage).toBe('file');
    expect(logs.some((l) => /falling back/.test(l))).toBe(true);
    const prod = new AutoSigningKeyProvider(async () => ({ available: true }), stub('ssm', denied), stub('file', fileSet), { fallbackOnSsmError: false });
    await expect(prod.getSigningKeys()).rejects.toThrow(/AccessDenied/);
  });
});

describe('detectAwsCredentials', () => {
  const client = (credentials: () => Promise<unknown>) => ({ config: { credentials } }) as never;
  it('credentials resolved -> available', async () => {
    await expect(detectAwsCredentials(client(async () => ({ accessKeyId: 'AKIA', secretAccessKey: 's' })), 500)).resolves.toEqual({ available: true });
  });
  it('credential chain fails -> unavailable with the reason', async () => {
    const r = await detectAwsCredentials(client(async () => Promise.reject(new Error('Could not load credentials from any providers'))), 500);
    expect(r).toEqual({ available: false, reason: 'Could not load credentials from any providers' });
  });
  it('credential chain hangs (no metadata service) -> unavailable after the timeout', async () => {
    const r = await detectAwsCredentials(client(() => new Promise(() => undefined)), 200);
    expect(r.available).toBe(false);
    expect(r.reason).toMatch(/200 ms/);
  });
});

describe('AWS credentials from environment variables only (AWS_CREDENTIALS_SOURCE=env)', () => {
  const saved = { ...process.env };
  afterEach(() => {
    for (const k of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });
  const client = () => createSsmClient({ AWS_REGION: 'ap-south-1', AWS_ENDPOINT_URL: '', AWS_CREDENTIALS_SOURCE: 'env' });

  it('is the default', () => {
    expect(parseEnv({ ...BASE_ENV }).AWS_CREDENTIALS_SOURCE).toBe('env');
    expect(parseEnv({ ...BASE_ENV, AWS_CREDENTIALS_SOURCE: 'chain' }).AWS_CREDENTIALS_SOURCE).toBe('chain');
  });
  it('no key variables -> no credentials, even when ~/.aws or a profile exists', async () => {
    delete process.env.AWS_ACCESS_KEY_ID;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    const r = await detectAwsCredentials(client(), 1000);
    expect(r).toEqual({ available: false, reason: 'AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set' });
  });
  it('empty values count as not set', async () => {
    process.env.AWS_ACCESS_KEY_ID = '';
    process.env.AWS_SECRET_ACCESS_KEY = '';
    expect((await detectAwsCredentials(client(), 1000)).available).toBe(false);
  });
  it('access key + secret key -> credentials (session token only when given)', async () => {
    process.env.AWS_ACCESS_KEY_ID = 'AKIAEXAMPLE';
    process.env.AWS_SECRET_ACCESS_KEY = 'secret';
    delete process.env.AWS_SESSION_TOKEN;
    await expect(envOnlyCredentials()).resolves.toEqual({ accessKeyId: 'AKIAEXAMPLE', secretAccessKey: 'secret' });
    expect((await detectAwsCredentials(client(), 1000)).available).toBe(true);
    process.env.AWS_SESSION_TOKEN = 'tok';
    await expect(envOnlyCredentials()).resolves.toMatchObject({ sessionToken: 'tok' });
  });
});

describe('createSigningKeyProvider', () => {
  it('file, ssm and auto map to their providers; kms has no key-set provider', () => {
    expect(createSigningKeyProvider(parseEnv({ ...BASE_ENV, KEY_PROVIDER: 'file' }))).toBeInstanceOf(FileSigningKeyProvider);
    expect(createSigningKeyProvider(parseEnv({ ...BASE_ENV, KEY_PROVIDER: 'ssm' }))).toBeInstanceOf(SsmSigningKeyProvider);
    expect(createSigningKeyProvider(parseEnv({ ...BASE_ENV }))).toBeInstanceOf(AutoSigningKeyProvider);
    expect(() => createSigningKeyProvider(parseEnv({ ...BASE_ENV, KEY_PROVIDER: 'kms' }))).toThrow(/kms/);
  });
  it('ssm describes itself with the parameter path', () => {
    const p = createSigningKeyProvider(parseEnv({ ...BASE_ENV, KEY_PROVIDER: 'ssm', SSM_SIGNING_KEYS_PARAMETER: '/miqaatcoredev/prod/auth/jwks-private-key' }));
    expect(p.describe()).toBe('ssm:/miqaatcoredev/prod/auth/jwks-private-key');
  });
  it('file key content stays a plain JSON key set on disk', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'keys-'));
    try {
      const p = createSigningKeyProvider(parseEnv({ ...BASE_ENV, KEY_PROVIDER: 'file', SIGNING_KEYS_FILE: join(dir, 'k.json') }));
      await p.saveSigningKeys({ keys: [await key('only', 'ACTIVE')] });
      expect(JSON.parse(await readFile(join(dir, 'k.json'), 'utf8')).keys[0].jwk.kid).toBe('only');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
