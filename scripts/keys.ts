/**
 * Signing key lifecycle (spec §24-25). The key set is read and written through the same provider the
 * service uses (KEY_PROVIDER):
 *   auto  AWS credentials available -> SSM Parameter Store, otherwise the local file
 *   ssm   SecureString at SSM_SIGNING_KEYS_PARAMETER
 *   file  SIGNING_KEYS_FILE
 *   kms   legacy: keys inside AWS KMS + signing_key_metadata
 *
 *   npm run keys -- list
 *   npm run keys -- generate                 new key: ACTIVE when none is active, else NEXT (prepublished)
 *                                            auto / ssm / file: RSA 2048 private JWK added to the key set
 *                                            kms:  CreateKey(RSA_2048, SIGN_VERIFY) + metadata row
 *   npm run keys -- activate <kid>           rotation: NEXT -> ACTIVE, previous ACTIVE -> RETIRING
 *   npm run keys -- retire <kid>             RETIRING -> RETIRED (removed from JWKS)
 *   npm run keys -- revoke <kid> [--revoke-sessions]
 *                                            EMERGENCY: key RETIRED + revoked_at, removed from JWKS at once.
 *                                            If it was ACTIVE, a NEXT key is promoted or a new key is created.
 *                                            --revoke-sessions also ends every active Core session.
 *
 * Normal rotation: generate (NEXT) -> wait >= JWKS cache time -> activate -> wait max token lifetime + skew
 * -> retire. Restart (or roll) the service after every change.
 */
import 'reflect-metadata';
import { CreateKeyCommand, GetPublicKeyCommand, ScheduleKeyDeletionCommand } from '@aws-sdk/client-kms';
import { createPublicKey, randomBytes } from 'node:crypto';
import Redis from 'ioredis';
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { loadDotEnv, parseEnv, type Env } from '../src/config/env';
import AppDataSource from '../src/database/data-source';
import { SigningKeyMetadata, type SigningKeyStatus } from '../src/database/entities';
import { SigningKeyRepository } from '../src/database/repositories/signing-key.repository';
import { AutoSigningKeyProvider } from '../src/modules/keys/auto-signing-key-provider';
import { createSigningKeyProvider } from '../src/modules/keys/create-signing-key-provider';
import type { StoredSigningKey } from '../src/modules/keys/key-file';
import { createKmsClient } from '../src/modules/keys/kms-signing-key';
import { parseArgs } from './cli-args';

loadDotEnv();
const env = parseEnv();
const args = parseArgs();
const [command = 'list', kidArg] = process.argv.slice(2).filter((a) => !a.startsWith('--'));

interface KeyView {
  kid: string;
  status: SigningKeyStatus;
  revoked: boolean;
}

function newKid(): string {
  const prefix = ({ production: 'prod', test: 'test' } as Record<string, string>)[env.NODE_ENV] ?? 'dev';
  return `${prefix}-${new Date().toISOString().slice(0, 7)}-${randomBytes(4).toString('hex')}`;
}

/** Common lifecycle operations over the two stores. */
interface KeyStore {
  list(): Promise<KeyView[]>;
  create(status: SigningKeyStatus): Promise<string>;
  setStatus(kid: string, status: SigningKeyStatus, revoked?: boolean): Promise<void>;
  save(): Promise<void>;
}

/** Key set in SSM or a local file, through the SigningKeyProvider (the same one the service loads). */
async function keySetStore(): Promise<KeyStore> {
  const provider = createSigningKeyProvider(env, { fallbackOnSsmError: false, log: (m) => console.log(m) });
  if (provider instanceof AutoSigningKeyProvider) await provider.resolve();
  const file = await provider.getSigningKeys({ allowMissing: true });
  console.log(`key provider: ${provider.describe()}`);
  // Only a real change is written back ("list" is read-only: no write, no ssm:PutParameter needed).
  let changed = false;
  const find = (kid: string) => {
    const k = file.keys.find((x) => x.jwk.kid === kid);
    if (!k) throw new Error(`unknown kid ${kid}`);
    return k;
  };
  return {
    async list() {
      return file.keys.map((k) => ({ kid: k.jwk.kid, status: k.status, revoked: Boolean(k.revokedAt) }));
    },
    async create(status) {
      const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
      const kid = newKid();
      const jwk = { ...(await exportJWK(privateKey)), kid, alg: 'RS256', use: 'sig' } as StoredSigningKey['jwk'];
      file.keys.push({ status, jwk });
      changed = true;
      return kid;
    },
    async setStatus(kid, status, revoked) {
      const k = find(kid);
      k.status = status;
      if (revoked) k.revokedAt = new Date().toISOString();
      changed = true;
    },
    async save() {
      if (!changed) return;
      await provider.saveSigningKeys(file);
      console.log(`written ${provider.describe()}`);
    },
  };
}

async function kmsStore(): Promise<KeyStore> {
  await AppDataSource.initialize();
  const repo = new SigningKeyRepository(AppDataSource.getRepository(SigningKeyMetadata));
  const kms = createKmsClient(env);
  return {
    async list() {
      return (await repo.findKms(env.NODE_ENV)).map((r) => ({ kid: r.kid, status: r.status, revoked: Boolean(r.revokedAt) }));
    },
    async create(status) {
      const created = await kms.send(
        new CreateKeyCommand({ KeySpec: 'RSA_2048', KeyUsage: 'SIGN_VERIFY', Description: `miqaat oidc_mfa_auth ${env.NODE_ENV} token signing` }),
      );
      const keyId = created.KeyMetadata?.KeyId;
      if (!keyId) throw new Error('KMS CreateKey returned no KeyId');
      const pub = await kms.send(new GetPublicKeyCommand({ KeyId: keyId }));
      if (!pub.PublicKey) throw new Error('KMS GetPublicKey returned no key');
      const kid = newKid();
      const publicJwk = {
        ...(createPublicKey({ key: Buffer.from(pub.PublicKey), format: 'der', type: 'spki' }).export({ format: 'jwk' }) as JWK),
        kid,
        alg: 'RS256',
        use: 'sig',
      };
      await repo.upsert({
        kid,
        alg: 'RS256',
        status,
        jwkThumbprint: await calculateJwkThumbprint(publicJwk, 'sha256'),
        publicJwk: publicJwk as Record<string, unknown>,
        keyProviderRef: `kms:${keyId}`,
        purpose: 'OIDC_TOKEN_SIGNING',
        environment: env.NODE_ENV,
      });
      return kid;
    },
    async setStatus(kid, status, revoked) {
      const row = await repo.findByKid(kid);
      if (!row || !row.keyProviderRef?.startsWith('kms:')) throw new Error(`unknown KMS kid ${kid}`);
      await repo.setStatus(kid, status, revoked ? { revokedAt: new Date() } : {});
      // A compromised key must also stop being usable at the source.
      if (revoked) await kms.send(new ScheduleKeyDeletionCommand({ KeyId: row.keyProviderRef.slice(4), PendingWindowInDays: 7 }));
    },
    async save() {
      await AppDataSource.destroy();
    },
  };
}

async function revokeAllSessions(e: Env): Promise<number> {
  if (!AppDataSource.isInitialized) await AppDataSource.initialize();
  const [, affected] = await AppDataSource.query(
    `UPDATE auth_sessions SET status = 'REVOKED', revoked_at = now(), revoke_reason = 'SIGNING_KEY_REVOKED', updated_at = now()
      WHERE status = 'ACTIVE'`,
  );
  // Hot copies must go too, otherwise a cached session would outlive the revocation.
  const redis = new Redis(e.REDIS_URL);
  try {
    let cursor = '0';
    do {
      const [next, keys] = await redis.scan(cursor, 'MATCH', `${e.REDIS_KEY_PREFIX}sso:*`, 'COUNT', 500);
      if (keys.length) await redis.del(...keys);
      cursor = next;
    } while (cursor !== '0');
  } finally {
    redis.disconnect();
  }
  return Number(affected ?? 0);
}

async function main() {
  const store = env.KEY_PROVIDER === 'kms' ? await kmsStore() : await keySetStore();
  const keys = await store.list();
  const need = (kid: string | undefined) => {
    const k = keys.find((x) => x.kid === kid);
    if (!k) throw new Error(`unknown kid ${kid ?? '(missing)'}`);
    return k;
  };

  switch (command) {
    case 'list':
      break;
    case 'generate': {
      const status: SigningKeyStatus = keys.some((k) => k.status === 'ACTIVE' && !k.revoked) ? 'NEXT' : 'ACTIVE';
      console.log(`generated ${await store.create(status)} (${status})`);
      break;
    }
    case 'activate': {
      const target = need(kidArg);
      if (target.status !== 'NEXT' || target.revoked) throw new Error(`${target.kid} must be NEXT (prepublished) to activate`);
      for (const k of keys) if (k.status === 'ACTIVE') await store.setStatus(k.kid, 'RETIRING');
      await store.setStatus(target.kid, 'ACTIVE');
      console.log(`${target.kid} is ACTIVE; previous active key is RETIRING`);
      break;
    }
    case 'retire': {
      const target = need(kidArg);
      if (target.status !== 'RETIRING') throw new Error(`${target.kid} must be RETIRING to retire`);
      await store.setStatus(target.kid, 'RETIRED');
      console.log(`${target.kid} is RETIRED`);
      break;
    }
    case 'revoke': {
      const target = need(kidArg);
      const wasActive = target.status === 'ACTIVE';
      await store.setStatus(target.kid, 'RETIRED', true);
      console.log(`REVOKED ${target.kid}: removed from JWKS, never signs again`);
      if (wasActive) {
        const next = keys.find((k) => k.status === 'NEXT' && !k.revoked);
        if (next) {
          await store.setStatus(next.kid, 'ACTIVE');
          console.log(`promoted prepublished key ${next.kid} to ACTIVE`);
        } else {
          console.log(`created emergency key ${await store.create('ACTIVE')} (ACTIVE)`);
        }
      }
      if (args.has('revoke-sessions')) console.log(`revoked ${await revokeAllSessions(env)} active Core session(s)`);
      console.log('Restart the service now, and ask BUs to refresh their JWKS cache.');
      break;
    }
    default:
      throw new Error(`unknown command ${command} (list | generate | activate | retire | revoke)`);
  }

  for (const k of await store.list()) console.log(`${k.kid}\t${k.status}${k.revoked ? ' (revoked)' : ''}`);
  await store.save();
  if (AppDataSource.isInitialized) await AppDataSource.destroy();
}

main().catch(async (e) => {
  console.error(e instanceof Error ? e.message : e);
  if (AppDataSource.isInitialized) await AppDataSource.destroy();
  process.exit(1);
});
