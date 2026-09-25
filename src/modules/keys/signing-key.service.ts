import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { calculateJwkThumbprint, type JWK } from 'jose';
import type { ExternalSigningKey } from 'oidc-provider';
import { AppConfig } from '../../config/config.module';
import type { SigningKeyStatus } from '../../database/entities';
import { SigningKeyRepository } from '../../database/repositories/signing-key.repository';
import { toPublicJwk } from './key-file';
import { createKmsClient, KmsSigningKey } from './kms-signing-key';
import type { SigningKeyProvider } from './signing-key-provider';

/** Nest token of the configured SigningKeyProvider (null for KEY_PROVIDER=kms). */
export const SIGNING_KEY_PROVIDER = Symbol('SIGNING_KEY_PROVIDER');

const ORDER: Record<SigningKeyStatus, number> = { ACTIVE: 0, NEXT: 1, RETIRING: 2, RETIRED: 3 };

export type ProviderKey = JWK | ExternalSigningKey;

interface ActiveSigner {
  kid: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * Supplies oidc-provider with its RS256 signing keys.
 *
 * oidc-provider signs with the FIRST suitable key and publishes ALL keys in the JWKS, so the order
 * implements the rotation lifecycle (spec §24):
 *   ACTIVE    first  -> signs new tokens
 *   NEXT      next   -> published before use (prepublished), not signing yet
 *   RETIRING  last   -> still published so already-issued tokens verify
 *   RETIRED / revoked -> never published
 *
 * Where the private key set comes from (KEY_PROVIDER) is the SigningKeyProvider's business:
 *   auto / ssm / file  RS256 private JWKs from SSM Parameter Store or a local file; this process signs
 *   kms (legacy)       AWS KMS keys listed in signing_key_metadata (key_provider_ref = kms:<KeyId>); the
 *                      private key never leaves KMS, signatures are produced by KMS Sign.
 */
@Injectable()
export class SigningKeyService {
  private readonly logger = new Logger(SigningKeyService.name);
  private active: ActiveSigner | null = null;
  private published: JWK[] = [];

  constructor(
    private readonly config: AppConfig,
    private readonly metadata: SigningKeyRepository,
    @Optional() @Inject(SIGNING_KEY_PROVIDER) private readonly provider: SigningKeyProvider | null = null,
  ) {}

  get usesExternalSigning(): boolean {
    return this.config.env.KEY_PROVIDER === 'kms';
  }

  async loadForProvider(): Promise<ProviderKey[]> {
    return this.usesExternalSigning ? this.loadKms() : this.loadKeySet();
  }

  /** RS256 private JWKs from the configured provider (SSM or file); signing happens in this process. */
  private async loadKeySet(): Promise<ProviderKey[]> {
    const env = this.config.env;
    if (!this.provider) throw new Error('no signing key provider configured');
    const file = await this.provider.getSigningKeys();
    const source = this.provider.describe();
    if (env.NODE_ENV === 'production' && this.provider.storage === 'file') {
      throw new Error(`production signing keys must not come from a local file (${source}); give the service AWS credentials for SSM`);
    }
    const usable = file.keys.filter((k) => k.status !== 'RETIRED' && !k.revokedAt).sort((a, b) => ORDER[a.status] - ORDER[b.status]);
    this.assertOneActive(usable.map((k) => k.status));
    for (const k of usable) {
      if (k.jwk.alg !== 'RS256' || k.jwk.kty !== 'RSA') throw new Error(`key ${k.jwk.kid}: only RS256 RSA keys are allowed`);
    }

    for (const k of file.keys) {
      const publicJwk = toPublicJwk(k.jwk);
      await this.metadata.upsert({
        kid: k.jwk.kid,
        alg: k.jwk.alg,
        status: k.revokedAt ? 'RETIRED' : k.status,
        jwkThumbprint: await calculateJwkThumbprint(publicJwk, 'sha256'),
        publicJwk: publicJwk as Record<string, unknown>,
        keyProviderRef: source,
        purpose: 'OIDC_TOKEN_SIGNING',
        environment: env.NODE_ENV,
        revokedAt: k.revokedAt ? new Date(k.revokedAt) : null,
      });
    }
    const activeKey = usable[0];
    const privateKey = createPrivateKey({ key: activeKey.jwk as never, format: 'jwk' });
    this.active = { kid: activeKey.jwk.kid, sign: async (data) => cryptoSign('sha256', data, privateKey) };
    this.published = usable.map((k) => ({ ...toPublicJwk(k.jwk), use: 'sig' }));
    this.logger.log(`signing keys (${source}): ${usable.map((k) => `${k.jwk.kid}(${k.status})`).join(', ')}`);
    return usable.map((k) => ({ ...k.jwk, use: 'sig' }));
  }

  private async loadKms(): Promise<ProviderKey[]> {
    const env = this.config.env;
    const rows = (await this.metadata.findPublishableKms(env.NODE_ENV)).sort((a, b) => ORDER[a.status] - ORDER[b.status]);
    this.assertOneActive(rows.map((r) => r.status));
    const kms = createKmsClient(env);
    const keys = rows.map((r) => {
      if (r.alg !== 'RS256' || !r.publicJwk || !r.keyProviderRef) throw new Error(`KMS key ${r.kid}: incomplete metadata`);
      return new KmsSigningKey(kms, r.keyProviderRef.slice('kms:'.length), r.kid, r.publicJwk as JWK);
    });
    // Fail at start-up, not at the first login, when KMS or the key is not usable.
    await keys[0].sign(new TextEncoder().encode('startup-self-test'));
    this.active = { kid: rows[0].kid, sign: (data) => keys[0].sign(data) };
    this.published = rows.map((r) => r.publicJwk as JWK);
    this.logger.log(`signing keys (kms): ${rows.map((r) => `${r.kid}(${r.status})`).join(', ')}`);
    return keys;
  }

  /** Public keys currently published in the JWKS (used to verify our own id_token_hint). */
  get publicJwks(): JWK[] {
    return this.published;
  }

  /**
   * Compact RS256 JWS signed with the ACTIVE key - the same key (file or KMS) that signs ID tokens.
   * Used for Miqaat-specific assertions such as back-channel logout (spec §28).
   */
  async signJws(payload: Record<string, unknown>, typ: string): Promise<string> {
    if (!this.active) throw new Error('signing keys are not loaded');
    const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const input = `${enc({ alg: 'RS256', kid: this.active.kid, typ })}.${enc(payload)}`;
    const signature = await this.active.sign(new TextEncoder().encode(input));
    return `${input}.${Buffer.from(signature).toString('base64url')}`;
  }

  private assertOneActive(statuses: SigningKeyStatus[]): void {
    const active = statuses.filter((s) => s === 'ACTIVE').length;
    if (active !== 1) {
      throw new Error(`exactly one ACTIVE signing key is required (found ${active}). Use: npm run keys -- list`);
    }
  }
}
