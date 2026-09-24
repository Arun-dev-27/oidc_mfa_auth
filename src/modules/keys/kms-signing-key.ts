import { KMSClient, SignCommand } from '@aws-sdk/client-kms';
import { createPublicKey, type KeyObject } from 'node:crypto';
import type { JWK } from 'jose';
import { ExternalSigningKey } from 'oidc-provider';
import type { Env } from '../../config/env';

export function createKmsClient(env: Pick<Env, 'AWS_REGION' | 'AWS_ENDPOINT_URL'>): KMSClient {
  return new KMSClient({ region: env.AWS_REGION, ...(env.AWS_ENDPOINT_URL ? { endpoint: env.AWS_ENDPOINT_URL } : {}) });
}

/**
 * An RS256 signing key whose private half lives in AWS KMS (spec §23): oidc-provider hands the
 * JWS signing input to sign(), KMS returns the RSASSA-PKCS1-v1_5 SHA-256 signature. Only the public
 * key (from signing_key_metadata.public_jwk) is ever in this process.
 */
export class KmsSigningKey extends ExternalSigningKey {
  private readonly publicKey: KeyObject;

  constructor(
    private readonly kms: KMSClient,
    private readonly keyId: string,
    kid: string,
    publicJwk: JWK,
  ) {
    super();
    // The base class has kid / alg setters at runtime; its typings only declare the getters.
    Object.assign(this, { kid, alg: 'RS256' });
    this.publicKey = createPublicKey({ key: publicJwk as never, format: 'jwk' });
  }

  override keyObject(): KeyObject {
    return this.publicKey;
  }

  override async sign(data: Uint8Array): Promise<Uint8Array> {
    const out = await this.kms.send(
      new SignCommand({ KeyId: this.keyId, Message: data, MessageType: 'RAW', SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256' }),
    );
    if (!out.Signature) throw new Error(`KMS returned no signature for ${this.kid}`);
    return out.Signature;
  }
}
