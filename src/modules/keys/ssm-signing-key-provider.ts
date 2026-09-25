import { GetParameterCommand, ParameterNotFound, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import type { Env } from '../../config/env';
import { toPublicJwk, type StoredSigningKey } from './key-file';
import { activeKeyOf, parseKeySet, type SigningKeyProvider, type SigningKeySet } from './signing-key-provider';

/** SSM parameter values are at most 8 KB (Advanced tier); Intelligent-Tiering picks the tier by size. */
const MAX_PARAMETER_BYTES = 8192;

/**
 * Credentials from the environment variables ONLY (AWS_CREDENTIALS_SOURCE=env): AWS_ACCESS_KEY_ID +
 * AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN for temporary keys). ~/.aws files, SSO and roles are never read.
 */
export async function envOnlyCredentials(): Promise<{ accessKeyId: string; secretAccessKey: string; sessionToken?: string }> {
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID?.trim();
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY?.trim();
  if (!accessKeyId || !secretAccessKey) throw new Error('AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set');
  const sessionToken = process.env.AWS_SESSION_TOKEN?.trim();
  return { accessKeyId, secretAccessKey, ...(sessionToken ? { sessionToken } : {}) };
}

export function createSsmClient(env: Pick<Env, 'AWS_REGION' | 'AWS_ENDPOINT_URL'> & Partial<Pick<Env, 'AWS_CREDENTIALS_SOURCE'>>): SSMClient {
  return new SSMClient({
    region: env.AWS_REGION,
    ...(env.AWS_ENDPOINT_URL ? { endpoint: env.AWS_ENDPOINT_URL } : {}),
    // 'chain' leaves credentials to the SDK default chain; 'env' (default) uses the variables only.
    ...((env.AWS_CREDENTIALS_SOURCE ?? 'env') === 'env' ? { credentials: envOnlyCredentials } : {}),
  });
}

/**
 * Key set in AWS SSM Parameter Store as ONE SecureString parameter (encrypted at rest with the AWS
 * managed key aws/ssm, or SSM_KMS_KEY_ID). The value is the same JSON as the local key file.
 * The service needs ssm:GetParameter (+ kms:Decrypt on a customer key); the keys CLI also needs
 * ssm:PutParameter. KMS is only used by SSM to encrypt the value - signing stays in this process.
 *
 * RETIRED / revoked keys are stored as public JWKs only: they never sign again, only their metadata
 * is kept, and it keeps the value well under the parameter size limit.
 */
export class SsmSigningKeyProvider implements SigningKeyProvider {
  readonly storage = 'ssm' as const;

  constructor(
    private readonly client: Pick<SSMClient, 'send'>,
    private readonly name: string,
    private readonly kmsKeyId = '',
  ) {}

  describe(): string {
    return `ssm:${this.name}`;
  }

  async getSigningKeys(options: { allowMissing?: boolean } = {}): Promise<SigningKeySet> {
    try {
      const out = await this.client.send(new GetParameterCommand({ Name: this.name, WithDecryption: true }));
      const value = out.Parameter?.Value;
      if (!value) throw new Error(`${this.describe()}: parameter has no value`);
      return parseKeySet(value, this.describe());
    } catch (error) {
      if (isNotFound(error)) {
        if (options.allowMissing) return { keys: [] };
        throw new Error(`Signing key parameter ${this.name} not found in SSM. Run: npm run keys -- generate`);
      }
      throw error;
    }
  }

  async getSigningKey(): Promise<StoredSigningKey> {
    return activeKeyOf(await this.getSigningKeys(), this.describe());
  }

  async saveSigningKeys(set: SigningKeySet): Promise<void> {
    const stored: SigningKeySet = {
      keys: set.keys.map((k) => (k.status === 'RETIRED' || k.revokedAt ? { ...k, jwk: toPublicJwk(k.jwk) as StoredSigningKey['jwk'] } : k)),
    };
    const value = JSON.stringify(stored);
    if (Buffer.byteLength(value) > MAX_PARAMETER_BYTES) {
      throw new Error(`${this.describe()}: key set is ${Buffer.byteLength(value)} bytes, SSM allows ${MAX_PARAMETER_BYTES}. Retire old keys first.`);
    }
    await this.client.send(
      new PutParameterCommand({
        Name: this.name,
        Value: value,
        Type: 'SecureString',
        Overwrite: true,
        Tier: 'Intelligent-Tiering',
        Description: 'Miqaat Core RS256 signing key set (private JWKs + rotation status)',
        ...(this.kmsKeyId ? { KeyId: this.kmsKeyId } : {}),
      }),
    );
  }
}

function isNotFound(error: unknown): boolean {
  return error instanceof ParameterNotFound || (error as { name?: string })?.name === 'ParameterNotFound';
}
