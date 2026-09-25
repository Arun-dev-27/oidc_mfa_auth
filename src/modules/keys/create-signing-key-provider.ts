import type { Env } from '../../config/env';
import { AutoSigningKeyProvider } from './auto-signing-key-provider';
import { detectAwsCredentials } from './aws-credentials';
import { FileSigningKeyProvider } from './file-signing-key-provider';
import type { SigningKeyProvider } from './signing-key-provider';
import { createSsmClient, SsmSigningKeyProvider } from './ssm-signing-key-provider';

type KeyEnv = Pick<
  Env,
  'KEY_PROVIDER' | 'AWS_CREDENTIALS_SOURCE' | 'SIGNING_KEYS_FILE' | 'SSM_SIGNING_KEYS_PARAMETER' | 'SSM_KMS_KEY_ID' | 'KEY_PROVIDER_DETECT_TIMEOUT_MS' | 'AWS_REGION' | 'AWS_ENDPOINT_URL' | 'NODE_ENV'
>;

/**
 * The one place that turns KEY_PROVIDER into a provider:
 *   ssm  -> SsmSigningKeyProvider
 *   file -> FileSigningKeyProvider
 *   auto -> AutoSigningKeyProvider (SSM when AWS credentials are available, else file)
 * KEY_PROVIDER=kms keeps its own KMS code path and never reaches this factory.
 *
 * `fallbackOnSsmError`: the running service may fall back to the file outside production; the keys CLI
 * passes false so a key is never written to a different store than the operator expects.
 */
export function createSigningKeyProvider(
  env: KeyEnv,
  options: { fallbackOnSsmError?: boolean; log?: (message: string) => void } = {},
): SigningKeyProvider {
  if (env.KEY_PROVIDER === 'kms') throw new Error('KEY_PROVIDER=kms uses AWS KMS keys, not a key-set provider');
  const file = new FileSigningKeyProvider(env.SIGNING_KEYS_FILE);
  if (env.KEY_PROVIDER === 'file') return file;

  const client = createSsmClient(env);
  const ssm = new SsmSigningKeyProvider(client, env.SSM_SIGNING_KEYS_PARAMETER, env.SSM_KMS_KEY_ID);
  if (env.KEY_PROVIDER === 'ssm') return ssm;

  return new AutoSigningKeyProvider(() => detectAwsCredentials(client, env.KEY_PROVIDER_DETECT_TIMEOUT_MS), ssm, file, {
    fallbackOnSsmError: (options.fallbackOnSsmError ?? true) && env.NODE_ENV !== 'production',
    log: options.log,
  });
}
