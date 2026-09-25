import type { SSMClient } from '@aws-sdk/client-ssm';

export interface AwsCredentialCheck {
  available: boolean;
  /** Why not, when unavailable (for the start-up log). */
  reason?: string;
}

/**
 * True when the SSM client can obtain credentials. With AWS_CREDENTIALS_SOURCE=env (default) that means
 * AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY are set - nothing else is looked at. With =chain it is the
 * full AWS default chain (env, AWS_PROFILE / ~/.aws, SSO, web identity, ECS task role, EC2 instance
 * role). Nothing is called on AWS itself; the result is bounded by a timeout.
 */
export async function detectAwsCredentials(client: Pick<SSMClient, 'config'>, timeoutMs: number): Promise<AwsCredentialCheck> {
  let timer: NodeJS.Timeout | undefined;
  try {
    const credentials = await Promise.race([
      client.config.credentials(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`no credentials within ${timeoutMs} ms`)), timeoutMs);
      }),
    ]);
    return credentials?.accessKeyId ? { available: true } : { available: false, reason: 'empty credentials' };
  } catch (error) {
    return { available: false, reason: error instanceof Error ? error.message.split('\n')[0] : String(error) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
