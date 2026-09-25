import type { StoredSigningKey } from './key-file';
import type { AwsCredentialCheck } from './aws-credentials';
import { activeKeyOf, type SigningKeyProvider, type SigningKeySet, type SigningKeyStorage } from './signing-key-provider';

export interface AutoOptions {
  /**
   * Outside production only: when AWS credentials exist but SSM cannot be read (parameter missing,
   * access denied, expired credentials, no network), continue with the local file instead of failing,
   * e.g. a developer laptop with an unrelated AWS profile. Production never falls back.
   */
  fallbackOnSsmError: boolean;
  log?: (message: string) => void;
}

/**
 * KEY_PROVIDER=auto: AWS credentials available -> SSM Parameter Store; otherwise -> local file.
 * The choice is made once, on first use, and then kept for the life of the process.
 */
export class AutoSigningKeyProvider implements SigningKeyProvider {
  private chosen: SigningKeyProvider | null = null;
  private deciding: Promise<SigningKeyProvider> | null = null;

  constructor(
    private readonly detect: () => Promise<AwsCredentialCheck>,
    private readonly ssm: SigningKeyProvider,
    private readonly file: SigningKeyProvider,
    private readonly options: AutoOptions,
  ) {}

  get storage(): SigningKeyStorage {
    if (!this.chosen) throw new Error('KEY_PROVIDER=auto has not been resolved yet');
    return this.chosen.storage;
  }

  describe(): string {
    return this.chosen ? this.chosen.describe() : 'auto (not resolved yet)';
  }

  /** Decides SSM or file (once). */
  resolve(): Promise<SigningKeyProvider> {
    if (this.chosen) return Promise.resolve(this.chosen);
    this.deciding ??= this.detect().then((check) => {
      if (check.available) {
        this.options.log?.(`KEY_PROVIDER=auto: AWS credentials found -> ${this.ssm.describe()}`);
        this.chosen = this.ssm;
      } else {
        this.options.log?.(`KEY_PROVIDER=auto: no AWS credentials (${check.reason ?? 'none'}) -> ${this.file.describe()}`);
        this.chosen = this.file;
      }
      return this.chosen;
    });
    return this.deciding;
  }

  async getSigningKeys(options: { allowMissing?: boolean } = {}): Promise<SigningKeySet> {
    const provider = await this.resolve();
    if (provider !== this.ssm) return provider.getSigningKeys(options);
    try {
      return await this.ssm.getSigningKeys(options);
    } catch (error) {
      if (!this.options.fallbackOnSsmError) throw error;
      this.options.log?.(
        `KEY_PROVIDER=auto: ${this.ssm.describe()} could not be read (${error instanceof Error ? error.message.split('\n')[0] : String(error)}) -> falling back to ${this.file.describe()} (not allowed in production)`,
      );
      this.chosen = this.file;
      return this.file.getSigningKeys(options);
    }
  }

  async getSigningKey(): Promise<StoredSigningKey> {
    return activeKeyOf(await this.getSigningKeys(), this.describe());
  }

  async saveSigningKeys(set: SigningKeySet): Promise<void> {
    return (await this.resolve()).saveSigningKeys(set);
  }
}
