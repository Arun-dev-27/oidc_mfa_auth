import { resolve } from 'node:path';
import { readKeyFile, writeKeyFile } from './key-file';
import { activeKeyOf, type SigningKeyProvider, type SigningKeySet } from './signing-key-provider';

/**
 * Key set in a local JSON file (mode 0600). For development and environments without AWS; the path
 * (SIGNING_KEYS_FILE) must be git-ignored. Refused in production by the configuration.
 */
export class FileSigningKeyProvider implements SigningKeyProvider {
  readonly storage = 'file' as const;

  constructor(private readonly path: string) {}

  describe(): string {
    return `file:${this.path}`;
  }

  getSigningKeys(options: { allowMissing?: boolean } = {}): Promise<SigningKeySet> {
    return readKeyFile(resolve(this.path), options);
  }

  async getSigningKey() {
    return activeKeyOf(await this.getSigningKeys(), this.describe());
  }

  saveSigningKeys(set: SigningKeySet): Promise<void> {
    return writeKeyFile(resolve(this.path), set);
  }
}
