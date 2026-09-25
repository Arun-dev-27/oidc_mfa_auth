import type { SigningKeyFile, StoredSigningKey } from './key-file';

/** The complete private key set: every key with its kid, RS256 JWK and rotation status. */
export type SigningKeySet = SigningKeyFile;

export type SigningKeyStorage = 'file' | 'ssm';

/**
 * Where the private signing key set lives. The signing service and the keys CLI only talk to this
 * interface; they never read a file or call AWS themselves.
 *
 *   FileSigningKeyProvider  local JSON file (development)
 *   SsmSigningKeyProvider   AWS SSM Parameter Store SecureString
 *   AutoSigningKeyProvider  SSM when AWS credentials are available, otherwise the file
 *
 * The stored value is the same JSON in every store: { "keys": [ { status, revokedAt?, jwk } ] }, so
 * the rotation lifecycle NEXT -> ACTIVE -> RETIRING -> RETIRED works unchanged in both.
 */
export interface SigningKeyProvider {
  /** The store actually used (auto resolves on first use). */
  readonly storage: SigningKeyStorage;
  /** Human / audit reference, e.g. `file:./.keys/signing-keys.json` or `ssm:/miqaatcoredev/prod/auth/jwks-private-key`. */
  describe(): string;
  /** Loads the whole key set. `allowMissing` returns an empty set instead of failing (key generation). */
  getSigningKeys(options?: { allowMissing?: boolean }): Promise<SigningKeySet>;
  /** The key that signs new tokens (exactly one ACTIVE, not revoked). */
  getSigningKey(): Promise<StoredSigningKey>;
  /** Replaces the whole key set (key generation and rotation). */
  saveSigningKeys(set: SigningKeySet): Promise<void>;
}

/** Shared by the providers: validates what was loaded, whatever the store. */
export function parseKeySet(raw: string, source: string): SigningKeySet {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${source}: the signing key set is not valid JSON`);
  }
  const set = parsed as SigningKeySet;
  if (!set || !Array.isArray(set.keys)) throw new Error(`${source}: expected { "keys": [...] }`);
  for (const k of set.keys) {
    if (!k?.jwk?.kid || !k.status) throw new Error(`${source}: every key needs jwk.kid and status`);
  }
  return set;
}

/** The ACTIVE, non-revoked key of a set. */
export function activeKeyOf(set: SigningKeySet, source: string): StoredSigningKey {
  const active = set.keys.filter((k) => k.status === 'ACTIVE' && !k.revokedAt);
  if (active.length !== 1) throw new Error(`${source}: exactly one ACTIVE signing key is required (found ${active.length}). Use: npm run keys -- list`);
  return active[0];
}
