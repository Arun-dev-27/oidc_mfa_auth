import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { JWK } from 'jose';
import type { SigningKeyStatus } from '../../database/entities';

/** One entry of the signing key file: a private JWK plus its lifecycle status. */
export interface StoredSigningKey {
  status: SigningKeyStatus;
  /** Set when the key was revoked (emergency). A revoked key is RETIRED and never published again. */
  revokedAt?: string;
  jwk: JWK & { kid: string; alg: string };
}

export interface SigningKeyFile {
  keys: StoredSigningKey[];
}

const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

export function toPublicJwk(jwk: JWK): JWK {
  const pub: Record<string, unknown> = { ...jwk };
  for (const m of PRIVATE_MEMBERS) delete pub[m];
  return pub as JWK;
}

export async function readKeyFile(path: string, { allowMissing = false } = {}): Promise<SigningKeyFile> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      if (allowMissing) return { keys: [] };
      throw new Error(`Signing key file ${path} not found. Run: npm run keys -- generate`);
    }
    throw error;
  }
  const parsed = JSON.parse(raw) as SigningKeyFile;
  if (!Array.isArray(parsed.keys)) throw new Error(`${path}: expected { "keys": [...] }`);
  return parsed;
}

export async function writeKeyFile(path: string, file: SigningKeyFile): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(file, null, 2), { encoding: 'utf8', mode: 0o600 });
}
