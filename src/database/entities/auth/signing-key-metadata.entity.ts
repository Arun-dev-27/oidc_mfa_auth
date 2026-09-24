import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * Existing status values: NEXT (= prepublished) | ACTIVE | RETIRING | RETIRED. A revoked key is
 * RETIRED with revoked_at set, so the existing CHECK constraint is left untouched.
 */
export type SigningKeyStatus = 'NEXT' | 'ACTIVE' | 'RETIRING' | 'RETIRED';

/** signing_key_metadata - existing table (metadata only; private keys never live in the database). */
@Entity({ name: 'signing_key_metadata' })
export class SigningKeyMetadata {
  @PrimaryColumn({ type: 'varchar', length: 128 })
  kid: string;

  @Column({ type: 'varchar', length: 16 })
  alg: string;

  @Column({ type: 'varchar', length: 16 })
  status: SigningKeyStatus;

  @Column({ name: 'jwk_thumbprint', type: 'varchar', length: 64, nullable: true })
  jwkThumbprint: string | null;

  @Column({ name: 'first_seen_at', type: 'timestamptz', default: () => 'now()' })
  firstSeenAt: Date;

  @Column({ name: 'status_changed_at', type: 'timestamptz', default: () => 'now()' })
  statusChangedAt: Date;

  /** (added) */
  @Column({ name: 'public_jwk', type: 'jsonb', nullable: true })
  publicJwk: Record<string, unknown> | null;

  /** (added) e.g. file:./.keys/signing-keys.json or a KMS key ARN */
  @Column({ name: 'key_provider_ref', type: 'text', nullable: true })
  keyProviderRef: string | null;

  /** (added) */
  @Column({ type: 'varchar', length: 40, nullable: true })
  purpose: string | null;

  /** (added) */
  @Column({ type: 'varchar', length: 32, nullable: true })
  environment: string | null;

  /** (added) */
  @Column({ name: 'activated_at', type: 'timestamptz', nullable: true })
  activatedAt: Date | null;

  /** (added) */
  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
