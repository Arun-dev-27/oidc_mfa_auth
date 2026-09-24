import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * users - SYNCED table (owned by the Mumin sync service). Read only for this service.
 * mumin_id is the ITS ID and becomes the OIDC `sub`.
 */
@Entity({ name: 'users' })
export class IdentityUser {
  @PrimaryColumn({ type: 'numeric' })
  id: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  /** Legacy reversible ciphertext - see legacy-password-cipher.ts. Never selected unless asked for. */
  @Column({ type: 'varchar', length: 100, nullable: true, select: false })
  password: string | null;

  @Column({ name: 'allow_login', type: 'boolean', nullable: true })
  allowLogin: boolean | null;

  @Column({ name: 'is_otprequired', type: 'boolean' })
  isOtpRequired: boolean;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;
}
