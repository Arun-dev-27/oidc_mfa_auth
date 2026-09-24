import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import type { MfaMethod } from './auth-session.entity';

export type MfaFactorStatus = 'PENDING' | 'ACTIVE' | 'DISABLED';

/**
 * user_mfa_factors - NEW. The second-factor methods a member may use.
 * No row at all = Email OTP to mumin_master.email (the platform default).
 */
@Entity({ name: 'user_mfa_factors' })
export class UserMfaFactor {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /** ITS ID (users.mumin_id). */
  @Column({ name: 'its_id', type: 'varchar', length: 64 })
  itsId: string;

  @Column({ type: 'varchar', length: 16 })
  method: MfaMethod;

  @Column({ name: 'is_default', type: 'boolean', default: false })
  isDefault: boolean;

  /** Email address or phone number, AES-GCM encrypted. Empty for TOTP. */
  @Column({ name: 'destination_enc', type: 'text', nullable: true })
  destinationEnc: string | null;

  /** TOTP shared secret (base32), AES-GCM encrypted. */
  @Column({ name: 'totp_secret_enc', type: 'text', nullable: true })
  totpSecretEnc: string | null;

  /** Last accepted TOTP time step - blocks replaying the same code. */
  @Column({ name: 'last_used_step', type: 'bigint', nullable: true })
  lastUsedStep: string | null;

  @Column({ type: 'varchar', length: 16, default: 'ACTIVE' })
  status: MfaFactorStatus;

  @Column({ name: 'verified_at', type: 'timestamptz', nullable: true })
  verifiedAt: Date | null;

  @Column({ name: 'last_used_at', type: 'timestamptz', nullable: true })
  lastUsedAt: Date | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
