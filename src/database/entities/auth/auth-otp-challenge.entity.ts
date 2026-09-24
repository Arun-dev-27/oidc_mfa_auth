import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from 'typeorm';

export type OtpChannel = 'EMAIL' | 'SMS';
export type OtpPurpose = 'LOGIN_MFA' | 'STEP_UP';

/**
 * auth_otp_challenges - NEW. One row per one-time code sent by Email or SMS.
 * The code itself is never stored: only an HMAC of it. A row is consumed at most once.
 */
@Entity({ name: 'auth_otp_challenges' })
export class AuthOtpChallenge {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64 })
  itsId: string;

  /** Core session the code belongs to. */
  @Column({ type: 'varchar', length: 64 })
  sid: string;

  /** oidc-provider interaction the code was issued for. */
  @Column({ name: 'interaction_uid', type: 'varchar', length: 64 })
  interactionUid: string;

  @Column({ type: 'varchar', length: 8 })
  channel: OtpChannel;

  @Column({ type: 'varchar', length: 16 })
  purpose: OtpPurpose;

  @Column({ name: 'destination_masked', type: 'varchar', length: 255 })
  destinationMasked: string;

  @Column({ name: 'code_hash', type: 'char', length: 64 })
  codeHash: string;

  @Column({ name: 'attempt_count', type: 'integer', default: 0 })
  attemptCount: number;

  @Column({ name: 'max_attempts', type: 'integer' })
  maxAttempts: number;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'consumed_at', type: 'timestamptz', nullable: true })
  consumedAt: Date | null;

  @Column({ name: 'provider_message_id', type: 'varchar', length: 255, nullable: true })
  providerMessageId: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
