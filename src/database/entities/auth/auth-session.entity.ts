import { Column, Entity, PrimaryColumn } from 'typeorm';
import type { AuthRealm } from './auth-realm';

export type SessionStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';
export type MfaMethod = 'EMAIL_OTP' | 'SMS_OTP' | 'TOTP';

/**
 * auth_sessions - existing table, used as the durable Core global realm session.
 * The hot copy lives in Redis (sso:<realm>:<hash>). Columns marked (added) come from the migration.
 */
@Entity({ name: 'auth_sessions' })
export class AuthSession {
  /** Public session id (correlation with BU sessions). Not the browser secret. */
  @PrimaryColumn({ type: 'varchar', length: 64 })
  sid: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64 })
  itsId: string;

  @Column({ name: 'auth_method', type: 'varchar', length: 32 })
  authMethod: string;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  /** Idle expiry. */
  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'absolute_expires_at', type: 'timestamptz' })
  absoluteExpiresAt: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz', nullable: true })
  lastSeenAt: Date | null;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  @Column({ name: 'revoke_reason', type: 'varchar', length: 64, nullable: true })
  revokeReason: string | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ name: 'user_agent', type: 'varchar', length: 512, nullable: true })
  userAgent: string | null;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;

  /** (added) */
  @Column({ name: 'auth_realm', type: 'varchar', length: 16, nullable: true })
  authRealm: AuthRealm | null;

  /** (added) SHA-256 of the browser cookie secret. */
  @Column({ name: 'session_secret_hash', type: 'varchar', length: 64, nullable: true })
  sessionSecretHash: string | null;

  /** (added) */
  @Column({ type: 'varchar', length: 16, nullable: true })
  status: SessionStatus | null;

  /** (added) 1 = password, 2 = password + second factor. */
  @Column({ type: 'smallint', nullable: true })
  aal: number | null;

  /** (added) e.g. ["pwd","otp"] */
  @Column({ type: 'jsonb', nullable: true })
  amr: string[] | null;

  /** (added) */
  @Column({ name: 'auth_time', type: 'timestamptz', nullable: true })
  authTime: Date | null;

  /** (added) */
  @Column({ name: 'mfa_verified_at', type: 'timestamptz', nullable: true })
  mfaVerifiedAt: Date | null;

  /** (added) */
  @Column({ name: 'mfa_method', type: 'varchar', length: 16, nullable: true })
  mfaMethod: MfaMethod | null;
}
