import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';
import type { AuthRealm } from './auth-realm';

export type LogoutJobStatus = 'PENDING' | 'COMPLETED' | 'COMPLETED_WITH_FAILURES';
export type LogoutDeliveryStatus = 'PENDING' | 'RETRY' | 'SUCCEEDED' | 'FAILED' | 'NO_ENDPOINT' | 'DEAD';

/** logout_jobs - NEW. One per revoked Core realm session. */
@Entity({ name: 'logout_jobs' })
export class LogoutJob {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 64 })
  sid: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64 })
  itsId: string;

  @Column({ name: 'auth_realm', type: 'varchar', length: 16 })
  authRealm: AuthRealm;

  @Column({ type: 'varchar', length: 64 })
  reason: string;

  @Column({ name: 'initiated_by_client', type: 'varchar', length: 64, nullable: true })
  initiatedByClient: string | null;

  @Column({ type: 'varchar', length: 24, default: 'PENDING' })
  status: LogoutJobStatus;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'completed_at', type: 'timestamptz', nullable: true })
  completedAt: Date | null;
}

/** logout_deliveries - NEW. One back-channel logout message per participating client. */
@Entity({ name: 'logout_deliveries' })
export class LogoutDelivery {
  @PrimaryColumn({ name: 'job_id', type: 'uuid' })
  jobId: string;

  @PrimaryColumn({ name: 'client_id', type: 'varchar', length: 64 })
  clientId: string;

  /** jti of the logout JWS (stable across retries, so the BU can de-duplicate). */
  @Column({ type: 'uuid' })
  jti: string;

  @Column({ type: 'varchar', length: 16, default: 'PENDING' })
  status: LogoutDeliveryStatus;

  @Column({ name: 'attempt_count', type: 'integer', default: 0 })
  attemptCount: number;

  @Column({ name: 'next_attempt_at', type: 'timestamptz' })
  nextAttemptAt: Date;

  @Column({ name: 'last_attempt_at', type: 'timestamptz', nullable: true })
  lastAttemptAt: Date | null;

  @Column({ name: 'last_http_status', type: 'integer', nullable: true })
  lastHttpStatus: number | null;

  @Column({ name: 'last_error_code', type: 'varchar', length: 80, nullable: true })
  lastErrorCode: string | null;

  @Column({ name: 'completed_at', type: 'timestamptz', nullable: true })
  completedAt: Date | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;
}
