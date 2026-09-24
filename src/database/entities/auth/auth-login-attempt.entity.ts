import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export type AttemptType = 'LOGIN' | 'MFA';

/** auth_login_attempts - existing table; attempt_type (added) separates password and MFA failures. */
@Entity({ name: 'auth_login_attempts' })
export class AuthLoginAttempt {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ name: 'identifier_hash', type: 'char', length: 64 })
  identifierHash: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64, nullable: true })
  itsId: string | null;

  @Column({ name: 'client_id', type: 'varchar', length: 64, nullable: true })
  clientId: string | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'boolean' })
  success: boolean;

  @Column({ name: 'failure_reason', type: 'varchar', length: 64, nullable: true })
  failureReason: string | null;

  @Column({ name: 'correlation_id', type: 'varchar', length: 128, nullable: true })
  correlationId: string | null;

  /** (added) */
  @Column({ name: 'attempt_type', type: 'varchar', length: 16, nullable: true })
  attemptType: AttemptType | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
