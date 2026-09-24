import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'INFO';

/** auth_audit_events - existing table. Never holds passwords, OTPs, tokens or cookies. */
@Entity({ name: 'auth_audit_events' })
export class AuthAuditEvent {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ name: 'event_type', type: 'varchar', length: 64 })
  eventType: string;

  @Column({ type: 'varchar', length: 16 })
  outcome: AuditOutcome;

  @Column({ name: 'its_id', type: 'varchar', length: 64, nullable: true })
  itsId: string | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  sid: string | null;

  @Column({ name: 'client_id', type: 'varchar', length: 64, nullable: true })
  clientId: string | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  jti: string | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ name: 'user_agent', type: 'varchar', length: 512, nullable: true })
  userAgent: string | null;

  @Column({ name: 'correlation_id', type: 'varchar', length: 128, nullable: true })
  correlationId: string | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, unknown> | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
