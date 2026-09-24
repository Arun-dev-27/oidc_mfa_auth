import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import type { AuthRealm } from './auth-realm';

export type HandoffStatus = 'PENDING' | 'COMPLETED' | 'EXPIRED' | 'CANCELLED';

/** auth_client_handoff_paths - NEW. Target-relative paths a handoff may open (e.g. /events/*). */
@Entity({ name: 'auth_client_handoff_paths' })
export class HandoffPath {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ name: 'client_id', type: 'varchar', length: 64 })
  clientId: string;

  // A star matches exactly one path segment, e.g. pattern "/events/STAR" matches /events/123.
  @Column({ name: 'path_pattern', type: 'varchar', length: 512 })
  pathPattern: string;

  @Column({ type: 'boolean', default: true })
  enabled: boolean;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;
}

/** handoff_requests - NEW. One transaction per handoff (Handoff spec §23). */
@Entity({ name: 'handoff_requests' })
export class HandoffRequest {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'source_client_id', type: 'varchar', length: 64 })
  sourceClientId: string;

  @Column({ name: 'target_client_id', type: 'varchar', length: 64 })
  targetClientId: string;

  @Column({ name: 'auth_realm', type: 'varchar', length: 16 })
  authRealm: AuthRealm;

  @Column({ name: 'requested_path', type: 'varchar', length: 512 })
  requestedPath: string;

  @Column({ type: 'varchar', length: 20, default: 'PENDING' })
  status: HandoffStatus;

  /** Bound when the browser completes the handoff (never taken from the source). */
  @Column({ name: 'its_id', type: 'varchar', length: 64, nullable: true })
  itsId: string | null;

  @Column({ type: 'varchar', length: 64, nullable: true })
  sid: string | null;

  @Column({ type: 'uuid', nullable: true })
  jti: string | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'completed_at', type: 'timestamptz', nullable: true })
  completedAt: Date | null;
}
