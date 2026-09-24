import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/** auth_session_clients - existing table: which clients joined a Core session (needed later for logout). */
@Entity({ name: 'auth_session_clients' })
export class AuthSessionClient {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ type: 'varchar', length: 64 })
  sid: string;

  @Column({ name: 'client_id', type: 'varchar', length: 64 })
  clientId: string;

  @Column({ name: 'first_assertion_at', type: 'timestamptz', default: () => 'now()' })
  firstAssertionAt: Date;

  @Column({ name: 'last_assertion_at', type: 'timestamptz', default: () => 'now()' })
  lastAssertionAt: Date;

  @Column({ name: 'assertion_count', type: 'integer', default: 1 })
  assertionCount: number;

  /** (added) LOGIN | HANDOFF */
  @Column({ name: 'established_by', type: 'varchar', length: 16, nullable: true })
  establishedBy: 'LOGIN' | 'HANDOFF' | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
