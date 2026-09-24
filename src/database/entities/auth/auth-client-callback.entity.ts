import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from 'typeorm';
import { AuthClient } from './auth-client.entity';

export type CallbackUriType = 'CALLBACK' | 'BACK_CHANNEL_LOGOUT' | 'POST_LOGOUT_REDIRECT';

/** auth_client_callbacks - existing table. CALLBACK rows are the OIDC redirect_uris (exact match). */
@Entity({ name: 'auth_client_callbacks' })
export class AuthClientCallback {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'client_ref', type: 'uuid' })
  clientRef: string;

  @ManyToOne(() => AuthClient, (c) => c.callbacks, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'client_ref' })
  client: AuthClient;

  @Column({ type: 'varchar', length: 2048 })
  uri: string;

  @Column({ name: 'uri_type', type: 'varchar', length: 32 })
  uriType: CallbackUriType;

  @Column({ name: 'is_primary', type: 'boolean', default: false })
  isPrimary: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
