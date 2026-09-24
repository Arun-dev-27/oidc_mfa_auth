import { Column, CreateDateColumn, Entity, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import type { AuthRealm } from './auth-realm';
import { AuthClientCallback } from './auth-client-callback.entity';

export type ClientStatus = 'PENDING' | 'SECURITY_REVIEW' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
export type TokenEndpointAuthMethod = 'private_key_jwt' | 'client_secret_basic' | 'client_secret_post';

/** auth_clients - existing registry table; the columns marked (added) come from the OidcMfaAuth migration. */
@Entity({ name: 'auth_clients' })
export class AuthClient {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'client_id', type: 'varchar', length: 64, unique: true })
  clientId: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ name: 'application_code', type: 'varchar', length: 64 })
  applicationCode: string;

  @Column({ name: 'application_name', type: 'varchar', length: 255 })
  applicationName: string;

  @Column({ name: 'business_unit', type: 'varchar', length: 255, nullable: true })
  businessUnit: string | null;

  @Column({ type: 'varchar', length: 32 })
  environment: string;

  @Column({ name: 'client_type', type: 'varchar', length: 16, default: 'WEB' })
  clientType: string;

  @Column({ name: 'authentication_mode', type: 'varchar', length: 24 })
  authenticationMode: string;

  @Column({ type: 'varchar', length: 24, default: 'PENDING' })
  status: ClientStatus;

  /** (added) ADMIN | MUMIN. A client without a realm is rejected. */
  @Column({ name: 'auth_realm', type: 'varchar', length: 16, nullable: true })
  authRealm: AuthRealm | null;

  /** (added) Defaults to client_secret_basic when empty; must be enabled in CLIENT_AUTH_METHODS. */
  @Column({ name: 'token_endpoint_auth_method', type: 'varchar', length: 40, nullable: true })
  tokenEndpointAuthMethod: TokenEndpointAuthMethod | null;

  /** (added) For private_key_jwt: the BU public keys, by URI or inline. */
  @Column({ name: 'client_jwks_uri', type: 'text', nullable: true })
  clientJwksUri: string | null;

  /** (added) */
  @Column({ name: 'client_jwks', type: 'jsonb', nullable: true })
  clientJwks: { keys: Record<string, unknown>[] } | null;

  /** (added) For client_secret_*: AES-GCM encrypted with DATA_ENCRYPTION_KEY. Never returned. */
  @Column({ name: 'client_secret_enc', type: 'text', nullable: true })
  clientSecretEnc: string | null;

  /** (added) Space separated scopes this client may request, e.g. "openid profile". */
  @Column({ name: 'allowed_scopes', type: 'varchar', length: 255, nullable: true })
  allowedScopes: string | null;

  /** (added) Default acr when the request has none, e.g. urn:miqaat:aal:2 for an MFA-only app. */
  @Column({ name: 'default_acr', type: 'varchar', length: 64, nullable: true })
  defaultAcr: string | null;

  /** (added) Where this client receives handoff assertions (POST, exact URI). */
  @Column({ name: 'handoff_callback_uri', type: 'text', nullable: true })
  handoffCallbackUri: string | null;

  /** (added) May receive handoffs from other apps of its realm. */
  @Column({ name: 'handoff_inbound_enabled', type: 'boolean', default: false })
  handoffInboundEnabled: boolean;

  /** (added) May start handoffs to other apps of its realm. */
  @Column({ name: 'handoff_outbound_enabled', type: 'boolean', default: false })
  handoffOutboundEnabled: boolean;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  @OneToMany(() => AuthClientCallback, (c) => c.client)
  callbacks: AuthClientCallback[];
}
