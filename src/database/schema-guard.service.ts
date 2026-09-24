import { Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { DataSource } from 'typeorm';

/** Columns and tables that must exist before the service can run (created by the migration). */
const REQUIRED: Record<string, string[]> = {
  users: ['mumin_id', 'password', 'allow_login', 'is_otprequired', 'is_source_deleted'],
  mumin_master: ['mumin_id', 'status_id', 'email', 'fullname', 'is_source_deleted'],
  user_eligible: ['mumin_id', 'is_source_deleted'],
  auth_clients: ['client_id', 'status', 'auth_realm', 'token_endpoint_auth_method', 'client_secret_enc', 'default_acr', 'handoff_callback_uri', 'handoff_inbound_enabled', 'handoff_outbound_enabled'],
  auth_client_callbacks: ['client_ref', 'uri', 'uri_type'],
  auth_sessions: ['sid', 'auth_realm', 'session_secret_hash', 'status', 'aal', 'amr', 'mfa_verified_at', 'mfa_method'],
  auth_session_clients: ['sid', 'client_id', 'established_by'],
  auth_login_attempts: ['identifier_hash', 'attempt_type'],
  auth_audit_events: ['event_type', 'outcome'],
  signing_key_metadata: ['kid', 'status', 'public_jwk'],
  user_mfa_factors: ['its_id', 'method', 'destination_enc', 'totp_secret_enc'],
  auth_otp_challenges: ['its_id', 'sid', 'code_hash', 'consumed_at'],
  logout_jobs: ['sid', 'auth_realm', 'status'],
  logout_deliveries: ['job_id', 'client_id', 'jti', 'status', 'next_attempt_at'],
  auth_client_handoff_paths: ['client_id', 'path_pattern', 'enabled'],
  handoff_requests: ['source_client_id', 'target_client_id', 'requested_path', 'status', 'expires_at'],
};

/**
 * Fails start-up with one clear message when the schema is not ready, instead of letting the first
 * login fail with "column does not exist". It never changes the schema itself.
 */
@Injectable()
export class SchemaGuardService implements OnModuleInit {
  private readonly logger = new Logger(SchemaGuardService.name);

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async onModuleInit(): Promise<void> {
    const rows: { table_name: string; column_name: string }[] = await this.db.query(
      `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = current_schema()`,
    );
    const present = new Map<string, Set<string>>();
    for (const r of rows) {
      if (!present.has(r.table_name)) present.set(r.table_name, new Set());
      present.get(r.table_name)!.add(r.column_name);
    }
    const missing: string[] = [];
    for (const [table, columns] of Object.entries(REQUIRED)) {
      const cols = present.get(table);
      if (!cols) {
        missing.push(`table ${table}`);
        continue;
      }
      for (const c of columns) if (!cols.has(c)) missing.push(`${table}.${c}`);
    }
    if (missing.length) {
      throw new Error(`Database schema is not ready (${missing.join(', ')}). Run: npm run migration:run`);
    }
    this.logger.log('database schema verified');
  }
}
