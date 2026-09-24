import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Schema for oidc_mfa_auth on the EXISTING identity database.
 *
 * Rules this migration follows:
 *  - Synced tables (users, mumin_master, user_eligible) are never created, altered or written.
 *  - Existing auth tables are created only when missing (CREATE TABLE IF NOT EXISTS, same DDL as
 *    core-authentication), so a fresh database and the current one end up identical.
 *  - New fields are added with ADD COLUMN IF NOT EXISTS, all nullable or with a constant default,
 *    so rows written by core-authentication stay valid and no table rewrite happens.
 *  - No data is migrated, copied or back-filled.
 *
 * Every statement is idempotent: running it against a database that already has some or all of
 * these objects is safe.
 */
export class OidcMfaAuthSchema1790300000000 implements MigrationInterface {
  name = 'OidcMfaAuthSchema1790300000000';

  public async up(q: QueryRunner): Promise<void> {
    await this.assertSyncedTablesPresent(q);

    // ---- 1. Existing auth tables: create only if missing -----------------------------------
    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_clients (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_id           varchar(64)  NOT NULL UNIQUE CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
        name                varchar(255) NOT NULL,
        application_code    varchar(64)  NOT NULL,
        application_name    varchar(255) NOT NULL,
        business_unit       varchar(255),
        utility             varchar(255),
        environment         varchar(32)  NOT NULL,
        client_type         varchar(16)  NOT NULL DEFAULT 'WEB' CHECK (client_type IN ('WEB', 'SPA', 'MOBILE', 'SERVICE')),
        authentication_mode varchar(24)  NOT NULL CHECK (authentication_mode IN ('EMBEDDED', 'REDIRECT', 'EMBEDDED_OR_REDIRECT')),
        status              varchar(24)  NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'SECURITY_REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
        initiate_login_uri  varchar(2048),
        created_at          timestamptz  NOT NULL DEFAULT now(),
        updated_at          timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_client_callbacks (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_ref uuid NOT NULL REFERENCES auth_clients (id) ON DELETE CASCADE,
        uri        varchar(2048) NOT NULL CHECK (uri !~ '\\*'),
        uri_type   varchar(32)   NOT NULL CHECK (uri_type IN ('CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT')),
        is_primary boolean       NOT NULL DEFAULT false,
        created_at timestamptz   NOT NULL DEFAULT now(),
        CONSTRAINT uq_auth_client_callbacks_client_uri_type UNIQUE (client_ref, uri, uri_type)
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_auth_client_callbacks_client ON auth_client_callbacks (client_ref)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        sid                 varchar(64)  PRIMARY KEY,
        its_id              varchar(64)  NOT NULL,
        auth_method         varchar(32)  NOT NULL,
        created_at          timestamptz  NOT NULL DEFAULT now(),
        expires_at          timestamptz  NOT NULL,
        absolute_expires_at timestamptz  NOT NULL,
        last_seen_at        timestamptz,
        revoked_at          timestamptz,
        revoke_reason       varchar(64),
        ip_address          varchar(64),
        user_agent          varchar(512),
        updated_at          timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_its ON auth_sessions (its_id, created_at DESC)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_session_clients (
        id                 bigserial   PRIMARY KEY,
        sid                varchar(64) NOT NULL REFERENCES auth_sessions (sid) ON DELETE CASCADE,
        client_id          varchar(64) NOT NULL,
        first_assertion_at timestamptz NOT NULL DEFAULT now(),
        last_assertion_at  timestamptz NOT NULL DEFAULT now(),
        assertion_count    integer     NOT NULL DEFAULT 1,
        logout_status      varchar(16) CHECK (logout_status IN ('PENDING', 'SUCCEEDED', 'FAILED', 'NO_ENDPOINT')),
        logout_at          timestamptz,
        created_at         timestamptz NOT NULL DEFAULT now(),
        updated_at         timestamptz NOT NULL DEFAULT now(),
        CONSTRAINT uq_auth_session_clients_sid_client UNIQUE (sid, client_id)
      )`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_login_attempts (
        id              bigserial    PRIMARY KEY,
        identifier_hash char(64)     NOT NULL,
        its_id          varchar(64),
        client_id       varchar(64),
        ip_address      varchar(64),
        success         boolean      NOT NULL,
        failure_reason  varchar(64),
        correlation_id  varchar(128),
        created_at      timestamptz  NOT NULL DEFAULT now(),
        updated_at      timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_login_attempts_its ON auth_login_attempts (its_id, created_at DESC)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_audit_events (
        id             bigserial    PRIMARY KEY,
        event_type     varchar(64)  NOT NULL,
        outcome        varchar(16)  NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'INFO')),
        its_id         varchar(64),
        sid            varchar(64),
        client_id      varchar(64),
        jti            varchar(64),
        ip_address     varchar(64),
        user_agent     varchar(512),
        correlation_id varchar(128),
        metadata       jsonb,
        created_at     timestamptz  NOT NULL DEFAULT now(),
        updated_at     timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_auth_audit_its ON auth_audit_events (its_id, created_at DESC)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS signing_key_metadata (
        kid               varchar(128) PRIMARY KEY,
        alg               varchar(16)  NOT NULL,
        status            varchar(16)  NOT NULL CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRING', 'RETIRED')),
        jwk_thumbprint    varchar(64),
        first_seen_at     timestamptz  NOT NULL DEFAULT now(),
        status_changed_at timestamptz  NOT NULL DEFAULT now(),
        created_at        timestamptz  NOT NULL DEFAULT now(),
        updated_at        timestamptz  NOT NULL DEFAULT now()
      )`);

    // ---- 2. New fields on existing tables ---------------------------------------------------
    await q.query(`
      ALTER TABLE auth_clients
        ADD COLUMN IF NOT EXISTS auth_realm                 varchar(16) CHECK (auth_realm IN ('ADMIN', 'MUMIN')),
        ADD COLUMN IF NOT EXISTS token_endpoint_auth_method varchar(40)
          CHECK (token_endpoint_auth_method IN ('private_key_jwt', 'client_secret_basic', 'client_secret_post')),
        ADD COLUMN IF NOT EXISTS client_jwks_uri            text,
        ADD COLUMN IF NOT EXISTS client_jwks                jsonb,
        ADD COLUMN IF NOT EXISTS client_secret_enc          text,
        ADD COLUMN IF NOT EXISTS allowed_scopes             varchar(255),
        ADD COLUMN IF NOT EXISTS default_acr                varchar(64)`);

    await q.query(`
      ALTER TABLE auth_sessions
        ADD COLUMN IF NOT EXISTS auth_realm          varchar(16) CHECK (auth_realm IN ('ADMIN', 'MUMIN')),
        ADD COLUMN IF NOT EXISTS session_secret_hash varchar(64),
        ADD COLUMN IF NOT EXISTS status              varchar(16) CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
        ADD COLUMN IF NOT EXISTS aal                 smallint CHECK (aal IN (1, 2)),
        ADD COLUMN IF NOT EXISTS amr                 jsonb,
        ADD COLUMN IF NOT EXISTS auth_time           timestamptz,
        ADD COLUMN IF NOT EXISTS mfa_verified_at     timestamptz,
        ADD COLUMN IF NOT EXISTS mfa_method          varchar(16) CHECK (mfa_method IN ('EMAIL_OTP', 'SMS_OTP', 'TOTP'))`);
    await q.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_sessions_secret_hash
        ON auth_sessions (session_secret_hash) WHERE session_secret_hash IS NOT NULL`);
    await q.query(`
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_its_realm_status
        ON auth_sessions (its_id, auth_realm, status)`);

    await q.query(`
      ALTER TABLE auth_session_clients
        ADD COLUMN IF NOT EXISTS established_by varchar(16) CHECK (established_by IN ('LOGIN', 'HANDOFF'))`);

    await q.query(`
      ALTER TABLE auth_login_attempts
        ADD COLUMN IF NOT EXISTS attempt_type varchar(16) CHECK (attempt_type IN ('LOGIN', 'MFA'))`);

    await q.query(`
      ALTER TABLE signing_key_metadata
        ADD COLUMN IF NOT EXISTS public_jwk       jsonb,
        ADD COLUMN IF NOT EXISTS key_provider_ref text,
        ADD COLUMN IF NOT EXISTS purpose          varchar(40),
        ADD COLUMN IF NOT EXISTS environment      varchar(32),
        ADD COLUMN IF NOT EXISTS activated_at     timestamptz,
        ADD COLUMN IF NOT EXISTS revoked_at       timestamptz`);

    // ---- 3. New tables -----------------------------------------------------------------------
    await q.query(`
      CREATE TABLE IF NOT EXISTS user_mfa_factors (
        id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        its_id          varchar(64)  NOT NULL,
        method          varchar(16)  NOT NULL CHECK (method IN ('EMAIL_OTP', 'SMS_OTP', 'TOTP')),
        is_default      boolean      NOT NULL DEFAULT false,
        destination_enc text,
        totp_secret_enc text,
        last_used_step  bigint,
        status          varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED')),
        verified_at     timestamptz,
        last_used_at    timestamptz,
        created_at      timestamptz  NOT NULL DEFAULT now(),
        updated_at      timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT ck_user_mfa_factors_payload CHECK (
          (method = 'TOTP' AND totp_secret_enc IS NOT NULL) OR (method <> 'TOTP' AND destination_enc IS NOT NULL)
        )
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_user_mfa_factors_its ON user_mfa_factors (its_id, status)`);
    await q.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS uq_user_mfa_factors_one_default
        ON user_mfa_factors (its_id) WHERE is_default AND status = 'ACTIVE'`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_otp_challenges (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        its_id              varchar(64)  NOT NULL,
        sid                 varchar(64)  NOT NULL,
        interaction_uid     varchar(64)  NOT NULL,
        channel             varchar(8)   NOT NULL CHECK (channel IN ('EMAIL', 'SMS')),
        purpose             varchar(16)  NOT NULL CHECK (purpose IN ('LOGIN_MFA', 'STEP_UP')),
        destination_masked  varchar(255) NOT NULL,
        code_hash           char(64)     NOT NULL,
        attempt_count       integer      NOT NULL DEFAULT 0,
        max_attempts        integer      NOT NULL CHECK (max_attempts > 0),
        expires_at          timestamptz  NOT NULL,
        consumed_at         timestamptz,
        provider_message_id varchar(255),
        created_at          timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_auth_otp_challenges_its ON auth_otp_challenges (its_id, created_at DESC)`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_auth_otp_challenges_sid ON auth_otp_challenges (sid, interaction_uid)`);
  }

  /**
   * Removes only what this migration ADDED: the two new tables and the new columns.
   * Pre-existing auth tables are never dropped, because they may predate this service.
   */
  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE IF EXISTS auth_otp_challenges`);
    await q.query(`DROP TABLE IF EXISTS user_mfa_factors`);
    await q.query(`DROP INDEX IF EXISTS idx_auth_sessions_its_realm_status`);
    await q.query(`DROP INDEX IF EXISTS uq_auth_sessions_secret_hash`);
    await q.query(`
      ALTER TABLE signing_key_metadata
        DROP COLUMN IF EXISTS revoked_at, DROP COLUMN IF EXISTS activated_at, DROP COLUMN IF EXISTS environment,
        DROP COLUMN IF EXISTS purpose, DROP COLUMN IF EXISTS key_provider_ref, DROP COLUMN IF EXISTS public_jwk`);
    await q.query(`ALTER TABLE auth_login_attempts DROP COLUMN IF EXISTS attempt_type`);
    await q.query(`ALTER TABLE auth_session_clients DROP COLUMN IF EXISTS established_by`);
    await q.query(`
      ALTER TABLE auth_sessions
        DROP COLUMN IF EXISTS mfa_method, DROP COLUMN IF EXISTS mfa_verified_at, DROP COLUMN IF EXISTS auth_time,
        DROP COLUMN IF EXISTS amr, DROP COLUMN IF EXISTS aal, DROP COLUMN IF EXISTS status,
        DROP COLUMN IF EXISTS session_secret_hash, DROP COLUMN IF EXISTS auth_realm`);
    await q.query(`
      ALTER TABLE auth_clients
        DROP COLUMN IF EXISTS default_acr, DROP COLUMN IF EXISTS allowed_scopes, DROP COLUMN IF EXISTS client_secret_enc,
        DROP COLUMN IF EXISTS client_jwks, DROP COLUMN IF EXISTS client_jwks_uri,
        DROP COLUMN IF EXISTS token_endpoint_auth_method, DROP COLUMN IF EXISTS auth_realm`);
  }

  /** A missing synced table means DB_* points at the wrong database: refuse to create anything there. */
  private async assertSyncedTablesPresent(q: QueryRunner): Promise<void> {
    const rows: { table_name: string }[] = await q.query(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name IN ('users', 'mumin_master', 'user_eligible')`,
    );
    const found = new Set(rows.map((r) => r.table_name));
    const missing = ['users', 'mumin_master', 'user_eligible'].filter((t) => !found.has(t));
    if (missing.length) {
      throw new Error(`Synced identity tables missing in schema "${await this.schema(q)}": ${missing.join(', ')}. Is DB_* pointing at the identity database?`);
    }
  }

  private async schema(q: QueryRunner): Promise<string> {
    const [{ current_schema }] = await q.query(`SELECT current_schema()`);
    return current_schema;
  }
}
