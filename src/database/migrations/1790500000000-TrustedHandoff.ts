import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Trusted handoff (Handoff spec §23, Core spec §26.1 / §26.4).
 *  - auth_clients: where a target receives handoff assertions, and whether it may send / receive them
 *  - auth_client_handoff_paths: the target-relative paths a handoff may open (allowlist)
 *  - handoff_requests: one pending / completed transaction per handoff
 * New nullable columns / new tables only; nothing existing is changed and no data is migrated.
 */
export class TrustedHandoff1790500000000 implements MigrationInterface {
  name = 'TrustedHandoff1790500000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      ALTER TABLE auth_clients
        ADD COLUMN IF NOT EXISTS handoff_callback_uri     text,
        ADD COLUMN IF NOT EXISTS handoff_inbound_enabled  boolean NOT NULL DEFAULT false,
        ADD COLUMN IF NOT EXISTS handoff_outbound_enabled boolean NOT NULL DEFAULT false`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS auth_client_handoff_paths (
        id           bigserial    PRIMARY KEY,
        client_id    varchar(64)  NOT NULL REFERENCES auth_clients (client_id) ON DELETE CASCADE,
        path_pattern varchar(512) NOT NULL CHECK (path_pattern LIKE '/%' AND path_pattern NOT LIKE '//%' AND path_pattern !~ '[\\\\:]'),
        enabled      boolean      NOT NULL DEFAULT true,
        created_at   timestamptz  NOT NULL DEFAULT now(),
        CONSTRAINT uq_handoff_paths_client_pattern UNIQUE (client_id, path_pattern)
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_handoff_paths_client ON auth_client_handoff_paths (client_id, enabled)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS handoff_requests (
        id               uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
        source_client_id varchar(64)  NOT NULL,
        target_client_id varchar(64)  NOT NULL,
        auth_realm       varchar(16)  NOT NULL CHECK (auth_realm IN ('ADMIN', 'MUMIN')),
        requested_path   varchar(512) NOT NULL,
        status           varchar(20)  NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'COMPLETED', 'EXPIRED', 'CANCELLED')),
        its_id           varchar(64),
        sid              varchar(64),
        jti              uuid,
        created_at       timestamptz  NOT NULL DEFAULT now(),
        expires_at       timestamptz  NOT NULL,
        completed_at     timestamptz
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_handoff_pending_expiry ON handoff_requests (status, expires_at)`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE IF EXISTS handoff_requests`);
    await q.query(`DROP TABLE IF EXISTS auth_client_handoff_paths`);
    await q.query(`
      ALTER TABLE auth_clients
        DROP COLUMN IF EXISTS handoff_outbound_enabled, DROP COLUMN IF EXISTS handoff_inbound_enabled, DROP COLUMN IF EXISTS handoff_callback_uri`);
  }
}
