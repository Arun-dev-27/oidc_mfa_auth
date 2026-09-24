import type { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Realm-wide logout (spec §26.8 / §30): a durable logout job per revoked Core session and one delivery
 * row per participating client, worked by the back-channel delivery worker with retries.
 * New tables only; nothing existing is altered and no data is migrated.
 */
export class LogoutDelivery1790400000000 implements MigrationInterface {
  name = 'LogoutDelivery1790400000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE IF NOT EXISTS logout_jobs (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        sid                 varchar(64)  NOT NULL,
        its_id              varchar(64)  NOT NULL,
        auth_realm          varchar(16)  NOT NULL CHECK (auth_realm IN ('ADMIN', 'MUMIN')),
        reason              varchar(64)  NOT NULL,
        initiated_by_client varchar(64),
        status              varchar(24)  NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'COMPLETED', 'COMPLETED_WITH_FAILURES')),
        created_at          timestamptz  NOT NULL DEFAULT now(),
        completed_at        timestamptz
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_logout_jobs_sid ON logout_jobs (sid)`);

    await q.query(`
      CREATE TABLE IF NOT EXISTS logout_deliveries (
        job_id           uuid         NOT NULL REFERENCES logout_jobs (id) ON DELETE CASCADE,
        client_id        varchar(64)  NOT NULL,
        jti              uuid         NOT NULL DEFAULT gen_random_uuid(),
        status           varchar(16)  NOT NULL DEFAULT 'PENDING'
                           CHECK (status IN ('PENDING', 'RETRY', 'SUCCEEDED', 'FAILED', 'NO_ENDPOINT', 'DEAD')),
        attempt_count    integer      NOT NULL DEFAULT 0,
        next_attempt_at  timestamptz  NOT NULL DEFAULT now(),
        last_attempt_at  timestamptz,
        last_http_status integer,
        last_error_code  varchar(80),
        completed_at     timestamptz,
        created_at       timestamptz  NOT NULL DEFAULT now(),
        PRIMARY KEY (job_id, client_id)
      )`);
    await q.query(`CREATE INDEX IF NOT EXISTS idx_logout_deliveries_due ON logout_deliveries (next_attempt_at) WHERE status IN ('PENDING', 'RETRY')`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE IF EXISTS logout_deliveries`);
    await q.query(`DROP TABLE IF EXISTS logout_jobs`);
  }
}
