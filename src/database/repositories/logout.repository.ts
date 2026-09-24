import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { DataSource } from 'typeorm';
import type { AuthRealm, LogoutDeliveryStatus } from '../entities';

export interface DueDelivery {
  jobId: string;
  clientId: string;
  jti: string;
  attemptCount: number;
  sid: string;
  itsId: string;
  authRealm: AuthRealm;
  reason: string;
  jobCreatedAt: Date;
}

/**
 * logout_jobs + logout_deliveries: a durable queue in PostgreSQL (spec §30).
 * Claiming uses FOR UPDATE SKIP LOCKED plus a lease on next_attempt_at, so several service instances
 * can run the worker without sending the same message twice, and a crash mid-send is retried.
 */
@Injectable()
export class LogoutRepository {
  constructor(@InjectDataSource() private readonly db: DataSource) {}

  /** One job for the revoked session and one delivery per participating client, in one transaction. */
  async createJob(input: { sid: string; itsId: string; realm: AuthRealm; reason: string; initiatedByClient: string | null; clientIds: string[] }): Promise<string> {
    return this.db.transaction(async (m) => {
      const [{ id }] = await m.query(
        `INSERT INTO logout_jobs (sid, its_id, auth_realm, reason, initiated_by_client, status, completed_at)
         VALUES ($1, $2, $3, $4, $5, $6::varchar, CASE WHEN $6::varchar = 'COMPLETED' THEN now() END) RETURNING id`,
        [input.sid, input.itsId, input.realm, input.reason, input.initiatedByClient, input.clientIds.length ? 'PENDING' : 'COMPLETED'],
      );
      for (const clientId of input.clientIds) {
        await m.query(`INSERT INTO logout_deliveries (job_id, client_id) VALUES ($1, $2)`, [id, clientId]);
      }
      if (input.clientIds.length) {
        await m.query(`UPDATE auth_session_clients SET logout_status = 'PENDING', updated_at = now() WHERE sid = $1`, [input.sid]);
      }
      return id as string;
    });
  }

  /** Claims up to `limit` due deliveries and leases them for `leaseSeconds`. */
  async claimDue(limit: number, leaseSeconds: number): Promise<DueDelivery[]> {
    const rows: Record<string, unknown>[] = await this.db.query(
      `WITH due AS (
         SELECT job_id, client_id FROM logout_deliveries
          WHERE status IN ('PENDING', 'RETRY') AND next_attempt_at <= now()
          ORDER BY next_attempt_at
          LIMIT $1
          FOR UPDATE SKIP LOCKED
       )
       UPDATE logout_deliveries d
          SET next_attempt_at = now() + make_interval(secs => $2::int), attempt_count = d.attempt_count + 1, last_attempt_at = now()
         FROM due, logout_jobs j
        WHERE d.job_id = due.job_id AND d.client_id = due.client_id AND j.id = d.job_id
       RETURNING d.job_id, d.client_id, d.jti, d.attempt_count, j.sid, j.its_id, j.auth_realm, j.reason, j.created_at`,
      [limit, leaseSeconds],
    );
    const list = (Array.isArray(rows[0]) ? rows[0] : rows) as Record<string, unknown>[];
    return list.map((r) => ({
      jobId: r.job_id as string,
      clientId: r.client_id as string,
      jti: r.jti as string,
      attemptCount: Number(r.attempt_count),
      sid: r.sid as string,
      itsId: r.its_id as string,
      authRealm: r.auth_realm as AuthRealm,
      reason: r.reason as string,
      jobCreatedAt: new Date(r.created_at as string),
    }));
  }

  /** Records the outcome; finished deliveries also update auth_session_clients and may complete the job. */
  async record(
    d: DueDelivery,
    outcome: { status: LogoutDeliveryStatus; httpStatus: number | null; errorCode: string | null; retryInSeconds?: number },
  ): Promise<void> {
    const final = outcome.status !== 'RETRY';
    await this.db.query(
      `UPDATE logout_deliveries
          SET status = $3::varchar, last_http_status = $4::int, last_error_code = $5::varchar,
              next_attempt_at = CASE WHEN $3::varchar = 'RETRY' THEN now() + make_interval(secs => $6::int) ELSE next_attempt_at END,
              completed_at = CASE WHEN $3::varchar = 'RETRY' THEN NULL ELSE now() END
        WHERE job_id = $1 AND client_id = $2`,
      [d.jobId, d.clientId, outcome.status, outcome.httpStatus, outcome.errorCode, outcome.retryInSeconds ?? 0],
    );
    if (!final) return;
    const sessionStatus = outcome.status === 'SUCCEEDED' ? 'SUCCEEDED' : outcome.status === 'NO_ENDPOINT' ? 'NO_ENDPOINT' : 'FAILED';
    await this.db.query(
      `UPDATE auth_session_clients SET logout_status = $3, logout_at = now(), updated_at = now() WHERE sid = $1 AND client_id = $2`,
      [d.sid, d.clientId, sessionStatus],
    );
    await this.db.query(
      `UPDATE logout_jobs j
          SET status = CASE WHEN EXISTS (SELECT 1 FROM logout_deliveries x WHERE x.job_id = j.id AND x.status IN ('FAILED', 'DEAD'))
                            THEN 'COMPLETED_WITH_FAILURES' ELSE 'COMPLETED' END,
              completed_at = now()
        WHERE j.id = $1 AND j.status = 'PENDING'
          AND NOT EXISTS (SELECT 1 FROM logout_deliveries x WHERE x.job_id = j.id AND x.status IN ('PENDING', 'RETRY'))`,
      [d.jobId],
    );
  }
}
