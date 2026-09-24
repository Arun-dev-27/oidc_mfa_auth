import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { AuthLoginAttempt, type AttemptType } from '../entities';

export interface NewAttempt {
  identifierHash: string;
  itsId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  success: boolean;
  failureReason: string | null;
  attemptType: AttemptType;
  correlationId?: string | null;
}

/** auth_login_attempts - durable record used for account lockout (password and MFA). */
@Injectable()
export class LoginAttemptRepository {
  constructor(@InjectRepository(AuthLoginAttempt) private readonly attempts: Repository<AuthLoginAttempt>) {}

  async record(a: NewAttempt): Promise<void> {
    await this.attempts.insert({ ...a, correlationId: a.correlationId ?? null });
  }

  /**
   * Failures with `reason` since the last success of the same type, inside the window.
   * A successful attempt resets the count.
   */
  async recentFailures(
    itsId: string,
    type: AttemptType,
    reason: string,
    windowSeconds: number,
  ): Promise<{ failures: number; secondsSinceLast: number | null }> {
    const [row] = await this.attempts.query(
      `WITH last_ok AS (
         SELECT max(created_at) AS at FROM auth_login_attempts
          WHERE its_id = $1 AND success AND COALESCE(attempt_type, 'LOGIN') = $2
       )
       SELECT count(*)::int AS failures,
              EXTRACT(EPOCH FROM (now() - max(created_at)))::int AS seconds_since_last
         FROM auth_login_attempts, last_ok
        WHERE its_id = $1
          AND NOT success
          AND COALESCE(attempt_type, 'LOGIN') = $2
          AND failure_reason = $3
          AND created_at > now() - make_interval(secs => $4)
          AND (last_ok.at IS NULL OR created_at > last_ok.at)`,
      [itsId, type, reason, windowSeconds],
    );
    return { failures: row?.failures ?? 0, secondsSinceLast: row?.seconds_since_last ?? null };
  }
}
