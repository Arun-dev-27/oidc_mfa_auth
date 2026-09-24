import { Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { AppConfig } from '../../config/config.module';
import type { LogoutDeliveryStatus } from '../../database/entities';
import { ClientRepository } from '../../database/repositories/client.repository';
import { LogoutRepository, type DueDelivery } from '../../database/repositories/logout.repository';
import { AuditService } from '../audit/audit.service';
import { SigningKeyService } from '../keys/signing-key.service';

/** Seconds a claimed delivery is leased before another worker may retry it (> HTTP timeout). */
const LEASE_SECONDS = 60;
const BATCH = 20;
const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/**
 * Back-channel logout delivery (spec §28-30). Works the logout_deliveries queue:
 *   - builds a signed logout JWS per client (typ miqaat-logout+jwt, 120 s, stable jti per delivery)
 *   - POSTs it as `logout_token` (form) to the client's registered BACK_CHANNEL_LOGOUT URI
 *   - 2xx -> SUCCEEDED; 4xx (except 408/429) -> FAILED, no retry (configuration / validation problem);
 *     5xx, 408, 429, timeout, network error -> RETRY on LOGOUT_RETRY_SCHEDULE_SECONDS, then DEAD
 *     (dead letter); no registered URI -> NO_ENDPOINT
 *   - every outcome is audited. A failed delivery never restores the Core session: it is already revoked.
 */
@Injectable()
export class LogoutDeliveryWorker implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger('LogoutDelivery');
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private again = false;

  constructor(
    private readonly config: AppConfig,
    private readonly logouts: LogoutRepository,
    private readonly clients: ClientRepository,
    private readonly keys: SigningKeyService,
    private readonly audit: AuditService,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.config.env.LOGOUT_WORKER_ENABLED) return;
    this.timer = setInterval(() => void this.tick(), this.config.env.LOGOUT_WORKER_INTERVAL_MS);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** Run a pass now (called right after a logout, so delivery is immediate). */
  kick(): void {
    if (this.config.env.LOGOUT_WORKER_ENABLED) setImmediate(() => void this.tick());
  }

  async tick(): Promise<void> {
    if (this.running) {
      this.again = true;
      return;
    }
    this.running = true;
    try {
      do {
        this.again = false;
        const due = await this.logouts.claimDue(BATCH, LEASE_SECONDS);
        await Promise.all(due.map((d) => this.deliver(d)));
        if (due.length === BATCH) this.again = true;
      } while (this.again);
    } catch (error) {
      this.logger.error(`delivery pass failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      this.running = false;
    }
  }

  private async deliver(d: DueDelivery): Promise<void> {
    const env = this.config.env;
    const client = await this.clients.findByClientId(d.clientId);
    const uri = client?.callbacks.find((c) => c.uriType === 'BACK_CHANNEL_LOGOUT')?.uri;
    if (!uri) return this.finish(d, 'NO_ENDPOINT', null, 'NO_BACKCHANNEL_URI');
    if (this.config.isProduction && !uri.startsWith('https://')) return this.finish(d, 'FAILED', null, 'INSECURE_ENDPOINT');

    const now = Math.floor(Date.now() / 1000);
    let status: number | null = null;
    let errorCode: string | null = null;
    try {
      const token = await this.keys.signJws(
        {
          iss: env.ISSUER,
          aud: d.clientId,
          sub: d.itsId,
          sid: d.sid,
          auth_realm: d.authRealm,
          reason: d.reason,
          iat: now,
          exp: now + env.LOGOUT_TOKEN_TTL_SECONDS,
          jti: d.jti,
          events: { [BACKCHANNEL_EVENT]: {} },
        },
        'miqaat-logout+jwt',
      );
      const res = await fetch(uri, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({ logout_token: token }).toString(),
        redirect: 'manual',
        signal: AbortSignal.timeout(env.LOGOUT_HTTP_TIMEOUT_MS),
      });
      status = res.status;
      await res.arrayBuffer().catch(() => undefined);
      if (res.status >= 200 && res.status < 300) return this.finish(d, 'SUCCEEDED', status, null);
      errorCode = `HTTP_${res.status}`;
      if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) {
        return this.finish(d, 'FAILED', status, errorCode);
      }
    } catch (error) {
      errorCode = error instanceof Error && error.name === 'TimeoutError' ? 'TIMEOUT' : 'NETWORK_ERROR';
    }

    const schedule = env.LOGOUT_RETRY_SCHEDULE_SECONDS;
    if (d.attemptCount < schedule.length) {
      return this.finish(d, 'RETRY', status, errorCode, schedule[d.attemptCount]);
    }
    return this.finish(d, 'DEAD', status, errorCode);
  }

  private async finish(d: DueDelivery, outcome: LogoutDeliveryStatus, httpStatus: number | null, errorCode: string | null, retryInSeconds?: number) {
    await this.logouts.record(d, { status: outcome, httpStatus, errorCode, retryInSeconds });
    if (outcome === 'DEAD' || outcome === 'FAILED') {
      this.logger.warn(`back-channel logout to ${d.clientId} ${outcome} after ${d.attemptCount} attempt(s): ${errorCode}`);
    }
    await this.audit.record({
      eventType: `LOGOUT_DELIVERY_${outcome}`,
      outcome: outcome === 'SUCCEEDED' ? 'SUCCESS' : outcome === 'RETRY' || outcome === 'NO_ENDPOINT' ? 'INFO' : 'FAILURE',
      itsId: d.itsId,
      sid: d.sid,
      clientId: d.clientId,
      metadata: { attempt: d.attemptCount, httpStatus, errorCode, ...(retryInSeconds !== undefined ? { retryInSeconds } : {}) },
    });
  }
}
