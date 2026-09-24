import { Injectable } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import type { DataSource, Repository } from 'typeorm';
import { AuthClient, HandoffPath, HandoffRequest, type AuthRealm } from '../entities';

/** auth_client_handoff_paths, handoff_requests and the handoff fields of auth_clients. */
@Injectable()
export class HandoffRepository {
  constructor(
    @InjectRepository(HandoffPath) private readonly paths: Repository<HandoffPath>,
    @InjectRepository(HandoffRequest) private readonly requests: Repository<HandoffRequest>,
    @InjectDataSource() private readonly db: DataSource,
  ) {}

  async enabledPatterns(clientId: string): Promise<string[]> {
    return (await this.paths.find({ where: { clientId, enabled: true } })).map((p) => p.pathPattern);
  }

  create(input: { sourceClientId: string; targetClientId: string; realm: AuthRealm; requestedPath: string; ttlSeconds: number }): Promise<HandoffRequest> {
    return this.requests.save(
      this.requests.create({
        sourceClientId: input.sourceClientId,
        targetClientId: input.targetClientId,
        authRealm: input.realm,
        requestedPath: input.requestedPath,
        status: 'PENDING',
        expiresAt: new Date(Date.now() + input.ttlSeconds * 1000),
      }),
    );
  }

  /** The request if it is still PENDING and not expired; an expired one is marked EXPIRED on the way. */
  async findPending(id: string): Promise<HandoffRequest | null> {
    const request = await this.requests.findOne({ where: { id } });
    if (!request || request.status !== 'PENDING') return null;
    if (request.expiresAt.getTime() <= Date.now()) {
      await this.requests.update({ id, status: 'PENDING' }, { status: 'EXPIRED' });
      return null;
    }
    return request;
  }

  /** Binds the Core identity and completes the request. Atomic: only the first caller wins. */
  async complete(id: string, itsId: string, sid: string, jti: string): Promise<boolean> {
    const rows: unknown[] = await this.db.query(
      `UPDATE handoff_requests SET status = 'COMPLETED', its_id = $2, sid = $3, jti = $4, completed_at = now()
        WHERE id = $1 AND status = 'PENDING' AND expires_at > now() RETURNING id`,
      [id, itsId, sid, jti],
    );
    const list = Array.isArray(rows[0]) ? (rows[0] as unknown[]) : rows;
    return list.length === 1;
  }

  async cancel(id: string): Promise<void> {
    await this.requests.update({ id, status: 'PENDING' }, { status: 'CANCELLED' });
  }

  /** Registration tooling: handoff settings and allowed paths of a client (replaces the path list). */
  async configure(clientId: string, cfg: { callbackUri: string | null; inbound: boolean; outbound: boolean; patterns: string[] }): Promise<void> {
    await this.db.transaction(async (m) => {
      const updated = await m.getRepository(AuthClient).update(
        { clientId },
        { handoffCallbackUri: cfg.callbackUri, handoffInboundEnabled: cfg.inbound, handoffOutboundEnabled: cfg.outbound },
      );
      if (!updated.affected) throw new Error(`unknown client ${clientId}`);
      const repo = m.getRepository(HandoffPath);
      await repo.delete({ clientId });
      for (const pathPattern of cfg.patterns) await repo.save(repo.create({ clientId, pathPattern, enabled: true }));
    });
  }
}
