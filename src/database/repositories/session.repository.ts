import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { type Repository } from 'typeorm';
import { AuthSession, AuthSessionClient, type AuthRealm, type MfaMethod } from '../entities';

export interface NewSession {
  sid: string;
  itsId: string;
  authRealm: AuthRealm;
  sessionSecretHash: string;
  authTime: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
}

/** auth_sessions - durable copy of the Core realm session. */
@Injectable()
export class SessionRepository {
  constructor(@InjectRepository(AuthSession) private readonly sessions: Repository<AuthSession>) {}

  async insert(s: NewSession): Promise<void> {
    await this.sessions.insert({
      sid: s.sid,
      itsId: s.itsId,
      authMethod: 'PASSWORD',
      authRealm: s.authRealm,
      sessionSecretHash: s.sessionSecretHash,
      status: 'ACTIVE',
      aal: 1,
      amr: ['pwd'],
      authTime: s.authTime,
      expiresAt: s.expiresAt,
      absoluteExpiresAt: s.absoluteExpiresAt,
      lastSeenAt: s.authTime,
      ipAddress: s.ipAddress,
      userAgent: s.userAgent?.slice(0, 512) ?? null,
    });
  }

  /** Durable fallback when the Redis hot copy is missing. */
  findActiveBySecretHash(realm: AuthRealm, hash: string): Promise<AuthSession | null> {
    return this.sessions.findOne({ where: { sessionSecretHash: hash, authRealm: realm, status: 'ACTIVE' } });
  }

  async touch(sid: string, lastSeenAt: Date, expiresAt: Date): Promise<void> {
    await this.sessions.update({ sid }, { lastSeenAt, expiresAt, updatedAt: lastSeenAt });
  }

  async upgradeAssurance(sid: string, amr: string[], method: MfaMethod, at: Date, newSecretHash: string): Promise<void> {
    await this.sessions.update(
      { sid },
      { aal: 2, amr, mfaMethod: method, mfaVerifiedAt: at, sessionSecretHash: newSecretHash, updatedAt: at },
    );
  }

  /** Atomically revokes an ACTIVE session; false when it was already revoked (idempotent logout). */
  async revoke(sid: string, reason: string, at: Date): Promise<boolean> {
    const result = await this.sessions.update({ sid, status: 'ACTIVE' }, { status: 'REVOKED', revokedAt: at, revokeReason: reason, updatedAt: at });
    return (result.affected ?? 0) === 1;
  }

  findBySid(sid: string): Promise<AuthSession | null> {
    return this.sessions.findOne({ where: { sid } });
  }
}

/** auth_session_clients - which clients joined a Core session. */
@Injectable()
export class SessionParticipantRepository {
  constructor(@InjectRepository(AuthSessionClient) private readonly participants: Repository<AuthSessionClient>) {}

  async clientIds(sid: string): Promise<string[]> {
    return (await this.participants.find({ where: { sid }, select: { clientId: true } })).map((p) => p.clientId);
  }

  /** Insert, or bump the counters when the client already joined this session (one atomic statement). */
  async join(sid: string, clientId: string, establishedBy: 'LOGIN' | 'HANDOFF'): Promise<void> {
    await this.participants.query(
      `INSERT INTO auth_session_clients (sid, client_id, established_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (sid, client_id) DO UPDATE
         SET last_assertion_at = now(),
             assertion_count   = auth_session_clients.assertion_count + 1,
             updated_at        = now()`,
      [sid, clientId, establishedBy],
    );
  }
}
