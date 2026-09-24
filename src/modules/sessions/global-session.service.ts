import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type Redis from 'ioredis';
import { randomUUID } from 'node:crypto';
import { AppConfig } from '../../config/config.module';
import { randomToken, sha256Hex } from '../../common/crypto.util';
import type { RequestMeta } from '../../common/request-meta';
import type { AuthRealm, MfaMethod } from '../../database/entities';
import { SessionRepository } from '../../database/repositories/session.repository';
import { InjectRedis } from '../../redis/redis.module';

/** The Core global session of ONE realm. Stored server side; the browser only holds an opaque secret. */
export interface RealmSession {
  sid: string;
  itsId: string;
  realm: AuthRealm;
  aal: 1 | 2;
  amr: string[];
  /** epoch ms */
  authTime: number;
  mfaVerifiedAt: number | null;
  mfaMethod: MfaMethod | null;
  idleExpiresAt: number;
  absoluteExpiresAt: number;
}

interface Loaded {
  session: RealmSession;
  secretHash: string;
}

/**
 * Core realm sessions (spec §6-7):
 *  - one cookie and one server-side session per realm (ADMIN / MUMIN), never shared;
 *  - the cookie value is a random secret; only its SHA-256 is stored;
 *  - hot copy in Redis (sso:<realm>:<hash>), durable row in auth_sessions;
 *  - the cookie is rotated after login and after MFA (session fixation protection).
 */
@Injectable()
export class GlobalSessionService {
  constructor(
    @InjectRedis() private readonly redis: Redis,
    private readonly sessions: SessionRepository,
    private readonly config: AppConfig,
  ) {}

  cookieName(realm: AuthRealm): string {
    return realm === 'ADMIN' ? this.config.env.SSO_COOKIE_ADMIN : this.config.env.SSO_COOKIE_MUMIN;
  }

  /** The valid session of this realm for this browser, or null. Only this realm's cookie is read. */
  async read(realm: AuthRealm, req: FastifyRequest): Promise<RealmSession | null> {
    const loaded = await this.load(realm, req);
    return loaded?.session ?? null;
  }

  async create(realm: AuthRealm, itsId: string, meta: RequestMeta, reply: FastifyReply): Promise<RealmSession> {
    const env = this.config.env;
    const now = Date.now();
    const secret = randomToken(32);
    const secretHash = sha256Hex(secret);
    const session: RealmSession = {
      sid: randomUUID(),
      itsId,
      realm,
      aal: 1,
      amr: ['pwd'],
      authTime: now,
      mfaVerifiedAt: null,
      mfaMethod: null,
      idleExpiresAt: now + env.SESSION_IDLE_TTL_SECONDS * 1000,
      absoluteExpiresAt: now + env.SESSION_ABSOLUTE_TTL_SECONDS * 1000,
    };
    await this.sessions.insert({
      sid: session.sid,
      itsId,
      authRealm: realm,
      sessionSecretHash: secretHash,
      authTime: new Date(now),
      expiresAt: new Date(session.idleExpiresAt),
      absoluteExpiresAt: new Date(session.absoluteExpiresAt),
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
    });
    await this.writeHot(secretHash, session);
    this.setCookie(reply, realm, secret, session);
    return session;
  }

  /** Slides the idle expiry (never past the absolute expiry). */
  async touch(realm: AuthRealm, req: FastifyRequest): Promise<void> {
    const loaded = await this.load(realm, req);
    if (!loaded) return;
    const now = Date.now();
    const s = loaded.session;
    s.idleExpiresAt = Math.min(now + this.config.env.SESSION_IDLE_TTL_SECONDS * 1000, s.absoluteExpiresAt);
    await this.writeHot(loaded.secretHash, s);
    await this.sessions.touch(s.sid, new Date(now), new Date(s.idleExpiresAt));
  }

  /**
   * After a successful second factor: AAL2 on the SAME session, new amr and MFA time, and a new
   * cookie secret (the old one stops working immediately).
   */
  async upgradeToAal2(session: RealmSession, method: MfaMethod, req: FastifyRequest, reply: FastifyReply): Promise<RealmSession> {
    const loaded = await this.load(session.realm, req);
    if (!loaded || loaded.session.sid !== session.sid) throw new Error('session changed during MFA');
    const now = Date.now();
    const upgraded: RealmSession = {
      ...loaded.session,
      aal: 2,
      amr: ['pwd', 'otp'],
      mfaVerifiedAt: now,
      mfaMethod: method,
    };
    const secret = randomToken(32);
    const secretHash = sha256Hex(secret);
    await this.sessions.upgradeAssurance(upgraded.sid, upgraded.amr, method, new Date(now), secretHash);
    await this.redis.del(this.hotKey(session.realm, loaded.secretHash));
    await this.writeHot(secretHash, upgraded);
    this.setCookie(reply, session.realm, secret, upgraded);
    return upgraded;
  }

  /**
   * Ends this browser's realm session: server-side revocation first (DB + Redis hot copy), then the
   * cookie is cleared. Returns the session that was revoked, or null when there was none.
   */
  async revoke(realm: AuthRealm, req: FastifyRequest, reply: FastifyReply, reason: string): Promise<RealmSession | null> {
    const loaded = await this.load(realm, req);
    if (loaded) {
      await this.redis.del(this.hotKey(realm, loaded.secretHash));
      await this.sessions.revoke(loaded.session.sid, reason, new Date());
    }
    reply.clearCookie(this.cookieName(realm), { path: '/' });
    return loaded?.session ?? null;
  }

  private async load(realm: AuthRealm, req: FastifyRequest): Promise<Loaded | null> {
    const secret = req.cookies[this.cookieName(realm)];
    if (!secret || secret.length < 32 || secret.length > 128) return null;
    const secretHash = sha256Hex(secret);

    let session: RealmSession | null = null;
    const hot = await this.redis.get(this.hotKey(realm, secretHash));
    if (hot) {
      session = JSON.parse(hot) as RealmSession;
    } else {
      // Durable fallback (e.g. Redis was flushed): rebuild the hot copy from auth_sessions.
      const row = await this.sessions.findActiveBySecretHash(realm, secretHash);
      if (row && row.authRealm) {
        session = {
          sid: row.sid,
          itsId: row.itsId,
          realm: row.authRealm,
          aal: row.aal === 2 ? 2 : 1,
          amr: row.amr ?? ['pwd'],
          authTime: (row.authTime ?? row.createdAt).getTime(),
          mfaVerifiedAt: row.mfaVerifiedAt?.getTime() ?? null,
          mfaMethod: row.mfaMethod,
          idleExpiresAt: row.expiresAt.getTime(),
          absoluteExpiresAt: row.absoluteExpiresAt.getTime(),
        };
      }
    }
    if (!session || session.realm !== realm) return null;
    const now = Date.now();
    if (now >= session.idleExpiresAt || now >= session.absoluteExpiresAt) return null;
    if (!hot) await this.writeHot(secretHash, session);
    return { session, secretHash };
  }

  private hotKey(realm: AuthRealm, secretHash: string): string {
    return `sso:${realm}:${secretHash}`;
  }

  private async writeHot(secretHash: string, s: RealmSession): Promise<void> {
    const ttl = Math.ceil((Math.min(s.idleExpiresAt, s.absoluteExpiresAt) - Date.now()) / 1000);
    if (ttl <= 0) return;
    await this.redis.set(this.hotKey(s.realm, secretHash), JSON.stringify(s), 'EX', ttl);
  }

  private setCookie(reply: FastifyReply, realm: AuthRealm, secret: string, s: RealmSession): void {
    reply.setCookie(this.cookieName(realm), secret, {
      httpOnly: true,
      secure: this.config.env.COOKIE_SECURE,
      sameSite: 'lax',
      path: '/',
      // Browser keeps it until the absolute expiry; the server enforces idle expiry itself.
      expires: new Date(s.absoluteExpiresAt),
    });
  }
}
