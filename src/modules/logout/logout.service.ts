import { Inject, Injectable, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type Redis from 'ioredis';
import { createLocalJWKSet, decodeJwt, jwtVerify, type JWTPayload } from 'jose';
import { AppConfig } from '../../config/config.module';
import { requestMeta } from '../../common/request-meta';
import { AUTH_REALMS, isAuthRealm, type AuthRealm } from '../../database/entities';
import { LogoutRepository } from '../../database/repositories/logout.repository';
import { SessionParticipantRepository } from '../../database/repositories/session.repository';
import { InjectRedis } from '../../redis/redis.module';
import { AuditService } from '../audit/audit.service';
import { SigningKeyService } from '../keys/signing-key.service';
import { ClientRegistryService } from '../oidc/client-registry.service';
import { grantContextKey, OIDC_PROVIDER, sessionGrantsKey, type OidcProvider } from '../oidc/oidc.constants';
import { CsrfService } from '../security/csrf.service';
import { GlobalSessionService, type RealmSession } from '../sessions/global-session.service';
import { ViewService } from '../views/view.service';
import { LogoutDeliveryWorker } from './logout-delivery.worker';

/** CSRF binding for the confirmation form (there is no interaction uid on logout). */
const CSRF_SCOPE = 'core-logout';

export interface LogoutParams {
  client_id?: string;
  post_logout_redirect_uri?: string;
  state?: string;
  id_token_hint?: string;
  csrf?: string;
}

interface LogoutContext {
  clientId: string;
  clientName: string;
  realm: AuthRealm;
  redirectUri: string | null;
  state: string | null;
  hint: JWTPayload | null;
}

type Resolved = { ok: true; ctx: LogoutContext } | { ok: false; status: number; code: string; message: string };

/**
 * Realm-wide logout (spec §24-26, BU spec §15):
 *   GET  /logout?client_id&post_logout_redirect_uri&state[&id_token_hint]
 *   POST /logout/confirm   (confirmation form, CSRF protected)
 *
 * The realm comes from the registered client. With a valid id_token_hint for the current realm
 * session, logout happens at once; otherwise the member confirms on a Core page (so another site cannot
 * sign people out). Processing order: revoke the realm session (DB + Redis) -> revoke every token
 * issued in it -> clear the realm cookie -> queue signed back-channel logout for every participating
 * client -> redirect to the exact registered post-logout URI. The other realm is never touched, and
 * delivery never blocks the browser.
 */
@Injectable()
export class LogoutService {
  private readonly logger = new Logger(LogoutService.name);

  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: OidcProvider,
    @InjectRedis() private readonly redis: Redis,
    private readonly config: AppConfig,
    private readonly clients: ClientRegistryService,
    private readonly sessions: GlobalSessionService,
    private readonly participants: SessionParticipantRepository,
    private readonly logouts: LogoutRepository,
    private readonly keys: SigningKeyService,
    private readonly worker: LogoutDeliveryWorker,
    private readonly csrf: CsrfService,
    private readonly audit: AuditService,
    private readonly views: ViewService,
  ) {}

  /** GET /logout */
  async start(req: FastifyRequest, reply: FastifyReply, raw: LogoutParams): Promise<void> {
    const params = withClientFromHint(raw);
    // No client at all (address bar, bookmark, /session/end): sign out of this browser's realm sessions
    // after a confirmation instead of failing with CLIENT_NOT_FOUND.
    if (!params.client_id) return this.startWithoutClient(req, reply);
    const resolved = await this.resolve(params);
    if (!resolved.ok) return this.error(reply, resolved);
    const { ctx } = resolved;

    const session = await this.sessions.read(ctx.realm, req);
    if (!session) {
      // Nothing to end: idempotent success (e.g. already logged out in another tab).
      reply.clearCookie(this.sessions.cookieName(ctx.realm), { path: '/' });
      return this.done(reply, ctx);
    }
    if (ctx.hint && ctx.hint.sid === session.sid) return this.perform(req, reply, ctx);

    return this.send(reply, 200, 'logout', {
      title: 'Sign out',
      realmLabel: realmLabel(ctx.realm),
      clientName: ctx.clientName,
      csrf: this.csrf.issue(req, reply, CSRF_SCOPE),
      clientId: ctx.clientId,
      redirectUri: ctx.redirectUri ?? '',
      state: ctx.state ?? '',
      cancelUrl: ctx.redirectUri ?? '',
    });
  }

  /** POST /logout/confirm */
  async confirm(req: FastifyRequest, reply: FastifyReply, form: LogoutParams): Promise<void> {
    if (!this.csrf.verify(req, CSRF_SCOPE, form.csrf)) {
      return this.error(reply, { status: 403, code: 'CSRF', message: 'This sign-out form expired. Go back to the application and sign out again.' });
    }
    if (!form.client_id) return this.performAll(req, reply);
    const resolved = await this.resolve({ ...form, id_token_hint: undefined });
    if (!resolved.ok) return this.error(reply, resolved);
    return this.perform(req, reply, resolved.ctx);
  }

  /** Realms this browser has an active Core session in. */
  private async activeRealms(req: FastifyRequest): Promise<AuthRealm[]> {
    const active: AuthRealm[] = [];
    for (const realm of AUTH_REALMS) if (await this.sessions.read(realm, req)) active.push(realm);
    return active;
  }

  /** GET /logout without a client: confirm, then end every realm session of this browser. */
  private async startWithoutClient(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const realms = await this.activeRealms(req);
    if (!realms.length) return this.send(reply, 200, 'logged-out', { title: 'Signed out', realmLabel: 'Miqaat' });
    return this.send(reply, 200, 'logout', {
      title: 'Sign out',
      realmLabel: realms.map(realmLabel).join(' and '),
      clientName: 'Miqaat',
      csrf: this.csrf.issue(req, reply, CSRF_SCOPE),
      clientId: '',
      redirectUri: '',
      state: '',
      cancelUrl: '',
    });
  }

  /** POST /logout/confirm without a client (CSRF already checked): same processing per realm. */
  private async performAll(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    const ended: AuthRealm[] = [];
    for (const realm of await this.activeRealms(req)) {
      const revoked = await this.sessions.revoke(realm, req, reply, 'USER_LOGOUT');
      if (!revoked) continue;
      ended.push(realm);
      try {
        await this.endSession(revoked, null, 'USER_LOGOUT', requestMeta(req));
      } catch (error) {
        this.logger.error(`logout follow-up failed for sid ${revoked.sid}: ${error instanceof Error ? error.message : String(error)}`);
        await this.audit.record({ eventType: 'LOGOUT_FOLLOWUP_FAILED', outcome: 'FAILURE', itsId: revoked.itsId, sid: revoked.sid, clientId: null });
      }
    }
    return this.send(reply, 200, 'logged-out', { title: 'Signed out', realmLabel: ended.length ? ended.map(realmLabel).join(' and ') : 'Miqaat' });
  }

  private async perform(req: FastifyRequest, reply: FastifyReply, ctx: LogoutContext): Promise<void> {
    const revoked = await this.sessions.revoke(ctx.realm, req, reply, 'USER_LOGOUT');
    if (revoked) {
      // Logout has succeeded once the Core session is revoked (spec §26); a failure in the follow-up
      // work is recorded but never turns the member's logout into an error.
      try {
        await this.endSession(revoked, ctx.clientId, 'USER_LOGOUT', requestMeta(req));
      } catch (error) {
        this.logger.error(`logout follow-up failed for sid ${revoked.sid}: ${error instanceof Error ? error.message : String(error)}`);
        await this.audit.record({ eventType: 'LOGOUT_FOLLOWUP_FAILED', outcome: 'FAILURE', itsId: revoked.itsId, sid: revoked.sid, clientId: ctx.clientId });
      }
    }
    return this.done(reply, ctx);
  }

  /**
   * Everything that follows a revoked realm session: its tokens, the participant notifications and
   * the audit record. Public so other revocation paths (e.g. an admin action) reuse it.
   */
  async endSession(session: RealmSession, initiatedBy: string | null, reason: string, meta?: { ip: string; userAgent: string | null }): Promise<void> {
    const grants = await this.revokeGrants(session.sid);
    const clientIds = await this.participants.clientIds(session.sid);
    const jobId = await this.logouts.createJob({ sid: session.sid, itsId: session.itsId, realm: session.realm, reason, initiatedByClient: initiatedBy, clientIds });
    await this.audit.record({
      eventType: 'LOGOUT',
      outcome: 'SUCCESS',
      itsId: session.itsId,
      sid: session.sid,
      clientId: initiatedBy,
      ipAddress: meta?.ip ?? null,
      userAgent: meta?.userAgent ?? null,
      metadata: { realm: session.realm, reason, participants: clientIds, grantsRevoked: grants, jobId },
    });
    this.worker.kick();
  }

  /** Every grant issued in the session, and every token of those grants, stops working. */
  private async revokeGrants(sid: string): Promise<number> {
    const grantIds = await this.redis.smembers(sessionGrantsKey(sid));
    for (const grantId of grantIds) {
      try {
        await this.provider.AccessToken.revokeByGrantId(grantId);
        await this.provider.AuthorizationCode.revokeByGrantId(grantId);
        const grant = await this.provider.Grant.find(grantId);
        if (grant) await grant.destroy();
      } catch (error) {
        this.logger.error(`grant ${grantId} revocation failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      await this.redis.del(grantContextKey(grantId));
    }
    await this.redis.del(sessionGrantsKey(sid));
    return grantIds.length;
  }

  private async resolve(params: LogoutParams): Promise<Resolved> {
    const clientId = typeof params.client_id === 'string' ? params.client_id : '';
    const metadata = clientId ? await this.clients.findMetadata(clientId) : undefined;
    const realm = metadata?.auth_realm;
    if (!metadata || !isAuthRealm(realm)) {
      return { ok: false, status: 400, code: 'CLIENT_NOT_FOUND', message: 'This application is not registered for sign-out.' };
    }
    const registered = Array.isArray(metadata.post_logout_redirect_uris) ? (metadata.post_logout_redirect_uris as string[]) : [];
    const redirectUri = typeof params.post_logout_redirect_uri === 'string' && params.post_logout_redirect_uri ? params.post_logout_redirect_uri : null;
    if (redirectUri && !registered.includes(redirectUri)) {
      return { ok: false, status: 400, code: 'POST_LOGOUT_URI_INVALID', message: 'The return address is not registered for this application.' };
    }
    const state = typeof params.state === 'string' && params.state ? params.state.slice(0, 512) : null;

    let hint: JWTPayload | null = null;
    if (typeof params.id_token_hint === 'string' && params.id_token_hint) {
      hint = await this.verifyHint(params.id_token_hint, clientId, realm);
      if (!hint) return { ok: false, status: 400, code: 'LOGOUT_HINT_INVALID', message: 'The sign-out request is not valid.' };
    }
    return { ok: true, ctx: { clientId, clientName: String(metadata.client_name ?? clientId), realm, redirectUri, state, hint } };
  }

  /**
   * An ID token we issued to THIS client, for THIS realm. Its expiry is not held against it (a member
   * signs out long after the 5-minute ID token expired), but it must be younger than a session can live.
   */
  private async verifyHint(token: string, clientId: string, realm: AuthRealm): Promise<JWTPayload | null> {
    try {
      const claims = decodeJwt(token);
      const iat = Number(claims.iat);
      if (!Number.isFinite(iat) || Date.now() / 1000 - iat > this.config.env.SESSION_ABSOLUTE_TTL_SECONDS) return null;
      const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: this.keys.publicJwks }), {
        issuer: this.config.env.ISSUER,
        audience: clientId,
        algorithms: ['RS256'],
        currentDate: new Date((iat + 1) * 1000),
      });
      return payload.auth_realm === realm ? payload : null;
    } catch {
      return null;
    }
  }

  private done(reply: FastifyReply, ctx: LogoutContext) {
    if (ctx.redirectUri) {
      const url = new URL(ctx.redirectUri);
      if (ctx.state) url.searchParams.set('state', ctx.state);
      return reply.header('cache-control', 'no-store').redirect(url.toString(), 303);
    }
    return this.send(reply, 200, 'logged-out', { title: 'Signed out', realmLabel: realmLabel(ctx.realm) });
  }

  private error(reply: FastifyReply, e: { status: number; code: string; message: string }) {
    return this.send(reply, e.status, 'error', { title: 'Sign-out could not continue', message: e.message, code: e.code });
  }

  private send(reply: FastifyReply, status: number, view: string, data: Record<string, string | number | boolean>) {
    return reply.code(status).header('content-type', 'text/html; charset=utf-8').header('cache-control', 'no-store').send(this.views.render(view, data));
  }
}

/**
 * OpenID Connect allows id_token_hint without client_id: the client is the token's audience. The hint is
 * still fully verified against that client in resolve().
 */
function withClientFromHint(params: LogoutParams): LogoutParams {
  if (params.client_id || typeof params.id_token_hint !== 'string' || !params.id_token_hint) return params;
  try {
    const aud = decodeJwt(params.id_token_hint).aud;
    const clientId = Array.isArray(aud) ? aud[0] : aud;
    return typeof clientId === 'string' ? { ...params, client_id: clientId } : params;
  } catch {
    return params;
  }
}

function realmLabel(realm: AuthRealm): string {
  return realm === 'ADMIN' ? 'Admin' : 'Mumin';
}
