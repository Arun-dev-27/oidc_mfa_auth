import { Injectable, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { AppConfig } from '../../config/config.module';
import { requestMeta } from '../../common/request-meta';
import { isAuthRealm, type AuthClient, type HandoffRequest, type MfaMethod } from '../../database/entities';
import { ClientRepository } from '../../database/repositories/client.repository';
import { HandoffRepository } from '../../database/repositories/handoff.repository';
import { SessionParticipantRepository } from '../../database/repositories/session.repository';
import { AuditService } from '../audit/audit.service';
import { CredentialService, type Member } from '../identity/credential.service';
import { SigningKeyService } from '../keys/signing-key.service';
import { ACR_AAL1, ACR_AAL2, MfaService, type MfaOption } from '../mfa/mfa.service';
import { AuthPagesService, loginFailureMessage, minutes, startFailureMessage, verifyFailureMessage, type PageTarget } from '../oidc/auth-pages.service';
import { ClientAuthService } from '../oidc/client-auth.service';
import { CsrfService } from '../security/csrf.service';
import { RateLimitService } from '../security/rate-limit.service';
import { GlobalSessionService, type RealmSession } from '../sessions/global-session.service';
import { isAllowedPath, normalizeRelativePath } from './handoff-path';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MFA_METHODS: readonly MfaMethod[] = ['EMAIL_OTP', 'SMS_OTP', 'TOTP'];

export interface ApiResult {
  status: number;
  body: Record<string, unknown>;
}

interface Pending {
  request: HandoffRequest;
  target: AuthClient;
  page: PageTarget;
}

/**
 * Trusted handoff at Core (Handoff spec §5-9, §21; Core spec §20).
 *
 *   POST /v1/handoff/requests   source BU backend (client-authenticated) asks for a handoff
 *   GET  /v1/handoff/:id        browser arrives; Core proves the identity from ITS OWN realm session
 *                               (login / MFA here first if needed), signs a one-time 60 s JWS and
 *                               auto-POSTs it to the target's registered handoff callback
 *
 * The source never supplies identity: sub comes from the Core session. Source and target must be the
 * same realm and environment, the path is a validated relative path on the target's allowlist, and
 * the target becomes a participant of the Core session so realm logout reaches it too.
 */
@Injectable()
export class HandoffService {
  private readonly logger = new Logger(HandoffService.name);

  constructor(
    private readonly config: AppConfig,
    private readonly clientAuth: ClientAuthService,
    private readonly clients: ClientRepository,
    private readonly handoffs: HandoffRepository,
    private readonly participants: SessionParticipantRepository,
    private readonly credentials: CredentialService,
    private readonly sessions: GlobalSessionService,
    private readonly mfa: MfaService,
    private readonly keys: SigningKeyService,
    private readonly csrf: CsrfService,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuditService,
    private readonly pages: AuthPagesService,
  ) {}

  // ---- POST /v1/handoff/requests -------------------------------------------------------------

  async createRequest(req: FastifyRequest, body: Record<string, unknown>): Promise<ApiResult> {
    const env = this.config.env;
    const issuer = env.ISSUER;
    const source = await this.clientAuth.authenticate(req, body, [issuer, `${issuer}/v1/handoff/requests`, `${issuer}/token`]);
    if (!source) return this.reject(req, null, null, 401, 'SOURCE_CLIENT_INVALID', 'Client authentication failed.');

    const limit = await this.rateLimit.hit('handoff', source.clientId, env.HANDOFF_RATE_LIMIT_PER_MINUTE, 60);
    if (!limit.allowed) return this.reject(req, source.clientId, null, 429, 'RATE_LIMITED', `Too many handoff requests; retry in ${limit.retryAfter} s.`);

    const src = await this.clients.findByClientId(source.clientId);
    if (!src || src.status !== 'ACTIVE' || !isAuthRealm(src.authRealm) || !src.handoffOutboundEnabled) {
      return this.reject(req, source.clientId, null, 403, 'SOURCE_CLIENT_INVALID', 'This client may not start handoffs.');
    }
    const targetId = typeof body.target_client_id === 'string' ? body.target_client_id : '';
    const target = targetId ? await this.clients.findByClientId(targetId) : null;
    if (!target || target.clientId === src.clientId) return this.reject(req, src.clientId, targetId, 400, 'TARGET_CLIENT_NOT_FOUND', 'Unknown target application.');
    if (target.status !== 'ACTIVE' || !target.handoffInboundEnabled || !target.handoffCallbackUri) {
      return this.reject(req, src.clientId, targetId, 400, 'TARGET_CLIENT_DISABLED', 'The target application does not accept handoffs.');
    }
    if (target.environment !== src.environment) return this.reject(req, src.clientId, targetId, 400, 'ENVIRONMENT_MISMATCH', 'Source and target belong to different environments.');
    if (target.authRealm !== src.authRealm) return this.reject(req, src.clientId, targetId, 400, 'REALM_MISMATCH', 'Source and target belong to different realms.');

    const path = normalizeRelativePath(body.requested_path);
    if (!path || !isAllowedPath(path, await this.handoffs.enabledPatterns(target.clientId))) {
      return this.reject(req, src.clientId, targetId, 400, 'HANDOFF_PATH_INVALID', 'The requested path is not allowed for the target application.');
    }

    const request = await this.handoffs.create({
      sourceClientId: src.clientId,
      targetClientId: target.clientId,
      realm: src.authRealm,
      requestedPath: path,
      ttlSeconds: env.HANDOFF_REQUEST_TTL_SECONDS,
    });
    await this.audit.record({
      eventType: 'HANDOFF_REQUESTED',
      outcome: 'SUCCESS',
      clientId: src.clientId,
      metadata: { handoffId: request.id, target: target.clientId, realm: src.authRealm, path },
      ...this.meta(req),
    });
    return {
      status: 201,
      body: { handoff_request_id: request.id, browser_redirect_url: `${issuer}/v1/handoff/${request.id}`, expires_in: env.HANDOFF_REQUEST_TTL_SECONDS },
    };
  }

  // ---- GET /v1/handoff/:id -----------------------------------------------------------------

  async open(req: FastifyRequest, reply: FastifyReply, id: string): Promise<void> {
    const pending = await this.pending(reply, id);
    if (!pending) return;
    const session = await this.sessions.read(pending.request.authRealm, req);
    if (!session) return this.pages.login(req, reply, pending.page, { info: `Sign in to continue to ${pending.target.name}.` });
    const member = await this.credentials.getActiveMember(session.itsId);
    if (!member) {
      await this.sessions.revoke(pending.request.authRealm, req, reply, 'MEMBER_NO_LONGER_ALLOWED');
      return this.pages.login(req, reply, pending.page, { info: 'Please sign in again.' });
    }
    return this.continue(req, reply, pending, member, session);
  }

  // ---- POST /v1/handoff/:id/login ----------------------------------------------------------

  async login(req: FastifyRequest, reply: FastifyReply, id: string, form: Record<string, string | undefined>): Promise<void> {
    const pending = await this.pending(reply, id);
    if (!pending) return;
    const itsIdInput = (form.its_id ?? '').trim().slice(0, 32);
    if (!this.csrf.verify(req, pending.page.csrfScope, form.csrf)) {
      return this.pages.login(req, reply, pending.page, { error: 'Your sign-in form expired. Please try again.', itsId: itsIdInput }, 403);
    }
    const env = this.config.env;
    const meta = requestMeta(req);
    const ipLimit = await this.rateLimit.hit('login-ip', meta.ip, env.LOGIN_MAX_ATTEMPTS_PER_IP, env.LOGIN_IP_WINDOW_SECONDS);
    if (!ipLimit.allowed) return this.pages.login(req, reply, pending.page, { error: `Too many attempts. Try again in ${minutes(ipLimit.retryAfter)}.`, itsId: itsIdInput }, 429);
    if (!itsIdInput || !form.password) return this.pages.login(req, reply, pending.page, { error: 'Enter your ITS ID and password.', itsId: itsIdInput }, 400);

    const result = await this.credentials.verifyPassword(itsIdInput, form.password.slice(0, 256), { ip: meta.ip, clientId: pending.target.clientId });
    if (!result.ok) {
      await this.audit.record({ eventType: 'LOGIN_FAILURE', outcome: 'FAILURE', itsId: result.itsId, clientId: pending.target.clientId, metadata: { reason: result.failure.code, via: 'handoff' }, ...meta });
      return this.pages.login(req, reply, pending.page, { error: loginFailureMessage(result.failure), itsId: itsIdInput }, 401);
    }
    const session = await this.sessions.create(pending.request.authRealm, result.member.itsId, meta, reply);
    await this.audit.record({ eventType: 'LOGIN_SUCCESS', outcome: 'SUCCESS', itsId: result.member.itsId, sid: session.sid, clientId: pending.target.clientId, metadata: { realm: pending.request.authRealm, via: 'handoff' }, ...meta });
    return this.continue(req, reply, pending, result.member, session);
  }

  // ---- MFA (same rules and pages as the OIDC interaction) -----------------------------------

  async verifyMfa(req: FastifyRequest, reply: FastifyReply, id: string, form: Record<string, string | undefined>): Promise<void> {
    const state = await this.mfaState(req, reply, id, form);
    if (!state) return;
    const { pending, member, session, options, option } = state;
    const result = await this.mfa.verify(member, session, `handoff:${id}`, option.method, form.challenge_id ?? null, (form.code ?? '').slice(0, 16), requestMeta(req).ip);
    if (!result.ok) {
      await this.audit.record({ eventType: 'MFA_FAILURE', outcome: 'FAILURE', itsId: member.itsId, sid: session.sid, clientId: pending.target.clientId, metadata: { method: option.method, reason: result.code, via: 'handoff' }, ...this.meta(req) });
      return this.pages.mfa(req, reply, pending.page, options, option, { challengeId: form.challenge_id ?? null, error: verifyFailureMessage(result) }, 401);
    }
    const upgraded = await this.sessions.upgradeToAal2(session, result.method, req, reply);
    await this.audit.record({ eventType: 'MFA_SUCCESS', outcome: 'SUCCESS', itsId: member.itsId, sid: upgraded.sid, clientId: pending.target.clientId, metadata: { method: result.method, via: 'handoff' }, ...this.meta(req) });
    return this.deliver(req, reply, pending, member, upgraded);
  }

  async sendCode(req: FastifyRequest, reply: FastifyReply, id: string, form: Record<string, string | undefined>, resend: boolean): Promise<void> {
    const state = await this.mfaState(req, reply, id, form);
    if (!state) return;
    const { pending, member, session, options, option } = state;
    if (option.method === 'TOTP') return this.pages.mfa(req, reply, pending.page, options, option, {});
    const started = await this.mfa.startOtp(member, session, `handoff:${id}`, option, { resend });
    return this.pages.mfa(req, reply, pending.page, options, option, started.ok ? { challengeId: started.challengeId, info: resend ? 'A new code has been sent.' : undefined } : { error: startFailureMessage(started) });
  }

  async abort(req: FastifyRequest, reply: FastifyReply, id: string, form: Record<string, string | undefined>): Promise<void> {
    const pending = await this.pending(reply, id);
    if (!pending) return;
    if (!this.csrf.verify(req, pending.page.csrfScope, form.csrf)) return this.pages.error(reply, 'Session expired', 'This form expired.', 'CSRF', 403);
    await this.handoffs.cancel(id);
    await this.audit.record({ eventType: 'HANDOFF_CANCELLED', outcome: 'INFO', clientId: pending.target.clientId, metadata: { handoffId: id }, ...this.meta(req) });
    return this.pages.error(reply, 'Cancelled', `Opening ${pending.target.name} was cancelled. You can close this page.`, 'HANDOFF_CANCELLED', 200);
  }

  // ---- flow ----------------------------------------------------------------------------------

  /** Valid realm session: satisfy the target's assurance requirement, then deliver. */
  private async continue(req: FastifyRequest, reply: FastifyReply, pending: Pending, member: Member, session: RealmSession): Promise<void> {
    const required = pending.target.defaultAcr ? [pending.target.defaultAcr] : [];
    if (!this.mfa.isRequired(member, required) || this.mfa.isFresh(session, this.config.env.MFA_MAX_AGE_SECONDS)) {
      return this.deliver(req, reply, pending, member, session);
    }
    const options = await this.mfa.options(member);
    if (!options.length) {
      return this.pages.error(reply, 'Verification is required', `${pending.target.name} needs a second verification step, but no method is registered for your account.`, 'ASSURANCE_REQUIRED', 403);
    }
    const option = options[0];
    if (option.method === 'TOTP') return this.pages.mfa(req, reply, pending.page, options, option, {});
    const started = await this.mfa.startOtp(member, session, `handoff:${pending.request.id}`, option, { resend: false });
    return this.pages.mfa(req, reply, pending.page, options, option, started.ok ? { challengeId: started.challengeId } : { error: startFailureMessage(started) });
  }

  /** Signs the one-time assertion, binds the request, records the participant, auto-POSTs to the target. */
  private async deliver(req: FastifyRequest, reply: FastifyReply, pending: Pending, member: Member, session: RealmSession): Promise<void> {
    const env = this.config.env;
    const { request, target } = pending;
    const aal2 = this.mfa.isFresh(session, env.MFA_MAX_AGE_SECONDS);
    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    let assertion: string;
    try {
      assertion = await this.keys.signJws(
        {
          iss: env.ISSUER,
          sub: member.itsId,
          aud: target.clientId,
          source_client_id: request.sourceClientId,
          target_client_id: target.clientId,
          auth_realm: request.authRealm,
          requested_path: request.requestedPath,
          sid: session.sid,
          auth_time: Math.floor(session.authTime / 1000),
          acr: aal2 ? ACR_AAL2 : ACR_AAL1,
          amr: aal2 ? session.amr : ['pwd'],
          ...(aal2 && session.mfaVerifiedAt ? { mfa_time: Math.floor(session.mfaVerifiedAt / 1000) } : {}),
          iat: now,
          exp: now + env.HANDOFF_ASSERTION_TTL_SECONDS,
          jti,
        },
        'miqaat-handoff+jwt',
      );
    } catch (error) {
      this.logger.error(`handoff signing failed: ${error instanceof Error ? error.message : String(error)}`);
      return this.pages.error(reply, 'Could not continue', 'The application could not be opened. Please try again.', 'SIGNING_FAILED', 503);
    }
    if (!(await this.handoffs.complete(request.id, member.itsId, session.sid, jti))) {
      return this.pages.error(reply, 'Link expired', 'This link has expired or was already used. Go back and try again.', 'HANDOFF_REQUEST_EXPIRED', 400);
    }
    await this.participants.join(session.sid, target.clientId, 'HANDOFF');
    await this.sessions.touch(request.authRealm, req);
    await this.audit.record({
      eventType: 'HANDOFF_COMPLETED',
      outcome: 'SUCCESS',
      itsId: member.itsId,
      sid: session.sid,
      clientId: target.clientId,
      metadata: { handoffId: request.id, source: request.sourceClientId, path: request.requestedPath, acr: aal2 ? ACR_AAL2 : ACR_AAL1 },
      ...this.meta(req),
    });
    reply.header('referrer-policy', 'no-referrer');
    return this.pages.send(reply, 200, 'handoff-post', { title: `Opening ${target.name}`, targetName: target.name, callback: target.handoffCallbackUri ?? '', assertion });
  }

  private async pending(reply: FastifyReply, id: string): Promise<Pending | null> {
    const request = UUID.test(id) ? await this.handoffs.findPending(id) : null;
    const target = request ? await this.clients.findByClientId(request.targetClientId) : null;
    if (!request || !target || target.status !== 'ACTIVE' || !target.handoffInboundEnabled || !target.handoffCallbackUri || !isAuthRealm(target.authRealm)) {
      await this.pages.error(reply, 'Link expired', 'This link has expired or was already used. Go back to the application and try again.', 'HANDOFF_REQUEST_EXPIRED', 400);
      return null;
    }
    return { request, target, page: { formBase: `/v1/handoff/${id}`, csrfScope: `handoff:${id}`, clientName: target.name, realm: target.authRealm } };
  }

  private async mfaState(req: FastifyRequest, reply: FastifyReply, id: string, form: Record<string, string | undefined>) {
    const pending = await this.pending(reply, id);
    if (!pending) return null;
    if (!this.csrf.verify(req, pending.page.csrfScope, form.csrf)) {
      await this.pages.error(reply, 'Session expired', 'Your verification form expired. Go back and try again.', 'CSRF', 403);
      return null;
    }
    const session = await this.sessions.read(pending.request.authRealm, req);
    const member = session ? await this.credentials.getActiveMember(session.itsId) : null;
    if (!session || !member) {
      await this.pages.login(req, reply, pending.page, { info: 'Please sign in again.' });
      return null;
    }
    const options = await this.mfa.options(member);
    const wanted = MFA_METHODS.includes(form.method as MfaMethod) ? (form.method as MfaMethod) : undefined;
    const option: MfaOption | undefined = options.find((o) => o.method === wanted) ?? options[0];
    if (!option) {
      await this.pages.error(reply, 'Verification is required', 'No verification method is available for your account.', 'ASSURANCE_REQUIRED', 403);
      return null;
    }
    return { pending, member, session, options, option };
  }

  private async reject(req: FastifyRequest, source: string | null, target: string | null, status: number, code: string, message: string): Promise<ApiResult> {
    await this.audit.record({ eventType: 'HANDOFF_REJECTED', outcome: 'FAILURE', clientId: source, metadata: { code, target }, ...this.meta(req) });
    return { status, body: { error: code, error_description: message } };
  }

  private meta(req: FastifyRequest) {
    const m = requestMeta(req);
    return { ipAddress: m.ip, userAgent: m.userAgent };
  }
}
