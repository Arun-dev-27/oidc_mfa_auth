import { Inject, Injectable, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type Redis from 'ioredis';
import { errors } from 'oidc-provider';
import { AppConfig } from '../../config/config.module';
import { requestMeta } from '../../common/request-meta';
import { isAuthRealm, type AuthRealm, type MfaMethod } from '../../database/entities';
import { SessionParticipantRepository } from '../../database/repositories/session.repository';
import { InjectRedis } from '../../redis/redis.module';
import { AuditService } from '../audit/audit.service';
import { CredentialService, type Member } from '../identity/credential.service';
import { ACR_AAL1, ACR_AAL2, MfaService, type MfaOption, type StartOtpResult, type VerifyResult } from '../mfa/mfa.service';
import { CsrfService } from '../security/csrf.service';
import { RateLimitService } from '../security/rate-limit.service';
import { GlobalSessionService, type RealmSession } from '../sessions/global-session.service';
import { AuthPagesService, loginFailureMessage, minutes, startFailureMessage, verifyFailureMessage, type PageTarget } from './auth-pages.service';
import { ClientRegistryService } from './client-registry.service';
import { grantContextKey, OIDC_PROVIDER, sessionGrantsKey, type GrantContext, type OidcProvider } from './oidc.constants';

/** Everything the interaction needs about the pending authorization request. */
interface InteractionContext {
  uid: string;
  clientId: string;
  clientName: string;
  realm: AuthRealm;
  requestedAcrs: string[];
  mfaMaxAge: number;
  scope: string;
  clientScope: string;
  grantId: string | undefined;
}

export interface LoginForm {
  its_id?: string;
  password?: string;
  csrf?: string;
}

export interface MfaForm {
  code?: string;
  challenge_id?: string;
  method?: string;
  csrf?: string;
}

const MFA_METHODS: readonly MfaMethod[] = ['EMAIL_OTP', 'SMS_OTP', 'TOTP'];

/**
 * The Core SSR interaction (spec §11-12, §15), called by oidc-provider for every /auth request:
 *
 *   realm gate  client_id -> auth_realm -> that realm's session only
 *   SSO         valid realm session -> no password (member re-checked: still allowed / eligible)
 *   login       ITS ID + password against the existing identity tables -> new realm session (AAL1)
 *   MFA         when the client asks for AAL2 (or policy requires it) and the session's MFA is not
 *               fresh: OTP by Email (default) / SMS, or TOTP -> same session upgraded to AAL2
 *   finish      grant + login result (accountId = ITS ID, acr, amr, auth_time) back to the provider
 */
@Injectable()
export class InteractionService {
  private readonly logger = new Logger(InteractionService.name);

  constructor(
    @Inject(OIDC_PROVIDER) private readonly provider: OidcProvider,
    @InjectRedis() private readonly redis: Redis,
    private readonly config: AppConfig,
    private readonly clients: ClientRegistryService,
    private readonly credentials: CredentialService,
    private readonly sessions: GlobalSessionService,
    private readonly participants: SessionParticipantRepository,
    private readonly mfa: MfaService,
    private readonly csrf: CsrfService,
    private readonly rateLimit: RateLimitService,
    private readonly audit: AuditService,
    private readonly pages: AuthPagesService,
  ) {}

  // ---- GET /interaction/:uid ---------------------------------------------------------------

  async show(req: FastifyRequest, reply: FastifyReply, uid: string): Promise<void> {
    const ctx = await this.context(req, reply, uid);
    if (!ctx) return;

    const session = await this.sessions.read(ctx.realm, req);
    if (!session) return this.renderLogin(req, reply, ctx, {});

    const member = await this.credentials.getActiveMember(session.itsId);
    if (!member) {
      await this.sessions.revoke(ctx.realm, req, reply, 'MEMBER_NO_LONGER_ALLOWED');
      return this.renderLogin(req, reply, ctx, { info: 'Please sign in again.' });
    }
    await this.audit.record({ eventType: 'SESSION_REUSED', outcome: 'SUCCESS', itsId: member.itsId, sid: session.sid, clientId: ctx.clientId, ...this.meta(req) });
    return this.afterPrimary(req, reply, ctx, member, session);
  }

  // ---- POST /interaction/:uid/login --------------------------------------------------------

  async login(req: FastifyRequest, reply: FastifyReply, uid: string, form: LoginForm): Promise<void> {
    const ctx = await this.context(req, reply, uid);
    if (!ctx) return;
    const itsIdInput = (form.its_id ?? '').trim().slice(0, 32);
    if (!this.csrf.verify(req, uid, form.csrf)) {
      return this.renderLogin(req, reply, ctx, { error: 'Your sign-in form expired. Please try again.', itsId: itsIdInput }, 403);
    }
    const env = this.config.env;
    const meta = requestMeta(req);
    const ipLimit = await this.rateLimit.hit('login-ip', meta.ip, env.LOGIN_MAX_ATTEMPTS_PER_IP, env.LOGIN_IP_WINDOW_SECONDS);
    if (!ipLimit.allowed) {
      return this.renderLogin(req, reply, ctx, { error: `Too many attempts. Try again in ${minutes(ipLimit.retryAfter)}.`, itsId: itsIdInput }, 429);
    }
    if (!itsIdInput || !form.password) {
      return this.renderLogin(req, reply, ctx, { error: 'Enter your ITS ID and password.', itsId: itsIdInput }, 400);
    }

    const result = await this.credentials.verifyPassword(itsIdInput, form.password.slice(0, 256), { ip: meta.ip, clientId: ctx.clientId });
    if (!result.ok) {
      await this.audit.record({ eventType: 'LOGIN_FAILURE', outcome: 'FAILURE', itsId: result.itsId, clientId: ctx.clientId, metadata: { reason: result.failure.code }, ...meta });
      return this.renderLogin(req, reply, ctx, { error: loginFailureMessage(result.failure), itsId: itsIdInput }, 401);
    }

    // Always a brand-new session and cookie secret after a password login (no fixation).
    const session = await this.sessions.create(ctx.realm, result.member.itsId, meta, reply);
    await this.audit.record({ eventType: 'LOGIN_SUCCESS', outcome: 'SUCCESS', itsId: result.member.itsId, sid: session.sid, clientId: ctx.clientId, metadata: { realm: ctx.realm }, ...meta });
    return this.afterPrimary(req, reply, ctx, result.member, session);
  }

  // ---- POST /interaction/:uid/mfa ----------------------------------------------------------

  async verifyMfa(req: FastifyRequest, reply: FastifyReply, uid: string, form: MfaForm): Promise<void> {
    const state = await this.mfaState(req, reply, uid, form);
    if (!state) return;
    const { ctx, member, session, options, option } = state;

    const result = await this.mfa.verify(member, session, uid, option.method, form.challenge_id ?? null, (form.code ?? '').slice(0, 16), requestMeta(req).ip);
    if (!result.ok) {
      await this.audit.record({ eventType: 'MFA_FAILURE', outcome: 'FAILURE', itsId: member.itsId, sid: session.sid, clientId: ctx.clientId, metadata: { method: option.method, reason: result.code }, ...this.meta(req) });
      return this.renderMfa(req, reply, ctx, options, option, { challengeId: form.challenge_id ?? null, error: verifyFailureMessage(result) }, 401);
    }

    const upgraded = await this.sessions.upgradeToAal2(session, result.method, req, reply);
    await this.audit.record({ eventType: 'MFA_SUCCESS', outcome: 'SUCCESS', itsId: member.itsId, sid: upgraded.sid, clientId: ctx.clientId, metadata: { method: result.method, ...(result.staticOtp ? { staticOtp: true } : {}) }, ...this.meta(req) });
    return this.finish(req, reply, ctx, member, upgraded);
  }

  // ---- POST /interaction/:uid/mfa/resend and /mfa/switch --------------------------------------

  async sendCode(req: FastifyRequest, reply: FastifyReply, uid: string, form: MfaForm, resend: boolean): Promise<void> {
    const state = await this.mfaState(req, reply, uid, form);
    if (!state) return;
    const { ctx, member, session, options, option } = state;
    if (option.method === 'TOTP') return this.renderMfa(req, reply, ctx, options, option, {});
    const started = await this.mfa.startOtp(member, session, uid, option, { resend });
    await this.auditChallenge(req, ctx, member, session, option, started);
    return this.renderMfa(req, reply, ctx, options, option, started.ok ? { challengeId: started.challengeId, info: resend ? 'A new code has been sent.' : undefined } : { error: startFailureMessage(started) });
  }

  // ---- POST /interaction/:uid/abort --------------------------------------------------------

  async abort(req: FastifyRequest, reply: FastifyReply, uid: string, form: { csrf?: string }): Promise<void> {
    const ctx = await this.context(req, reply, uid);
    if (!ctx) return;
    if (!this.csrf.verify(req, uid, form.csrf)) return this.renderLogin(req, reply, ctx, { error: 'Your sign-in form expired. Please try again.' }, 403);
    const redirectTo = await this.provider.interactionResult(
      req.raw,
      reply.raw,
      { error: 'access_denied', error_description: 'The user cancelled the sign-in.' },
      { mergeWithLastSubmission: false },
    );
    return reply.redirect(redirectTo, 303);
  }

  // ---- flow steps ----------------------------------------------------------------------------

  /** After a valid primary authentication (new login or reused session): MFA if needed, else finish. */
  private async afterPrimary(req: FastifyRequest, reply: FastifyReply, ctx: InteractionContext, member: Member, session: RealmSession): Promise<void> {
    const needsMfa = this.mfa.isRequired(member, ctx.requestedAcrs) && !this.mfa.isFresh(session, ctx.mfaMaxAge);
    if (!needsMfa) return this.finish(req, reply, ctx, member, session);

    const options = await this.mfa.options(member);
    if (!options.length) {
      await this.audit.record({ eventType: 'MFA_UNAVAILABLE', outcome: 'FAILURE', itsId: member.itsId, sid: session.sid, clientId: ctx.clientId, ...this.meta(req) });
      return this.renderError(reply, 'Verification is required', 'This application needs a second verification step, but no email address or other method is registered for your account. Please contact your Jamaat office.', 'MFA_REQUIRED', 403);
    }
    const option = options[0];
    if (option.method === 'TOTP') return this.renderMfa(req, reply, ctx, options, option, {});
    const started = await this.mfa.startOtp(member, session, ctx.uid, option, { resend: false });
    await this.auditChallenge(req, ctx, member, session, option, started);
    return this.renderMfa(req, reply, ctx, options, option, started.ok ? { challengeId: started.challengeId } : { error: startFailureMessage(started) });
  }

  /** Hands the result back to oidc-provider, which issues the one-time code to the client. */
  private async finish(req: FastifyRequest, reply: FastifyReply, ctx: InteractionContext, member: Member, session: RealmSession): Promise<void> {
    const env = this.config.env;
    const aal2 = this.mfa.isFresh(session, env.MFA_MAX_AGE_SECONDS);
    const acr = aal2 ? ACR_AAL2 : ACR_AAL1;
    const amr = aal2 ? session.amr : ['pwd'];

    // Grant = what this client may receive for this member. Only scopes the client is registered for.
    const existing = ctx.grantId ? await this.provider.Grant.find(ctx.grantId) : undefined;
    const grant =
      existing && existing.accountId === member.itsId && existing.clientId === ctx.clientId
        ? existing
        : new this.provider.Grant({ accountId: member.itsId, clientId: ctx.clientId });
    const allowed = new Set(ctx.clientScope.split(' ').filter(Boolean));
    const scopes = ctx.scope
      .split(' ')
      .filter((s) => s === 'openid' || allowed.has(s))
      .join(' ');
    grant.addOIDCScope(scopes || 'openid');
    const grantId = await grant.save();

    const context: GrantContext = { sid: session.sid, realm: ctx.realm };
    await this.redis.set(grantContextKey(grantId), JSON.stringify(context), 'EX', env.SESSION_ABSOLUTE_TTL_SECONDS);
    // Remember which grants (and so which tokens) belong to this Core session, for logout.
    await this.redis.multi().sadd(sessionGrantsKey(session.sid), grantId).expire(sessionGrantsKey(session.sid), env.SESSION_ABSOLUTE_TTL_SECONDS).exec();
    await this.participants.join(session.sid, ctx.clientId, 'LOGIN');
    await this.sessions.touch(ctx.realm, req);
    await this.audit.record({ eventType: 'AUTHORIZATION_COMPLETED', outcome: 'SUCCESS', itsId: member.itsId, sid: session.sid, clientId: ctx.clientId, metadata: { realm: ctx.realm, acr, amr }, ...this.meta(req) });

    const redirectTo = await this.provider.interactionResult(
      req.raw,
      reply.raw,
      {
        login: { accountId: member.itsId, acr, amr, ts: Math.floor(session.authTime / 1000), remember: false },
        consent: { grantId },
      },
      { mergeWithLastSubmission: false },
    );
    return reply.redirect(redirectTo, 303);
  }

  /** Common checks for every MFA POST: CSRF, pending interaction, realm session, chosen method. */
  private async mfaState(req: FastifyRequest, reply: FastifyReply, uid: string, form: MfaForm) {
    const ctx = await this.context(req, reply, uid);
    if (!ctx) return null;
    if (!this.csrf.verify(req, uid, form.csrf)) {
      await this.renderError(reply, 'Session expired', 'Your verification form expired. Go back to the application and sign in again.', 'CSRF', 403);
      return null;
    }
    const session = await this.sessions.read(ctx.realm, req);
    const member = session ? await this.credentials.getActiveMember(session.itsId) : null;
    if (!session || !member) {
      await this.renderLogin(req, reply, ctx, { info: 'Please sign in again.' });
      return null;
    }
    const options = await this.mfa.options(member);
    const wanted = MFA_METHODS.includes(form.method as MfaMethod) ? (form.method as MfaMethod) : undefined;
    const option = options.find((o) => o.method === wanted) ?? options[0];
    if (!option) {
      await this.renderError(reply, 'Verification is required', 'No verification method is available for your account.', 'MFA_REQUIRED', 403);
      return null;
    }
    return { ctx, member, session, options, option };
  }

  /** Loads the pending interaction; renders the "expired" page (and returns null) when it is gone. */
  private async context(req: FastifyRequest, reply: FastifyReply, uid: string): Promise<InteractionContext | null> {
    try {
      const details = await this.provider.interactionDetails(req.raw, reply.raw);
      if (details.uid !== uid) throw new errors.SessionNotFound('interaction mismatch');
      const clientId = String(details.params.client_id ?? '');
      const metadata = await this.clients.findMetadata(clientId);
      const realm = metadata?.auth_realm;
      if (!metadata || !isAuthRealm(realm)) {
        await this.renderError(reply, 'Application not available', 'This application is not registered for sign-in.', 'CLIENT_NOT_FOUND', 400);
        return null;
      }
      const acrParam = typeof details.params.acr_values === 'string' ? details.params.acr_values.split(' ').filter(Boolean) : [];
      const defaults = Array.isArray(metadata.default_acr_values) ? (metadata.default_acr_values as string[]) : [];
      const maxAge = Number.parseInt(String(details.params.mfa_max_age ?? ''), 10);
      return {
        uid: details.uid,
        clientId,
        clientName: String(metadata.client_name ?? clientId),
        realm,
        requestedAcrs: acrParam.length ? acrParam : defaults,
        mfaMaxAge: this.mfa.effectiveMaxAge(Number.isFinite(maxAge) ? maxAge : null),
        scope: String(details.params.scope ?? 'openid'),
        clientScope: String(metadata.scope ?? 'openid'),
        grantId: details.grantId,
      };
    } catch (error) {
      if (error instanceof errors.SessionNotFound || (error as { name?: string }).name === 'SessionNotFound') {
        await this.renderError(reply, 'Sign-in expired', 'This sign-in page has expired. Go back to the application and start again.', 'SESSION_EXPIRED', 400);
        return null;
      }
      throw error;
    }
  }

  // ---- rendering (shared Core pages) ------------------------------------------------------

  private page(ctx: InteractionContext): PageTarget {
    return { formBase: `/interaction/${ctx.uid}`, csrfScope: ctx.uid, clientName: ctx.clientName, realm: ctx.realm };
  }

  private renderLogin(req: FastifyRequest, reply: FastifyReply, ctx: InteractionContext, data: { error?: string; info?: string; itsId?: string }, status = 200) {
    return this.pages.login(req, reply, this.page(ctx), data, status);
  }

  private renderMfa(
    req: FastifyRequest,
    reply: FastifyReply,
    ctx: InteractionContext,
    options: MfaOption[],
    option: MfaOption,
    data: { challengeId?: string | null; error?: string; info?: string },
    status = 200,
  ) {
    return this.pages.mfa(req, reply, this.page(ctx), options, option, data, status);
  }

  private renderError(reply: FastifyReply, title: string, message: string, code: string, status: number) {
    return this.pages.error(reply, title, message, code, status);
  }

  private async auditChallenge(req: FastifyRequest, ctx: InteractionContext, member: Member, session: RealmSession, option: MfaOption, started: StartOtpResult) {
    await this.audit.record({
      eventType: started.ok ? 'MFA_CHALLENGE_SENT' : 'MFA_CHALLENGE_FAILED',
      outcome: started.ok ? 'SUCCESS' : 'FAILURE',
      itsId: member.itsId,
      sid: session.sid,
      clientId: ctx.clientId,
      metadata: { method: option.method, ...(started.ok ? {} : { reason: started.code }) },
      ...this.meta(req),
    });
  }

  private meta(req: FastifyRequest) {
    const m = requestMeta(req);
    return { ipAddress: m.ip, userAgent: m.userAgent };
  }
}
