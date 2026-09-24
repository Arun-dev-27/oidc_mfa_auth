import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '../../config/config.module';
import type { AuthRealm } from '../../database/entities';
import type { CredentialFailure } from '../identity/credential.service';
import type { MfaOption, StartOtpResult, VerifyResult } from '../mfa/mfa.service';
import { CsrfService } from '../security/csrf.service';
import { escapeHtml, ViewService, type ViewData } from '../views/view.service';

/**
 * Where a login / MFA page posts to. The same SSR pages serve two flows:
 *   OIDC interaction   formBase = /interaction/<uid>
 *   trusted handoff    formBase = /v1/handoff/<request id>
 * `csrfScope` binds the CSRF token to that flow instance.
 */
export interface PageTarget {
  formBase: string;
  csrfScope: string;
  clientName: string;
  realm: AuthRealm;
}

/** Renders the Core SSR pages (login, MFA, error) - one implementation for every flow. */
@Injectable()
export class AuthPagesService {
  constructor(
    private readonly config: AppConfig,
    private readonly csrf: CsrfService,
    private readonly views: ViewService,
  ) {}

  login(req: FastifyRequest, reply: FastifyReply, t: PageTarget, data: { error?: string; info?: string; itsId?: string }, status = 200) {
    return this.send(reply, status, 'login', {
      title: 'Login to Continue',
      formBase: t.formBase,
      csrf: this.csrf.issue(req, reply, t.csrfScope),
      clientName: t.clientName,
      realmLabel: t.realm === 'ADMIN' ? 'Admin portal' : 'Mumin portal',
      itsId: data.itsId ?? '',
      forgotUrl: this.config.env.FORGOT_PASSWORD_URL,
      error: data.error,
      info: data.info,
    });
  }

  mfa(
    req: FastifyRequest,
    reply: FastifyReply,
    t: PageTarget,
    options: MfaOption[],
    option: MfaOption,
    data: { challengeId?: string | null; error?: string; info?: string },
    status = 200,
  ) {
    const csrf = this.csrf.issue(req, reply, t.csrfScope);
    const alternatives = options
      .filter((o) => o.method !== option.method)
      .map(
        (o) =>
          `<form method="post" action="${escapeHtml(t.formBase)}/mfa/switch" class="inline-form">` +
          `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="method" value="${escapeHtml(o.method)}">` +
          `<button type="submit" class="link-button">Use ${escapeHtml(o.label)} (${escapeHtml(o.masked)}) instead</button></form>`,
      )
      .join('');
    return this.send(reply, status, 'mfa', {
      title: 'Verify it’s you',
      formBase: t.formBase,
      csrf,
      method: option.method,
      isTotp: option.method === 'TOTP',
      isOtp: option.method !== 'TOTP',
      destination: option.masked,
      channelLabel: option.label,
      challengeId: data.challengeId ?? '',
      canVerify: option.method === 'TOTP' || Boolean(data.challengeId),
      error: data.error,
      info: data.info,
      alternatives,
      hasAlternatives: alternatives.length > 0,
    });
  }

  error(reply: FastifyReply, title: string, message: string, code: string, status: number) {
    return this.send(reply, status, 'error', { title, message, code });
  }

  send(reply: FastifyReply, status: number, view: string, data: ViewData) {
    return reply
      .code(status)
      .header('content-type', 'text/html; charset=utf-8')
      .header('cache-control', 'no-store')
      .send(this.views.render(view, data));
  }
}

export function minutes(seconds: number): string {
  const m = Math.ceil(seconds / 60);
  return m <= 1 ? 'a minute' : `${m} minutes`;
}

export function loginFailureMessage(f: CredentialFailure): string {
  switch (f.code) {
    case 'ACCOUNT_LOCKED':
      return `Too many incorrect attempts. Try again in ${minutes(f.retryAfterSeconds)}.`;
    case 'ACCOUNT_UNAVAILABLE':
      return 'Your account cannot sign in at the moment. Please contact your Jamaat office.';
    case 'NOT_ELIGIBLE':
      return f.message;
    default:
      return 'Incorrect ITS ID or password.';
  }
}

export function startFailureMessage(r: Exclude<StartOtpResult, { ok: true }>): string {
  switch (r.code) {
    case 'RESEND_COOLDOWN':
      return `Please wait ${r.retryAfterSeconds} seconds before requesting another code.`;
    case 'TOO_MANY_CODES':
      return 'Too many codes were requested. Please try again later.';
    case 'CHANNEL_UNAVAILABLE':
      return 'This verification method is not available right now.';
    default:
      return 'We could not send the code. Please try again.';
  }
}

export function verifyFailureMessage(r: Exclude<VerifyResult, { ok: true }>): string {
  switch (r.code) {
    case 'INVALID_CODE':
      return r.remaining > 0 ? `Incorrect code. ${r.remaining} attempt${r.remaining === 1 ? '' : 's'} left.` : 'Incorrect code.';
    case 'TOO_MANY_ATTEMPTS':
      return 'Too many incorrect codes. Request a new code.';
    case 'METHOD_UNAVAILABLE':
      return 'This verification method is not available.';
    default:
      return 'This code has expired. Request a new one.';
  }
}
