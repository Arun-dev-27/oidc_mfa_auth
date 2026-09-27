import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '../../config/config.module';
import type { AuthRealm } from '../../database/entities';
import { CaptchaService } from '../identity/captcha.service';
import type { CredentialFailure } from '../identity/credential.service';
import type { MfaOption, StartOtpResult, VerifyResult } from '../mfa/mfa.service';
import { CsrfService } from '../security/csrf.service';
import { escapeHtml, ViewService, type ViewData } from '../views/view.service';

/** Where each form of the login / MFA pages posts to. */
export interface FormActions {
  login: string;
  verify: string;
  resend: string;
  switch: string;
  cancel: string;
}

/**
 * Where a login / MFA page posts to. The same SSR pages serve two flows:
 *   OIDC sign-in       /signin/<uid>/password | /verify | /verify/resend | /verify/switch | /cancel
 *   trusted handoff    /v1/handoff/<request id>/login | /mfa | /mfa/resend | /mfa/switch | /abort
 * `csrfScope` binds the CSRF token to that flow instance.
 */
export interface PageTarget {
  actions: FormActions;
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
    private readonly captcha: CaptchaService,
  ) {}

  /**
   * `captcha`: show the Google reCAPTCHA widget (the caller knows whether this ID reached the threshold).
   * Not given -> shown only when the captcha is on for every login (LOGIN_CAPTCHA_AFTER_FAILURES=0).
   */
  login(req: FastifyRequest, reply: FastifyReply, t: PageTarget, data: { error?: string; info?: string; itsId?: string; captcha?: boolean }, status = 200) {
    const showCaptcha = this.captcha.enabled && (data.captcha ?? this.config.env.LOGIN_CAPTCHA_AFTER_FAILURES === 0);
    return this.send(reply, status, 'login', {
      captcha: showCaptcha,
      captchaSiteKey: showCaptcha ? this.captcha.widget.siteKey : '',
      captchaScriptUrl: showCaptcha ? this.captcha.widget.scriptUrl : '',
      title: 'Login to Continue',
      loginAction: t.actions.login,
      cancelAction: t.actions.cancel,
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
          `<form method="post" action="${escapeHtml(t.actions.switch)}" class="inline-form">` +
          `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}"><input type="hidden" name="method" value="${escapeHtml(o.method)}">` +
          `<button type="submit" class="link-button">Use ${escapeHtml(o.label)} (${escapeHtml(o.masked)}) instead</button></form>`,
      )
      .join('');
    return this.send(reply, status, 'mfa', {
      title: 'Verify it’s you',
      verifyAction: t.actions.verify,
      resendAction: t.actions.resend,
      cancelAction: t.actions.cancel,
      csrf,
      method: option.method,
      isTotp: option.method === 'TOTP',
      // MFA_STATIC_OTP testing step for a member without any method (nothing is sent).
      isTestCode: option.method !== 'TOTP' && option.destination === null,
      // Only ever non-empty when MFA_STATIC_OTP is set (refused in production).
      staticCode: this.config.env.MFA_STATIC_OTP,
      isOtp: option.method !== 'TOTP' && option.destination !== null,
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

/** Short explanation shown when the captcha appears because of earlier failures. */
export function captchaInfo(r: { captcha: boolean; failure: CredentialFailure }): string | undefined {
  if (!r.captcha || r.failure.code.startsWith('CAPTCHA_')) return undefined;
  return 'For your security, please also confirm you are not a robot.';
}

export function loginFailureMessage(f: CredentialFailure): string {
  switch (f.code) {
    case 'ACCOUNT_LOCKED':
      return `Too many incorrect attempts. Try again in ${minutes(f.retryAfterSeconds)}.`;
    case 'ACCOUNT_UNAVAILABLE':
      return 'Your account cannot sign in at the moment. Please contact your Jamaat office.';
    case 'NOT_ELIGIBLE':
      return f.message;
    case 'CAPTCHA_REQUIRED':
      return 'Please confirm you are not a robot, then sign in again.';
    case 'CAPTCHA_INVALID':
      return 'The security check failed or expired. Please complete it again.';
    case 'CAPTCHA_UNAVAILABLE':
      return 'The security check is not available right now. Please try again in a moment.';
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
