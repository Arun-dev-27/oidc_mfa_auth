import { Injectable, Logger } from '@nestjs/common';
import { AppConfig } from '../../config/config.module';

export type CaptchaCheck = { ok: true } | { ok: false; code: 'CAPTCHA_REQUIRED' | 'CAPTCHA_INVALID' | 'CAPTCHA_UNAVAILABLE'; detail?: string };

interface SiteVerifyResponse {
  success?: boolean;
  hostname?: string;
  'error-codes'?: string[];
}

/**
 * Google reCAPTCHA v2 ("I'm not a robot" checkbox) for the login form.
 *
 * The browser solves the widget and posts its token as `g-recaptcha-response`; the server verifies it with
 * POST RECAPTCHA_VERIFY_URL (secret, response, remoteip). It fails CLOSED: when Google cannot be reached the
 * login is refused ("security check unavailable") instead of skipping the check.
 */
@Injectable()
export class CaptchaService {
  private readonly logger = new Logger(CaptchaService.name);

  constructor(private readonly config: AppConfig) {}

  /** The HTTP call to Google (overridden in unit tests). */
  protected post(url: string, body: string, signal: AbortSignal): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> {
    return fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, signal });
  }

  get enabled(): boolean {
    return this.config.env.LOGIN_CAPTCHA_ENABLED;
  }

  /** What the login page needs to render the widget. */
  get widget(): { siteKey: string; scriptUrl: string } {
    return { siteKey: this.config.env.RECAPTCHA_SITE_KEY, scriptUrl: this.config.env.RECAPTCHA_SCRIPT_URL };
  }

  async verify(token: string | undefined, remoteIp: string): Promise<CaptchaCheck> {
    const env = this.config.env;
    const response = (token ?? '').trim();
    if (!response) return { ok: false, code: 'CAPTCHA_REQUIRED' };
    if (response.length > 4096) return { ok: false, code: 'CAPTCHA_INVALID', detail: 'token too long' };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), env.RECAPTCHA_TIMEOUT_MS);
    let body: SiteVerifyResponse;
    try {
      const form = new URLSearchParams({ secret: env.RECAPTCHA_SECRET_KEY, response, ...(remoteIp ? { remoteip: remoteIp } : {}) });
      const res = await this.post(env.RECAPTCHA_VERIFY_URL, form.toString(), controller.signal);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      body = (await res.json()) as SiteVerifyResponse;
    } catch (error) {
      this.logger.warn(`captcha verification unavailable: ${error instanceof Error ? error.message : String(error)}`);
      return { ok: false, code: 'CAPTCHA_UNAVAILABLE' };
    } finally {
      clearTimeout(timer);
    }

    if (body.success !== true) return { ok: false, code: 'CAPTCHA_INVALID', detail: (body['error-codes'] ?? []).join(',') || 'not successful' };
    const hosts = env.RECAPTCHA_EXPECTED_HOSTNAMES;
    if (hosts.length && !hosts.includes(String(body.hostname ?? ''))) {
      return { ok: false, code: 'CAPTCHA_INVALID', detail: `hostname ${String(body.hostname)}` };
    }
    return { ok: true };
  }
}
