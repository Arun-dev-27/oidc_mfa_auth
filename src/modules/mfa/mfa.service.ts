import { Injectable, Logger } from '@nestjs/common';
import { AppConfig } from '../../config/config.module';
import { decryptString, hmacHex, maskEmail, maskPhone, randomDigits, safeEqual, sha256Hex, toKey32 } from '../../common/crypto.util';
import type { MfaMethod, OtpChannel } from '../../database/entities';
import { LoginAttemptRepository } from '../../database/repositories/login-attempt.repository';
import { MfaFactorRepository, OtpChallengeRepository } from '../../database/repositories/mfa.repository';
import type { Member } from '../identity/credential.service';
import { RateLimitService } from '../security/rate-limit.service';
import type { RealmSession } from '../sessions/global-session.service';
import { OtpAdapterRegistry } from './adapters/otp-adapter.registry';
import { verifyTotp } from './totp';

export const ACR_AAL1 = 'urn:miqaat:aal:1';
export const ACR_AAL2 = 'urn:miqaat:aal:2';

/** A second factor the member can use right now. `destination` never leaves the server. */
export interface MfaOption {
  method: MfaMethod;
  label: string;
  masked: string;
  factorId: string | null;
  destination: string | null;
  isDefault: boolean;
}

export type StartOtpResult =
  | { ok: true; challengeId: string; masked: string; channel: OtpChannel }
  | { ok: false; code: 'CHANNEL_UNAVAILABLE' | 'TOO_MANY_CODES' | 'DELIVERY_FAILED' }
  | { ok: false; code: 'RESEND_COOLDOWN'; retryAfterSeconds: number };

export type VerifyResult =
  | { ok: true; method: MfaMethod; /** accepted through MFA_STATIC_OTP (testing) */ staticOtp?: boolean }
  | { ok: false; code: 'INVALID_CODE'; remaining: number }
  | { ok: false; code: 'CODE_EXPIRED' | 'TOO_MANY_ATTEMPTS' | 'METHOD_UNAVAILABLE' };

const CHANNEL: Record<Exclude<MfaMethod, 'TOTP'>, OtpChannel> = { EMAIL_OTP: 'EMAIL', SMS_OTP: 'SMS' };

/**
 * Core-owned MFA (spec §15): decides whether AAL2 is needed, reuses a fresh AAL2 of the same realm
 * session, and otherwise runs a second factor: OTP by Email (default) or SMS, or TOTP.
 */
@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);
  private readonly dataKey: Buffer;

  constructor(
    private readonly config: AppConfig,
    private readonly factors: MfaFactorRepository,
    private readonly challenges: OtpChallengeRepository,
    private readonly attempts: LoginAttemptRepository,
    private readonly adapters: OtpAdapterRegistry,
    private readonly rateLimit: RateLimitService,
  ) {
    this.dataKey = toKey32(config.env.DATA_ENCRYPTION_KEY);
    if (config.env.MFA_STATIC_OTP) {
      this.logger.warn('MFA_STATIC_OTP is set: a fixed test code is accepted for every member and method (testing only)');
    }
  }

  /** AAL2 needed? The BU asks for it (acr_values / client default), or platform / member policy forces it. */
  isRequired(member: Member, requestedAcrs: string[]): boolean {
    const env = this.config.env;
    if (env.MFA_REQUIRED_FOR_ALL) return true;
    if (requestedAcrs.includes(ACR_AAL2)) return true;
    return env.MFA_HONOR_USER_OTP_FLAG && member.otpRequired;
  }

  /** The BU may ask for a shorter freshness, never a longer one than the platform cap. */
  effectiveMaxAge(requestedSeconds: number | null): number {
    const cap = this.config.env.MFA_MAX_AGE_SECONDS;
    return requestedSeconds && requestedSeconds > 0 ? Math.min(requestedSeconds, cap) : cap;
  }

  /** Reuse rule: same realm session (the caller passes that one only), AAL2, and fresh enough. */
  isFresh(session: RealmSession, maxAgeSeconds: number, now = Date.now()): boolean {
    return session.aal >= 2 && session.mfaVerifiedAt !== null && now - session.mfaVerifiedAt <= maxAgeSeconds * 1000;
  }

  /** Methods the member can use now, default first. Email to mumin_master.email is the fallback. */
  async options(member: Member): Promise<MfaOption[]> {
    const rows = await this.factors.findActive(member.itsId);
    const options: MfaOption[] = [];

    for (const f of rows) {
      if (f.method === 'TOTP') {
        if (f.totpSecretEnc) options.push({ method: 'TOTP', label: 'Authenticator app', masked: 'Authenticator app', factorId: f.id, destination: null, isDefault: f.isDefault });
        continue;
      }
      if (!f.destinationEnc || !this.adapters.get(CHANNEL[f.method])) continue;
      const destination = this.decrypt(f.destinationEnc);
      if (!destination) continue;
      options.push({
        method: f.method,
        label: f.method === 'EMAIL_OTP' ? 'Email' : 'SMS',
        masked: f.method === 'EMAIL_OTP' ? maskEmail(destination) : maskPhone(destination),
        factorId: f.id,
        destination,
        isDefault: f.isDefault,
      });
    }

    if (!options.some((o) => o.method === 'EMAIL_OTP') && member.email && this.adapters.get('EMAIL')) {
      options.push({ method: 'EMAIL_OTP', label: 'Email', masked: maskEmail(member.email), factorId: null, destination: member.email, isDefault: false });
    }

    // Testing (MFA_STATIC_OTP): a member without any method still gets a step only the static code completes.
    if (!options.length && this.config.env.MFA_STATIC_OTP) {
      options.push({ method: 'EMAIL_OTP', label: 'Test code', masked: 'test mode (use the static test code)', factorId: null, destination: null, isDefault: true });
    }

    const preferred = options.find((o) => o.isDefault) ?? options.find((o) => o.method === this.config.env.MFA_DEFAULT_METHOD) ?? options[0];
    return preferred ? [preferred, ...options.filter((o) => o !== preferred)] : [];
  }

  /** Creates a one-time code, stores only its HMAC, and sends it through the channel adapter. */
  async startOtp(member: Member, session: RealmSession, uid: string, option: MfaOption, opts: { resend: boolean }): Promise<StartOtpResult> {
    const env = this.config.env;
    const testOnly = Boolean(env.MFA_STATIC_OTP) && option.destination === null;
    if (option.method === 'TOTP' || (!option.destination && !testOnly)) return { ok: false, code: 'CHANNEL_UNAVAILABLE' };
    const channel = CHANNEL[option.method];
    const adapter = this.adapters.get(channel);
    if (!adapter && !testOnly) return { ok: false, code: 'CHANNEL_UNAVAILABLE' };

    if (opts.resend) {
      const wait = await this.rateLimit.cooldown('otp-resend', `${session.sid}:${uid}`, env.OTP_RESEND_COOLDOWN_SECONDS);
      if (wait > 0) return { ok: false, code: 'RESEND_COOLDOWN', retryAfterSeconds: wait };
    }
    // The hourly cap is not applied while testing with MFA_STATIC_OTP.
    if (!env.MFA_STATIC_OTP) {
      const sentLastHour = await this.challenges.countSentSince(member.itsId, new Date(Date.now() - 3_600_000));
      if (sentLastHour >= env.OTP_MAX_SENDS_PER_HOUR) return { ok: false, code: 'TOO_MANY_CODES' };
    }

    const code = randomDigits(env.OTP_LENGTH);
    const challenge = await this.challenges.create({
      itsId: member.itsId,
      sid: session.sid,
      interactionUid: uid,
      channel,
      purpose: session.aal === 1 && Date.now() - session.authTime < 60_000 ? 'LOGIN_MFA' : 'STEP_UP',
      destinationMasked: option.masked,
      codeHash: this.codeHash(code, member.itsId, session.sid, uid),
      maxAttempts: env.OTP_MAX_ATTEMPTS,
      expiresAt: new Date(Date.now() + env.OTP_TTL_SECONDS * 1000),
    });

    if (testOnly || !adapter || !option.destination) return { ok: true, challengeId: challenge.id, masked: option.masked, channel };
    try {
      const result = await adapter.send({ to: option.destination, code, ttlMinutes: Math.ceil(env.OTP_TTL_SECONDS / 60), itsId: member.itsId });
      await this.challenges.setProviderMessageId(challenge.id, result.providerMessageId);
    } catch (error) {
      await this.challenges.consume(challenge.id);
      this.logger.error(`OTP delivery failed via ${channel}: ${error instanceof Error ? error.message : String(error)}`);
      return { ok: false, code: 'DELIVERY_FAILED' };
    }
    return { ok: true, challengeId: challenge.id, masked: option.masked, channel };
  }

  /** Verifies an Email/SMS OTP (by challenge) or a TOTP code. */
  async verify(
    member: Member,
    session: RealmSession,
    uid: string,
    method: MfaMethod,
    challengeId: string | null,
    code: string,
    ip: string,
  ): Promise<VerifyResult> {
    const submitted = code.replace(/\s+/g, '');
    const result = method === 'TOTP' ? await this.verifyTotpCode(member, session, uid, submitted) : await this.verifyOtp(member, session, uid, challengeId, submitted);
    await this.attempts
      .record({
        identifierHash: sha256Hex(`ITS:${member.itsId}`),
        itsId: member.itsId,
        clientId: null,
        ipAddress: ip,
        success: result.ok,
        failureReason: result.ok ? null : result.code,
        attemptType: 'MFA',
      })
      .catch((e: unknown) => this.logger.error(`mfa attempt write failed: ${String(e)}`));
    return result;
  }

  private async verifyOtp(member: Member, session: RealmSession, uid: string, challengeId: string | null, code: string): Promise<VerifyResult> {
    if (!challengeId || !/^[0-9a-f-]{36}$/i.test(challengeId)) return { ok: false, code: 'CODE_EXPIRED' };
    const challenge = await this.challenges.findById(challengeId);
    // The challenge must belong to this member, this Core session and this interaction.
    if (!challenge || challenge.itsId !== member.itsId || challenge.sid !== session.sid || challenge.interactionUid !== uid) {
      return { ok: false, code: 'CODE_EXPIRED' };
    }
    const attempt = await this.challenges.spendAttempt(challenge.id);
    if (attempt === null) {
      return challenge.attemptCount >= challenge.maxAttempts ? { ok: false, code: 'TOO_MANY_ATTEMPTS' } : { ok: false, code: 'CODE_EXPIRED' };
    }
    const real = safeEqual(this.codeHash(code, member.itsId, session.sid, uid), challenge.codeHash);
    const staticOtp = !real && this.isStaticCode(code);
    if (!real && !staticOtp) {
      const remaining = challenge.maxAttempts - attempt;
      return remaining > 0 ? { ok: false, code: 'INVALID_CODE', remaining } : { ok: false, code: 'TOO_MANY_ATTEMPTS' };
    }
    if (!(await this.challenges.consume(challenge.id))) return { ok: false, code: 'CODE_EXPIRED' };
    return { ok: true, method: challenge.channel === 'EMAIL' ? 'EMAIL_OTP' : 'SMS_OTP', ...(staticOtp ? { staticOtp } : {}) };
  }

  private async verifyTotpCode(member: Member, session: RealmSession, uid: string, code: string): Promise<VerifyResult> {
    const env = this.config.env;
    const limit = await this.rateLimit.hit('totp', `${session.sid}:${uid}`, env.OTP_MAX_ATTEMPTS, env.OTP_TTL_SECONDS);
    if (!limit.allowed) return { ok: false, code: 'TOO_MANY_ATTEMPTS' };
    const factor = (await this.factors.findActive(member.itsId)).find((f) => f.method === 'TOTP' && f.totpSecretEnc);
    if (!factor?.totpSecretEnc) return { ok: false, code: 'METHOD_UNAVAILABLE' };
    if (this.isStaticCode(code)) return { ok: true, method: 'TOTP', staticOtp: true };
    const secret = this.decrypt(factor.totpSecretEnc);
    const step = secret ? verifyTotp(secret, code) : null;
    if (step === null || !(await this.factors.acceptTotpStep(factor.id, step))) {
      return { ok: false, code: 'INVALID_CODE', remaining: Math.max(0, env.OTP_MAX_ATTEMPTS - 1) };
    }
    return { ok: true, method: 'TOTP' };
  }

  /** Testing only: the configured MFA_STATIC_OTP (never set in production). */
  private isStaticCode(code: string): boolean {
    const fixed = this.config.env.MFA_STATIC_OTP;
    return Boolean(fixed) && safeEqual(code, fixed);
  }

  /** HMAC bound to the member, session and interaction: a code is useless anywhere else. */
  private codeHash(code: string, itsId: string, sid: string, uid: string): string {
    return hmacHex(this.config.env.OTP_HMAC_KEY, `${code}:${itsId}:${sid}:${uid}`);
  }

  private decrypt(payload: string): string | null {
    try {
      return decryptString(this.dataKey, payload);
    } catch {
      this.logger.error('could not decrypt an MFA factor (wrong DATA_ENCRYPTION_KEY?)');
      return null;
    }
  }
}
