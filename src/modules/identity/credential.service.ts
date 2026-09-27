import { Injectable, Logger } from '@nestjs/common';
import { AppConfig } from '../../config/config.module';
import { safeEqual, sha256Hex } from '../../common/crypto.util';
import { IdentityAccountRepository, type LoginAccount } from '../../database/repositories/identity-account.repository';
import { LoginAttemptRepository } from '../../database/repositories/login-attempt.repository';
import { CaptchaService } from './captcha.service';
import { decrypt } from './legacy-password-cipher';

/** users.mumin_id is a PostgreSQL integer: anything else can never be an account. */
const ITS_ID = /^[0-9]{1,10}$/;
const INT4_MAX = 2_147_483_647;
const WRONG_PASSWORD = 'INVALID_PASSWORD';
/**
 * Failed password logins that count towards the captcha: wrong password, unknown / inactive / malformed ID and
 * attempts on a locked account. Unknown IDs count the same as real ones, so the captcha reveals nothing.
 * Captcha refusals themselves never count (the password was not checked).
 */
const CAPTCHA_COUNTED = [WRONG_PASSWORD, 'ACCOUNT_NOT_FOUND_OR_INACTIVE', 'NO_PASSWORD', 'MALFORMED_ITS_ID', 'ACCOUNT_TEMPORARILY_LOCKED'];

export interface Member {
  /** ITS ID (users.mumin_id) - the OIDC sub. */
  itsId: string;
  displayName: string | null;
  email: string | null;
  /** Legacy users.is_otprequired. */
  otpRequired: boolean;
}

export type CredentialFailure =
  | { code: 'INVALID_CREDENTIALS' }
  | { code: 'ACCOUNT_LOCKED'; retryAfterSeconds: number }
  | { code: 'ACCOUNT_UNAVAILABLE' }
  | { code: 'NOT_ELIGIBLE'; message: string }
  | { code: 'CAPTCHA_REQUIRED' | 'CAPTCHA_INVALID' | 'CAPTCHA_UNAVAILABLE' };

/** `captcha`: the next login form for this ID must show the captcha. */
export type CredentialResult = { ok: true; member: Member } | { ok: false; failure: CredentialFailure; itsId: string | null; captcha: boolean };

export interface AttemptContext {
  ip: string;
  clientId: string | null;
  /** Google reCAPTCHA token from the form (g-recaptcha-response), when the widget was shown. */
  captchaToken?: string;
}

export function toMuminId(identifier: string): number | null {
  const trimmed = identifier.trim();
  if (!ITS_ID.test(trimmed)) return null;
  const value = Number(trimmed);
  return value > 0 && value <= INT4_MAX ? value : null;
}

/**
 * Primary authentication against the EXISTING identity tables (read only).
 *
 * Order of checks:
 *  0. captcha     only when LOGIN_CAPTCHA_ENABLED and this ID has LOGIN_CAPTCHA_AFTER_FAILURES recent failures:
 *                 a valid reCAPTCHA token is required before the password is even looked at
 *  1. account     users JOIN mumin_master, status_id = ACTIVE_STATUS_ID, not deleted at source
 *  2. lockout     durable count of wrong passwords (auth_login_attempts), when LOGIN_ACCOUNT_LOCK_ENABLED
 *  3. password    legacy Decrypt(users.password) == submitted password
 *  4. allow_login COALESCE(allow_login, true)
 *  5. eligible    user_eligible - ONLY when LOGIN_ELIGIBILITY_CHECK_ENABLED=true
 *
 * The allow_login / eligibility outcomes are revealed only after a correct password, so the form
 * cannot be used to learn which ITS IDs exist or are eligible.
 */
@Injectable()
export class CredentialService {
  private readonly logger = new Logger(CredentialService.name);

  constructor(
    private readonly accounts: IdentityAccountRepository,
    private readonly attempts: LoginAttemptRepository,
    private readonly config: AppConfig,
    private readonly captcha: CaptchaService,
  ) {}

  /** True when the login form for this identifier must show the captcha (also for the first form when the threshold is 0). */
  async captchaRequiredFor(identifier: string): Promise<boolean> {
    if (!this.captcha.enabled) return false;
    const threshold = this.config.env.LOGIN_CAPTCHA_AFTER_FAILURES;
    if (threshold === 0) return true;
    const trimmed = identifier.trim();
    if (!trimmed) return false;
    return (await this.attempts.recentIdentifierFailures(idHashOf(trimmed), CAPTCHA_COUNTED, this.config.env.LOGIN_CAPTCHA_WINDOW_SECONDS)) >= threshold;
  }

  async verifyPassword(identifier: string, password: string, ctx: AttemptContext): Promise<CredentialResult> {
    const env = this.config.env;
    const idHash = idHashOf(identifier.trim());
    const muminId = toMuminId(identifier);
    const typedId = muminId === null ? null : String(muminId);
    const fail = async (failure: CredentialFailure, itsId: string | null): Promise<CredentialResult> => ({
      ok: false,
      failure,
      itsId,
      captcha: await this.captchaRequiredFor(identifier),
    });

    // 0. Captcha gate: once required, nothing else (not even the password) is checked without a valid token,
    //    so automated guessing can neither continue nor lock the account.
    if (await this.captchaRequiredFor(identifier)) {
      const check = await this.captcha.verify(ctx.captchaToken, ctx.ip);
      if (!check.ok) {
        await this.record(idHash, typedId, ctx, false, check.code);
        return { ok: false, failure: { code: check.code }, itsId: typedId, captcha: true };
      }
    }

    if (muminId === null) {
      await this.record(idHash, null, ctx, false, 'MALFORMED_ITS_ID');
      return fail({ code: 'INVALID_CREDENTIALS' }, null);
    }
    const itsId = String(muminId);

    const account = await this.accounts.findLoginAccount(muminId, env.ACTIVE_STATUS_ID);
    if (!account || !account.password) {
      // Same decrypt-and-compare work as a real account, so an unknown ID is not faster to reject.
      safeEqual(decrypt('00'), password);
      await this.record(idHash, itsId, ctx, false, account ? 'NO_PASSWORD' : 'ACCOUNT_NOT_FOUND_OR_INACTIVE');
      return fail({ code: 'INVALID_CREDENTIALS' }, itsId);
    }

    const retryAfter = await this.lockedFor(itsId);
    if (retryAfter > 0) {
      await this.record(idHash, itsId, ctx, false, 'ACCOUNT_TEMPORARILY_LOCKED');
      return fail({ code: 'ACCOUNT_LOCKED', retryAfterSeconds: retryAfter }, itsId);
    }

    const plaintext = decrypt(account.password);
    if (!plaintext || !safeEqual(plaintext, password)) {
      await this.record(idHash, itsId, ctx, false, WRONG_PASSWORD);
      return fail({ code: 'INVALID_CREDENTIALS' }, itsId);
    }

    const gate = await this.loginGate(account, muminId);
    if (gate) {
      await this.record(idHash, itsId, ctx, false, gate.code);
      return fail(gate, itsId);
    }

    await this.record(idHash, itsId, ctx, true, null);
    return { ok: true, member: toMember(account) };
  }

  /**
   * Re-checks a member for SSO continuation (no password): still active, allowed and eligible.
   * A member who was disabled after signing in is not silently carried into another application.
   */
  async getActiveMember(itsId: string): Promise<Member | null> {
    const muminId = toMuminId(itsId);
    if (muminId === null) return null;
    const account = await this.accounts.findLoginAccount(muminId, this.config.env.ACTIVE_STATUS_ID);
    if (!account || !account.password) return null;
    if (await this.loginGate(account, muminId)) return null;
    return toMember(account);
  }

  private async loginGate(account: LoginAccount, muminId: number): Promise<CredentialFailure | null> {
    if (!account.allowLogin) return { code: 'ACCOUNT_UNAVAILABLE' };
    if (this.config.env.LOGIN_ELIGIBILITY_CHECK_ENABLED && !(await this.accounts.isEligible(muminId))) {
      return { code: 'NOT_ELIGIBLE', message: this.config.env.LOGIN_NOT_ELIGIBLE_MESSAGE };
    }
    return null;
  }

  private async lockedFor(itsId: string): Promise<number> {
    const env = this.config.env;
    if (!env.LOGIN_ACCOUNT_LOCK_ENABLED) return 0;
    const { failures, secondsSinceLast } = await this.attempts.recentFailures(itsId, 'LOGIN', WRONG_PASSWORD, env.LOGIN_ACCOUNT_LOCK_SECONDS);
    if (failures < env.LOGIN_MAX_FAILURES_PER_ACCOUNT) return 0;
    return Math.max(1, Math.ceil(env.LOGIN_ACCOUNT_LOCK_SECONDS - (secondsSinceLast ?? 0)));
  }

  private async record(idHash: string, itsId: string | null, ctx: AttemptContext, success: boolean, reason: string | null) {
    try {
      await this.attempts.record({
        identifierHash: idHash,
        itsId,
        clientId: ctx.clientId,
        ipAddress: ctx.ip,
        success,
        failureReason: reason,
        attemptType: 'LOGIN',
      });
    } catch (error) {
      this.logger.error(`login attempt write failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

/** Same identifier hash as auth_login_attempts.identifier_hash. */
function idHashOf(trimmedIdentifier: string): string {
  return sha256Hex(`ITS:${trimmedIdentifier}`);
}

function toMember(a: LoginAccount): Member {
  return {
    itsId: String(a.muminId),
    displayName: a.fullname?.trim() || null,
    email: a.email?.trim() || null,
    otpRequired: a.isOtpRequired === true,
  };
}
