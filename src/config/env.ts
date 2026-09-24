import { z } from 'zod';

const bool = (fallback: boolean) =>
  z
    .enum(['true', 'false', '1', '0'])
    .optional()
    .transform((v) => (v === undefined ? fallback : v === 'true' || v === '1'));

export const CLIENT_AUTH_METHOD_VALUES = ['client_secret_basic', 'private_key_jwt', 'client_secret_post'] as const;
export type ClientAuthMethod = (typeof CLIENT_AUTH_METHOD_VALUES)[number];

const int = (fallback: number, min = 0) => z.coerce.number().int().min(min).default(fallback);

const csv = z
  .string()
  .default('')
  .transform((v) =>
    v
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );

/**
 * Every setting the service reads. Parsed once at start-up; an invalid value stops the process
 * instead of surfacing later as a confusing runtime error.
 */
export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: int(4000, 1),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
    /** false | number of trusted proxy hops. "true" would trust a client-supplied X-Forwarded-For. */
    TRUST_PROXY: z
      .string()
      .default('false')
      .refine((v) => v === 'false' || /^[0-9]+$/.test(v), 'TRUST_PROXY must be false or a hop count')
      .transform((v) => (v === 'false' ? false : Number(v))),

    /** Public issuer: the externally visible origin of this service, no trailing slash. */
    ISSUER: z.string().url().transform((v) => v.replace(/\/+$/, '')),

    // --- Existing identity database ---------------------------------------------------------
    DB_HOST: z.string().min(1),
    DB_PORT: int(5432, 1),
    DB_NAME: z.string().min(1),
    DB_SCHEMA: z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/, 'DB_SCHEMA must be a plain lower-case identifier'),
    DB_USER: z.string().min(1),
    DB_PASSWORD: z.string().min(1),
    DB_SSL: bool(false),
    DB_POOL_MAX: int(20, 1),

    // --- Redis ------------------------------------------------------------------------------
    REDIS_URL: z.string().min(1),
    REDIS_KEY_PREFIX: z.string().default('oidcmfa:'),

    // --- Login rules ------------------------------------------------------------------------
    /** mumin_master.status_id that counts as an active member (legacy Status_ID = 3). */
    ACTIVE_STATUS_ID: int(3),
    /** true: the ITS ID must be present in user_eligible. false: no eligibility check at all. */
    LOGIN_ELIGIBILITY_CHECK_ENABLED: bool(true),
    LOGIN_NOT_ELIGIBLE_MESSAGE: z.string().default('You are not eligible to sign in. Please contact your Jamaat office.'),
    LOGIN_MAX_FAILURES_PER_ACCOUNT: int(5, 1),
    LOGIN_ACCOUNT_LOCK_SECONDS: int(900, 1),
    LOGIN_MAX_ATTEMPTS_PER_IP: int(30, 1),
    LOGIN_IP_WINDOW_SECONDS: int(300, 1),

    // --- Core realm sessions ----------------------------------------------------------------
    SSO_COOKIE_ADMIN: z.string().default('__Host-miqaat-admin-sso'),
    SSO_COOKIE_MUMIN: z.string().default('__Host-miqaat-mumin-sso'),
    COOKIE_SECURE: bool(true),
    SESSION_IDLE_TTL_SECONDS: int(1800, 30),
    SESSION_ABSOLUTE_TTL_SECONDS: int(28800, 30),
    /** Signing keys for oidc-provider's own cookies (comma separated, newest first, 32+ chars each). */
    OIDC_COOKIE_KEYS: csv.refine((keys) => keys.length > 0 && keys.every((k) => k.length >= 32), 'OIDC_COOKIE_KEYS needs at least one key of 32+ characters'),
    /** HMAC key for the SSR form CSRF tokens (32+ chars). */
    CSRF_SECRET: z.string().min(32),
    /**
     * Client authentication methods Core accepts at /token and at the handoff API (comma separated).
     * Standard: client_secret_basic only. private_key_jwt / client_secret_post can be re-enabled here;
     * a client registered for a method that is not listed cannot authenticate.
     */
    CLIENT_AUTH_METHODS: z
      .string()
      .default('client_secret_basic')
      .transform((v) => [...new Set(v.split(',').map((s) => s.trim()).filter(Boolean))])
      .refine((v) => v.length > 0 && v.every((m) => (CLIENT_AUTH_METHOD_VALUES as readonly string[]).includes(m)), 'CLIENT_AUTH_METHODS: one or more of client_secret_basic, private_key_jwt, client_secret_post')
      .transform((v) => v as ClientAuthMethod[]),

    // --- Tokens -----------------------------------------------------------------------------
    AUTH_CODE_TTL_SECONDS: int(60, 10),
    ID_TOKEN_TTL_SECONDS: int(300, 60),
    ACCESS_TOKEN_TTL_SECONDS: int(600, 60),
    INTERACTION_TTL_SECONDS: int(600, 60),

    // --- Logout (spec §24-31) -----------------------------------------------------------------
    /** Lifetime of the signed back-channel logout JWS. */
    LOGOUT_TOKEN_TTL_SECONDS: int(120, 30),
    /** Delivery attempts: delay before attempt 1, 2, ... (spec: immediate, 5 s, 30 s, 2 min, 10 min, 30 min). */
    LOGOUT_RETRY_SCHEDULE_SECONDS: csv
      .transform((v) => (v.length ? v : ['0', '5', '30', '120', '600', '1800']).map(Number))
      .refine((v) => v.every((n) => Number.isInteger(n) && n >= 0), 'LOGOUT_RETRY_SCHEDULE_SECONDS: comma separated seconds'),
    LOGOUT_WORKER_ENABLED: bool(true),
    LOGOUT_WORKER_INTERVAL_MS: int(2000, 200),
    LOGOUT_HTTP_TIMEOUT_MS: int(5000, 500),

    // --- Trusted handoff (Handoff spec) -------------------------------------------------------
    /** How long the one-time browser URL of a handoff request stays usable. */
    HANDOFF_REQUEST_TTL_SECONDS: int(90, 5),
    /** Lifetime of the signed handoff assertion (spec: 60 s). */
    HANDOFF_ASSERTION_TTL_SECONDS: int(60, 10),
    /** Handoff requests per source client per minute. */
    HANDOFF_RATE_LIMIT_PER_MINUTE: int(60, 1),

    // --- Signing keys -----------------------------------------------------------------------
    /** file: private JWKs in SIGNING_KEYS_FILE (development). kms: AWS KMS keys listed in signing_key_metadata. */
    SIGNING_KEY_PROVIDER: z.enum(['file', 'kms']).default('file'),
    SIGNING_KEYS_FILE: z.string().default('./.keys/signing-keys.json'),
    AWS_REGION: z.string().default('ap-south-1'),
    /** LocalStack / custom endpoint for development only; refused in production. */
    AWS_ENDPOINT_URL: z.union([z.string().url(), z.literal('')]).default(''),

    // --- Client secrets ---------------------------------------------------------------------
    /** 32-byte key (base64 or hex) that encrypts client secrets and MFA destinations/secrets at rest. */
    DATA_ENCRYPTION_KEY: z.string().min(32),

    // --- MFA --------------------------------------------------------------------------------
    MFA_DEFAULT_METHOD: z.enum(['EMAIL_OTP', 'SMS_OTP', 'TOTP']).default('EMAIL_OTP'),
    /** Platform cap on how old an MFA may be and still be reused (spec: Core caps freshness). */
    MFA_MAX_AGE_SECONDS: int(1800, 60),
    /** Require AAL2 for every login, whatever the client asks for. */
    MFA_REQUIRED_FOR_ALL: bool(false),
    /** Honour the legacy users.is_otprequired flag: those users always get MFA. */
    MFA_HONOR_USER_OTP_FLAG: bool(true),
    OTP_LENGTH: int(6, 4),
    OTP_TTL_SECONDS: int(300, 30),
    OTP_MAX_ATTEMPTS: int(5, 1),
    OTP_RESEND_COOLDOWN_SECONDS: int(30, 0),
    OTP_MAX_SENDS_PER_HOUR: int(10, 1),
    /** HMAC key for OTP hashes (32+ chars). */
    OTP_HMAC_KEY: z.string().min(32),
    /**
     * TESTING ONLY. When set (e.g. 123456), this code is accepted for every member and every method -
     * Email OTP, SMS OTP and TOTP - besides the real code; members without any method get an Email-OTP
     * style step that only this code completes, and the hourly OTP cap is not applied.
     * Empty = off (default). Refused in production.
     */
    MFA_STATIC_OTP: z
      .string()
      .default('')
      .transform((v) => v.trim())
      .refine((v) => v === '' || /^[0-9]{4,8}$/.test(v), 'MFA_STATIC_OTP: 4-8 digits (e.g. 123456) or empty'),

    // --- Email adapter ----------------------------------------------------------------------
    /** smtp: real mail. outbox: writes each message to OUTBOX_DIR (development only). */
    EMAIL_TRANSPORT: z.enum(['smtp', 'outbox']).default('smtp'),
    SMTP_HOST: z.string().default(''),
    SMTP_PORT: int(587, 1),
    SMTP_SECURE: bool(false),
    SMTP_USER: z.string().default(''),
    SMTP_PASSWORD: z.string().default(''),
    EMAIL_FROM: z.string().default('Miqaat <no-reply@miqaat.com>'),

    // --- SMS adapter ------------------------------------------------------------------------
    /** disabled | http (JSON POST to SMS_HTTP_URL) | outbox (development only). */
    SMS_TRANSPORT: z.enum(['disabled', 'http', 'outbox']).default('disabled'),
    SMS_HTTP_URL: z.string().default(''),
    SMS_HTTP_TOKEN: z.string().default(''),
    SMS_SENDER_ID: z.string().default('MIQAAT'),

    OUTBOX_DIR: z.string().default('./.outbox'),

    // --- Branding on the SSR pages ----------------------------------------------------------
    BRAND_TAGLINE: z.string().default('Your Miqaat, in one place'),
    /**
     * Shown at the top of every Core page when set, e.g. on a hosted test environment:
     * "Test environment - test accounts only. Never enter a real ITS password." Empty = no banner.
     */
    ENVIRONMENT_BANNER: z.string().default(''),
    /** Google Search Console ownership token (meta google-site-verification), e.g. to request a Safe Browsing review. */
    GOOGLE_SITE_VERIFICATION: z
      .string()
      .default('')
      .refine((v) => v === '' || /^[A-Za-z0-9_-]{10,100}$/.test(v), 'GOOGLE_SITE_VERIFICATION: the token only (letters, digits, - and _)'),
    /** Optional link for "Forgot password?" (hidden when empty). */
    FORGOT_PASSWORD_URL: z.union([z.string().url(), z.literal('')]).default(''),
  })
  .superRefine((env, ctx) => {
    for (const key of ['SSO_COOKIE_ADMIN', 'SSO_COOKIE_MUMIN'] as const) {
      if (env[key].startsWith('__Host-') && !env.COOKIE_SECURE) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: '__Host- cookies require COOKIE_SECURE=true (use a name without the prefix for plain-http local development)' });
      }
    }
    if (env.SSO_COOKIE_ADMIN === env.SSO_COOKIE_MUMIN) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SSO_COOKIE_MUMIN'], message: 'ADMIN and MUMIN realms must use different cookies' });
    }
    if (env.NODE_ENV === 'production') {
      if (!env.COOKIE_SECURE) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['COOKIE_SECURE'], message: 'must be true in production' });
      if (!env.ISSUER.startsWith('https://')) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ISSUER'], message: 'must be https in production' });
      if (env.EMAIL_TRANSPORT === 'outbox') ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['EMAIL_TRANSPORT'], message: 'outbox is for development only' });
      if (env.SMS_TRANSPORT === 'outbox') ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SMS_TRANSPORT'], message: 'outbox is for development only' });
      if (env.SIGNING_KEY_PROVIDER !== 'kms') ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SIGNING_KEY_PROVIDER'], message: 'production signing keys must live in KMS (SIGNING_KEY_PROVIDER=kms)' });
      if (env.AWS_ENDPOINT_URL) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['AWS_ENDPOINT_URL'], message: 'must be empty in production' });
      if (env.MFA_STATIC_OTP) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['MFA_STATIC_OTP'], message: 'a static OTP is for testing only and must be empty in production' });
    }
    if (env.MFA_STATIC_OTP && env.MFA_STATIC_OTP.length !== env.OTP_LENGTH) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['MFA_STATIC_OTP'], message: `must have OTP_LENGTH (${env.OTP_LENGTH}) digits` });
    }
    if (env.EMAIL_TRANSPORT === 'smtp' && !env.SMTP_HOST) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SMTP_HOST'], message: 'required when EMAIL_TRANSPORT=smtp' });
    }
    if (env.SMS_TRANSPORT === 'http' && !env.SMS_HTTP_URL) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SMS_HTTP_URL'], message: 'required when SMS_TRANSPORT=http' });
    }
  });

export type Env = z.infer<typeof envSchema>;

/** Loads a .env file (if present) without overriding variables already set by the environment. */
export function loadDotEnv(path = '.env'): void {
  // Node >= 20.12 ships process.loadEnvFile; it never overrides existing variables.
  try {
    process.loadEnvFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

export function parseEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
    throw new Error(`Invalid configuration:\n${lines.join('\n')}`);
  }
  return result.data;
}
