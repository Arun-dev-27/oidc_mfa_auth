import { AuthAuditEvent } from './auth/auth-audit-event.entity';
import { AuthClientCallback } from './auth/auth-client-callback.entity';
import { AuthClient } from './auth/auth-client.entity';
import { AuthLoginAttempt } from './auth/auth-login-attempt.entity';
import { AuthOtpChallenge } from './auth/auth-otp-challenge.entity';
import { AuthSessionClient } from './auth/auth-session-client.entity';
import { AuthSession } from './auth/auth-session.entity';
import { LogoutDelivery, LogoutJob } from './auth/logout.entity';
import { HandoffPath, HandoffRequest } from './auth/handoff.entity';
import { SigningKeyMetadata } from './auth/signing-key-metadata.entity';
import { UserMfaFactor } from './auth/user-mfa-factor.entity';
import { IdentityUser } from './identity/identity-user.entity';
import { MuminMaster } from './identity/mumin-master.entity';
import { UserEligible } from './identity/user-eligible.entity';

export * from './auth/auth-realm';
export type { ClientStatus, TokenEndpointAuthMethod } from './auth/auth-client.entity';
export type { CallbackUriType } from './auth/auth-client-callback.entity';
export type { MfaMethod, SessionStatus } from './auth/auth-session.entity';
export type { AttemptType } from './auth/auth-login-attempt.entity';
export type { AuditOutcome } from './auth/auth-audit-event.entity';
export type { SigningKeyStatus } from './auth/signing-key-metadata.entity';
export type { MfaFactorStatus } from './auth/user-mfa-factor.entity';
export type { OtpChannel, OtpPurpose } from './auth/auth-otp-challenge.entity';
export type { LogoutDeliveryStatus, LogoutJobStatus } from './auth/logout.entity';
export type { HandoffStatus } from './auth/handoff.entity';
export {
  AuthAuditEvent,
  AuthClient,
  AuthClientCallback,
  AuthLoginAttempt,
  AuthOtpChallenge,
  AuthSession,
  AuthSessionClient,
  HandoffPath,
  HandoffRequest,
  IdentityUser,
  LogoutDelivery,
  LogoutJob,
  MuminMaster,
  SigningKeyMetadata,
  UserEligible,
  UserMfaFactor,
};

/** Synced tables owned by the Mumin sync service: SELECT only, never created or altered here. */
export const SYNCED_ENTITIES = [IdentityUser, MuminMaster, UserEligible];

export const AUTH_ENTITIES = [
  AuthClient,
  AuthClientCallback,
  AuthSession,
  AuthSessionClient,
  AuthLoginAttempt,
  AuthAuditEvent,
  SigningKeyMetadata,
  UserMfaFactor,
  AuthOtpChallenge,
  LogoutJob,
  LogoutDelivery,
  HandoffPath,
  HandoffRequest,
];

export const ALL_ENTITIES = [...SYNCED_ENTITIES, ...AUTH_ENTITIES];
