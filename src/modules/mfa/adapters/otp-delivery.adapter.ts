import type { OtpChannel } from '../../../database/entities';

export interface OtpMessage {
  /** Email address or phone number (plaintext, only in memory). */
  to: string;
  code: string;
  ttlMinutes: number;
  itsId: string;
}

export interface OtpDeliveryResult {
  providerMessageId: string | null;
}

/**
 * A 2FA delivery adapter. Email is the default; SMS plugs in behind the same interface, and a new
 * channel (WhatsApp, push, ...) only needs another implementation registered in OtpAdapterRegistry.
 * Implementations must never log the code.
 */
export interface OtpDeliveryAdapter {
  readonly channel: OtpChannel;
  /** false when the adapter is switched off by configuration. */
  isEnabled(): boolean;
  send(message: OtpMessage): Promise<OtpDeliveryResult>;
}

export const OTP_DELIVERY_ADAPTERS = Symbol('OTP_DELIVERY_ADAPTERS');
