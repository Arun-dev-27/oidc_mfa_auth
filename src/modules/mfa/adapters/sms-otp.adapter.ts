import { Injectable } from '@nestjs/common';
import { AppConfig } from '../../../config/config.module';
import type { OtpDeliveryAdapter, OtpDeliveryResult, OtpMessage } from './otp-delivery.adapter';
import { writeToOutbox } from './outbox.writer';

/**
 * SMS OTP. Off by default (SMS_TRANSPORT=disabled). With SMS_TRANSPORT=http it POSTs JSON to a
 * gateway: { to, from, message } with "Authorization: Bearer SMS_HTTP_TOKEN". Adjust send() to the
 * chosen provider's API when one is selected.
 */
@Injectable()
export class SmsOtpAdapter implements OtpDeliveryAdapter {
  readonly channel = 'SMS' as const;

  constructor(private readonly config: AppConfig) {}

  isEnabled(): boolean {
    return this.config.env.SMS_TRANSPORT !== 'disabled';
  }

  async send(m: OtpMessage): Promise<OtpDeliveryResult> {
    const env = this.config.env;
    const text = `${m.code} is your Miqaat verification code. It expires in ${m.ttlMinutes} min. Do not share it.`;

    if (env.SMS_TRANSPORT === 'outbox') {
      return { providerMessageId: await writeToOutbox(env.OUTBOX_DIR, 'sms', m.to, text) };
    }
    if (env.SMS_TRANSPORT !== 'http') throw new Error('SMS delivery is disabled');

    const response = await fetch(env.SMS_HTTP_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(env.SMS_HTTP_TOKEN ? { authorization: `Bearer ${env.SMS_HTTP_TOKEN}` } : {}),
      },
      body: JSON.stringify({ to: m.to, from: env.SMS_SENDER_ID, message: text }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`SMS gateway answered ${response.status}`);
    const body = (await response.json().catch(() => ({}))) as { id?: string; messageId?: string };
    return { providerMessageId: body.id ?? body.messageId ?? null };
  }
}
