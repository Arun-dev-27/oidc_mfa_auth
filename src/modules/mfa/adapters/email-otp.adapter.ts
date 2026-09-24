import { Injectable } from '@nestjs/common';
import { createTransport, type Transporter } from 'nodemailer';
import { AppConfig } from '../../../config/config.module';
import type { OtpDeliveryAdapter, OtpDeliveryResult, OtpMessage } from './otp-delivery.adapter';
import { writeToOutbox } from './outbox.writer';

/** Email OTP - the default second factor. SMTP in real environments, file outbox in development. */
@Injectable()
export class EmailOtpAdapter implements OtpDeliveryAdapter {
  readonly channel = 'EMAIL' as const;
  private transporter: Transporter | null = null;

  constructor(private readonly config: AppConfig) {}

  isEnabled(): boolean {
    return true;
  }

  async send(m: OtpMessage): Promise<OtpDeliveryResult> {
    const env = this.config.env;
    const subject = 'Your Miqaat sign-in code';
    const text =
      `Your Miqaat verification code is ${m.code}\n\n` +
      `It expires in ${m.ttlMinutes} minutes. Do not share it with anyone.\n` +
      `If you did not try to sign in, you can ignore this email.`;

    if (env.EMAIL_TRANSPORT === 'outbox') {
      return { providerMessageId: await writeToOutbox(env.OUTBOX_DIR, 'email', m.to, `Subject: ${subject}\n\n${text}`) };
    }

    const info = await this.smtp().sendMail({ from: env.EMAIL_FROM, to: m.to, subject, text });
    return { providerMessageId: info.messageId ?? null };
  }

  private smtp(): Transporter {
    if (!this.transporter) {
      const env = this.config.env;
      this.transporter = createTransport({
        host: env.SMTP_HOST,
        port: env.SMTP_PORT,
        secure: env.SMTP_SECURE,
        auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASSWORD } : undefined,
      });
    }
    return this.transporter;
  }
}
