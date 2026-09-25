/**
 * Checks the SMTP settings (SMTP_* / EMAIL_FROM from .env) and optionally sends one test email.
 *
 *   npm run email:test                          -> login check only (nothing is sent)
 *   npm run email:test -- --to you@example.com  -> login check + one test email
 *
 * Uses the same transport options as the Email OTP adapter. Never prints the SMTP password.
 */
import { createTransport } from 'nodemailer';
import { loadDotEnv } from '../src/config/env';
import { parseArgs } from './cli-args';

loadDotEnv();

async function main() {
  const to = parseArgs().get('to')?.[0];
  const host = process.env.SMTP_HOST ?? '';
  if (!host) throw new Error('SMTP_HOST is not set in .env');
  const port = Number(process.env.SMTP_PORT ?? 587);
  const secure = ['true', '1'].includes(process.env.SMTP_SECURE ?? '');
  const user = process.env.SMTP_USER ?? '';
  const from = process.env.EMAIL_FROM || 'Miqaat <no-reply@miqaat.com>';
  const transporter = createTransport({ host, port, secure, auth: user ? { user, pass: process.env.SMTP_PASSWORD ?? '' } : undefined });

  console.log(`SMTP ${host}:${port} (${secure ? 'TLS' : 'STARTTLS'}) as ${user || '(no login)'}, from ${from}`);
  await transporter.verify();
  console.log('  login OK');
  if (!to) return console.log('  no --to given: nothing sent');

  const info = await transporter.sendMail({
    from,
    to,
    subject: 'Miqaat sign-in: SMTP test',
    text: 'This is a test email from the Miqaat authentication service (npm run email:test). No action is needed.',
  });
  console.log(`  sent to ${to}: ${info.messageId ?? ''} ${info.response ?? ''}`);
}

main().catch((e: { code?: string; response?: string; message?: string }) => {
  console.error(`SMTP check FAILED: ${e.code ?? ''} ${e.response ?? e.message ?? String(e)}`);
  if (/Unauthorized IP/i.test(e.response ?? '')) console.error('  Brevo blocks this IP: add it under Security -> Authorised IPs (or turn the IP restriction off).');
  process.exit(1);
});
