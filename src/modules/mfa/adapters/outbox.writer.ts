import { mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

/**
 * Development-only "mail catcher": writes each outgoing message to OUTBOX_DIR as a file, so the
 * OTP flow can be tested locally without an SMTP server or SMS gateway. Refused in production by
 * the env schema.
 */
export async function writeToOutbox(dir: string, channel: 'email' | 'sms', to: string, body: string): Promise<string> {
  const id = randomUUID();
  const folder = resolve(dir);
  await mkdir(folder, { recursive: true });
  const file = join(folder, `${new Date().toISOString().replace(/[:.]/g, '-')}_${channel}_${id}.txt`);
  await writeFile(file, `To: ${to}\nChannel: ${channel}\n\n${body}\n`, { encoding: 'utf8', mode: 0o600 });
  return `outbox:${id}`;
}
