/**
 * Adds a second-factor method for a member (admin / support tool).
 *
 *   npm run mfa:add-factor -- --its 10110101 --method EMAIL_OTP --destination member@example.com [--default]
 *   npm run mfa:add-factor -- --its 10110101 --method SMS_OTP   --destination +919800000000
 *   npm run mfa:add-factor -- --its 10110101 --method TOTP                       (prints the otpauth:// URI once)
 *
 * Without any factor a member gets Email OTP to mumin_master.email - this is for overrides and extra methods.
 */
import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { encryptString, toKey32 } from '../src/common/crypto.util';
import AppDataSource from '../src/database/data-source';
import { UserMfaFactor, type MfaMethod } from '../src/database/entities';
import { MfaFactorRepository } from '../src/database/repositories/mfa.repository';
import { base32Encode } from '../src/modules/mfa/totp';
import { one, parseArgs } from './cli-args';

async function main() {
  const args = parseArgs();
  const itsId = one(args, 'its');
  if (!/^[0-9]{1,10}$/.test(itsId)) throw new Error('--its must be an ITS ID');
  const method = one(args, 'method').toUpperCase() as MfaMethod;
  if (!['EMAIL_OTP', 'SMS_OTP', 'TOTP'].includes(method)) throw new Error('--method must be EMAIL_OTP, SMS_OTP or TOTP');
  const key = toKey32(process.env.DATA_ENCRYPTION_KEY ?? '');

  let destinationEnc: string | null = null;
  let totpSecretEnc: string | null = null;
  let totpSecret: string | null = null;
  if (method === 'TOTP') {
    totpSecret = base32Encode(randomBytes(20));
    totpSecretEnc = encryptString(key, totpSecret);
  } else {
    const destination = one(args, 'destination').trim();
    if (method === 'EMAIL_OTP' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(destination)) throw new Error('invalid email');
    if (method === 'SMS_OTP' && !/^\+?[0-9]{8,15}$/.test(destination)) throw new Error('invalid phone number (E.164 digits)');
    destinationEnc = encryptString(key, destination);
  }

  await AppDataSource.initialize();
  try {
    const repo = new MfaFactorRepository(AppDataSource.getRepository(UserMfaFactor));
    const factor = await repo.create({ itsId, method, isDefault: args.has('default'), destinationEnc, totpSecretEnc });
    console.log(`added ${method} factor ${factor.id} for ${itsId}${factor.isDefault ? ' (default)' : ''}`);
    if (totpSecret) {
      console.log(`otpauth://totp/Miqaat:${itsId}?secret=${totpSecret}&issuer=Miqaat&algorithm=SHA1&digits=6&period=30`);
    }
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
