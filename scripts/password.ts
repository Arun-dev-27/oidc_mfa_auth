/**
 * Legacy password cipher tool (users.password format).
 *
 *   npm run password -- encrypt --value '<plain>'     prints a ciphertext the legacy Decrypt() accepts
 *   npm run password -- verify --its 10110101 --value '<plain>'
 *                                                      checks a password against users.password (read only)
 *   npm run password -- roundtrip                      decrypt -> encrypt -> decrypt every stored password
 *                                                      and report mismatches (never prints passwords)
 *
 *   npm run password -- show --its 10110101         (development only) prints the member's password for manual testing
 * This service never writes users.password (the table belongs to the Mumin sync service); the
 * ciphertext from `encrypt` is for the owning system / test data.
 */
import 'reflect-metadata';
import AppDataSource from '../src/database/data-source';
import { safeEqual } from '../src/common/crypto.util';
import { decrypt, encrypt } from '../src/modules/identity/legacy-password-cipher';
import { one, parseArgs } from './cli-args';

async function main() {
  const [command] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const args = parseArgs();

  if (command === 'encrypt') {
    const value = one(args, 'value');
    console.log(encrypt(value));
    return;
  }

  await AppDataSource.initialize();
  try {
    if (command === 'verify') {
      const itsId = Number(one(args, 'its'));
      const [row] = await AppDataSource.query('SELECT password FROM users WHERE mumin_id = $1 AND NOT is_source_deleted ORDER BY id DESC LIMIT 1', [itsId]);
      const ok = Boolean(row?.password) && safeEqual(decrypt(row.password), one(args, 'value'));
      console.log(ok ? 'MATCH' : 'NO MATCH');
      process.exitCode = ok ? 0 : 2;
      return;
    }
    if (command === 'show') {
      // Local testing only: shows a member's plaintext so you can type it on the login page.
      if (process.env.NODE_ENV === 'production') throw new Error('show is disabled in production');
      const itsId = Number(one(args, 'its'));
      const [row] = await AppDataSource.query('SELECT password FROM users WHERE mumin_id = $1 AND NOT is_source_deleted ORDER BY id DESC LIMIT 1', [itsId]);
      console.log(row?.password ? decrypt(row.password) : `no password stored for ${itsId}`);
      return;
    }
    if (command === 'roundtrip') {
      const rows: { mumin_id: number; password: string }[] = await AppDataSource.query('SELECT mumin_id, password FROM users WHERE password IS NOT NULL');
      let failed = 0;
      for (const r of rows) {
        const plain = decrypt(r.password);
        const again = encrypt(plain);
        const ok = decrypt(again) === plain && again !== r.password;
        if (!ok) failed++;
        console.log(`${r.mumin_id}: ${ok ? 'ok (new random ciphertext decrypts to the same password)' : 'FAILED'}`);
      }
      console.log(`${rows.length - failed}/${rows.length} passwords round-trip`);
      process.exitCode = failed ? 1 : 0;
      return;
    }
    throw new Error('usage: npm run password -- encrypt|verify|show|roundtrip ...');
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
