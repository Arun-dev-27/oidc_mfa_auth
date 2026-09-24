/**
 * Prepares a FRESH non-production database (e.g. a hosted demo on Render) for oidc_mfa_auth:
 *
 *   npm run seed:dev-db -- --yes
 *
 *   1. creates the identity schema from db/dev-bootstrap-schema.sql when it does not exist yet, and
 *      records the oidc_mfa_auth migrations it already contains as applied;
 *   2. creates the fixed test members 10110101..10110110 (password Test@001..Test@010, stored with the
 *      legacy cipher) and their MFA factors (encrypted with this environment's DATA_ENCRYPTION_KEY).
 *
 * Nothing is copied from another database. It only ever writes those ten test ITS IDs, refuses
 * NODE_ENV=production, and refuses a database whose users table holds anyone else (a real, synced
 * identity database must never be seeded).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { encryptString, sha256Hex, toKey32 } from '../src/common/crypto.util';
import { loadDotEnv } from '../src/config/env';
import { encrypt } from '../src/modules/identity/legacy-password-cipher';
import { base32Encode } from '../src/modules/mfa/totp';

loadDotEnv();

interface TestMember {
  itsId: number;
  first: string;
  last: string;
  email: string | null;
  statusId: number;
  allowLogin: boolean | null;
  eligible: boolean;
  factors: { method: 'EMAIL_OTP' | 'SMS_OTP' | 'TOTP'; isDefault: boolean; destination?: string }[];
}

/** Same profiles as the local test data and the e2e suite (scripts/e2e-suite.ts, const M). */
const MEMBERS: TestMember[] = [
  { itsId: 10110101, first: 'Test', last: 'Member 101', email: 'member.10110101@example.test', statusId: 3, allowLogin: true, eligible: true, factors: [{ method: 'EMAIL_OTP', isDefault: true, destination: 'member.10110101@example.test' }, { method: 'SMS_OTP', isDefault: false, destination: '+919800000101' }] },
  { itsId: 10110102, first: 'Test', last: 'Member 102', email: null, statusId: 3, allowLogin: true, eligible: true, factors: [] },
  { itsId: 10110103, first: 'Test', last: 'Member 103', email: 'member.10110103@example.test', statusId: 3, allowLogin: null, eligible: true, factors: [{ method: 'TOTP', isDefault: true }] },
  { itsId: 10110104, first: 'Test', last: 'Member 104', email: 'member.10110104@example.test', statusId: 3, allowLogin: true, eligible: true, factors: [{ method: 'SMS_OTP', isDefault: true, destination: '+919800000104' }] },
  { itsId: 10110105, first: 'Test', last: 'Member 105', email: 'member.10110105@example.test', statusId: 3, allowLogin: true, eligible: true, factors: [{ method: 'EMAIL_OTP', isDefault: true, destination: 'member.10110105@example.test' }] },
  { itsId: 10110106, first: 'Test', last: 'Member 106', email: 'member.10110106@example.test', statusId: 3, allowLogin: true, eligible: false, factors: [] },
  { itsId: 10110107, first: 'Test', last: 'Member 107', email: 'member.10110107@example.test', statusId: 2, allowLogin: true, eligible: true, factors: [] },
  { itsId: 10110108, first: 'Test', last: 'Member 108', email: 'member.10110108@example.test', statusId: 3, allowLogin: false, eligible: true, factors: [] },
  { itsId: 10110109, first: 'Test', last: 'Member 109', email: 'member.10110109@example.test', statusId: 3, allowLogin: true, eligible: true, factors: [] },
  { itsId: 10110110, first: 'Test', last: 'Member 110', email: 'member.10110110@example.test', statusId: 3, allowLogin: true, eligible: true, factors: [{ method: 'EMAIL_OTP', isDefault: true, destination: 'member.10110110@example.test' }] },
];
const IDS = MEMBERS.map((m) => m.itsId);
const MIGRATIONS: [number, string][] = [
  [1790300000000, 'OidcMfaAuthSchema1790300000000'],
  [1790400000000, 'LogoutDelivery1790400000000'],
  [1790500000000, 'TrustedHandoff1790500000000'],
];

async function main() {
  if (process.env.NODE_ENV === 'production') throw new Error('refusing to seed with NODE_ENV=production');
  if (!process.argv.includes('--yes')) throw new Error('this writes test members into the database in DB_HOST / DB_NAME; re-run with --yes');
  const schema = process.env.DB_SCHEMA ?? 'miqaat_core';
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new Error('DB_SCHEMA must be a plain identifier');
  const dataKey = process.env.DATA_ENCRYPTION_KEY ?? '';
  if (dataKey.length < 32) throw new Error('DATA_ENCRYPTION_KEY (the one the service will use) is required');

  const db = new Client({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT ?? 5432),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    ssl: ['true', '1'].includes(process.env.DB_SSL ?? '') ? { rejectUnauthorized: true } : false,
  });
  await db.connect();
  try {
    const exists = (await db.query(`SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'users'`, [schema])).rowCount;
    if (!exists) {
      const ddl = readFileSync(resolve(__dirname, '../db/dev-bootstrap-schema.sql'), 'utf8').replace(/\bmiqaat_core\b/g, schema);
      await db.query('BEGIN');
      await db.query(ddl);
      await db.query(`SET search_path TO ${schema}`);
      for (const [i, [ts, name]] of MIGRATIONS.entries()) {
        await db.query('INSERT INTO oidc_mfa_auth_migrations (id, "timestamp", name) VALUES ($1, $2, $3)', [i + 1, ts, name]);
      }
      await db.query('COMMIT');
      console.log(`schema ${schema}: created (${MIGRATIONS.length} migrations recorded as applied)`);
    } else console.log(`schema ${schema}: already present`);

    await db.query(`SET search_path TO ${schema}`);
    const others = (await db.query('SELECT count(*)::int AS n FROM users WHERE NOT (mumin_id = ANY($1::int[]))', [IDS])).rows[0].n as number;
    if (others > 0) throw new Error(`users holds ${others} member(s) that are not test members - this looks like a real identity database; not seeding`);

    const key = toKey32(dataKey);
    const run = randomUUID();
    const now = new Date();
    const hash = (v: unknown) => sha256Hex(JSON.stringify(v));
    await db.query('BEGIN');
    await db.query('DELETE FROM user_mfa_factors WHERE its_id = ANY($1::text[])', [IDS.map(String)]);
    await db.query('DELETE FROM user_eligible WHERE mumin_id = ANY($1::int[])', [IDS]);
    await db.query('DELETE FROM users WHERE mumin_id = ANY($1::int[])', [IDS]);
    await db.query('DELETE FROM mumin_master WHERE mumin_id = ANY($1::int[])', [IDS]);
    for (const [i, m] of MEMBERS.entries()) {
      const n = i + 1;
      const fullname = `${m.first} ${m.last}`;
      await db.query(
        `INSERT INTO mumin_master (person_id, mumin_id, first_name, l_name, gender, email, jamaat_id, fullname, status_id, status, hof,
                                   source_row_hash, source_run_id, source_synced_at, source_last_seen_at)
         VALUES ($1, $2, $3, $4, 'M', $5, 1, $6, $7, $8, false, $9, $10, $11, $11)`,
        [900000 + n, m.itsId, m.first, m.last, m.email, fullname, m.statusId, m.statusId === 3 ? 'Active' : 'Inactive', hash(m), run, now],
      );
      await db.query(
        `INSERT INTO users (id, mumin_id, password, person_master_id, is_otprequired, add_date, allow_login,
                            source_row_hash, source_run_id, source_synced_at, source_last_seen_at)
         VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8, $9, $9)`,
        [900000 + n, m.itsId, encrypt(`Test@${String(n).padStart(3, '0')}`), 900000 + n, now, m.allowLogin, hash([m.itsId, 'user']), run, now],
      );
      if (m.eligible) {
        await db.query(
          `INSERT INTO user_eligible (id, mumin_id, add_date, source_row_hash, source_run_id, source_synced_at, source_last_seen_at)
           VALUES ($1, $2, $3, $4, $5, $6, $6)`,
          [900000 + n, m.itsId, now, hash([m.itsId, 'eligible']), run, now],
        );
      }
      for (const f of m.factors) {
        const totp = f.method === 'TOTP' ? base32Encode(randomBytes(20)) : null;
        await db.query(
          `INSERT INTO user_mfa_factors (its_id, method, is_default, destination_enc, totp_secret_enc, status, verified_at)
           VALUES ($1, $2, $3, $4, $5, 'ACTIVE', now())`,
          [String(m.itsId), f.method, f.isDefault, f.destination ? encryptString(key, f.destination) : null, totp ? encryptString(key, totp) : null],
        );
      }
    }
    await db.query('COMMIT');
    console.log(`test members: ${MEMBERS.length} created (${IDS[0]}..${IDS[IDS.length - 1]}, passwords Test@001..Test@010)`);
    for (const m of MEMBERS) {
      const notes = [m.statusId !== 3 && 'inactive', m.allowLogin === false && 'allow_login=false', !m.eligible && 'not eligible', !m.email && 'no email'].filter(Boolean);
      console.log(`  ${m.itsId}  MFA: ${m.factors.map((f) => f.method + (f.isDefault ? '*' : '')).join(', ') || (m.email ? 'EMAIL_OTP (mumin_master)' : '-')}${notes.length ? `  (${notes.join(', ')})` : ''}`);
    }
  } catch (error) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    await db.end();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
