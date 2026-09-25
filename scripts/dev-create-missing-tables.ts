/**
 * DEVELOPMENT ONLY: creates the tables that are MISSING from the database schema - nothing else.
 *
 *   npm run db:create-missing-tables              # dry run: lists what would be created
 *   npm run db:create-missing-tables -- --yes     # creates the missing tables
 *
 * Source of truth: db/dev-bootstrap-schema.sql (structure only). For every table in it that does not
 * exist in DB_SCHEMA, the table is created together with its own sequences, defaults, constraints,
 * indexes, comments, triggers and foreign keys (a foreign key only when the table it points to exists).
 *
 *   - Existing tables are never dropped, altered or written - not even when their columns differ.
 *   - No rows are inserted anywhere: no users, no test members, no migration history, no data copy.
 *     Missing tables are created empty (users, mumin_master and user_eligible included).
 *   - Refuses NODE_ENV=production. Everything runs in one transaction: all or nothing.
 *
 * Columns added by oidc_mfa_auth to tables that already exist are the migration's job:
 * `npm run migration:run` (idempotent, ADD COLUMN IF NOT EXISTS) after this script.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { loadDotEnv } from '../src/config/env';

loadDotEnv();

interface Block {
  name: string;
  type: string;
  sql: string;
  /** Table the block belongs to (null for schema / function). */
  table: string | null;
}

/** Splits the pg_dump file into its "-- Name: ...; Type: ...;" blocks and maps each one to its table. */
function parseDump(sql: string, schema: string): Block[] {
  const header = /^--\n-- Name: (.+?); Type: (.+?); Schema: .*?; Owner: .*\n--\n/gm;
  const heads = [...sql.matchAll(header)];
  const blocks: Block[] = heads.map((m, i) => {
    const start = (m.index ?? 0) + m[0].length;
    const end = i + 1 < heads.length ? heads[i + 1].index : sql.length;
    return { name: m[1], type: m[2], sql: sql.slice(start, end).trim(), table: null };
  });
  const q = (s: string) => new RegExp(`\\b${schema}\\.(\\w+)`).exec(s)?.[1] ?? null;
  const seqOwner = new Map<string, string>();
  for (const b of blocks) {
    if (b.type === 'SEQUENCE OWNED BY') {
      const m = new RegExp(`OWNED BY ${schema}\\.(\\w+)\\.`).exec(b.sql);
      if (m) seqOwner.set(b.name, m[1]);
    }
  }
  for (const b of blocks) {
    switch (b.type) {
      case 'TABLE':
        b.table = b.name;
        break;
      case 'SEQUENCE':
      case 'SEQUENCE OWNED BY':
        b.table = seqOwner.get(b.name) ?? null;
        break;
      case 'DEFAULT':
      case 'CONSTRAINT':
      case 'FK CONSTRAINT':
      case 'TRIGGER':
        b.table = b.name.split(' ')[0];
        break;
      case 'INDEX':
        b.table = new RegExp(` ON (?:ONLY )?${schema}\\.(\\w+)`).exec(b.sql)?.[1] ?? null;
        break;
      case 'COMMENT':
        b.table = q(b.sql);
        break;
    }
  }
  return blocks;
}

/** Make the statements safe to run next to existing objects (a leftover sequence or index is reused). */
function ifNotExists(sql: string): string {
  return sql
    .replace(/^CREATE TABLE /gm, 'CREATE TABLE IF NOT EXISTS ')
    .replace(/^CREATE SEQUENCE /gm, 'CREATE SEQUENCE IF NOT EXISTS ')
    .replace(/^CREATE (UNIQUE )?INDEX /gm, (_m, u: string | undefined) => `CREATE ${u ?? ''}INDEX IF NOT EXISTS `);
}

async function main() {
  if (process.env.NODE_ENV === 'production') throw new Error('development only: refused with NODE_ENV=production');
  const apply = process.argv.includes('--yes');
  const schema = process.env.DB_SCHEMA ?? 'miqaat_core';
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new Error('DB_SCHEMA must be a plain identifier');

  const dump = readFileSync(resolve(__dirname, '../db/dev-bootstrap-schema.sql'), 'utf8').replace(/\bmiqaat_core\b/g, schema);
  const blocks = parseDump(dump, schema);
  const wanted = blocks.filter((b) => b.type === 'TABLE').map((b) => b.name);

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
    const existing = new Set(
      (await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1`, [schema])).rows.map((r) => r.table_name as string),
    );
    const missing = wanted.filter((t) => !existing.has(t));
    console.log(`database ${process.env.DB_NAME} · schema ${schema}`);
    console.log(`  present (${wanted.length - missing.length}): ${wanted.filter((t) => existing.has(t)).join(', ') || '-'}`);
    console.log(`  missing (${missing.length}): ${missing.join(', ') || '-'}`);
    if (!missing.length) return console.log('nothing to create');

    const creating = new Set(missing);
    const willExist = (t: string) => existing.has(t) || creating.has(t);
    const plan: string[] = [];
    const skipped: string[] = [];
    const schemaExists = (await db.query('SELECT 1 FROM information_schema.schemata WHERE schema_name = $1', [schema])).rowCount;
    if (!schemaExists) plan.push(`CREATE SCHEMA IF NOT EXISTS ${schema};`);
    const fnExists = (await db.query(
      `SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1 AND p.proname = 'auth_set_updated_at'`,
      [schema],
    )).rowCount;
    for (const b of blocks) {
      if (b.type === 'FUNCTION') {
        const needed = blocks.some((t) => t.type === 'TRIGGER' && t.table && creating.has(t.table));
        if (needed && !fnExists) plan.push(b.sql);
        continue;
      }
      if (!b.table || !creating.has(b.table)) continue;
      if (b.type === 'FK CONSTRAINT') {
        const target = new RegExp(`REFERENCES ${schema}\\.(\\w+)`).exec(b.sql)?.[1];
        if (target && !willExist(target)) {
          skipped.push(`${b.name} (references missing ${target})`);
          continue;
        }
      }
      plan.push(ifNotExists(b.sql));
    }
    console.log(`\n${plan.length} statement(s) for the missing tables${skipped.length ? `; skipped: ${skipped.join(', ')}` : ''}`);

    if (!apply) {
      for (const s of plan) console.log(`\n${s}`);
      console.log('\nDRY RUN - nothing changed. Re-run with --yes to create the missing tables.');
      return;
    }
    await db.query('BEGIN');
    for (const s of plan) await db.query(s);
    await db.query('COMMIT');
    const after = new Set((await db.query(`SELECT table_name FROM information_schema.tables WHERE table_schema = $1`, [schema])).rows.map((r) => r.table_name as string));
    const created = missing.filter((t) => after.has(t));
    console.log(`created ${created.length} table(s): ${created.join(', ')} (empty; no rows written)`);
    console.log('Next: npm run migration:run   (adds any oidc_mfa_auth columns missing on existing tables)');
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
