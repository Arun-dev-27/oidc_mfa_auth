/**
 * Configures trusted handoff for a registered client (Core spec §9 / §26.1 / §26.4).
 *
 *   npm run client:handoff -- --client-id ams-admin-dev \
 *     --callback https://ams.example.com/auth/core/handoff \
 *     --paths "/dashboard,/events/*,/events/* /details,/bookings/*" --inbound --outbound
 *
 *   --inbound    the client may RECEIVE handoffs (needs --callback and --paths)
 *   --outbound   the client may START handoffs to other apps of its realm
 *   --paths      allowlist; "*" = exactly one path segment; replaces the previous list
 *   --disable    turns handoff off for the client
 */
import 'reflect-metadata';
import AppDataSource from '../src/database/data-source';
import { HandoffPath, HandoffRequest } from '../src/database/entities';
import { HandoffRepository } from '../src/database/repositories/handoff.repository';
import { many, one, parseArgs } from './cli-args';

async function main() {
  const args = parseArgs();
  const clientId = one(args, 'client-id');
  const disable = args.has('disable');
  const inbound = !disable && args.has('inbound');
  const outbound = !disable && args.has('outbound');
  const callback = disable ? null : (args.get('callback')?.[0] ?? null);
  const patterns = disable ? [] : many(args, 'paths').map((p) => p.replace(/\s+/g, ''));

  if (inbound && (!callback || !patterns.length)) throw new Error('--inbound needs --callback and --paths');
  if (callback) {
    const u = new URL(callback);
    if (u.protocol !== 'https:' && u.hostname !== 'localhost') throw new Error('--callback: https required outside localhost');
  }
  for (const p of patterns) {
    if (!p.startsWith('/') || p.startsWith('//') || /[\\:?#]/.test(p) || p.split('/').some((s) => s === '..' || s === '.')) {
      throw new Error(`invalid path pattern ${p} (relative path, "*" = one segment)`);
    }
  }

  await AppDataSource.initialize();
  try {
    const repo = new HandoffRepository(AppDataSource.getRepository(HandoffPath), AppDataSource.getRepository(HandoffRequest), AppDataSource);
    await repo.configure(clientId, { callbackUri: callback, inbound, outbound, patterns });
    console.log(`${clientId}: handoff inbound=${inbound} outbound=${outbound} callback=${callback ?? '-'} paths=${patterns.join(', ') || '-'}`);
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
