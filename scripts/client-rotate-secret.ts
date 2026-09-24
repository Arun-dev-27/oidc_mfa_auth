/**
 * Issues a new client secret for a registered client (client_secret_basic, the standard method).
 *
 *   npm run client:rotate-secret -- --client-id rms-admin-dev [--out .e2e-rms-admin.txt]
 *
 * The new secret is stored encrypted and printed ONCE; the previous secret stops working immediately,
 * so update the BU secret store and restart the BU right after. A client registered for
 * private_key_jwt / client_secret_post is moved to client_secret_basic (its keys are cleared).
 * --out also writes the same lines to a file (development tooling, e.g. the Test Console secrets).
 */
import 'reflect-metadata';
import { writeFileSync } from 'node:fs';
import AppDataSource from '../src/database/data-source';
import { one, parseArgs } from './cli-args';
import { rotateClientSecret } from './lib/client-admin';

async function main() {
  const args = parseArgs();
  const clientId = one(args, 'client-id');
  const out = args.get('out')?.[0];

  await AppDataSource.initialize();
  try {
    const r = await rotateClientSecret(AppDataSource, clientId);
    const text = [
      `rotated ${clientId} (realm ${r.realm ?? '-'}, client_secret_basic; was ${r.previousMethod})`,
      `client_secret (shown once, store it in the BU secret store): ${r.secret}`,
    ].join('\n');
    console.log(text);
    if (out) writeFileSync(out, `${text}\n`, { mode: 0o600 });
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
