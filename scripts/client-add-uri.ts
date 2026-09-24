/**
 * Adds a callback URI to an existing client.
 *
 *   npm run client:add-uri -- --client-id rms-admin-dev --type POST_LOGOUT_REDIRECT --uri http://localhost:5173/logged-out
 *   npm run client:add-uri -- --client-id rms-admin-dev --type BACK_CHANNEL_LOGOUT --uri http://localhost:5173/auth/core/logout
 *   npm run client:add-uri -- --client-id rms-admin-dev --type CALLBACK --uri http://localhost:5173/auth/callback
 *
 * URIs are exact-match; https is required outside localhost; wildcards are refused.
 */
import 'reflect-metadata';
import AppDataSource from '../src/database/data-source';
import { AuthClient, type CallbackUriType } from '../src/database/entities';
import { ClientRepository } from '../src/database/repositories/client.repository';
import { one, parseArgs } from './cli-args';

const TYPES: CallbackUriType[] = ['CALLBACK', 'POST_LOGOUT_REDIRECT', 'BACK_CHANNEL_LOGOUT'];

async function main() {
  const args = parseArgs();
  const clientId = one(args, 'client-id');
  const type = one(args, 'type').toUpperCase() as CallbackUriType;
  if (!TYPES.includes(type)) throw new Error(`--type must be one of ${TYPES.join(', ')}`);
  const uri = one(args, 'uri');
  const u = new URL(uri);
  if (u.protocol !== 'https:' && u.hostname !== 'localhost') throw new Error('https required outside localhost');
  if (uri.includes('*')) throw new Error('wildcards are not allowed');
  await AppDataSource.initialize();
  try {
    await new ClientRepository(AppDataSource.getRepository(AuthClient), AppDataSource).addCallback(clientId, type, uri);
    console.log(`${clientId}: ${type} ${uri}`);
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
