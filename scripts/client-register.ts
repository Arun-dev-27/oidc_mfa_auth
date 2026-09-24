/**
 * Registers a Business Unit application in auth_clients (Core administration process, spec §9).
 *
 *   npm run client:register -- --client-id rms-mumin-dev --name "RMS Mumin" --realm MUMIN \
 *     --redirect http://localhost:5173/auth/callback [--redirect ...] [--post-logout http://localhost:5173/] \
 *     [--auth-method client_secret_basic | private_key_jwt (--jwks-uri https://bu/.well-known/jwks.json | --jwks-file bu-public-jwks.json)] \
 *     [--scopes "openid profile"] [--default-acr urn:miqaat:aal:2] [--business-unit RMS] [--environment DEV] \n *     [--backchannel-logout https://bu/auth/core/logout]
 *
 * For client_secret_* a random secret is generated, stored encrypted and printed ONCE.
 */
import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { encryptString, toKey32 } from '../src/common/crypto.util';
import AppDataSource from '../src/database/data-source';
import { AuthClient, isAuthRealm, type TokenEndpointAuthMethod } from '../src/database/entities';
import { ClientRepository } from '../src/database/repositories/client.repository';
import { many, one, parseArgs } from './cli-args';

const METHODS: TokenEndpointAuthMethod[] = ['private_key_jwt', 'client_secret_basic', 'client_secret_post'];

async function main() {
  const args = parseArgs();
  const clientId = one(args, 'client-id');
  const realm = one(args, 'realm').toUpperCase();
  if (!isAuthRealm(realm)) throw new Error('--realm must be ADMIN or MUMIN');
  if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(clientId)) throw new Error('--client-id: lower-case letters, digits and dashes (3-64)');
  const method = one(args, 'auth-method', 'private_key_jwt') as TokenEndpointAuthMethod;
  if (!METHODS.includes(method)) throw new Error(`--auth-method must be one of ${METHODS.join(', ')}`);
  const redirectUris = many(args, 'redirect');
  if (!redirectUris.length) throw new Error('at least one --redirect is required');
  const backchannel = args.get('backchannel-logout')?.[0] ?? null;
  for (const uri of [...redirectUris, ...many(args, 'post-logout'), ...(backchannel ? [backchannel] : [])]) {
    const u = new URL(uri);
    if (u.protocol !== 'https:' && u.hostname !== 'localhost') throw new Error(`${uri}: https required outside localhost`);
    if (uri.includes('*')) throw new Error(`${uri}: wildcards are not allowed`);
  }
  const jwksUri = args.get('jwks-uri')?.[0] ?? null;
  const jwksFile = args.get('jwks-file')?.[0];
  const jwks = jwksFile ? (JSON.parse(readFileSync(jwksFile, 'utf8')) as { keys: Record<string, unknown>[] }) : null;
  if (jwks && (!Array.isArray(jwks.keys) || jwks.keys.some((k) => 'd' in k))) throw new Error('--jwks-file must be a PUBLIC JWKS { keys: [...] }');
  if (method === 'private_key_jwt' && !jwksUri && !jwks) throw new Error('private_key_jwt needs --jwks-uri or --jwks-file');

  await AppDataSource.initialize();
  try {
    const repo = new ClientRepository(AppDataSource.getRepository(AuthClient), AppDataSource);
    if (await repo.findByClientId(clientId)) throw new Error(`${clientId} already exists`);

    const secret = method === 'private_key_jwt' ? null : randomBytes(32).toString('hex');
    const key = toKey32(process.env.DATA_ENCRYPTION_KEY ?? '');
    await repo.create({
      clientId,
      name: one(args, 'name', clientId),
      applicationCode: one(args, 'application-code', clientId.replace(/-(dev|uat|prod)$/, '')),
      businessUnit: args.get('business-unit')?.[0] ?? null,
      environment: one(args, 'environment', 'DEV').toUpperCase(),
      authRealm: realm,
      tokenEndpointAuthMethod: method,
      clientSecretEnc: secret ? encryptString(key, secret) : null,
      clientJwksUri: jwksUri,
      clientJwks: jwks,
      allowedScopes: one(args, 'scopes', 'openid profile'),
      defaultAcr: args.get('default-acr')?.[0] ?? null,
      redirectUris,
      postLogoutRedirectUris: many(args, 'post-logout'),
      backchannelLogoutUri: backchannel,
    });
    console.log(`registered ${clientId} (realm ${realm}, ${method})`);
    if (secret) console.log(`client_secret (shown once, store it in the BU secret store): ${secret}`);
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
