/**
 * Registers a Business Unit application in auth_clients (Core administration process, spec §9).
 *
 *   npm run client:register -- --client-id rms-mumin-dev --name "RMS Mumin" --realm MUMIN \
 *     --redirect http://localhost:5173/auth/callback [--redirect ...] [--post-logout http://localhost:5173/] \
 *     [--auth-method client_secret_basic (default) | private_key_jwt (--jwks-uri https://bu/.well-known/jwks.json | --jwks-file bu-public-jwks.json)] \
 *     [--scopes "openid profile"] [--default-acr urn:miqaat:aal:2] [--business-unit RMS] [--environment DEV] \
 *     [--backchannel-logout https://bu/auth/core/logout]
 *
 * Standard: client_secret_basic. A random secret is generated, stored encrypted and printed ONCE; the
 * app sends it as "Authorization: Basic base64(client_id:client_secret)". Rotate it with
 * npm run client:rotate-secret. Other methods must also be enabled in CLIENT_AUTH_METHODS.
 * The same registration is available in the Test Console (development) - both use scripts/lib/client-admin.ts.
 */
import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import AppDataSource from '../src/database/data-source';
import { many, one, parseArgs } from './cli-args';
import { registerClient, validateRegistration, type RegisterInput } from './lib/client-admin';

async function main() {
  const args = parseArgs();
  const jwksFile = args.get('jwks-file')?.[0];
  const input: RegisterInput = {
    clientId: one(args, 'client-id'),
    name: args.get('name')?.[0],
    realm: one(args, 'realm'),
    redirectUris: many(args, 'redirect'),
    postLogoutUris: many(args, 'post-logout'),
    backchannelLogoutUri: args.get('backchannel-logout')?.[0] ?? null,
    authMethod: args.get('auth-method')?.[0],
    jwksUri: args.get('jwks-uri')?.[0] ?? null,
    jwks: jwksFile ? (JSON.parse(readFileSync(jwksFile, 'utf8')) as { keys: Record<string, unknown>[] }) : null,
    scopes: args.get('scopes')?.[0],
    defaultAcr: args.get('default-acr')?.[0] ?? null,
    businessUnit: args.get('business-unit')?.[0] ?? null,
    environment: args.get('environment')?.[0],
    applicationCode: args.get('application-code')?.[0],
  };
  validateRegistration(input); // fail before touching the database

  await AppDataSource.initialize();
  try {
    const r = await registerClient(AppDataSource, input);
    for (const w of r.warnings) console.warn(`warning: ${w}`);
    console.log(`registered ${r.clientId} (realm ${r.realm}, ${r.method})`);
    if (r.secret) console.log(`client_secret (shown once, store it in the BU secret store): ${r.secret}`);
  } finally {
    await AppDataSource.destroy();
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
