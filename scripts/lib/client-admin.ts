/**
 * Client administration shared by the CLI scripts (client:register, client:rotate-secret) and the
 * Test Console registration UI, so both apply exactly the same validation.
 */
import { randomBytes } from 'node:crypto';
import type { DataSource } from 'typeorm';
import { encryptString, toKey32 } from '../../src/common/crypto.util';
import { AuthClient, HandoffPath, HandoffRequest, isAuthRealm, type AuthRealm, type ClientStatus, type TokenEndpointAuthMethod } from '../../src/database/entities';
import { ClientRepository } from '../../src/database/repositories/client.repository';
import { HandoffRepository } from '../../src/database/repositories/handoff.repository';

export const AUTH_METHODS: TokenEndpointAuthMethod[] = ['client_secret_basic', 'private_key_jwt', 'client_secret_post'];
export const ACR_VALUES = ['urn:miqaat:aal:1', 'urn:miqaat:aal:2'];
const CLIENT_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;

export interface RegisterInput {
  clientId: string;
  name?: string;
  realm: string;
  redirectUris: string[];
  postLogoutUris?: string[];
  backchannelLogoutUri?: string | null;
  authMethod?: string;
  jwksUri?: string | null;
  jwks?: { keys: Record<string, unknown>[] } | null;
  scopes?: string;
  defaultAcr?: string | null;
  businessUnit?: string | null;
  environment?: string;
  applicationCode?: string;
  handoff?: { callbackUri: string | null; inbound: boolean; outbound: boolean; patterns: string[] } | null;
}

export interface RegisterResult {
  clientId: string;
  realm: AuthRealm;
  method: TokenEndpointAuthMethod;
  /** Plain secret, returned ONCE (null for private_key_jwt). */
  secret: string | null;
  warnings: string[];
}

export interface ClientSummary {
  clientId: string;
  name: string;
  realm: string | null;
  status: string;
  method: string;
  environment: string;
  defaultAcr: string | null;
  hasSecret: boolean;
  redirectUris: string[];
  postLogoutUris: string[];
  backchannelLogoutUri: string | null;
  handoff: { callbackUri: string | null; inbound: boolean; outbound: boolean; patterns: string[] };
  usable: boolean;
  problems: string[];
  createdAt: string;
}

/** Redirect / logout URIs: absolute, https (http only for localhost), no wildcard or fragment. */
export function checkUri(uri: string, label: string): string {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    throw new Error(`${label}: "${uri}" is not an absolute URL`);
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1'))) {
    throw new Error(`${label}: ${uri} - https required outside localhost`);
  }
  if (uri.includes('*')) throw new Error(`${label}: ${uri} - wildcards are not allowed`);
  if (u.hash) throw new Error(`${label}: ${uri} - fragments are not allowed`);
  if (u.username || u.password) throw new Error(`${label}: ${uri} - credentials in the URL are not allowed`);
  return uri;
}

export function checkHandoffPattern(p: string): string {
  if (!p.startsWith('/') || p.startsWith('//') || /[\\:?#\s]/.test(p) || p.split('/').some((s) => s === '..' || s === '.')) {
    throw new Error(`handoff path "${p}": must be a relative path such as /events/* ("*" = one segment)`);
  }
  return p;
}

function enabledMethods(): string[] {
  return (process.env.CLIENT_AUTH_METHODS ?? 'client_secret_basic').split(',').map((m) => m.trim()).filter(Boolean);
}

const trimList = (v: string[] | undefined) => [...new Set((v ?? []).map((s) => s.trim()).filter(Boolean))];

/** Validates everything first; nothing is written unless the whole registration is valid. */
export function validateRegistration(input: RegisterInput) {
  const clientId = (input.clientId ?? '').trim();
  if (!CLIENT_ID.test(clientId)) throw new Error('Client ID: lower-case letters, digits and dashes, 3-64 characters, e.g. ams-admin-dev');
  const realm = (input.realm ?? '').trim().toUpperCase();
  if (!isAuthRealm(realm)) throw new Error('Realm must be ADMIN or MUMIN');
  const method = (input.authMethod?.trim() || 'client_secret_basic') as TokenEndpointAuthMethod;
  if (!AUTH_METHODS.includes(method)) throw new Error(`Auth method must be one of ${AUTH_METHODS.join(', ')}`);

  const redirectUris = trimList(input.redirectUris).map((u) => checkUri(u, 'Redirect URI'));
  if (!redirectUris.length) throw new Error('At least one redirect URI is required');
  const postLogoutUris = trimList(input.postLogoutUris).map((u) => checkUri(u, 'Post-logout URI'));
  const backchannel = input.backchannelLogoutUri?.trim() ? checkUri(input.backchannelLogoutUri.trim(), 'Back-channel logout URI') : null;

  const jwksUri = input.jwksUri?.trim() ? checkUri(input.jwksUri.trim(), 'JWKS URI') : null;
  const jwks = input.jwks ?? null;
  if (jwks && (!Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.some((k) => 'd' in k))) throw new Error('JWKS must be a PUBLIC key set { "keys": [...] } (no private "d")');
  if (method === 'private_key_jwt' && !jwksUri && !jwks) throw new Error('private_key_jwt needs a JWKS URI or a public JWKS');
  if (method !== 'private_key_jwt' && (jwksUri || jwks)) throw new Error('A JWKS is only used with private_key_jwt');

  const scopes = (input.scopes?.trim() || 'openid profile').split(/\s+/);
  if (!scopes.includes('openid')) throw new Error('Scopes must include openid');
  if (scopes.some((s) => !/^[a-z_]{2,32}$/.test(s))) throw new Error('Scopes: space separated words, e.g. "openid profile"');
  const defaultAcr = input.defaultAcr?.trim() || null;
  if (defaultAcr && !ACR_VALUES.includes(defaultAcr)) throw new Error(`Default ACR must be ${ACR_VALUES.join(' or ')}`);
  const environment = (input.environment?.trim() || 'DEV').toUpperCase();
  if (!/^[A-Z]{2,16}$/.test(environment)) throw new Error('Environment: letters only, e.g. DEV, UAT, PROD');
  const name = (input.name?.trim() || clientId).slice(0, 255);

  let handoff: RegisterInput['handoff'] = null;
  if (input.handoff && (input.handoff.inbound || input.handoff.outbound)) {
    const patterns = trimList(input.handoff.patterns).map(checkHandoffPattern);
    const callbackUri = input.handoff.callbackUri?.trim() ? checkUri(input.handoff.callbackUri.trim(), 'Handoff callback URI') : null;
    if (input.handoff.inbound && (!callbackUri || !patterns.length)) throw new Error('Receiving handoffs needs a handoff callback URI and at least one allowed path');
    handoff = { callbackUri, inbound: input.handoff.inbound, outbound: input.handoff.outbound, patterns };
  }

  const warnings: string[] = [];
  if (!enabledMethods().includes(method)) warnings.push(`${method} is not in CLIENT_AUTH_METHODS (${enabledMethods().join(', ')}): this client cannot sign in until it is enabled`);
  if (!postLogoutUris.length) warnings.push('No post-logout URI: after logout Core shows its own "Signed out" page');

  return {
    clientId,
    realm: realm as AuthRealm,
    method,
    redirectUris,
    postLogoutUris,
    backchannel,
    jwksUri,
    jwks,
    scopes: scopes.join(' '),
    defaultAcr,
    environment,
    name,
    businessUnit: input.businessUnit?.trim() || null,
    applicationCode: (input.applicationCode?.trim() || clientId.replace(/-(dev|uat|prod)$/, '')).slice(0, 64),
    handoff,
    warnings,
  };
}

const repos = (ds: DataSource) => ({
  clients: new ClientRepository(ds.getRepository(AuthClient), ds),
  handoff: new HandoffRepository(ds.getRepository(HandoffPath), ds.getRepository(HandoffRequest), ds),
});

const dataKey = () => toKey32(process.env.DATA_ENCRYPTION_KEY ?? '');

export async function registerClient(ds: DataSource, input: RegisterInput): Promise<RegisterResult> {
  const v = validateRegistration(input);
  const { clients, handoff } = repos(ds);
  if (await clients.findByClientId(v.clientId)) throw new Error(`${v.clientId} already exists`);
  const secret = v.method === 'private_key_jwt' ? null : randomBytes(32).toString('hex');
  await clients.create({
    clientId: v.clientId,
    name: v.name,
    applicationCode: v.applicationCode,
    businessUnit: v.businessUnit,
    environment: v.environment,
    authRealm: v.realm,
    tokenEndpointAuthMethod: v.method,
    clientSecretEnc: secret ? encryptString(dataKey(), secret) : null,
    clientJwksUri: v.jwksUri,
    clientJwks: v.jwks,
    allowedScopes: v.scopes,
    defaultAcr: v.defaultAcr,
    redirectUris: v.redirectUris,
    postLogoutRedirectUris: v.postLogoutUris,
    backchannelLogoutUri: v.backchannel,
  });
  if (v.handoff) await handoff.configure(v.clientId, v.handoff);
  return { clientId: v.clientId, realm: v.realm, method: v.method, secret, warnings: v.warnings };
}

/** New client_secret_basic secret, returned once; the old one stops working at once. */
export async function rotateClientSecret(ds: DataSource, clientId: string): Promise<{ secret: string; previousMethod: string; realm: string | null }> {
  const { clients } = repos(ds);
  const client = await clients.findByClientId(clientId);
  if (!client) throw new Error(`unknown client ${clientId}`);
  const secret = randomBytes(32).toString('hex');
  await clients.setSecret(clientId, encryptString(dataKey(), secret), 'client_secret_basic');
  return { secret, previousMethod: client.tokenEndpointAuthMethod ?? 'unset', realm: client.authRealm };
}

export async function setClientStatus(ds: DataSource, clientId: string, status: string): Promise<void> {
  if (!['ACTIVE', 'SUSPENDED'].includes(status)) throw new Error('Status must be ACTIVE or SUSPENDED');
  await repos(ds).clients.setStatus(clientId, status as ClientStatus);
}

/** Every client with what Core needs to accept it; secrets are never returned. */
export async function listClients(ds: DataSource): Promise<ClientSummary[]> {
  const rows = await ds.getRepository(AuthClient).find({ relations: { callbacks: true }, order: { createdAt: 'DESC' } });
  const paths: { client_id: string; path_pattern: string }[] = await ds.query('SELECT client_id, path_pattern FROM auth_client_handoff_paths WHERE enabled ORDER BY path_pattern');
  const enabled = enabledMethods();
  return rows.map((c) => {
    const method = c.tokenEndpointAuthMethod ?? 'client_secret_basic';
    const redirectUris = c.callbacks.filter((x) => x.uriType === 'CALLBACK').map((x) => x.uri);
    const problems: string[] = [];
    if (c.status !== 'ACTIVE') problems.push(`status ${c.status}`);
    if (!c.authRealm) problems.push('no realm');
    if (!redirectUris.length) problems.push('no redirect URI');
    if (!enabled.includes(method)) problems.push(`${method} not enabled`);
    if (method !== 'private_key_jwt' && !c.clientSecretEnc) problems.push('no secret');
    if (method === 'private_key_jwt' && !c.clientJwks && !c.clientJwksUri) problems.push('no JWKS');
    return {
      clientId: c.clientId,
      name: c.name,
      realm: c.authRealm,
      status: c.status,
      method,
      environment: c.environment,
      defaultAcr: c.defaultAcr,
      hasSecret: Boolean(c.clientSecretEnc),
      redirectUris,
      postLogoutUris: c.callbacks.filter((x) => x.uriType === 'POST_LOGOUT_REDIRECT').map((x) => x.uri),
      backchannelLogoutUri: c.callbacks.find((x) => x.uriType === 'BACK_CHANNEL_LOGOUT')?.uri ?? null,
      handoff: {
        callbackUri: c.handoffCallbackUri,
        inbound: c.handoffInboundEnabled,
        outbound: c.handoffOutboundEnabled,
        patterns: paths.filter((p) => p.client_id === c.clientId).map((p) => p.path_pattern),
      },
      usable: problems.length === 0,
      problems,
      createdAt: c.createdAt.toISOString(),
    };
  });
}
