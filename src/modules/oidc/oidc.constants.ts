import type Provider from 'oidc-provider';

export const OIDC_PROVIDER = Symbol('OIDC_PROVIDER');

/** Paths served by oidc-provider itself; everything else is a NestJS route. */
export const OIDC_ROUTES = {
  authorization: '/auth',
  token: '/token',
  jwks: '/.well-known/jwks.json',
  userinfo: '/me',
  revocation: '/token/revocation',
} as const;

/** Fastify paths that are handed to oidc-provider (discovery included). */
export const OIDC_MOUNT_PATHS = [
  '/.well-known/openid-configuration',
  OIDC_ROUTES.authorization,
  `${OIDC_ROUTES.authorization}/:uid`,
  OIDC_ROUTES.token,
  OIDC_ROUTES.jwks,
  OIDC_ROUTES.userinfo,
  OIDC_ROUTES.revocation,
];

export type OidcProvider = Provider;

/** Redis key: grant id -> Core session correlation, read when the ID token is built. */
export const grantContextKey = (grantId: string) => `oidc:grantctx:${grantId}`;

/** Redis set: Core session sid -> grant ids issued in it (revoked together at logout). */
export const sessionGrantsKey = (sid: string) => `oidc:sidgrants:${sid}`;

export interface GrantContext {
  sid: string;
  realm: string;
}
