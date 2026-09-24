import { Logger } from '@nestjs/common';
import type Redis from 'ioredis';
import Provider, { errors, interactionPolicy, type Configuration, type KoaContextWithOIDC } from 'oidc-provider';
import type { Env } from '../../config/env';
import { isAuthRealm } from '../../database/entities';
import type { IdentityAccountRepository } from '../../database/repositories/identity-account.repository';
import { ACR_AAL1, ACR_AAL2 } from '../mfa/mfa.service';
import type { ProviderKey } from '../keys/signing-key.service';
import type { ViewService } from '../views/view.service';
import type { ClientRegistryService } from './client-registry.service';
import { grantContextKey, OIDC_ROUTES, type GrantContext } from './oidc.constants';
import { OidcRedisAdapter } from './oidc-redis.adapter';

export interface ProviderDeps {
  env: Env;
  redis: Redis;
  jwks: ProviderKey[];
  /** true when keys are ExternalSigningKey instances (KMS). */
  externalSigning: boolean;
  clients: ClientRegistryService;
  accounts: IdentityAccountRepository;
  views: ViewService;
}

/**
 * oidc-provider is the protocol engine (authorization code + PKCE S256, client authentication,
 * token endpoint, discovery, JWKS). The Core realm session - not the provider's own session - is
 * the authoritative SSO decision (spec §8), enforced by the policy check below.
 */
export function createProvider(d: ProviderDeps): Provider {
  const { env } = d;
  const logger = new Logger('oidc-provider');

  const { Check, base } = interactionPolicy;
  const policy = base();
  // Every authorization request goes through the Core interaction, which runs the realm gate:
  // resolve realm from client_id, check THAT realm's session, reuse it silently (SSO) or show
  // login / MFA. The provider's own session never decides alone, so an ADMIN login can never
  // satisfy a MUMIN client. When the interaction has finished, its result satisfies the check.
  // With prompt=none the provider cannot show the gate, so it answers the standard login_required.
  policy.get('login')!.checks.add(
    new Check('miqaat_realm_gate', 'End-User authentication is required', 'login_required', (ctx: KoaContextWithOIDC) =>
      ctx.oidc.result?.login ? Check.NO_NEED_TO_PROMPT : Check.REQUEST_PROMPT,
    ),
    0,
  );

  const configuration: Configuration = {
    adapter: (name: string) => (name === 'Client' ? d.clients.adapter() : new OidcRedisAdapter(name, d.redis)),

    async findAccount(ctx, sub, token) {
      return {
        accountId: sub,
        async claims(_use, scope) {
          const grantId = (token as { grantId?: string } | undefined)?.grantId ?? ctx.oidc.entities.Grant?.jti;
          const raw = grantId ? await d.redis.get(grantContextKey(grantId)) : null;
          const context = raw ? (JSON.parse(raw) as GrantContext) : null;
          const clientRealm = (ctx.oidc.client as unknown as { auth_realm?: string } | undefined)?.auth_realm;
          const claims: Record<string, unknown> = {
            sub,
            auth_realm: context?.realm ?? clientRealm,
            sid: context?.sid,
          };
          if (scope.split(' ').includes('profile')) {
            const account = await d.accounts.findLoginAccount(Number(sub), env.ACTIVE_STATUS_ID);
            if (account?.fullname) claims.name = account.fullname.trim();
          }
          return claims as { sub: string };
        },
      };
    },

    claims: {
      // Every ID token carries the assurance (acr, amr) so a BU can always check AAL; the values come
      // from the login result, not from findAccount. auth_time is forced by require_auth_time.
      openid: ['sub', 'auth_realm', 'sid', 'acr', 'amr'],
      profile: ['name'],
    },
    // Claims belong in the ID token itself (BUs consume sub / auth_realm / sid / acr / amr from it).
    conformIdTokenClaims: false,
    acrValues: [ACR_AAL1, ACR_AAL2],
    extraParams: ['mfa_max_age'],
    extraClientMetadata: {
      properties: ['auth_realm'],
      validator(_ctx, key, value) {
        if (key === 'auth_realm' && !isAuthRealm(value)) {
          throw new errors.InvalidClientMetadata('auth_realm must be ADMIN or MUMIN');
        }
      },
    },

    interactions: {
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
      policy,
    },

    routes: { ...OIDC_ROUTES },
    // Realm-wide logout is served by Core itself (LogoutController), advertised for BU clients.
    discovery: { end_session_endpoint: `${env.ISSUER}/logout` },
    responseTypes: ['code'],
    pkce: { required: () => true },
    clientAuthMethods: ['private_key_jwt', 'client_secret_basic', 'client_secret_post'],
    enabledJWA: {
      idTokenSigningAlgValues: ['RS256'],
      clientAuthSigningAlgValues: ['RS256', 'PS256', 'ES256'],
    },
    issueRefreshToken: () => false,
    features: {
      devInteractions: { enabled: false },
      // Logout is Core's own realm-wide /logout (spec §24-31), not oidc-provider's per-session one.
      rpInitiatedLogout: { enabled: false },
      revocation: { enabled: true },
      userinfo: { enabled: true },
      // KMS keys are ExternalSigningKey instances (oidc-provider experimental feature, pinned ack).
      externalSigningSupport: d.externalSigning ? { enabled: true, ack: 'experimental-01' } : { enabled: false },
    },
    clockTolerance: 30,
    cookies: {
      keys: env.OIDC_COOKIE_KEYS,
      long: { httpOnly: true, sameSite: 'lax', signed: true },
      short: { httpOnly: true, sameSite: 'lax', signed: true },
    },
    jwks: { keys: d.jwks as NonNullable<Configuration['jwks']>['keys'] },
    ttl: {
      AuthorizationCode: env.AUTH_CODE_TTL_SECONDS,
      IdToken: env.ID_TOKEN_TTL_SECONDS,
      AccessToken: env.ACCESS_TOKEN_TTL_SECONDS,
      Interaction: env.INTERACTION_TTL_SECONDS,
      Session: env.SESSION_ABSOLUTE_TTL_SECONDS,
      Grant: env.SESSION_ABSOLUTE_TTL_SECONDS,
    },

    async renderError(ctx, out, error) {
      logger.warn(`${out.error}: ${out.error_description ?? ''} (${error instanceof Error ? error.constructor.name : 'error'})`);
      ctx.type = 'html';
      ctx.body = d.views.render('error', {
        title: 'Sign-in could not continue',
        message: out.error_description || 'The sign-in request is invalid or has expired.',
        code: out.error,
      });
    },
  };

  const provider = new Provider(env.ISSUER, configuration);
  provider.proxy = env.TRUST_PROXY !== false;
  provider.on('server_error', (_ctx, err) => logger.error(`server_error: ${err.message}`));
  provider.on('grant.error', (_ctx, err) => logger.warn(`grant.error: ${err.message}`));
  return provider;
}
