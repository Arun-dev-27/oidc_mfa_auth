import { Injectable, Logger } from '@nestjs/common';
import type { Adapter, AdapterPayload } from 'oidc-provider';
import { AppConfig } from '../../config/config.module';
import { decryptString, toKey32 } from '../../common/crypto.util';
import { isAuthRealm, type AuthClient } from '../../database/entities';
import { ClientRepository } from '../../database/repositories/client.repository';

const SECRET_METHODS = new Set(['client_secret_basic', 'client_secret_post']);

/**
 * Registered clients come from auth_clients (+ auth_client_callbacks), never from dynamic
 * registration. A client is usable only when it is ACTIVE, has an auth_realm and at least one
 * CALLBACK URI, and its token_endpoint_auth_method (default client_secret_basic) is enabled in
 * CLIENT_AUTH_METHODS; otherwise oidc-provider answers invalid_client. The realm is exposed to the
 * provider as the custom client metadata `auth_realm` and can never come from the request.
 */
@Injectable()
export class ClientRegistryService {
  private readonly logger = new Logger(ClientRegistryService.name);
  private readonly dataKey: Buffer;
  private readonly allowedMethods: ReadonlySet<string>;

  constructor(
    private readonly clients: ClientRepository,
    config: AppConfig,
  ) {
    this.dataKey = toKey32(config.env.DATA_ENCRYPTION_KEY);
    this.allowedMethods = new Set(config.env.CLIENT_AUTH_METHODS);
  }

  async findMetadata(clientId: string): Promise<AdapterPayload | undefined> {
    if (!/^[a-z0-9][a-z0-9-]{2,63}$/.test(clientId)) return undefined;
    const client = await this.clients.findByClientId(clientId);
    if (!client) return undefined;
    return this.toMetadata(client);
  }

  /** The adapter oidc-provider uses for its Client model: read-only, backed by the database. */
  adapter(): Adapter {
    const find = (id: string) => this.findMetadata(id);
    const readOnly = async () => {
      throw new Error('clients are managed in auth_clients, not through oidc-provider');
    };
    return {
      find,
      upsert: readOnly,
      destroy: readOnly,
      consume: readOnly,
      revokeByGrantId: readOnly,
      findByUid: async () => undefined,
      findByUserCode: async () => undefined,
    };
  }

  private toMetadata(c: AuthClient): AdapterPayload | undefined {
    if (c.status !== 'ACTIVE') return undefined;
    if (!isAuthRealm(c.authRealm)) {
      this.logger.warn(`client ${c.clientId} has no auth_realm and is rejected`);
      return undefined;
    }
    const redirectUris = c.callbacks.filter((cb) => cb.uriType === 'CALLBACK').map((cb) => cb.uri);
    if (!redirectUris.length) return undefined;

    const method = c.tokenEndpointAuthMethod ?? 'client_secret_basic';
    if (!this.allowedMethods.has(method)) {
      this.logger.warn(`client ${c.clientId} uses ${method}, which is not enabled in CLIENT_AUTH_METHODS; it is rejected`);
      return undefined;
    }
    const metadata: AdapterPayload = {
      client_id: c.clientId,
      client_name: c.name,
      application_type: 'web',
      redirect_uris: redirectUris,
      post_logout_redirect_uris: c.callbacks.filter((cb) => cb.uriType === 'POST_LOGOUT_REDIRECT').map((cb) => cb.uri),
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: method,
      id_token_signed_response_alg: 'RS256',
      // BUs need auth_time to judge assurance age; always include it in the ID token.
      require_auth_time: true,
      scope: c.allowedScopes?.trim() || 'openid',
      auth_realm: c.authRealm,
    };
    if (c.defaultAcr) metadata.default_acr_values = [c.defaultAcr];

    if (SECRET_METHODS.has(method)) {
      if (!c.clientSecretEnc) return undefined;
      metadata.client_secret = decryptString(this.dataKey, c.clientSecretEnc);
    } else if (method === 'private_key_jwt') {
      if (c.clientJwksUri) metadata.jwks_uri = c.clientJwksUri;
      else if (c.clientJwks) metadata.jwks = c.clientJwks as AdapterPayload['jwks'];
      else return undefined;
      metadata.token_endpoint_auth_signing_alg = 'RS256';
    }
    return metadata;
  }
}
