import { Injectable } from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import type { DataSource, Repository } from 'typeorm';
import { AuthClient, AuthClientCallback, type AuthRealm, type CallbackUriType, type TokenEndpointAuthMethod } from '../entities';

export interface NewClient {
  clientId: string;
  name: string;
  applicationCode: string;
  businessUnit: string | null;
  environment: string;
  authRealm: AuthRealm;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  clientSecretEnc: string | null;
  clientJwksUri: string | null;
  clientJwks?: { keys: Record<string, unknown>[] } | null;
  allowedScopes: string;
  defaultAcr: string | null;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  backchannelLogoutUri?: string | null;
}

/** auth_clients + auth_client_callbacks. */
@Injectable()
export class ClientRepository {
  constructor(
    @InjectRepository(AuthClient) private readonly clients: Repository<AuthClient>,
    @InjectDataSource() private readonly db: DataSource,
  ) {}

  /** The client with its callbacks, whatever its status (the caller decides what a status means). */
  findByClientId(clientId: string): Promise<AuthClient | null> {
    return this.clients.findOne({ where: { clientId }, relations: { callbacks: true } });
  }

  /**
   * Adds a URI to an existing client (idempotent). A client has at most one BACK_CHANNEL_LOGOUT URI,
   * so adding one replaces the previous.
   */
  async addCallback(clientId: string, uriType: CallbackUriType, uri: string): Promise<void> {
    const client = await this.findByClientId(clientId);
    if (!client) throw new Error(`unknown client ${clientId}`);
    await this.db.transaction(async (m) => {
      const repo = m.getRepository(AuthClientCallback);
      if (uriType === 'BACK_CHANNEL_LOGOUT') await repo.delete({ clientRef: client.id, uriType });
      const exists = await repo.exists({ where: { clientRef: client.id, uriType, uri } });
      if (!exists) await repo.save(repo.create({ clientRef: client.id, uriType, uri, isPrimary: false }));
    });
  }

  /** Removes clients by exact id (test tooling only; callbacks cascade). */
  async deleteByClientIds(clientIds: string[]): Promise<void> {
    if (clientIds.length) await this.clients.delete(clientIds.map((clientId) => ({ clientId })));
  }

  /** Creates a client and its callbacks in one transaction (used by the registration script). */
  async create(input: NewClient): Promise<AuthClient> {
    return this.db.transaction(async (m) => {
      const client = await m.getRepository(AuthClient).save(
        m.getRepository(AuthClient).create({
          clientId: input.clientId,
          name: input.name,
          applicationCode: input.applicationCode,
          applicationName: input.name,
          businessUnit: input.businessUnit,
          environment: input.environment,
          clientType: 'WEB',
          authenticationMode: 'REDIRECT',
          status: 'ACTIVE',
          authRealm: input.authRealm,
          tokenEndpointAuthMethod: input.tokenEndpointAuthMethod,
          clientSecretEnc: input.clientSecretEnc,
          clientJwksUri: input.clientJwksUri,
          clientJwks: input.clientJwks ?? null,
          allowedScopes: input.allowedScopes,
          defaultAcr: input.defaultAcr,
        }),
      );
      const callbacks: { uri: string; uriType: CallbackUriType }[] = [
        ...input.redirectUris.map((uri) => ({ uri, uriType: 'CALLBACK' as const })),
        ...input.postLogoutRedirectUris.map((uri) => ({ uri, uriType: 'POST_LOGOUT_REDIRECT' as const })),
        ...(input.backchannelLogoutUri ? [{ uri: input.backchannelLogoutUri, uriType: 'BACK_CHANNEL_LOGOUT' as const }] : []),
      ];
      const repo = m.getRepository(AuthClientCallback);
      for (const [i, cb] of callbacks.entries()) {
        await repo.save(repo.create({ clientRef: client.id, uri: cb.uri, uriType: cb.uriType, isPrimary: i === 0 }));
      }
      return client;
    });
  }
}
