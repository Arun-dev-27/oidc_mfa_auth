import { Injectable } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type Redis from 'ioredis';
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify, type JWK, type JWTVerifyGetKey } from 'jose';
import { AppConfig } from '../../config/config.module';
import { safeEqual } from '../../common/crypto.util';
import { InjectRedis } from '../../redis/redis.module';
import { ClientRegistryService } from './client-registry.service';

const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface AuthenticatedClient {
  clientId: string;
  metadata: Record<string, unknown>;
}

/**
 * Authenticates a registered client calling a Core API directly (e.g. the handoff API, Handoff spec §5),
 * with the same methods as the token endpoint:
 *   client_secret_basic   Authorization: Basic base64(client_id:client_secret)   (standard)
 *   private_key_jwt       client_assertion signed with the client's registered key   (if enabled)
 *   client_secret_post    client_id + client_secret in the body                      (if enabled)
 * Only methods listed in CLIENT_AUTH_METHODS are accepted, and a client may only use the method it
 * is registered for. The client_id is taken from the verified
 * credentials, never from an unauthenticated body field.
 */
@Injectable()
export class ClientAuthService {
  private readonly remoteJwks = new Map<string, JWTVerifyGetKey>();

  constructor(
    private readonly clients: ClientRegistryService,
    private readonly config: AppConfig,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  /** Returns the authenticated client, or null (the caller answers 401). */
  async authenticate(req: FastifyRequest, body: Record<string, unknown>, audiences: string[]): Promise<AuthenticatedClient | null> {
    const allowed = this.config.env.CLIENT_AUTH_METHODS;
    if (body.client_assertion_type === JWT_BEARER && typeof body.client_assertion === 'string') {
      return allowed.includes('private_key_jwt') ? this.privateKeyJwt(body.client_assertion, audiences) : null;
    }
    const basic = parseBasic(req.headers.authorization);
    if (basic) return allowed.includes('client_secret_basic') ? this.secret(basic.id, basic.secret, 'client_secret_basic') : null;
    if (allowed.includes('client_secret_post') && typeof body.client_id === 'string' && typeof body.client_secret === 'string') {
      return this.secret(body.client_id, body.client_secret, 'client_secret_post');
    }
    return null;
  }

  private async secret(clientId: string, secret: string, method: string): Promise<AuthenticatedClient | null> {
    const metadata = await this.clients.findMetadata(clientId);
    if (!metadata || metadata.token_endpoint_auth_method !== method || typeof metadata.client_secret !== 'string') return null;
    return safeEqual(metadata.client_secret, secret) ? { clientId, metadata } : null;
  }

  private async privateKeyJwt(assertion: string, audiences: string[]): Promise<AuthenticatedClient | null> {
    let clientId: string;
    try {
      const [, payload] = assertion.split('.');
      clientId = String(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).iss ?? '');
    } catch {
      return null;
    }
    const metadata = await this.clients.findMetadata(clientId);
    if (!metadata || metadata.token_endpoint_auth_method !== 'private_key_jwt') return null;
    const keys = metadata.jwks_uri
      ? this.remote(String(metadata.jwks_uri))
      : metadata.jwks
        ? createLocalJWKSet(metadata.jwks as { keys: JWK[] })
        : null;
    if (!keys) return null;
    try {
      const { payload } = await jwtVerify(assertion, keys, {
        issuer: clientId,
        subject: clientId,
        audience: audiences,
        algorithms: ['RS256', 'PS256', 'ES256'],
        clockTolerance: 30,
        maxTokenAge: '5m',
        requiredClaims: ['jti', 'exp', 'iat'],
      });
      // One-time use of the assertion (Core spec §10: jti replay protected).
      const ttl = Math.max(60, Number(payload.exp) - Math.floor(Date.now() / 1000) + 60);
      const fresh = await this.redis.set(`clientassert:jti:${clientId}:${String(payload.jti)}`, '1', 'EX', ttl, 'NX');
      return fresh === 'OK' ? { clientId, metadata } : null;
    } catch {
      return null;
    }
  }

  private remote(uri: string): JWTVerifyGetKey {
    let set = this.remoteJwks.get(uri);
    if (!set) {
      set = createRemoteJWKSet(new URL(uri), { cacheMaxAge: 300_000 });
      this.remoteJwks.set(uri, set);
    }
    return set;
  }
}

function parseBasic(header: string | undefined): { id: string; secret: string } | null {
  if (!header?.startsWith('Basic ')) return null;
  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const i = decoded.indexOf(':');
  if (i <= 0) return null;
  try {
    return { id: decodeURIComponent(decoded.slice(0, i)), secret: decodeURIComponent(decoded.slice(i + 1)) };
  } catch {
    return null;
  }
}
