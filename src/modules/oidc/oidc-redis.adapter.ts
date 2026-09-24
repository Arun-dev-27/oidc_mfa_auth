import type Redis from 'ioredis';
import type { Adapter, AdapterPayload } from 'oidc-provider';

const GRANTABLE = new Set(['AccessToken', 'AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest']);
const CONSUMABLE = new Set(['AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest']);

/**
 * oidc-provider storage in Redis (spec §4.5): sessions, interactions, grants, authorization codes...
 * Keys: oidc:<Model>:<id>. Every artifact carries its own TTL. Consumable artifacts (authorization
 * codes) are hashes so `consume` marks them atomically; the provider then rejects a second use.
 */
export class OidcRedisAdapter implements Adapter {
  constructor(
    private readonly name: string,
    private readonly redis: Redis,
  ) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const key = this.key(id);
    const multi = this.redis.multi();
    if (CONSUMABLE.has(this.name)) {
      multi.del(key);
      multi.hset(key, { payload: JSON.stringify(payload) });
    } else {
      multi.set(key, JSON.stringify(payload));
    }
    if (expiresIn) multi.expire(key, expiresIn);

    if (GRANTABLE.has(this.name) && payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);
      multi.rpush(grantKey, key);
      const ttl = await this.redis.ttl(grantKey);
      if (expiresIn > ttl) multi.expire(grantKey, expiresIn);
    }
    if (payload.userCode) {
      multi.set(userCodeKeyFor(payload.userCode), id);
      if (expiresIn) multi.expire(userCodeKeyFor(payload.userCode), expiresIn);
    }
    if (payload.uid) {
      multi.set(uidKeyFor(payload.uid), id);
      if (expiresIn) multi.expire(uidKeyFor(payload.uid), expiresIn);
    }
    await multi.exec();
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    if (CONSUMABLE.has(this.name)) {
      const data = await this.redis.hgetall(this.key(id));
      if (!data || !data.payload) return undefined;
      const { payload, ...rest } = data;
      return { ...rest, ...(JSON.parse(payload) as AdapterPayload), ...(rest.consumed ? { consumed: Number(rest.consumed) } : {}) };
    }
    const data = await this.redis.get(this.key(id));
    return data ? (JSON.parse(data) as AdapterPayload) : undefined;
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const id = await this.redis.get(uidKeyFor(uid));
    return id ? this.find(id) : undefined;
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const id = await this.redis.get(userCodeKeyFor(userCode));
    return id ? this.find(id) : undefined;
  }

  async destroy(id: string): Promise<void> {
    await this.redis.del(this.key(id));
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const multi = this.redis.multi();
    const tokens = await this.redis.lrange(grantKeyFor(grantId), 0, -1);
    for (const token of tokens) multi.del(token);
    multi.del(grantKeyFor(grantId));
    await multi.exec();
  }

  async consume(id: string): Promise<void> {
    await this.redis.hset(this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  private key(id: string): string {
    return `oidc:${this.name}:${id}`;
  }
}

function grantKeyFor(id: string): string {
  return `oidc:grant:${id}`;
}
function userCodeKeyFor(userCode: string): string {
  return `oidc:userCode:${userCode}`;
}
function uidKeyFor(uid: string): string {
  return `oidc:uid:${uid}`;
}
