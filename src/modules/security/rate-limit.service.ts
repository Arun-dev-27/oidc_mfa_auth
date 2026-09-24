import { Injectable } from '@nestjs/common';
import type Redis from 'ioredis';
import { InjectRedis } from '../../redis/redis.module';

export interface RateLimitResult {
  allowed: boolean;
  /** Seconds until the window resets (only meaningful when not allowed). */
  retryAfter: number;
}

/** Fixed-window counters in Redis (ratelimit:<dimension>:<key>). */
@Injectable()
export class RateLimitService {
  constructor(@InjectRedis() private readonly redis: Redis) {}

  async hit(dimension: string, key: string, limit: number, windowSeconds: number): Promise<RateLimitResult> {
    const redisKey = `ratelimit:${dimension}:${key}`;
    const [[, count], [, ttl]] = (await this.redis
      .multi()
      .incr(redisKey)
      .ttl(redisKey)
      .exec()) as [[null, number], [null, number]];
    if (ttl < 0) await this.redis.expire(redisKey, windowSeconds);
    const retryAfter = ttl > 0 ? ttl : windowSeconds;
    return { allowed: count <= limit, retryAfter };
  }

  /** A single-use cooldown, e.g. "one OTP resend every 30 s". Returns seconds left, or 0 when free. */
  async cooldown(dimension: string, key: string, seconds: number): Promise<number> {
    if (seconds <= 0) return 0;
    const redisKey = `cooldown:${dimension}:${key}`;
    const set = await this.redis.set(redisKey, '1', 'EX', seconds, 'NX');
    if (set === 'OK') return 0;
    return Math.max(1, await this.redis.ttl(redisKey));
  }
}
