import { Controller, Get, HttpCode, Res } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import type { FastifyReply } from 'fastify';
import type Redis from 'ioredis';
import type { DataSource } from 'typeorm';
import { InjectRedis } from '../../redis/redis.module';

/** Liveness / readiness: the service is only ready when PostgreSQL and Redis both answer. */
@Controller('health')
export class HealthController {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @InjectRedis() private readonly redis: Redis,
  ) {}

  @Get('live')
  @HttpCode(200)
  live() {
    return { status: 'ok' };
  }

  @Get('ready')
  async ready(@Res() reply: FastifyReply) {
    const checks = { database: 'down', redis: 'down' };
    await this.db.query('SELECT 1').then(() => (checks.database = 'up')).catch(() => undefined);
    await this.redis.ping().then(() => (checks.redis = 'up')).catch(() => undefined);
    const ok = checks.database === 'up' && checks.redis === 'up';
    return reply.code(ok ? 200 : 503).send({ status: ok ? 'ok' : 'unavailable', checks });
  }
}
