import { Global, Inject, Injectable, Logger, Module, type OnApplicationShutdown } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '../config/config.module';

export const REDIS = Symbol('REDIS');
export const InjectRedis = () => Inject(REDIS);

@Injectable()
class RedisLifecycle implements OnApplicationShutdown {
  constructor(@InjectRedis() private readonly redis: Redis) {}

  async onApplicationShutdown(): Promise<void> {
    await this.redis.quit().catch(() => undefined);
  }
}

/**
 * One shared ioredis client. Every key gets REDIS_KEY_PREFIX, so this service can share a Redis
 * instance without colliding with other services. Commands fail fast when Redis is down, and
 * login then fails closed, as the spec requires.
 */
@Global()
@Module({
  providers: [
    {
      provide: REDIS,
      inject: [AppConfig],
      useFactory: (config: AppConfig) => {
        const logger = new Logger('Redis');
        const client = new Redis(config.env.REDIS_URL, {
          keyPrefix: config.env.REDIS_KEY_PREFIX,
          maxRetriesPerRequest: 2,
          enableOfflineQueue: false,
          lazyConnect: false,
        });
        client.on('error', (err) => logger.error(`redis error: ${err.message}`));
        return client;
      },
    },
    RedisLifecycle,
  ],
  exports: [REDIS],
})
export class RedisModule {}
