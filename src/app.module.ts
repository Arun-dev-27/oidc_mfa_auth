import { Module } from '@nestjs/common';
import { ConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { HealthController } from './modules/health/health.controller';
import { OidcModule } from './modules/oidc/oidc.module';
import { RedisModule } from './redis/redis.module';

@Module({
  imports: [ConfigModule, DatabaseModule, RedisModule, OidcModule],
  controllers: [HealthController],
})
export class AppModule {}
