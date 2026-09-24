import { Module } from '@nestjs/common';
import type Redis from 'ioredis';
import { AppConfig } from '../../config/config.module';
import { IdentityAccountRepository } from '../../database/repositories/identity-account.repository';
import { REDIS } from '../../redis/redis.module';
import { IdentityModule } from '../identity/identity.module';
import { HandoffController } from '../handoff/handoff.controller';
import { HandoffService } from '../handoff/handoff.service';
import { KeysModule } from '../keys/keys.module';
import { LogoutDeliveryWorker } from '../logout/logout-delivery.worker';
import { LogoutController } from '../logout/logout.controller';
import { LogoutService } from '../logout/logout.service';
import { SigningKeyService } from '../keys/signing-key.service';
import { MfaModule } from '../mfa/mfa.module';
import { SecurityModule } from '../security/security.module';
import { SessionsModule } from '../sessions/sessions.module';
import { ViewsModule } from '../views/views.module';
import { ViewService } from '../views/view.service';
import { AuthPagesService } from './auth-pages.service';
import { ClientAuthService } from './client-auth.service';
import { ClientRegistryService } from './client-registry.service';
import { InteractionController } from './interaction.controller';
import { InteractionService } from './interaction.service';
import { OIDC_PROVIDER } from './oidc.constants';
import { createProvider } from './provider.factory';

@Module({
  imports: [KeysModule, IdentityModule, SessionsModule, MfaModule, SecurityModule, ViewsModule],
  controllers: [InteractionController, LogoutController, HandoffController],
  providers: [
    ClientRegistryService,
    {
      provide: OIDC_PROVIDER,
      inject: [AppConfig, REDIS, SigningKeyService, ClientRegistryService, IdentityAccountRepository, ViewService],
      useFactory: async (
        config: AppConfig,
        redis: Redis,
        keys: SigningKeyService,
        clients: ClientRegistryService,
        accounts: IdentityAccountRepository,
        views: ViewService,
      ) => createProvider({ env: config.env, redis, jwks: await keys.loadForProvider(), externalSigning: keys.usesExternalSigning, clients, accounts, views }),
    },
    AuthPagesService,
    ClientAuthService,
    InteractionService,
    HandoffService,
    LogoutDeliveryWorker,
    LogoutService,
  ],
  exports: [OIDC_PROVIDER],
})
export class OidcModule {}
