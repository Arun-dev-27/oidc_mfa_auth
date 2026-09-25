import { Logger, Module } from '@nestjs/common';
import { AppConfig } from '../../config/config.module';
import { createSigningKeyProvider } from './create-signing-key-provider';
import { SIGNING_KEY_PROVIDER, SigningKeyService } from './signing-key.service';

/** Signing keys for oidc-provider, mirrored into signing_key_metadata. */
@Module({
  providers: [
    {
      provide: SIGNING_KEY_PROVIDER,
      inject: [AppConfig],
      useFactory: (config: AppConfig) => {
        if (config.env.KEY_PROVIDER === 'kms') return null;
        const logger = new Logger('SigningKeyProvider');
        return createSigningKeyProvider(config.env, { log: (m) => logger.log(m) });
      },
    },
    SigningKeyService,
  ],
  exports: [SigningKeyService],
})
export class KeysModule {}
