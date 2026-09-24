import { Module } from '@nestjs/common';
import { SigningKeyService } from './signing-key.service';

/** Signing keys for oidc-provider, mirrored into signing_key_metadata. */
@Module({
  providers: [SigningKeyService],
  exports: [SigningKeyService],
})
export class KeysModule {}
