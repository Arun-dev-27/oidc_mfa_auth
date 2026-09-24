import { Module } from '@nestjs/common';
import { CredentialService } from './credential.service';

/** Primary authentication against the existing identity tables (read only). */
@Module({
  providers: [CredentialService],
  exports: [CredentialService],
})
export class IdentityModule {}
