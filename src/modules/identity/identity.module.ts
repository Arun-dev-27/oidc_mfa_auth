import { Module } from '@nestjs/common';
import { CaptchaService } from './captcha.service';
import { CredentialService } from './credential.service';

/** Primary authentication against the existing identity tables (read only). */
@Module({
  providers: [CredentialService, CaptchaService],
  exports: [CredentialService, CaptchaService],
})
export class IdentityModule {}
