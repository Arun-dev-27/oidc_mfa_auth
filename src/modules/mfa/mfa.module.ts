import { Module } from '@nestjs/common';
import { SecurityModule } from '../security/security.module';
import { EmailOtpAdapter } from './adapters/email-otp.adapter';
import { OtpAdapterRegistry } from './adapters/otp-adapter.registry';
import { OTP_DELIVERY_ADAPTERS, type OtpDeliveryAdapter } from './adapters/otp-delivery.adapter';
import { SmsOtpAdapter } from './adapters/sms-otp.adapter';
import { MfaService } from './mfa.service';

/** MFA with pluggable OTP delivery adapters: Email (default) and SMS. Add new channels here. */
@Module({
  imports: [SecurityModule],
  providers: [
    EmailOtpAdapter,
    SmsOtpAdapter,
    {
      provide: OTP_DELIVERY_ADAPTERS,
      inject: [EmailOtpAdapter, SmsOtpAdapter],
      useFactory: (...adapters: OtpDeliveryAdapter[]) => adapters,
    },
    OtpAdapterRegistry,
    MfaService,
  ],
  exports: [MfaService],
})
export class MfaModule {}
