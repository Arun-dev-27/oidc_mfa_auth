import { Inject, Injectable } from '@nestjs/common';
import type { OtpChannel } from '../../../database/entities';
import { OTP_DELIVERY_ADAPTERS, type OtpDeliveryAdapter } from './otp-delivery.adapter';

/** Looks up the delivery adapter for a channel (EMAIL, SMS, ...). */
@Injectable()
export class OtpAdapterRegistry {
  private readonly byChannel: Map<OtpChannel, OtpDeliveryAdapter>;

  constructor(@Inject(OTP_DELIVERY_ADAPTERS) adapters: OtpDeliveryAdapter[]) {
    this.byChannel = new Map(adapters.map((a) => [a.channel, a]));
  }

  get(channel: OtpChannel): OtpDeliveryAdapter | null {
    const adapter = this.byChannel.get(channel);
    return adapter && adapter.isEnabled() ? adapter : null;
  }
}
