import { Module } from '@nestjs/common';
import { GlobalSessionService } from './global-session.service';

/** Core realm sessions: Redis hot copy + auth_sessions. */
@Module({
  providers: [GlobalSessionService],
  exports: [GlobalSessionService],
})
export class SessionsModule {}
