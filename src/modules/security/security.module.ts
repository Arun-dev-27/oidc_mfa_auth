import { Module } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { CsrfService } from './csrf.service';
import { RateLimitService } from './rate-limit.service';

@Module({
  providers: [RateLimitService, CsrfService, AuditService],
  exports: [RateLimitService, CsrfService, AuditService],
})
export class SecurityModule {}
