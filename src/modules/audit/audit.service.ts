import { Injectable, Logger } from '@nestjs/common';
import { AuditEventRepository, type NewAuditEvent } from '../../database/repositories/audit-event.repository';

/**
 * Security audit trail (auth_audit_events). An audit write failure is logged but never breaks a
 * login. Callers must never pass passwords, OTPs, tokens or cookie values in metadata.
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger('Audit');

  constructor(private readonly events: AuditEventRepository) {}

  async record(event: NewAuditEvent): Promise<void> {
    this.logger.log({ event: event.eventType, outcome: event.outcome, itsId: event.itsId, sid: event.sid, clientId: event.clientId });
    try {
      await this.events.insert(event);
    } catch (error) {
      this.logger.error(`audit write failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
