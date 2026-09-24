import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { AuthAuditEvent, type AuditOutcome } from '../entities';

export interface NewAuditEvent {
  eventType: string;
  outcome: AuditOutcome;
  itsId?: string | null;
  sid?: string | null;
  clientId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  correlationId?: string | null;
  metadata?: Record<string, unknown> | null;
}

/** auth_audit_events - append only. */
@Injectable()
export class AuditEventRepository {
  constructor(@InjectRepository(AuthAuditEvent) private readonly events: Repository<AuthAuditEvent>) {}

  async insert(e: NewAuditEvent): Promise<void> {
    await this.events.save(this.events.create({
      eventType: e.eventType,
      outcome: e.outcome,
      itsId: e.itsId ?? null,
      sid: e.sid ?? null,
      clientId: e.clientId ?? null,
      jti: null,
      ipAddress: e.ipAddress ?? null,
      userAgent: e.userAgent?.slice(0, 512) ?? null,
      correlationId: e.correlationId ?? null,
      metadata: e.metadata ?? null,
    }));
  }
}
