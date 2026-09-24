import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { MoreThan, type Repository } from 'typeorm';
import { AuthOtpChallenge, UserMfaFactor, type MfaMethod, type OtpChannel, type OtpPurpose } from '../entities';

/** user_mfa_factors */
@Injectable()
export class MfaFactorRepository {
  constructor(@InjectRepository(UserMfaFactor) private readonly factors: Repository<UserMfaFactor>) {}

  findActive(itsId: string): Promise<UserMfaFactor[]> {
    return this.factors.find({ where: { itsId, status: 'ACTIVE' }, order: { isDefault: 'DESC', createdAt: 'ASC' } });
  }

  async create(input: {
    itsId: string;
    method: MfaMethod;
    isDefault: boolean;
    destinationEnc: string | null;
    totpSecretEnc: string | null;
  }): Promise<UserMfaFactor> {
    return this.factors.manager.transaction(async (m) => {
      const repo = m.getRepository(UserMfaFactor);
      if (input.isDefault) await repo.update({ itsId: input.itsId, isDefault: true }, { isDefault: false });
      return repo.save(repo.create({ ...input, status: 'ACTIVE', verifiedAt: new Date() }));
    });
  }

  /**
   * Accepts a TOTP time step only if it is newer than the last accepted one (atomic), so the same
   * code cannot be used twice. Returns false for a replay.
   */
  async acceptTotpStep(id: string, step: number): Promise<boolean> {
    const result = await this.factors
      .createQueryBuilder()
      .update()
      .set({ lastUsedStep: String(step), lastUsedAt: () => 'now()' })
      .where('id = :id AND (last_used_step IS NULL OR last_used_step < :step)', { id, step })
      .execute();
    return (result.affected ?? 0) === 1;
  }

  async markUsed(id: string): Promise<void> {
    await this.factors.update({ id }, { lastUsedAt: new Date() });
  }
}

export interface NewOtpChallenge {
  itsId: string;
  sid: string;
  interactionUid: string;
  channel: OtpChannel;
  purpose: OtpPurpose;
  destinationMasked: string;
  codeHash: string;
  maxAttempts: number;
  expiresAt: Date;
}

/** auth_otp_challenges */
@Injectable()
export class OtpChallengeRepository {
  constructor(@InjectRepository(AuthOtpChallenge) private readonly challenges: Repository<AuthOtpChallenge>) {}

  create(c: NewOtpChallenge): Promise<AuthOtpChallenge> {
    return this.challenges.save(this.challenges.create({ ...c, attemptCount: 0 }));
  }

  findById(id: string): Promise<AuthOtpChallenge | null> {
    return this.challenges.findOne({ where: { id } });
  }

  async setProviderMessageId(id: string, providerMessageId: string | null): Promise<void> {
    if (providerMessageId) await this.challenges.update({ id }, { providerMessageId: providerMessageId.slice(0, 255) });
  }

  /**
   * Spends one attempt atomically. Returns the attempt number, or null when the challenge is
   * already consumed, expired or out of attempts - so parallel guesses cannot exceed the limit.
   */
  async spendAttempt(id: string): Promise<number | null> {
    const rows: { attempt_count: number }[] = await this.challenges.query(
      `UPDATE auth_otp_challenges
          SET attempt_count = attempt_count + 1
        WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() AND attempt_count < max_attempts
        RETURNING attempt_count`,
      [id],
    );
    // TypeORM returns [rows, affected] for UPDATE ... RETURNING on postgres.
    const list = Array.isArray(rows[0]) ? (rows[0] as unknown as { attempt_count: number }[]) : rows;
    return list.length ? list[0].attempt_count : null;
  }

  /** Marks the challenge used. Only the first caller wins. */
  async consume(id: string): Promise<boolean> {
    const result = await this.challenges
      .createQueryBuilder()
      .update()
      .set({ consumedAt: () => 'now()' })
      .where('id = :id AND consumed_at IS NULL', { id })
      .execute();
    return (result.affected ?? 0) === 1;
  }

  /** Codes sent to a member in the last hour - caps email/SMS cost and abuse. */
  countSentSince(itsId: string, since: Date): Promise<number> {
    return this.challenges.count({ where: { itsId, createdAt: MoreThan(since) } });
  }
}
