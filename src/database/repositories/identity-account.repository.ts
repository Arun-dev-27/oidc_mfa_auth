import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import type { Repository } from 'typeorm';
import { IdentityUser, MuminMaster, UserEligible } from '../entities';

/** One login-relevant view of a member (users JOIN mumin_master). */
export interface LoginAccount {
  /** ITS ID = users.mumin_id = OIDC sub. */
  muminId: number;
  fullname: string | null;
  email: string | null;
  /** Legacy reversible ciphertext from users.password. */
  password: string | null;
  /** COALESCE(users.allow_login, true) - legacy ISNULL(Allow_Login, 1). */
  allowLogin: boolean;
  isOtpRequired: boolean;
}

/**
 * Read-only access to the SYNCED identity tables (users, mumin_master, user_eligible).
 * There is intentionally no insert / update / delete here: the Mumin sync service owns these tables.
 */
@Injectable()
export class IdentityAccountRepository {
  constructor(
    @InjectRepository(IdentityUser) private readonly users: Repository<IdentityUser>,
    @InjectRepository(UserEligible) private readonly eligible: Repository<UserEligible>,
  ) {}

  /**
   * Legacy "Login Authentication Query":
   *   users JOIN mumin_master ON mumin_id, member status = active, neither row deleted at source.
   */
  async findLoginAccount(muminId: number, activeStatusId: number): Promise<LoginAccount | null> {
    const row = await this.users
      .createQueryBuilder('u')
      .innerJoin(MuminMaster, 'mm', 'mm.muminId = u.muminId')
      .select('u.muminId', 'muminId')
      .addSelect('mm.fullname', 'fullname')
      .addSelect('mm.email', 'email')
      .addSelect('u.password', 'password')
      .addSelect('COALESCE(u.allowLogin, true)', 'allowLogin')
      .addSelect('u.isOtpRequired', 'isOtpRequired')
      .where('u.muminId = :muminId', { muminId })
      .andWhere('mm.statusId = :activeStatusId', { activeStatusId })
      .andWhere('u.isSourceDeleted = false')
      .andWhere('mm.isSourceDeleted = false')
      .orderBy('u.id', 'DESC')
      .limit(1)
      .getRawOne<LoginAccount>();
    return row ?? null;
  }

  /** Legacy "Login Restriction Query": the member must be listed in user_eligible. */
  isEligible(muminId: number): Promise<boolean> {
    return this.eligible.exists({ where: { muminId, isSourceDeleted: false } });
  }
}
