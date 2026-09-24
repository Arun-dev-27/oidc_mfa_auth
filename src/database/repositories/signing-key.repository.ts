import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, Like, Not, type Repository } from 'typeorm';
import { SigningKeyMetadata, type SigningKeyStatus } from '../entities';

export interface KeyMetadataInput {
  kid: string;
  alg: string;
  status: SigningKeyStatus;
  jwkThumbprint: string;
  publicJwk: Record<string, unknown>;
  keyProviderRef: string;
  purpose: string;
  environment: string;
  revokedAt?: Date | null;
}

/** signing_key_metadata - public metadata about signing keys; never private material. */
@Injectable()
export class SigningKeyRepository {
  constructor(@InjectRepository(SigningKeyMetadata) private readonly keys: Repository<SigningKeyMetadata>) {}

  /** Records the key and its status; first_seen_at of a known key is kept, status changes are timestamped. */
  async upsert(k: KeyMetadataInput): Promise<void> {
    const now = new Date();
    const existing = await this.keys.findOne({ where: { kid: k.kid } });
    const row =
      existing ??
      this.keys.create({ kid: k.kid, firstSeenAt: now, statusChangedAt: now, activatedAt: null, revokedAt: null, createdAt: now });
    if (existing && existing.status !== k.status) row.statusChangedAt = now;
    if (k.status === 'ACTIVE' && !row.activatedAt) row.activatedAt = now;
    if (k.revokedAt !== undefined) row.revokedAt = k.revokedAt ?? row.revokedAt;
    row.alg = k.alg;
    row.status = k.status;
    row.jwkThumbprint = k.jwkThumbprint;
    row.publicJwk = k.publicJwk;
    row.keyProviderRef = k.keyProviderRef;
    row.purpose = k.purpose;
    row.environment = k.environment;
    row.updatedAt = now;
    await this.keys.save(row);
  }

  /** KMS-backed keys of one environment that may still be published (not retired, not revoked). */
  findPublishableKms(environment: string): Promise<SigningKeyMetadata[]> {
    return this.keys.find({
      where: { keyProviderRef: Like('kms:%'), environment, status: Not('RETIRED'), revokedAt: IsNull() },
    });
  }

  findKms(environment: string): Promise<SigningKeyMetadata[]> {
    return this.keys.find({ where: { keyProviderRef: Like('kms:%'), environment }, order: { createdAt: 'ASC' } });
  }

  findByKid(kid: string): Promise<SigningKeyMetadata | null> {
    return this.keys.findOne({ where: { kid } });
  }

  async setStatus(kid: string, status: SigningKeyStatus, extra: { revokedAt?: Date } = {}): Promise<void> {
    const now = new Date();
    await this.keys.update(
      { kid },
      { status, statusChangedAt: now, updatedAt: now, ...(status === 'ACTIVE' ? { activatedAt: now } : {}), ...extra },
    );
  }
}
