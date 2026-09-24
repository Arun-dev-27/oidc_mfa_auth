import { Column, Entity, PrimaryColumn } from 'typeorm';

/** user_eligible - SYNCED table. Read only. Used only when LOGIN_ELIGIBILITY_CHECK_ENABLED=true. */
@Entity({ name: 'user_eligible' })
export class UserEligible {
  @PrimaryColumn({ type: 'numeric' })
  id: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;
}
