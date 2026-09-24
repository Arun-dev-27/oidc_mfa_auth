import { Column, Entity, PrimaryColumn } from 'typeorm';

/** mumin_master - SYNCED table. Read only. Source of the member status, name and email. */
@Entity({ name: 'mumin_master' })
export class MuminMaster {
  @PrimaryColumn({ name: 'person_id', type: 'numeric' })
  personId: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  @Column({ name: 'status_id', type: 'smallint', nullable: true })
  statusId: number | null;

  @Column({ type: 'varchar', nullable: true })
  fullname: string | null;

  @Column({ type: 'varchar', nullable: true })
  email: string | null;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;
}
