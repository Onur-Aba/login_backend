import { Entity, Column, Index } from 'typeorm';
import { AbstractBaseEntity } from '../../common/abstract.entity';

export enum OutboxStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

@Entity('outbox')
export class OutboxEntity extends AbstractBaseEntity {
  @Index()
  @Column()
  type!: string; // Örn: 'USER_REGISTERED', 'FORGOT_PASSWORD'

  @Column({ type: 'jsonb' })
  payload!: Record<string, any>;

  @Index() // Worker bu statüye göre sorgu atacak
  @Column({
    type: 'enum',
    enum: OutboxStatus,
    default: OutboxStatus.PENDING,
  })
  status!: OutboxStatus;

  @Column({ nullable: true })
  retry_count!: number;

  @Column({ nullable: true })
  last_error!: string;
}