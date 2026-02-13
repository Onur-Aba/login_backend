import { Entity, Column, ManyToOne, JoinColumn, Index } from 'typeorm';
import { AbstractBaseEntity } from '../../common/abstract.entity';
import { UserEntity } from '../../users/entities/user.entity';

@Entity('sessions')
export class SessionEntity extends AbstractBaseEntity {
  @Column()
  refresh_token_hash!: string;

  @Index()
  @Column({ type: 'uuid' })
  token_family!: string;

  // --- EKSİK OLAN KISIM BAŞLANGIÇ ---
  // Tarayıcı bilgisini (Chrome, Firefox vs.) string olarak tutacağız.
  @Column({ nullable: true })
  user_agent!: string; 
  // --- EKSİK OLAN KISIM BİTİŞ ---

  @Column({ type: 'jsonb', nullable: true })
  device_info!: Record<string, any>; // İşletim sistemi vs. detaylar buraya

  @Column({ type: 'inet', nullable: true })
  ip_address!: string;

  @Column({ type: 'timestamptz' })
  expires_at!: Date;

  @Column({ type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  last_active_at!: Date;

  // --- GRACE PERIOD (TOLERANS) İÇİN YENİ ALANLAR ---
  @Column({ nullable: true })
  previous_refresh_token_hash!: string;

  @Column({ type: 'timestamptz', nullable: true })
  rotated_at!: Date;
  // ------------------------------------------------

  @Column({ default: false })
  is_revoked!: boolean;

  @ManyToOne(() => UserEntity, (user) => user.sessions, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: UserEntity;

  @Column({ type: 'uuid' })
  user_id!: string;
}