import { Entity, Column, OneToOne, JoinColumn, Index } from 'typeorm';
import { AbstractBaseEntity } from '../../common/abstract.entity';
import { UserEntity } from './user.entity';

@Entity('profiles')
export class ProfileEntity extends AbstractBaseEntity {
  // Sorgu Performansı için kritik alanlar ayrı kolon oldu
  @Column()
  first_name!: string;

  @Column()
  last_name!: string;

  // İsim arama (Search) için index
  @Index() 
  @Column({ nullable: true })
  display_name!: string;

  @Column({ nullable: true })
  avatar_url!: string;

  // İş mantığında (Business Logic) kullanılacak alanlar kolon oldu (JSONB değil)
  @Index()
  @Column({ default: 'tr-TR', length: 10 })
  locale!: string;

  @Index()
  @Column({ default: 'Europe/Istanbul' })
  timezone!: string;

  // Sadece Frontend'in kullanacağı, Backend'in sorgulamayacağı veriler JSONB
  @Column({ type: 'jsonb', default: {} })
  ui_preferences!: Record<string, any>;

  // --- İLİŞKİLER ---

  @OneToOne(() => UserEntity, (user) => user.profile, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' }) // user_id sütunu bu tabloda olacak
  user!: UserEntity;

  @Column({ type: 'uuid' })
  user_id!: string;
}