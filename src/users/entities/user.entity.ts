import { Entity, Column, Index, OneToOne, OneToMany } from 'typeorm';
import { AbstractBaseEntity } from '../../common/abstract.entity';
import { ProfileEntity } from './profile.entity';
import { SessionEntity } from '../../auth/entities/session.entity';
import { AuditLogEntity } from '../../audit_logs/entities/audit_log.entity';

export enum AccountStatus {
  UNVERIFIED = 'UNVERIFIED',
  ACTIVE = 'ACTIVE',
  SUSPENDED = 'SUSPENDED',
  ARCHIVED = 'ARCHIVED',
}

@Entity('users')
// KRİTİK NOKTA: Silinmiş (Soft Delete) kullanıcıların emaili unique index'i bozmasın.
// Sadece deleted_at IS NULL olanlar unique olsun.
@Index(['email'], { unique: true, where: '"deleted_at" IS NULL' })
@Index(['username'], { unique: true, where: '"deleted_at" IS NULL' })
export class UserEntity extends AbstractBaseEntity {
  @Column()
  email!: string;

  // DÜZELTME: nullable olduğu için string | null
@Column({ type: 'varchar', nullable: true }) // Açıkça varchar olduğunu belirttik
  username!: string | null;

  @Column({ select: false }) // Şifreyi asla default sorguda getirme
  password_hash!: string;

  // Güvenlik damgası: Şifre değişince bu değişir, eski tokenlar patlar.
  @Column({ type: 'uuid', generated: 'uuid' }) 
  security_stamp!: string;

  @Column({
    type: 'enum',
    enum: AccountStatus,
    default: AccountStatus.UNVERIFIED,
  })
  account_status!: AccountStatus;

  @Column({ default: false })
  two_factor_enabled!: boolean;

  // DÜZELTME: nullable olduğu için string | null
@Column({ type: 'varchar', nullable: true, select: false })
  two_factor_secret!: string | null;

  // --- ŞİFRE SIFIRLAMA İÇİN YENİ ALANLAR ---
  // DÜZELTME: nullable olduğu için string | null
@Column({ type: 'varchar', nullable: true, select: false })
  password_reset_hash!: string | null;

  // DÜZELTME: nullable olduğu için Date | null
  @Column({ type: 'timestamptz', nullable: true })
  password_reset_expires_at!: Date | null;

  // --- İLİŞKİLER ---

  @OneToOne(() => ProfileEntity, (profile) => profile.user, {
    cascade: true, // User silinirse profil de silinsin (soft delete)
  })
  profile!: ProfileEntity;

  @OneToMany(() => SessionEntity, (session) => session.user)
  sessions!: SessionEntity[];

  @OneToMany(() => AuditLogEntity, (log) => log.user)
  audit_logs!: AuditLogEntity[];

  // --- EMAIL 2FA (OTP) İÇİN YENİ ALANLAR ---
  // DÜZELTME: nullable olduğu için string | null
@Column({ type: 'varchar', nullable: true, select: false })
  two_factor_otp_hash!: string | null;

  // DÜZELTME: nullable olduğu için Date | null
  @Column({ type: 'timestamptz', nullable: true })
  two_factor_otp_expires_at!: Date | null;

  // --- E-POSTA DOĞRULAMA İÇİN YENİ ALANLAR ---
  // DÜZELTME: nullable olduğu için string | null
@Column({ type: 'varchar', nullable: true, select: false })
  email_verification_hash!: string | null;

  // DÜZELTME: nullable olduğu için Date | null
  @Column({ type: 'timestamptz', nullable: true })
  email_verification_expires_at!: Date | null;
}