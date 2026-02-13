import { Entity, Column, ManyToOne, JoinColumn } from 'typeorm';
import { AbstractBaseEntity } from '../../common/abstract.entity';
import { UserEntity } from '../../users/entities/user.entity';

export enum AuditAction {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILED = 'LOGIN_FAILED',
  REGISTER = 'REGISTER',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  LOGOUT = 'LOGOUT',
}

@Entity('audit_logs')
export class AuditLogEntity extends AbstractBaseEntity {
  @Column({ type: 'enum', enum: AuditAction })
  action!: AuditAction;

  @Column({ type: 'jsonb', nullable: true })
  metadata!: Record<string, any>; // Örn: { reason: "Wrong password" }

  @Column({ type: 'inet', nullable: true })
  ip_address!: string;

  @Column({ nullable: true })
  user_agent!: string;

  // --- İLİŞKİLER ---

  // User silinse bile loglar kalmalı -> onDelete: 'SET NULL'
  @ManyToOne(() => UserEntity, (user) => user.audit_logs, { onDelete: 'SET NULL' })
  @JoinColumn({ name: 'user_id' })
  user!: UserEntity;

  @Column({ type: 'uuid', nullable: true })
  user_id!: string | null;
}