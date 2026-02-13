import {
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  BaseEntity,
  BeforeInsert,
} from 'typeorm';
import { v7 as uuidv7 } from 'uuid';

export abstract class AbstractBaseEntity extends BaseEntity {
  // UUID v7 kullanacağımız için PrimaryGeneratedColumn değil, PrimaryColumn kullanıyoruz.
  // Değeri BeforeInsert ile biz atayacağız.
  @PrimaryColumn('uuid')
  id!: string;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;

  // Soft Delete sütunu. Silinenler buraya tarih alır.
  @DeleteDateColumn({ type: 'timestamptz', nullable: true })
  deleted_at!: Date | null;

  @BeforeInsert()
  generateId() {
    if (!this.id) {
      this.id = uuidv7(); // Zaman sıralı UUID v7
    }
  }
}