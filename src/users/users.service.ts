import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import * as argon2 from 'argon2';
import { CreateUserDto } from './dto/create-user.dto';
import { UserEntity, AccountStatus } from './entities/user.entity';
import { ProfileEntity } from './entities/profile.entity';
import { OutboxEntity, OutboxStatus } from '../outbox/entities/outbox.entity';

@Injectable()
export class UsersService {
  constructor(private readonly dataSource: DataSource) {}

  async create(createUserDto: CreateUserDto) {
    // 1. Transaction Başlatıcı (QueryRunner)
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // --- ADIM 1: Şifreyi Hashle ---
      const hashedPassword = await argon2.hash(createUserDto.password);

      // --- ADIM 2: User Entity Hazırla ---
      const user = new UserEntity();
      user.email = createUserDto.email;
      user.password_hash = hashedPassword;
      user.account_status = AccountStatus.UNVERIFIED; // Mail onayı lazım
      // security_stamp ve id otomatik oluşacak (AbstractBaseEntity)

      // Transaction içinde kaydet (Henüz DB'de görünmez, hafızada)
      const savedUser = await queryRunner.manager.save(UserEntity, user);

      // --- ADIM 3: Profile Entity Hazırla ---
      const profile = new ProfileEntity();
      profile.user_id = savedUser.id; // İlişkiyi kuruyoruz
      profile.first_name = createUserDto.first_name;
      profile.last_name = createUserDto.last_name;
      profile.locale = 'tr-TR'; // İleride header'dan dinamik alabiliriz
      profile.ui_preferences = { theme: 'system' }; // Varsayılan JSONB

      await queryRunner.manager.save(ProfileEntity, profile);

      // --- ADIM 4: Outbox (Dual Write Çözümü) ---
      // Mail servisi çökse bile bu emir DB'ye yazılacak.
      const outboxEvent = new OutboxEntity();
      outboxEvent.type = 'USER_REGISTERED';
      outboxEvent.payload = {
        userId: savedUser.id,
        email: savedUser.email,
        name: `${profile.first_name} ${profile.last_name}`,
      };
      outboxEvent.status = OutboxStatus.PENDING;

      await queryRunner.manager.save(OutboxEntity, outboxEvent);

      // --- ADIM 5: Her şey hatasızsa ONAYLA (Commit) ---
      await queryRunner.commitTransaction();

      return {
        message: 'Kayıt başarılı. Lütfen e-posta adresinizi doğrulayın.',
        userId: savedUser.id,
      };

    } catch (error: any) {
      // --- HATA ANINDA GERİ AL (Rollback) ---
      await queryRunner.rollbackTransaction();
      console.log('Veritabanı Hatası Detayı:', error); 
      console.log('Hata Kodu:', error.code);

      // Postgres Unique Violation Hatası (Kod: 23505)
      if (error?.code === '23505') {
        throw new ConflictException('Bu e-posta adresi zaten kullanımda.');
      }

      console.error('Registration Transaction Error:', error);
      throw new InternalServerErrorException('Kayıt işlemi sırasında bir hata oluştu.');
    } finally {
      // Bağlantıyı havuza iade et
      await queryRunner.release();
    }
  }
}