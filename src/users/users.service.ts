import * as crypto from 'crypto'; // <-- EKLENDİ
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

      // --- ADIM 2: User Entity Hazırla (GÜNCELLEME) ---
      const user = new UserEntity();
      user.email = createUserDto.email;
      user.username = createUserDto.username as any; // <-- DÜZELTME BURADA (TS Hatası önlemi)
      user.password_hash = hashedPassword;
      user.account_status = AccountStatus.UNVERIFIED; // Baştan doğrulanmamış kabul ediyoruz

      // 1. Doğrulama Token'ı Üret (24 saat geçerli)
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationTokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');
      
      user.email_verification_hash = verificationTokenHash;
      user.email_verification_expires_at = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 Saat

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

      // --- ADIM 4: Outbox (GÜNCELLEME) ---
      const outboxEvent = new OutboxEntity();
      outboxEvent.type = 'VERIFY_EMAIL'; // TİPİ DEĞİŞTİRDİK
      outboxEvent.payload = {
        email: savedUser.email,
        name: `${profile.first_name} ${profile.last_name}`,
        // Frontend URL'niz:
        verifyLink: `https://senin-frontend.com/verify-email?token=${verificationToken}`, 
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