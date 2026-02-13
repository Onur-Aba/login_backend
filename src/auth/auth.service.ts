import * as crypto from 'crypto'; // En üste eklendi (Node.js yerleşik modülü)
import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  InternalServerErrorException,
  BadRequestException, // <-- EKLENDİ
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as argon2 from 'argon2';
import { v7 as uuidv7 } from 'uuid'; // Session ID ve Token Family için

import { UserEntity, AccountStatus } from '../users/entities/user.entity';
import { SessionEntity } from './entities/session.entity';
import { OutboxEntity, OutboxStatus } from '../outbox/entities/outbox.entity'; 
import { LoginDto } from '../auth/dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto'; 
import { ForgotPasswordDto } from './dto/forgot-password.dto'; 
import { ResetPasswordDto } from './dto/reset-password.dto'; 
import { Verify2FaDto } from './dto/verify-2fa.dto'; 
import { VerifyEmailDto } from './dto/verify-email.dto'; 

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    @InjectRepository(OutboxEntity)
    private readonly outboxRepository: Repository<OutboxEntity>,
    @InjectRepository(SessionEntity)
    private readonly sessionRepository: Repository<SessionEntity>,
    private readonly jwtService: JwtService,
  ) {}

  async login(loginDto: LoginDto, userAgent: string, ipAddress: string) {
    const { identifier, password } = loginDto;

    // 1. KULLANICIYI BUL (Email VEYA Username ile)
    // TypeORM QueryBuilder kullanarak "OR" sorgusu atıyoruz.
    const user = await this.userRepository
      .createQueryBuilder('user')
      .addSelect('user.password_hash') // Şifre default hidden, burada lazım
      .addSelect('user.account_status') // Statü kontrolü için gerekli
      .where('user.email = :identifier', { identifier })
      .orWhere('user.username = :identifier', { identifier })
      .getOne();

    // 2. GÜVENLİK: Kullanıcı yoksa bile "hata" hemen dönülmemeli (Timing Attack önlemi)
    // Ancak Argon2 zaten yavaş olduğu için burada fake bir işlem yapmaya gerek yok.
    if (!user) {
      throw new UnauthorizedException('Giriş bilgileri hatalı.');
    }

    // 3. ŞİFRE KONTROLÜ
    const isPasswordValid = await argon2.verify(user.password_hash, password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Giriş bilgileri hatalı.');
    }

    // 4. STATÜ KONTROLÜ (Enterprise Kuralı)
    if (user.account_status === AccountStatus.SUSPENDED) {
      throw new ForbiddenException('Hesabınız askıya alınmıştır.');
    }
    
    // YENİ EKLENEN KISIM: Doğrulanmamış hesapları kapıdan çevir
    if (user.account_status === AccountStatus.UNVERIFIED) {
      throw new ForbiddenException('Lütfen önce e-posta adresinize gönderilen linke tıklayarak hesabınızı doğrulayın.');
    }

    // --- 2FA KONTROLÜ (ENTERPRISE MANTIĞI) ---
    if (user.two_factor_enabled) {
      // 1. 6 Haneli Rastgele Kod Üret
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString(); // Örn: "482915"

      // 2. Kodu Hashle (SHA256, kısa ömürlü olduğu için yeterli ve hızlıdır)
      const otpHash = crypto.createHash('sha256').update(otpCode).digest('hex');

      // 3. Veritabanına kaydet (Ömrü: 3 Dakika)
      user.two_factor_otp_hash = otpHash;
      user.two_factor_otp_expires_at = new Date(Date.now() + 3 * 60 * 1000);
      await this.userRepository.save(user);

      // 4. Outbox'a Mail Emri Bırak
      const outboxEvent = new OutboxEntity();
      outboxEvent.type = 'TWO_FACTOR_OTP';
      outboxEvent.payload = { email: user.email, code: otpCode };
      outboxEvent.status = OutboxStatus.PENDING;
      await this.outboxRepository.save(outboxEvent);

      // 5. Geçici "Pending Token" Üret (Ömrü 5 Dakika)
      const pendingToken = this.jwtService.sign(
        { sub: user.id, type: '2FA_PENDING' },
        { expiresIn: '5m' }
      );

      // ASIL TOKENLARI VERME, SADECE BEKLEME JETONUNU VER
      return {
        message: 'Güvenlik kodu e-posta adresinize gönderildi.',
        requires2FA: true,
        pendingToken,
      };
    }

    // --- 2FA KAPALIYSA NORMAL AKIŞA DEVAM ET ---
    // 5. SESSION VE TOKEN OLUŞTURMA
    return this.createSession(user, userAgent, ipAddress);
  }

  async verify2Fa(verify2FaDto: Verify2FaDto, ip: string, userAgent: string) {
    const { pendingToken, code } = verify2FaDto;

    try {
      // 1. Pending Token'ı Doğrula (Süresi geçmiş mi? Gerçekten 2FA token'ı mı?)
      const payload = this.jwtService.verify(pendingToken);
      
      if (payload.type !== '2FA_PENDING') {
        throw new UnauthorizedException('Geçersiz token tipi.');
      }

      // 2. Kullanıcıyı ve Hashlenmiş Kodu Çek
      const user = await this.userRepository.findOne({
        where: { id: payload.sub },
        select: ['id', 'email', 'username', 'two_factor_otp_hash', 'two_factor_otp_expires_at'],
      });

      if (!user) {
        throw new UnauthorizedException('Kullanıcı bulunamadı.');
      }

      // 3. Kodun Süresi Dolmuş mu?
      if (!user.two_factor_otp_expires_at || user.two_factor_otp_expires_at < new Date()) {
        throw new UnauthorizedException('Güvenlik kodunun süresi dolmuş. Lütfen tekrar giriş yapın.');
      }

      // 4. Gelen Kodu Hashle ve Karşılaştır
      const hashedInputCode = crypto.createHash('sha256').update(code).digest('hex');
      if (user.two_factor_otp_hash !== hashedInputCode) {
        throw new UnauthorizedException('Hatalı güvenlik kodu.');
      }

      // 5. BAŞARILI! Kodu Temizle (Tek kullanımlık olmasını garanti altına al)
      user.two_factor_otp_hash = null as any; // <-- TS Hatası önlemi eklendi
      user.two_factor_otp_expires_at = null as any; // <-- TS Hatası önlemi eklendi
      await this.userRepository.save(user);

      // 6. Artık Gerçek Oturumu Başlatabiliriz
      return this.createSession(user, userAgent, ip);

    } catch (error) {
      throw new UnauthorizedException('Doğrulama başarısız veya kodun süresi dolmuş.');
    }
  }

  // Kullanıcının 2FA'yı açıp kapatabilmesi için ayar metodu
  async toggle2Fa(userId: string, enable: boolean) {
    // 1. Veritabanında 2FA durumunu güncelle
    await this.userRepository.update(userId, { two_factor_enabled: enable });

    // 2. ENTERPRISE KURALI: 2FA açıldıysa acımadan tüm oturumları patlat!
    if (enable) {
      // Daha önce yazdığımız "Tüm Cihazlardan Çıkış Yap" metodunu tetikliyoruz
      await this.logoutAllDevices(userId);
      
      return { 
        message: 'İki aşamalı doğrulama AKTİF edildi. Güvenliğiniz için tüm oturumlarınız kapatıldı. Lütfen e-postanıza gelecek kod ile tekrar giriş yapın.' 
      };
    }

    return { message: 'İki aşamalı doğrulama KAPATILDI.' };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto, ip: string, userAgent: string) {
    const { refreshToken } = refreshTokenDto;

    try {
      // 1. Token'ı çöz (Süresi dolmuş mu, geçerli mi?)
      // secret'ı configService'den aldığını varsayıyorum, eğer constructor'da configService yoksa eklemelisin.
      const payload = this.jwtService.verify(refreshToken, {
         // Eğer JWT modülüne default secret verdiysen burayı boş bırakabilirsin, 
         // vermediysen { secret: process.env.JWT_SECRET } yazabilirsin.
      });

      const { sub: userId, family: tokenFamily } = payload;

      // 2. Veritabanında bu Session'ı bul (Token Family'ye göre)
      const session = await this.sessionRepository.findOne({
        where: { token_family: tokenFamily, user_id: userId },
        relations: ['user'], // Yeni token üretirken user bilgileri gerekecek
      });

      if (!session) {
        throw new UnauthorizedException('Geçersiz oturum.');
      }

      if (session.is_revoked) {
        throw new UnauthorizedException('Oturum sonlandırılmış.');
      }

      // 3. HASH KONTROLÜ VE REUSE DETECTION (HIRSIZLIK KORUMASI)
      const isCurrentToken = await argon2.verify(session.refresh_token_hash, refreshToken);

      if (!isCurrentToken) {
        // Eğer gelen token CURRENT (mevcut) değilse, ya hırsızlıktır ya da network gecikmesidir (Race Condition).
        
        const isPreviousToken = session.previous_refresh_token_hash 
          ? await argon2.verify(session.previous_refresh_token_hash, refreshToken) 
          : false;

        if (isPreviousToken && session.rotated_at) {
          // GRACE PERIOD KONTROLÜ: Token daha yeni mi değişti? (Örn: Son 20 saniye içinde)
          const gracePeriodMs = 20 * 1000; // 20 saniye tolerans
          const timeSinceRotation = Date.now() - session.rotated_at.getTime();

          if (timeSinceRotation <= gracePeriodMs) {
             // Ağ gecikmesi olmuş. Frontend 2 kere istek atmış. 
             // Mevcut olan SAĞLAM tokenları bozmadan aynen geri dönüyoruz.
             // (Bu noktada yeni token üretmiyoruz, son üretileni kurtarmaya çalışıyoruz veya tekrar login olmasını istiyoruz.
             // En güvenlisi bu durumda hata fırlatıp tekrar login yapmasını istemek veya tolerans göstermektir.
             // Biz şimdilik "Eski isteği reddet, geçerli token sende var zaten" mantığıyla ilerliyoruz).
             throw new UnauthorizedException('Ağ gecikmesi tespit edildi. İşlem reddedildi.');
          }
        }

        // EĞER BURAYA DÜŞTÜYSE: Tolerans süresi geçmiş ve eski bir token kullanılmıştır. = HIRSIZLIK!
        console.warn(`[GÜVENLİK İHLALİ] Çalınmış token kullanımı tespiti! User: ${userId}, Family: ${tokenFamily}`);
        
        // Ceza: Bu ailenin tüm oturumunu patlat (Revoke)
        session.is_revoked = true;
        await this.sessionRepository.save(session);
        
        // Log tablosuna yazılabilir (İlerideki adım).
        throw new UnauthorizedException('Güvenlik ihlali algılandı. Lütfen tekrar giriş yapın.');
      }

      // 4. NORMAL AKIŞ: TOKEN ROTATION (Döndürme)
      // Token doğru. Şimdi yeni bir çift üretelim.
      const newPayload = { sub: userId, email: session.user.email, family: tokenFamily };
      
      const newAccessToken = this.jwtService.sign(newPayload, { expiresIn: '15m' });
      const newRefreshToken = this.jwtService.sign(newPayload, { expiresIn: '7d' });
      
      const newRefreshTokenHash = await argon2.hash(newRefreshToken);

      // Session'ı Güncelle (Eski token'ı previous'a alıyoruz, yenisini kaydediyoruz)
      session.previous_refresh_token_hash = session.refresh_token_hash;
      session.refresh_token_hash = newRefreshTokenHash;
      session.rotated_at = new Date();
      session.last_active_at = new Date();
      session.ip_address = ip;
      session.user_agent = userAgent;

      await this.sessionRepository.save(session);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };

    } catch (error) {
      throw new UnauthorizedException('Refresh token geçersiz veya süresi dolmuş.');
    }
  }

  private async createSession(user: UserEntity, userAgent: string, ip: string) {
    // A. Token Family ID oluştur (Reuse Detection için)
    const tokenFamily = uuidv7();

    // B. Payload Hazırla
    const payload = {
      sub: user.id,
      email: user.email,
      family: tokenFamily, // Token ailesini payload'a gömüyoruz
    };

    // C. Tokenları Üret
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    // D. Refresh Token'ı Hashle (DB'de düz saklanmaz!)
    const refreshTokenHash = await argon2.hash(refreshToken);

    // E. Session Tablosuna Kaydet (Cihaz Yönetimi İçin)
    const session = new SessionEntity();
    session.user = user;
    session.user_id = user.id;
    session.refresh_token_hash = refreshTokenHash;
    session.token_family = tokenFamily;
    session.user_agent = userAgent; // Şimdilik ham string, ileride parser kullanırız
    session.ip_address = ip;
    session.expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 Gün

    await this.sessionRepository.save(session);

    // F. Kullanıcıya Dön
    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
      },
    };
  }

  // --- GÜVENLİ ÇIKIŞ İŞLEMLERİ ---

  async logout(refreshTokenDto: RefreshTokenDto, userId: string) {
    const { refreshToken } = refreshTokenDto;

    try {
      // 1. Token'ı çöz (Doğrulama yapmıyoruz, sadece içindeki payload'u okuyoruz. 
      // Çünkü token süresi dolmuş olsa bile çıkış yapabilmeli)
      const payload = this.jwtService.decode(refreshToken) as any;

      if (!payload || payload.sub !== userId) {
        throw new UnauthorizedException('Geçersiz token veya yetkisiz işlem.');
      }

      // 2. İlgili Session'ı bul
      const session = await this.sessionRepository.findOne({
        where: { token_family: payload.family, user_id: userId },
      });

      // 3. Zaten iptal edilmemişse, İptal Et (Revoke)
      if (session && !session.is_revoked) {
        session.is_revoked = true;
        await this.sessionRepository.save(session);
      }

      return { message: 'Başarıyla çıkış yapıldı.' };
    } catch (error) {
      throw new InternalServerErrorException('Çıkış işlemi sırasında bir hata oluştu.');
    }
  }

  // Bonus: Netflix/Google Tarzı "Tüm Cihazlardan Çıkış Yap"
  async logoutAllDevices(userId: string) {
    try {
      // Kullanıcıya ait, henüz iptal edilmemiş TÜM oturumları bul ve iptal et
      await this.sessionRepository.update(
        { user_id: userId, is_revoked: false },
        { is_revoked: true }
      );

      // İsteğe bağlı: Burada AuditLog tablosuna "Tüm cihazlardan çıkış yapıldı" logu düşülebilir.

      return { message: 'Tüm cihazlardan başarıyla çıkış yapıldı.' };
    } catch (error) {
      throw new InternalServerErrorException('İşlem sırasında bir hata oluştu.');
    }
  }

  // --- ŞİFRE SIFIRLAMA İŞLEMLERİ ---

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.userRepository.findOne({ where: { email } });

    // GÜVENLİK KURALI: Kullanıcı olmasa bile HATA VERME! 
    // "Böyle bir mail yok" demek, kötü niyetli kişilerin sistemdeki mailleri taramasını sağlar (Enumeration Attack).
    if (!user) {
      return { message: 'Eğer bu e-posta sistemde kayıtlıysa, şifre sıfırlama bağlantısı gönderilmiştir.' };
    }

    // 1. Kriptografik Rastgele Token Üret
    const resetToken = crypto.randomBytes(32).toString('hex'); // Kullanıcıya maille gidecek temiz token
    
    // 2. Token'ı Hashle (Veritabanında güvenle saklamak için)
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    // 3. Kullanıcıya kaydet (Ömrü: 1 Saat)
    user.password_reset_hash = resetTokenHash;
    user.password_reset_expires_at = new Date(Date.now() + 60 * 60 * 1000);
    await this.userRepository.save(user);

    // 4. Outbox'a Mail Emri Yaz (Dual Write - Güvenli)
    const outboxEvent = new OutboxEntity();
    outboxEvent.type = 'PASSWORD_RESET_REQUESTED';
    outboxEvent.payload = {
      email: user.email,
      // URL frontend'in adresi olmalı. Biz şimdilik örnek veriyoruz.
      resetLink: `https://senin-frontend.com/reset-password?token=${resetToken}`,
    };
    outboxEvent.status = OutboxStatus.PENDING;
    // Not: Outbox kaydı için this.dataSource.manager veya ayrı bir repository çağırman gerekebilir.
    // constructor'a @InjectRepository(OutboxEntity) private readonly outboxRepository: Repository<OutboxEntity> eklemelisin.
    await this.outboxRepository.save(outboxEvent);
    // Geçici çözüm: transaction olmadan hızlıca kaydediyoruz (Aslında outbox service üzerinden gitmek daha iyidir)
    // AuthModule imports kısmına OutboxEntity'yi eklemeyi unutma!

    return { message: 'Eğer bu e-posta sistemde kayıtlıysa, şifre sıfırlama bağlantısı gönderilmiştir.' };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, newPassword } = resetPasswordDto;

    // 1. Gelen token'ı aynı yöntemle hashle
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // 2. Veritabanında bu hash'i ve süresi geçmemiş kaydı bul
    const user = await this.userRepository.findOne({
      where: { password_reset_hash: hashedToken },
      select: ['id', 'password_hash', 'password_reset_expires_at', 'security_stamp'],
    });

    if (!user || user.password_reset_expires_at < new Date()) {
      throw new UnauthorizedException('Şifre sıfırlama bağlantısı geçersiz veya süresi dolmuş.');
    }

    // 3. Yeni şifreyi Argon2 ile hashle
    user.password_hash = await argon2.hash(newPassword);

    // 4. GÜVENLİK: Şifre değişti, eski oturumları patlat!
    user.password_reset_hash = null as any; // <-- DÜZELTME BURADA
    user.password_reset_expires_at = null as any; // <-- DÜZELTME BURADA
    user.security_stamp = uuidv7(); // Bu değiştiğinde tüm mevcut tokenlar geçersiz hale gelir!

    await this.userRepository.save(user);

    // 5. Session tablosundaki açık oturumları Revoke et (Güvenli Çıkış metodu)
    await this.logoutAllDevices(user.id);

    return { message: 'Şifreniz başarıyla güncellendi. Yeni şifrenizle giriş yapabilirsiniz.' };
  }

  // --- E-POSTA DOĞRULAMA İŞLEMİ ---

  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const { token } = verifyEmailDto;

    // 1. Gelen token'ı hashle
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // 2. Veritabanında ara
    const user = await this.userRepository.findOne({
      where: { email_verification_hash: hashedToken },
      select: ['id', 'account_status', 'email_verification_expires_at'],
    });

    // 3. Token geçersiz mi veya süresi dolmuş mu?
    if (!user || user.email_verification_expires_at < new Date()) {
      throw new BadRequestException('Doğrulama bağlantısı geçersiz veya süresi dolmuş.');
    }

    // Zaten onaylıysa
    if (user.account_status === AccountStatus.ACTIVE) {
      return { message: 'Hesabınız zaten doğrulanmış.' };
    }

    // 4. KİLİDİ AÇ (ACTIVE yap) ve tokenları temizle
    user.account_status = AccountStatus.ACTIVE;
    user.email_verification_hash = null as any; // <-- TS Hatası önlemi
    user.email_verification_expires_at = null as any; // <-- TS Hatası önlemi

    await this.userRepository.save(user);

    return { message: 'E-posta adresiniz başarıyla doğrulandı. Artık giriş yapabilirsiniz.' };
  }
}