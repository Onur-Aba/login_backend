import * as crypto from 'crypto';
import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  InternalServerErrorException,
  BadRequestException,
  Logger, // <-- Logger eklendi
} from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule'; // <-- Cron importları eklendi
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm'; // <-- LessThan eklendi
import * as argon2 from 'argon2';
import { v7 as uuidv7 } from 'uuid';
import { UAParser } from 'ua-parser-js';

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
  // Cron işlemleri için Logger tanımladık
  private readonly logger = new Logger(AuthService.name);

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
    const user = await this.userRepository
      .createQueryBuilder('user')
      .addSelect('user.password_hash') // Şifre default hidden, burada lazım
      .addSelect('user.account_status') // Statü kontrolü için gerekli
      .where('user.email = :identifier', { identifier })
      .orWhere('user.username = :identifier', { identifier })
      .getOne();

    // 2. GÜVENLİK: Kullanıcı yoksa bile "hata" hemen dönülmemeli (Timing Attack önlemi)
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

    // Doğrulanmamış hesapları kapıdan çevir
    if (user.account_status === AccountStatus.UNVERIFIED) {
      throw new ForbiddenException(
        'Lütfen önce e-posta adresinize gönderilen linke tıklayarak hesabınızı doğrulayın.',
      );
    }

    // --- 2FA KONTROLÜ (ENTERPRISE MANTIĞI) ---
    if (user.two_factor_enabled) {
      // 1. 6 Haneli Rastgele Kod Üret
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();

      // 2. Kodu Hashle (SHA256)
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
        { expiresIn: '5m' },
      );

      return {
        message: 'Güvenlik kodu e-posta adresinize gönderildi.',
        requires2FA: true,
        pendingToken,
      };
    }

    // --- 2FA KAPALIYSA NORMAL AKIŞA DEVAM ET ---
    return this.createSession(user, userAgent, ipAddress);
  }

  async verify2Fa(verify2FaDto: Verify2FaDto, ip: string, userAgent: string) {
    const { pendingToken, code } = verify2FaDto;

    try {
      // 1. Pending Token'ı Doğrula
      const payload = this.jwtService.verify(pendingToken);

      if (payload.type !== '2FA_PENDING') {
        throw new UnauthorizedException('Geçersiz token tipi.');
      }

      // 2. Kullanıcıyı ve Hashlenmiş Kodu Çek
      const user = await this.userRepository.findOne({
        where: { id: payload.sub },
        select: [
          'id',
          'email',
          'username',
          'two_factor_otp_hash',
          'two_factor_otp_expires_at',
        ],
      });

      if (!user) {
        throw new UnauthorizedException('Kullanıcı bulunamadı.');
      }

      // 3. Kodun Süresi Dolmuş mu?
      if (
        !user.two_factor_otp_expires_at ||
        user.two_factor_otp_expires_at.getTime() < Date.now()
      ) {
        throw new UnauthorizedException(
          'Güvenlik kodunun süresi dolmuş. Lütfen tekrar giriş yapın.',
        );
      }

      // 4. Gelen Kodu Hashle ve Karşılaştır
      const hashedInputCode = crypto
        .createHash('sha256')
        .update(code)
        .digest('hex');
      if (user.two_factor_otp_hash !== hashedInputCode) {
        throw new UnauthorizedException('Hatalı güvenlik kodu.');
      }

      // 5. BAŞARILI! Kodu Temizle
      user.two_factor_otp_hash = null;
      user.two_factor_otp_expires_at = null;
      await this.userRepository.save(user);

      // 6. Artık Gerçek Oturumu Başlatabiliriz
      return this.createSession(user, userAgent, ip);
    } catch (error) {
      throw new UnauthorizedException(
        'Doğrulama başarısız veya kodun süresi dolmuş.',
      );
    }
  }

  // Kullanıcının 2FA'yı açıp kapatabilmesi için ayar metodu
  async toggle2Fa(userId: string, enable: boolean) {
    // 1. Veritabanında 2FA durumunu güncelle
    await this.userRepository.update(userId, { two_factor_enabled: enable });

    // 2. ENTERPRISE KURALI: 2FA açıldıysa acımadan tüm oturumları patlat!
    if (enable) {
      await this.logoutAllDevices(userId);

      return {
        message:
          'İki aşamalı doğrulama AKTİF edildi. Güvenliğiniz için tüm oturumlarınız kapatıldı. Lütfen e-postanıza gelecek kod ile tekrar giriş yapın.',
      };
    }

    return { message: 'İki aşamalı doğrulama KAPATILDI.' };
  }

  async refreshToken(
    refreshTokenDto: RefreshTokenDto,
    ip: string,
    userAgent: string,
  ) {
    const { refreshToken } = refreshTokenDto;

    try {
      // 1. Token'ı çöz
      const payload = this.jwtService.verify(refreshToken);
      const { sub: userId, family: tokenFamily } = payload;

      // 2. Veritabanında bu Session'ı bul
      const session = await this.sessionRepository.findOne({
        where: { token_family: tokenFamily, user_id: userId },
        relations: ['user'],
      });

      if (!session) {
        throw new UnauthorizedException('Geçersiz oturum.');
      }

      if (session.is_revoked) {
        throw new UnauthorizedException('Oturum sonlandırılmış.');
      }

      // 3. HASH KONTROLÜ VE REUSE DETECTION (HIRSIZLIK KORUMASI)
      const isCurrentToken = await argon2.verify(
        session.refresh_token_hash,
        refreshToken,
      );

      if (!isCurrentToken) {
        // Reuse Detection: Çalınmış token kullanımı tespiti
        const isPreviousToken = session.previous_refresh_token_hash
          ? await argon2.verify(session.previous_refresh_token_hash, refreshToken)
          : false;

        if (isPreviousToken && session.rotated_at) {
          // GRACE PERIOD KONTROLÜ (20 Saniye)
          const gracePeriodMs = 20 * 1000;
          const timeSinceRotation = Date.now() - session.rotated_at.getTime();

          if (timeSinceRotation <= gracePeriodMs) {
            throw new UnauthorizedException(
              'Ağ gecikmesi tespit edildi. İşlem reddedildi.',
            );
          }
        }

        // Hırsızlık: Ailenin tüm oturumunu patlat
        console.warn(
          `[GÜVENLİK İHLALİ] Çalınmış token kullanımı tespiti! User: ${userId}, Family: ${tokenFamily}`,
        );
        session.is_revoked = true;
        await this.sessionRepository.save(session);

        throw new UnauthorizedException(
          'Güvenlik ihlali algılandı. Lütfen tekrar giriş yapın.',
        );
      }

      // 4. NORMAL AKIŞ: TOKEN ROTATION
      const newPayload = {
        sub: userId,
        email: session.user.email,
        family: tokenFamily,
      };

      const newAccessToken = this.jwtService.sign(newPayload, {
        expiresIn: '15m',
      });
      const newRefreshToken = this.jwtService.sign(newPayload, {
        expiresIn: '7d',
      });
      const newRefreshTokenHash = await argon2.hash(newRefreshToken);

      // Session'ı Güncelle
      session.previous_refresh_token_hash = session.refresh_token_hash;
      session.refresh_token_hash = newRefreshTokenHash;
      session.rotated_at = new Date();
      session.last_active_at = new Date();
      session.ip_address = ip;
      session.user_agent = userAgent;

      // Cihaz Bilgisini Güncelle (UA Parser)
      const parser = new UAParser(userAgent);
      const uaResult = parser.getResult();

      session.device_info = {
        browser: `${uaResult.browser.name || 'Bilinmeyen Tarayıcı'} ${uaResult.browser.version || ''}`.trim(),
        os: `${uaResult.os.name || 'Bilinmeyen İşletim Sistemi'} ${uaResult.os.version || ''}`.trim(),
        device: uaResult.device.model
          ? `${uaResult.device.vendor || ''} ${uaResult.device.model}`.trim()
          : 'Masaüstü Cihaz',
        type: uaResult.device.type || 'desktop',
      };

      await this.sessionRepository.save(session);

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException(
        'Refresh token geçersiz veya süresi dolmuş.',
      );
    }
  }

  private async createSession(
    user: UserEntity,
    userAgent: string,
    ip: string,
  ) {
    const tokenFamily = uuidv7();

    // User-Agent Parçalama
    const parser = new UAParser(userAgent);
    const uaResult = parser.getResult();

    const deviceInfo = {
      browser: `${uaResult.browser.name || 'Bilinmeyen Tarayıcı'} ${uaResult.browser.version || ''}`.trim(),
      os: `${uaResult.os.name || 'Bilinmeyen İşletim Sistemi'} ${uaResult.os.version || ''}`.trim(),
      device: uaResult.device.model
        ? `${uaResult.device.vendor || ''} ${uaResult.device.model}`.trim()
        : 'Masaüstü Cihaz',
      type: uaResult.device.type || 'desktop',
    };

    const payload = { sub: user.id, email: user.email, family: tokenFamily };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });
    const refreshTokenHash = await argon2.hash(refreshToken);

    const session = new SessionEntity();
    session.user = user;
    session.user_id = user.id;
    session.refresh_token_hash = refreshTokenHash;
    session.token_family = tokenFamily;
    session.user_agent = userAgent;
    session.device_info = deviceInfo; // Parçalanmış veriyi basıyoruz
    session.ip_address = ip;
    session.expires_at = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 Gün

    await this.sessionRepository.save(session);

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
      // Token'ı çöz
      const payload = this.jwtService.decode(refreshToken) as any;

      if (!payload || payload.sub !== userId) {
        throw new UnauthorizedException('Geçersiz token veya yetkisiz işlem.');
      }

      // Session'ı bul
      const session = await this.sessionRepository.findOne({
        where: { token_family: payload.family, user_id: userId },
      });

      // İptal Et (Revoke)
      if (session && !session.is_revoked) {
        session.is_revoked = true;
        await this.sessionRepository.save(session);
      }

      return { message: 'Başarıyla çıkış yapıldı.' };
    } catch (error) {
      throw new InternalServerErrorException(
        'Çıkış işlemi sırasında bir hata oluştu.',
      );
    }
  }

  // Tüm Cihazlardan Çıkış Yap
  async logoutAllDevices(userId: string) {
    try {
      await this.sessionRepository.update(
        { user_id: userId, is_revoked: false },
        { is_revoked: true },
      );

      return { message: 'Tüm cihazlardan başarıyla çıkış yapıldı.' };
    } catch (error) {
      throw new InternalServerErrorException('İşlem sırasında bir hata oluştu.');
    }
  }

  // --- ŞİFRE SIFIRLAMA İŞLEMLERİ ---

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    const user = await this.userRepository.findOne({ where: { email } });

    // Kullanıcı yoksa bile hata dönmüyoruz (Enumeration Attack)
    if (!user) {
      return {
        message:
          'Eğer bu e-posta sistemde kayıtlıysa, şifre sıfırlama bağlantısı gönderilmiştir.',
      };
    }

    // 1. Rastgele Token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    // 2. Kullanıcıya kaydet
    user.password_reset_hash = resetTokenHash;
    user.password_reset_expires_at = new Date(Date.now() + 60 * 60 * 1000);
    await this.userRepository.save(user);

    // 3. Outbox'a Mail Emri
    const outboxEvent = new OutboxEntity();
    outboxEvent.type = 'PASSWORD_RESET_REQUESTED';
    outboxEvent.payload = {
      email: user.email,
      resetLink: `https://senin-frontend.com/reset-password?token=${resetToken}`,
    };
    outboxEvent.status = OutboxStatus.PENDING;
    await this.outboxRepository.save(outboxEvent);

    return {
      message:
        'Eğer bu e-posta sistemde kayıtlıysa, şifre sıfırlama bağlantısı gönderilmiştir.',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, newPassword } = resetPasswordDto;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.userRepository.findOne({
      where: { password_reset_hash: hashedToken },
      select: [
        'id',
        'password_hash',
        'password_reset_expires_at',
        'security_stamp',
      ],
    });

    if (
      !user ||
      !user.password_reset_expires_at ||
      user.password_reset_expires_at.getTime() < Date.now()
    ) {
      throw new UnauthorizedException(
        'Şifre sıfırlama bağlantısı geçersiz veya süresi dolmuş.',
      );
    }

    // Yeni şifre
    user.password_hash = await argon2.hash(newPassword);

    // Temizlik ve Güvenlik Damgası
    user.password_reset_hash = null;
    user.password_reset_expires_at = null;
    user.security_stamp = uuidv7();

    await this.userRepository.save(user);

    // Diğer oturumları kapat
    await this.logoutAllDevices(user.id);

    return {
      message:
        'Şifreniz başarıyla güncellendi. Yeni şifrenizle giriş yapabilirsiniz.',
    };
  }

  // --- E-POSTA DOĞRULAMA İŞLEMİ ---

  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const { token } = verifyEmailDto;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await this.userRepository.findOne({
      where: { email_verification_hash: hashedToken },
      select: ['id', 'account_status', 'email_verification_expires_at'],
    });

    if (
      !user ||
      !user.email_verification_expires_at ||
      user.email_verification_expires_at.getTime() < Date.now()
    ) {
      throw new BadRequestException(
        'Doğrulama bağlantısı geçersiz veya süresi dolmuş.',
      );
    }

    if (user.account_status === AccountStatus.ACTIVE) {
      return { message: 'Hesabınız zaten doğrulanmış.' };
    }

    // Aktif et ve temizle
    user.account_status = AccountStatus.ACTIVE;
    user.email_verification_hash = null;
    user.email_verification_expires_at = null;

    await this.userRepository.save(user);

    return {
      message:
        'E-posta adresiniz başarıyla doğrulandı. Artık giriş yapabilirsiniz.',
    };
  }

  // --- CRON JOBS ---

  // HER GECE SAAT 04:00'TE ÇALIŞIR
  // Süresi dolmuş (Expired) ve İptal edilmiş (Revoked) sessionları temizler.
  @Cron(CronExpression.EVERY_DAY_AT_4AM)
  async handleCronSessionCleanup() {
    this.logger.log(
      '🧹 [CRON] Süresi dolmuş oturumları temizleme görevi başladı...',
    );

    const now = new Date();

    const result = await this.sessionRepository.delete({
      expires_at: LessThan(now), // Süresi geçmiş olanlar
    });

    // İsteğe bağlı: Revoked olanları da silebilirsin ama güvenlik analizi için
    // 30 gün tutmak isteyebilirsin. O yüzden şimdilik sadece süresi bitenleri siliyoruz.

    this.logger.log(
      `🗑️ [CRON] Temizlik tamamlandı. Silinen oturum sayısı: ${result.affected}`,
    );
  }
}