import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class RecaptchaGuard implements CanActivate {
  private readonly logger = new Logger(RecaptchaGuard.name);

  constructor(private readonly configService: ConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const { recaptchaToken, identifier, email } = request.body;
    
    // IP adresini temiz bir şekilde alalım (Baştaki olası boşlukları vb. temizleyelim)
    let clientIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress;
    if (typeof clientIp === 'string') {
        clientIp = clientIp.split(',')[0].trim();
    }

    // 1. RİSK MOTORU ÇALIŞIYOR (Artık asenkron bir istek olduğu için başına 'await' ekledik)
    const isSuspicious = await this.checkIfSuspicious(clientIp, identifier || email);

    // 2. KULLANICI TEMİZSE VE TOKEN YOKSA -> DİREKT GEÇİŞ!
    if (!isSuspicious && !recaptchaToken) {
      this.logger.log(`Temiz kullanıcı girişi: ${clientIp}`);
      return true; 
    }

    // 3. KULLANICI ŞÜPHELİYSE AMA TOKEN GÖNDERMEMİŞSE -> FRONTEND'İ UYAR!
    if (isSuspicious && !recaptchaToken) {
      this.logger.warn(`Şüpheli işlem saptandı, Captcha istendi: ${clientIp}`);
      throw new ForbiddenException({
        message: 'Şüpheli işlem tespit edildi. Lütfen güvenlik doğrulamasını tamamlayın.',
        code: 'CAPTCHA_REQUIRED' // Frontend bu kodu bekleyecek
      });
    }

    // 4. KULLANICI TOKEN GÖNDERDİYSE -> GOOGLE'DAN DOĞRULA
    const secretKey = this.configService.get<string>('RECAPTCHA_SECRET_KEY');
    
    try {
      const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
        params: { secret: secretKey, response: recaptchaToken, remoteip: clientIp },
      });

      if (!response.data.success) {
        throw new ForbiddenException('Güvenlik doğrulaması başarısız.');
      }
      return true;
    } catch (error) {
      throw new ForbiddenException('Güvenlik servisine ulaşılamadı.');
    }
  }

  // --- KENDİ RİSK MANTIĞIN (Artık async çalışıyor) ---
  private async checkIfSuspicious(ip: string, userIdentifier: string): Promise<boolean> {
    
    // 1. Statik Kural: Manuel belirlediğin şüpheli kelimeler
    if (userIdentifier && userIdentifier.includes('bot')) {
      return true; // Şüpheli!
    }

    // 2. Geliştirici (Localhost) Koruması
    // Localhost IP'leri (127.0.0.1, ::1) dış API'lere gönderildiğinde hata fırlatır, bunu atlıyoruz.
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return false;
    }

    // 3. Dinamik VPN ve Proxy Kontrolü
    try {
      // Not: proxycheck.io günde 1000 isteğe kadar ücretsiz ve keysiz çalışır.
      // İleride kendi projen için IPQualityScore veya VPNAPI.io kullanabilirsin.
      const response = await axios.get(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1`);
      
      const ipData = response.data[ip];
      
      // Servis bu IP'nin VPN veya Proxy olduğunu onaylarsa
      if (ipData && ipData.proxy === 'yes') {
        this.logger.warn(`🛑 VPN/Proxy bağlantısı tespit edildi! IP: ${ip} (Firma: ${ipData.provider})`);
        return true; // Şüpheli!
      }
      
    } catch (error: any) {
      // FAIL-OPEN PRENSİBİ: Eğer VPN kontrol API'si çökerse sistemi kilitleme, girişe izin ver.
      this.logger.error(`VPN kontrol servisine erişilemedi: ${error.message}`);
    }

    // Hiçbir riske takılmayan normal kullanıcılar için temiz (false) dön.
    return false;
  }
}