import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class RecaptchaGuard implements CanActivate {
  private readonly logger = new Logger(RecaptchaGuard.name);

  constructor(private readonly configService: ConfigService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const { recaptchaToken } = request.body;
    
    // IP Adresini al (Proxy arkasındaysan x-forwarded-for, yoksa socket ip)
    const clientIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress;

    // 1. TEST ORTAMI BYPASS (Geliştirme yaparken bizi yormasın)
    const isDev = this.configService.get('NODE_ENV') === 'development';
    if (isDev && recaptchaToken === 'TEST_TOKEN') {
      this.logger.debug('Test ortamı için Recaptcha bypass edildi.');
      return true;
    }

    if (!recaptchaToken) {
      throw new ForbiddenException('Güvenlik doğrulaması (Captcha) eksik.');
    }

    // 2. GOOGLE'A SOR (IP ADRESİNİ DE GÖNDERİYORUZ!)
    const secretKey = this.configService.get('RECAPTCHA_SECRET_KEY');
    
    try {
      // Google API'sine remoteip parametresini eklemek VPN tespitini güçlendirir.
      const response = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify`,
        null,
        {
          params: {
            secret: secretKey,
            response: recaptchaToken,
            remoteip: clientIp, // <-- Kritik Nokta: Google'a IP'yi ispiyonluyoruz
          },
        }
      );

      const { success, score, action } = response.data;

      // 3. SKOR KONTROLÜ
      // 1.0 = İnsan, 0.0 = Bot
      // 0.5 altı genelde şüphelidir (VPN veya Bot).
      if (!success || score < 0.5) {
        this.logger.warn(`Bot aktivitesi engellendi! IP: ${clientIp}, Skor: ${score}`);
        throw new ForbiddenException('Şüpheli trafik algılandı. Lütfen VPN kapatıp tekrar deneyin.');
      }

      return true;
    } catch (error) {
      this.logger.error('Recaptcha servisine ulaşılamadı:', error);
      throw new ForbiddenException('Güvenlik servisi şu an yanıt vermiyor.');
    }
  }
}