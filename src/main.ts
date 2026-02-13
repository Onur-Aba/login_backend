import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet'; // <-- İTHAL ET

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 1. HELMET: Temel HTTP güvenlik başlıklarını otomatik ayarlar.
  // Çoğu tarayıcı tabanlı saldırıyı (XSS, Sniffing) engeller.
  app.use(helmet());

  // 2. CORS (Cross-Origin Resource Sharing): 
  // Hangi frontend domainlerinin bu API'ye istek atabileceğini belirler.
  // Gecici çözüm değil, Enterprise kuralı: Asla origin: '*' kullanma!
  app.enableCors({
    origin: process.env.NODE_ENV === 'production' 
      ? ['https://senin-gercek-siten.com', 'https://app.senin-siten.com'] 
      : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080'], // Geliştirme ortamları
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // Frontend cookie gönderecekse (ileride lazım olabilir) şarttır
  });

  // Enterprise Validasyon Ayarı
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // DTO'da olmayan fazlalık verileri otomatik siler (Güvenlik)
      forbidNonWhitelisted: true, // Fazla veri gelirse hata fırlatır
      transform: true, // Gelen veriyi otomatik DTO sınıfına çevirir
    }),
  );

  // Global Prefix (Opsiyonel ama önerilir: /api/v1/auth/register)
  app.setGlobalPrefix('api/v1');

  await app.listen(3000);
}
bootstrap();