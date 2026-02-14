import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config'; 
import helmet from 'helmet';
import hpp from 'hpp';
import { json, urlencoded } from 'express'; // <-- YENİ: Body-parser araçları

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // ConfigService'e erişim sağlıyoruz
  const configService = app.get(ConfigService);
  const nodeEnv = configService.get<string>('NODE_ENV');
  const frontendUrl = configService.get<string>('FRONTEND_URL');

  // 1. HELMET: Temel HTTP güvenlik başlıklarını otomatik ayarlar.
  app.use(helmet());

  // 2. HPP (HTTP Parameter Pollution) Koruması: 
  // ?id=1&id=2 gibi saldırıları engellemek için son parametreyi baz alır.
  app.use(hpp());

  // 3. PAYLOAD SIZE LIMITING (DoS Koruması):
  // Sunucuyu yormamak adına gelen istek boyutunu 50kb ile sınırlandırıyoruz.
  app.use(json({ limit: '50kb' }));
  app.use(urlencoded({ extended: true, limit: '50kb' }));

  // 4. KURUMSAL CORS AYARI: 
  // Dinamik olarak .env dosyasından beslenir.
  app.enableCors({
    // Eğer prod ortamındaysak sadece .env'deki domain, değilsek local ortamlar
    origin: nodeEnv === 'production' 
      ? [frontendUrl] 
      : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080'], 
    
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // JWT'yi cookie üzerinden yönetmek istersen bu kritik
    allowedHeaders: 'Content-Type, Accept, Authorization',
  });

  // Enterprise Validasyon Ayarı
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // DTO'da olmayan fazlalık verileri otomatik siler (Güvenlik)
      forbidNonWhitelisted: true, // Fazla veri gelirse hata fırlatır
      transform: true, // Gelen veriyi otomatik DTO sınıfına çevirir
    }),
  );

  // Global Prefix (api/v1/auth/login şeklinde erişim sağlar)
  app.setGlobalPrefix('api/v1');

  await app.listen(3000);
}
bootstrap();