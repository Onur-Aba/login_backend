import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

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