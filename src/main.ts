import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config'; 
import helmet from 'helmet';
import hpp from 'hpp';
import { json, urlencoded } from 'express';
// YENİ IMPORTLAR:
import compression from 'compression';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // ConfigService'e erişim sağlıyoruz
  const configService = app.get(ConfigService);
  const nodeEnv = configService.get<string>('NODE_ENV');
  const frontendUrl = configService.get<string>('FRONTEND_URL');

  // --- SWAGGER KURULUMU (YENİ) ---
  // Sadece Development ortamında açmak güvenlik için iyidir
  if (nodeEnv !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Enterprise Auth API')
      .setDescription('NestJS ile geliştirilmiş güvenli auth sistemi')
      .setVersion('1.0')
      .addBearerAuth() // JWT Token desteği
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  // --- RESPONSE COMPRESSION (YENİ) ---
  // Gzip Sıkıştırma: API yanıt boyutunu küçültür
  app.use(compression());

  // 1. HELMET: Temel HTTP güvenlik başlıklarını otomatik ayarlar.
  app.use(helmet());

  // 2. HPP (HTTP Parameter Pollution) Koruması: 
  app.use(hpp());

  // 3. PAYLOAD SIZE LIMITING (DoS Koruması):
  app.use(json({ limit: '50kb' }));
  app.use(urlencoded({ extended: true, limit: '50kb' }));

  // 4. KURUMSAL CORS AYARI: 
  app.enableCors({
    // Eğer prod ortamındaysak sadece .env'deki domain, değilsek local ortamlar
    origin: nodeEnv === 'production' 
      ? [frontendUrl] 
      : ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:8080'], 
    
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
    allowedHeaders: 'Content-Type, Accept, Authorization',
  });

  // Enterprise Validasyon Ayarı
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, 
      forbidNonWhitelisted: true, 
      transform: true, 
    }),
  );

  // --- GRACEFUL SHUTDOWN (YENİ) ---
  // Sunucu kapanırken (CTRL+C) açık bağlantıları bekler, işlemleri yarım bırakmaz.
  app.enableShutdownHooks();

  // Global Prefix 
  app.setGlobalPrefix('api/v1');

  await app.listen(3000);
}
bootstrap();