import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config'; 
import helmet from 'helmet';
import hpp from 'hpp';
import { json, urlencoded } from 'express';
import compression from 'compression';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
// YENİ IMPORTLAR (Winston):
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

async function bootstrap() {
  // 1. Winston Logger Oluşturma (YENİ)
  const logger = WinstonModule.createLogger({
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.ms(),
          winston.format.colorize(),
          winston.format.printf(({ timestamp, level, message, context, ms }) => {
            return `${timestamp} [${context}] ${level}: ${message} ${ms}`;
          }),
        ),
      }),
    ],
  });

  // 2. NestJS'e Logger'ı Tanıt (DEĞİŞTİ)
  const app = await NestFactory.create(AppModule, { logger });
  
  // ConfigService'e erişim sağlıyoruz
  const configService = app.get(ConfigService);
  const nodeEnv = configService.get<string>('NODE_ENV');
  const frontendUrl = configService.get<string>('FRONTEND_URL');

  // --- SWAGGER KURULUMU ---
  if (nodeEnv !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('Enterprise Auth API')
      .setDescription('NestJS ile geliştirilmiş güvenli auth sistemi')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document);
  }

  // --- RESPONSE COMPRESSION ---
  app.use(compression());

  // 1. HELMET
  app.use(helmet());

  // 2. HPP
  app.use(hpp());

  // 3. PAYLOAD SIZE LIMITING
  app.use(json({ limit: '50kb' }));
  app.use(urlencoded({ extended: true, limit: '50kb' }));

  // 4. KURUMSAL CORS AYARI
  app.enableCors({
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

  // --- GRACEFUL SHUTDOWN ---
  app.enableShutdownHooks();

  // Global Prefix 
  app.setGlobalPrefix('api/v1');

  await app.listen(3000);
  
  // Uygulamanın başladığını yeni logger ile bildir (YENİ)
  logger.log(`Application running on: ${await app.getUrl()}`);
}
bootstrap();