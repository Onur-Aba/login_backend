import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { OutboxModule } from './outbox/outbox.module';
import { AuditLogsModule } from './audit_logs/audit_logs.module';
import { CommonModule } from './common/common.module';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { envValidationSchema } from './config/env.validation'; // <-- EKLENDİ

@Module({
  imports: [
    ScheduleModule.forRoot(),
    // 1. Önce ConfigModule yüklenmeli (isGlobal: true önemli)
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: envValidationSchema, // <-- EKLENDİ
      validationOptions: {
        allowUnknown: true, // Şemada olmayan diğer değişkenlere izin ver
        abortEarly: true,   // İlk hatada dur
      },
    }),

    // 2. Sonra Veritabanı Bağlantısı kurulmalı
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get<string>('DB_HOST'),
        port: configService.get<number>('DB_PORT'),
        username: configService.get<string>('DB_USERNAME'),
        password: configService.get<string>('DB_PASSWORD'),
        database: configService.get<string>('DB_NAME'),
        entities: [__dirname + '/**/*.entity{.ts,.js}'],
        synchronize: true, // Development ortamında true
        ssl: {
          rejectUnauthorized: false,
        },
      }),
    }),

    // GÜVENLİK: İstek Sınırlandırma (Rate Limiting)
    ThrottlerModule.forRoot([{
      name: 'default', // Genel endpointler için (Örn: Profil getirme)
      ttl: 60000,      // 60 saniye (Milisaniye cinsinden 60000)
      limit: 100,      // 60 saniyede maksimum 100 istek
    }, {
      name: 'auth',    // Hassas Auth işlemleri için (Login, 2FA, Register)
      ttl: 60000,      // 60 saniye
      limit: 5,        // 60 saniyede SADECE 5 İSTEK (Brute force imkansızlaşır)
    }]),

    // 3. En son Feature Modüller yüklenmeli
    CommonModule,
    UsersModule,
    AuthModule,
    OutboxModule,
    AuditLogsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    // Uygulamadaki TÜM endpointleri otomatik olarak default limite sokar
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}