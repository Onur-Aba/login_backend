import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config'; // ConfigService lazım

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { SessionEntity } from './entities/session.entity';
import { UserEntity } from '../users/entities/user.entity'; // UserRepo için lazım
import { JwtStrategy } from './strategies/jwt.strategy'; // <-- EKLENDİ
import { OutboxEntity } from '../outbox/entities/outbox.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([SessionEntity, UserEntity, OutboxEntity]), // UserEntity ekledik!
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // .env'den okuyacak
        signOptions: { expiresIn: '15m' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy], // <-- EKLENDİ
})
export class AuthModule {}