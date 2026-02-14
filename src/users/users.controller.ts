import { Controller, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler'; // <-- Hız Limiti için
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { RecaptchaGuard } from '../common/guards/recaptcha.guard'; // <-- Bot Koruması için

@Controller('auth') // Endpoint prefix'i 'auth' yapıyoruz (Genel kabul)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  // GÜVENLİK: 
  // 1. Önce RecaptchaGuard çalışır ve token'ı doğrular.
  // 2. Sonra Throttle çalışır ve hız sınırını kontrol eder (1 dakikada 5 istek).
  @UseGuards(RecaptchaGuard)
  @Throttle({ auth: { limit: 5, ttl: 60000 } }) 
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }
}