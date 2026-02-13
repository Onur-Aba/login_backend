import { Controller, Post, Body, Ip, Headers, HttpCode, HttpStatus, Get, UseGuards, Request } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler'; // <-- EKLENDİ
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto'; // <-- EKLENDİ
import { JwtAuthGuard } from './guards/jwt-auth.guard'; // Guard'ı çağır
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Verify2FaDto } from './dto/verify-2fa.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // GÜVENLİK: 1 dakikada sadece 5 deneme yapılabilir
  @Throttle({ auth: { limit: 5, ttl: 60000 } })
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(
    @Body() loginDto: LoginDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authService.login(loginDto, userAgent, ip);
  }

  // --- YENİ EKLENEN REFRESH ENDPOINT ---
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authService.refreshToken(refreshTokenDto, ip, userAgent);
  }

  // --- YENİ ENDPOINT ---
  @UseGuards(JwtAuthGuard) // KİLİT BURADA! Token yoksa içeri almaz.
  @Get('me')
  getProfile(@Request() req) {
    // req.user, JwtStrategy içindeki validate metodundan geliyor.
    return req.user;
  }

  @UseGuards(JwtAuthGuard) // Kimlik doğrulama zorunlu
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Body() refreshTokenDto: RefreshTokenDto, @Request() req) {
    // req.user.id, JwtStrategy'den geliyor
    return this.authService.logout(refreshTokenDto, req.user.id);
  }

  @UseGuards(JwtAuthGuard) // Kimlik doğrulama zorunlu
  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  logoutAll(@Request() req) {
    return this.authService.logoutAllDevices(req.user.id);
  }

  @Throttle({ auth: { limit: 3, ttl: 60000 } })
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Throttle({ auth: { limit: 3, ttl: 60000 } })
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }

  // GÜVENLİK: 2FA Kodunu kaba kuvvetle kırmayı engeller
  @Throttle({ auth: { limit: 3, ttl: 60000 } }) // 2FA için daha da katı: 1 dakikada 3 deneme
  @Post('verify-2fa')
  @HttpCode(HttpStatus.OK)
  verify2Fa(
    @Body() verify2FaDto: Verify2FaDto,
    @Ip() ip: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authService.verify2Fa(verify2FaDto, ip, userAgent);
  }

  // Korunan Endpoint: Sadece login olmuş biri kendi 2FA'sını açıp kapatabilir
  @UseGuards(JwtAuthGuard)
  @Post('toggle-2fa')
  @HttpCode(HttpStatus.OK)
  toggle2Fa(@Request() req, @Body('enable') enable: boolean) {
    return this.authService.toggle2Fa(req.user.id, enable);
  }
  @Throttle({ auth: { limit: 5, ttl: 60000 } })
  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  verifyEmail(@Body() verifyEmailDto: VerifyEmailDto) {
    return this.authService.verifyEmail(verifyEmailDto);
  }
}