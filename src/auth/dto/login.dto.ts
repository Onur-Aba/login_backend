import { IsNotEmpty, IsOptional, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty({ message: 'Kullanıcı adı veya E-posta zorunludur.' })
  identifier!: string; // Email VEYA Username buraya gelecek

  @IsString()
  @IsNotEmpty({ message: 'Şifre zorunludur.' })
  @MinLength(6, { message: 'Şifre çok kısa.' })
  password!: string;

  // YENİ: Captcha Token (Testlerde zorunlu olmasın diye Optional yaptık ama Guard kontrol edecek)
  @IsOptional()
  @IsString()
  recaptchaToken?: string;
}