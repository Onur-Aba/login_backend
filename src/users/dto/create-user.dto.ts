import { IsEmail, IsNotEmpty, IsString, MinLength, MaxLength, Matches, IsOptional } from 'class-validator';
import { IsRealEmail } from '../../common/validators/is-real-email.validator';

export class CreateUserDto {
  @IsEmail({}, { message: 'Geçerli bir e-posta adresi giriniz.' })
  @IsRealEmail()
  @IsNotEmpty()
  email!: string;

  @IsString()
  @MinLength(8, { message: 'Şifre en az 8 karakter olmalıdır.' })
  @MaxLength(32, { message: 'Şifre çok uzun.' })
  // Enterprise Seviye Şifre Kuralı: En az 1 büyük harf, 1 küçük harf, 1 rakam.
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Şifre en az 1 büyük harf, 1 küçük harf ve 1 rakam içermelidir.',
  })
  password!: string;

  @IsString()
  @IsNotEmpty()
  first_name!: string;

  @IsString()
  @IsNotEmpty()
  last_name!: string;
  
  @IsString()
  @IsOptional()
  @MinLength(3)
  @MaxLength(20)
  username?: string;

  // YENİ: Captcha Token
  @IsOptional()
  @IsString()
  recaptchaToken?: string;
}