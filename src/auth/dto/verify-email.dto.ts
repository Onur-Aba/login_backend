import { IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
  @IsString()
  @IsNotEmpty({ message: 'Doğrulama tokenı zorunludur.' })
  token!: string;
}