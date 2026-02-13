import { IsNotEmpty, IsString, Length } from 'class-validator';

export class Verify2FaDto {
  @IsString()
  @IsNotEmpty({ message: 'Pending token zorunludur.' })
  pendingToken!: string;

  @IsString()
  @Length(6, 6, { message: 'Kod tam olarak 6 haneli olmalıdır.' })
  code!: string;
}