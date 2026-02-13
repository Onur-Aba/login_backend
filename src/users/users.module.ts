import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { UserEntity } from './entities/user.entity';
import { ProfileEntity } from './entities/profile.entity';

@Module({
  imports: [
    // Entityleri buraya koyuyoruz, providers'a DEĞİL.
    TypeOrmModule.forFeature([UserEntity, ProfileEntity]),
  ],
  controllers: [UsersController],
  
  // DİKKAT: Burada SADECE Service olmalı. UserEntity BURADA OLMAMALI.
  providers: [UsersService], 
  
  exports: [UsersService],
})
export class UsersModule {}