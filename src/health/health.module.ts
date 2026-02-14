import { Module } from '@nestjs/common';
import { TerminusModule } from '@nestjs/terminus';
import { HttpModule } from '@nestjs/axios';
import { HealthController } from './health.controller';

@Module({
  imports: [
    TerminusModule, 
    HttpModule, // Dış servislere ping atmak istersen lazım olur
  ],
  controllers: [HealthController],
})
export class HealthModule {}