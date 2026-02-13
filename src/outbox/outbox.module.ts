import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OutboxService } from './outbox.service';
import { OutboxEntity } from './entities/outbox.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([OutboxEntity]),
  ],
  // DİKKAT: controllers: [OutboxController] satırını sildik!
  providers: [OutboxService],
  exports: [OutboxService], 
})
export class OutboxModule {}