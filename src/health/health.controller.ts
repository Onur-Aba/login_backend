import { Controller, Get } from '@nestjs/common';
import { 
  HealthCheckService, 
  HealthCheck, 
  TypeOrmHealthIndicator, 
  MemoryHealthIndicator 
} from '@nestjs/terminus';

@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private memory: MemoryHealthIndicator,
  ) {}

  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      // Veritabanı bağlantısını kontrol et (Timeout: 1500ms)
      () => this.db.pingCheck('database', { timeout: 1500 }),
      // RAM kullanımını kontrol et (150MB'ı geçerse alarm ver)
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
    ]);
  }
}