import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { OutboxEntity, OutboxStatus } from './entities/outbox.entity';

@Injectable()
export class OutboxService {
  private readonly logger = new Logger(OutboxService.name);

  constructor(
    @InjectRepository(OutboxEntity)
    private readonly outboxRepository: Repository<OutboxEntity>,
    private readonly dataSource: DataSource,
  ) {}

  // Her 10 saniyede bir çalışır (Enterprise projelerde genelde 5-10 sn arasıdır)
  @Cron('*/10 * * * * *')
  async processOutboxMessages() {
    this.logger.debug('Outbox Worker uyandı, bekleyen işleri kontrol ediyor...');

    // Transaction başlatıyoruz çünkü veriyi KİLİTLEYECEĞİZ
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // 1. KİLİTLİ SORGULAMA (SKIP LOCKED - Enterprise Kalitesi)
      const pendingEvents = await queryRunner.manager
        .createQueryBuilder(OutboxEntity, 'outbox')
        .where('outbox.status = :status', { status: OutboxStatus.PENDING })
        .orderBy('outbox.created_at', 'ASC')
        .take(5)
        .setLock('pessimistic_write')
        .setOnLocked('skip_locked')
        .getMany();

      if (pendingEvents.length === 0) {
        await queryRunner.rollbackTransaction();
        return; // İş yoksa uyu
      }

      this.logger.log(`${pendingEvents.length} adet yeni iş bulundu. İşleniyor...`);

      // 2. İŞLERİ (EVENTS) SIRAYLA İŞLE
      for (const event of pendingEvents) {
        try {
          event.status = OutboxStatus.PROCESSING;
          await queryRunner.manager.save(event);

          // Hangi tip iş gelmiş?
          if (event.type === 'USER_REGISTERED') {
            await this.simulateSendEmail(
              event.payload.email,
              'Hoşgeldiniz! Hesabınız oluşturuldu.'
            );
          } else if (event.type === 'VERIFY_EMAIL') {
            await this.simulateSendEmail(
              event.payload.email,
              `Aramıza hoşgeldin ${event.payload.name}! Lütfen hesabınızı doğrulamak için şu linke tıklayın: ${event.payload.verifyLink}`
            );
          } else if (event.type === 'PASSWORD_RESET_REQUESTED') {
            await this.simulateSendEmail(
              event.payload.email,
              `Şifre Sıfırlama Bağlantınız: ${event.payload.resetLink}`
            );
          } else if (event.type === 'TWO_FACTOR_OTP') {
            // İŞTE YENİ 2FA MAİLİ BURADA GİDİYOR
            await this.simulateSendEmail(
              event.payload.email,
              `Güvenlik Kodunuz (3 dakika geçerlidir): ${event.payload.code}`
            );
          }
          // İleride buraya başka event tipleri eklenecek.

          // Başarılı olursa durumu COMPLETED yap
          event.status = OutboxStatus.COMPLETED;
          this.logger.log(`İşlem BAŞARILI: [${event.type}] - ID: ${event.id}`);

        } catch (error: any) {
          // 3. HATA YÖNETİMİ VE TEKRAR DENEME (RETRY MECHANISM)
          const currentRetries = event.retry_count || 0;
          
          if (currentRetries >= 3) {
            event.status = OutboxStatus.FAILED;
            event.last_error = error.message;
            this.logger.error(`İşlem BAŞARISIZ (Kalıcı): [${event.type}] - Sebep: ${error.message}`);
          } else {
            event.status = OutboxStatus.PENDING;
            event.retry_count = currentRetries + 1;
            event.last_error = error.message;
            this.logger.warn(`İşlem Hatası (Tekrar denenecek): [${event.type}] - Deneme: ${event.retry_count}`);
          }
        }

        // Değişiklikleri kaydet
        await queryRunner.manager.save(event);
      }

      // 4. TRANSACTION'I ONAYLA
      await queryRunner.commitTransaction();

    } catch (error: any) {
      this.logger.error('Outbox Worker genel bir hata ile karşılaştı:', error);
      await queryRunner.rollbackTransaction();
    } finally {
      await queryRunner.release();
    }
  }

  // GEÇİCİ OLMAYAN, İLERİDE GERÇEK MAİL SERVİSİNE BAĞLANACAK METOT (İki parametre alacak şekilde güncellendi)
  private async simulateSendEmail(email: string, content: string): Promise<void> {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const isEmailServiceDown = Math.random() < 0.1;
        
        if (isEmailServiceDown) {
          reject(new Error('SMTP Sunucusuna bağlanılamadı (Timeout)'));
        } else {
          // Log çıktısını daha dinamik hale getirdik (Artık içeriği de göreceğiz)
          this.logger.debug(`[📧 MAİL GÖNDERİLDİ] Alıcı: ${email} | İçerik: ${content}`);
          resolve();
        }
      }, Math.floor(Math.random() * 1500) + 500);
    });
  }
}