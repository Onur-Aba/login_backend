import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';

// .env dosyasını okuyoruz
dotenv.config();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  // DİKKAT: Entity'lerin yolunu doğru göstermeliyiz
  entities: ['dist/**/*.entity.js'], 
  migrations: ['dist/migrations/*.js'],
  synchronize: false, // ARTIK FALSE!
  logging: true,
});