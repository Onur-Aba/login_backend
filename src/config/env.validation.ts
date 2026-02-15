import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  
  // Veritabanı Değişkenleri
  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().default(5432),
  DB_USERNAME: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  DB_NAME: Joi.string().required(),
  DB_SYNC: Joi.boolean().default(false),

  // Kritik Güvenlik Değişkenleri (Zorunlu)
  JWT_SECRET: Joi.string().required().min(32).messages({
    'any.required': 'HATA: "JWT_SECRET" çevre değişkeni eksik!',
    'string.min': 'HATA: "JWT_SECRET" güvenliğiniz için en az 32 karakter olmalıdır!',
  }),
  JWT_REFRESH_SECRET: Joi.string().required().min(32),
  
  FRONTEND_URL: Joi.string().required().messages({
    'any.required': 'HATA: "FRONTEND_URL" (CORS için) tanımlanmamış!',
  }),

  // Redis Kuralları
  REDIS_HOST: Joi.string().required(),
  REDIS_PORT: Joi.number().default(6379),
});