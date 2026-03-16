import { z } from 'zod'
import dotenv from 'dotenv'

dotenv.config()

const envSchema = z.object({
  NODE_ENV:          z.enum(['development', 'production', 'test']).default('development'),
  PORT:              z.coerce.number().default(3000),

  // Database
  POSTGRES_HOST:     z.string().default('localhost'),
  POSTGRES_PORT:     z.coerce.number().default(5432),
  POSTGRES_DB:       z.string().default('auth_db'),
  POSTGRES_USER:     z.string().default('auth_user'),
  POSTGRES_PASSWORD: z.string().min(1, 'POSTGRES_PASSWORD is required'),

  // JWT — single secret for all tenants
  JWT_SECRET:        z.string().min(64, 'JWT_SECRET must be at least 64 characters'),

  // SMTP
  SMTP_HOST:         z.string().default('localhost'),
  SMTP_PORT:         z.coerce.number().default(587),
  SMTP_SECURE:       z.coerce.boolean().default(false),
  SMTP_USER:         z.string().optional(),
  SMTP_PASS:         z.string().optional(),
  SMTP_FROM:         z.string().email().default('noreply@auth-server.local'),

  // App
  APP_URL:           z.string().url().default('http://localhost:3000'),
  CORS_ORIGINS:      z.string().default('http://localhost:3000'),
})

const parsed = envSchema.safeParse(process.env)

if (!parsed.success) {
  console.error('❌ Invalid environment variables:')
  parsed.error.errors.forEach(err => {
    console.error(`   ${err.path.join('.')}: ${err.message}`)
  })
  process.exit(1)
}

export const env = parsed.data
export type Env = typeof env
