import { Pool, PoolClient } from 'pg'
import { env } from '../config/env'

export const db = new Pool({
  host:     env.POSTGRES_HOST,
  port:     env.POSTGRES_PORT,
  database: env.POSTGRES_DB,
  user:     env.POSTGRES_USER,
  password: env.POSTGRES_PASSWORD,
  max:      20,
  idleTimeoutMillis:    30000,
  connectionTimeoutMillis: 5000,
})

db.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err)
})

export async function connectDB(): Promise<void> {
  const client = await db.connect()
  client.release()
  console.log('✅ PostgreSQL connected')
}

// Helper: run multiple queries in a single transaction
export async function withTransaction<T>(
  fn: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await db.connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (err) {
    await client.query('ROLLBACK')
    throw err
  } finally {
    client.release()
  }
}
