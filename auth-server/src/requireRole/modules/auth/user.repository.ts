import { PoolClient } from 'pg'
import { db } from '../../../db/pool'
import type { UserRow } from '../../../types'

export async function findUserByEmail(
  tenantId: string,
  email: string
): Promise<UserRow | null> {
  const result = await db.query<UserRow>(
    `SELECT * FROM users WHERE tenant_id = $1 AND email = $2`,
    [tenantId, email]
  )
  return result.rows[0] ?? null
}

export async function findUserById(id: string): Promise<UserRow | null> {
  const result = await db.query<UserRow>(
    `SELECT * FROM users WHERE id = $1`,
    [id]
  )
  return result.rows[0] ?? null
}

export async function createUser(
  client: PoolClient,
  opts: {
    tenantId:     string
    email:        string
    passwordHash: string
  }
): Promise<UserRow> {
  const result = await client.query<UserRow>(
    `INSERT INTO users (tenant_id, email, password_hash)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [opts.tenantId, opts.email, opts.passwordHash]
  )
  return result.rows[0]
}

export async function markEmailVerified(userId: string): Promise<void> {
  await db.query(
    `UPDATE users
     SET email_verified = TRUE, email_verified_at = NOW(), updated_at = NOW()
     WHERE id = $1`,
    [userId]
  )
}

export async function updatePassword(userId: string, passwordHash: string): Promise<void> {
  await db.query(
    `UPDATE users
     SET password_hash = $1, updated_at = NOW()
     WHERE id = $2`,
    [passwordHash, userId]
  )
}

export async function incrementFailedLogins(userId: string): Promise<number> {
  const result = await db.query<{ failed_login_count: number }>(
    `UPDATE users
     SET failed_login_count = failed_login_count + 1,
         last_failed_login  = NOW(),
         updated_at         = NOW()
     WHERE id = $1
     RETURNING failed_login_count`,
    [userId]
  )
  return result.rows[0].failed_login_count
}

export async function resetFailedLogins(userId: string): Promise<void> {
  await db.query(
    `UPDATE users
     SET failed_login_count = 0, last_failed_login = NULL,
         last_login_at = NOW(), updated_at = NOW()
     WHERE id = $1`,
    [userId]
  )
}

export async function lockUser(userId: string, reason: string): Promise<void> {
  await db.query(
    `UPDATE users
     SET is_locked = TRUE, locked_at = NOW(), locked_reason = $1, updated_at = NOW()
     WHERE id = $2`,
    [reason, userId]
  )
}

export async function getUserRoles(userId: string): Promise<string[]> {
  const result = await db.query<{ name: string }>(
    `SELECT r.name
     FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = $1`,
    [userId]
  )
  return result.rows.map(r => r.name)
}
