import { PoolClient } from 'pg'
import { db } from '../../../db/pool'

// ── Email verification ────────────────────────────────────────────────────────

export async function createEmailVerificationToken(
  client: PoolClient,
  opts: { userId: string; tenantId: string; tokenHash: string }
): Promise<void> {
  // Invalidate any existing unused tokens for this user first
  await client.query(
    `DELETE FROM email_verification_tokens
     WHERE user_id = $1 AND used_at IS NULL`,
    [opts.userId]
  )

  await client.query(
    `INSERT INTO email_verification_tokens (user_id, tenant_id, token_hash)
     VALUES ($1, $2, $3)`,
    [opts.userId, opts.tenantId, opts.tokenHash]
  )
}

export async function findEmailVerificationToken(tokenHash: string) {
  const result = await db.query<{
    id: string; user_id: string; tenant_id: string;
    expires_at: Date; used_at: Date | null
  }>(
    `SELECT id, user_id, tenant_id, expires_at, used_at
     FROM email_verification_tokens
     WHERE token_hash = $1`,
    [tokenHash]
  )
  return result.rows[0] ?? null
}

export async function markEmailVerificationTokenUsed(tokenId: string): Promise<void> {
  await db.query(
    `UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1`,
    [tokenId]
  )
}

// ── Password reset ────────────────────────────────────────────────────────────

export async function createPasswordResetToken(
  client: PoolClient,
  opts: {
    userId:    string
    tenantId:  string
    tokenHash: string
    ipAddress?: string
  }
): Promise<void> {
  // Invalidate existing unused tokens
  await client.query(
    `DELETE FROM password_reset_tokens
     WHERE user_id = $1 AND used_at IS NULL`,
    [opts.userId]
  )

  await client.query(
    `INSERT INTO password_reset_tokens (user_id, tenant_id, token_hash, ip_requested)
     VALUES ($1, $2, $3, $4)`,
    [opts.userId, opts.tenantId, opts.tokenHash, opts.ipAddress ?? null]
  )
}

export async function findPasswordResetToken(tokenHash: string) {
  const result = await db.query<{
    id: string; user_id: string; tenant_id: string;
    expires_at: Date; used_at: Date | null
  }>(
    `SELECT id, user_id, tenant_id, expires_at, used_at
     FROM password_reset_tokens
     WHERE token_hash = $1`,
    [tokenHash]
  )
  return result.rows[0] ?? null
}

export async function markPasswordResetTokenUsed(tokenId: string): Promise<void> {
  await db.query(
    `UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`,
    [tokenId]
  )
}
