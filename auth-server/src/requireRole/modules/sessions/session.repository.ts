import { PoolClient } from 'pg'
import { db } from '../../../db/pool'
import type { SessionRow } from '../../../types'

export async function createSession(
  client: PoolClient,
  opts: {
    userId:           string
    tenantId:         string
    refreshTokenHash: string
    tokenFamily:      string
    expiresAt:        Date
    deviceName?:      string
    deviceType?:      string
    os?:              string
    browser?:         string
    ipAddress?:       string
    country?:         string
    city?:            string
    userAgent?:       string
  }
): Promise<SessionRow> {
  const result = await client.query<SessionRow>(
    `INSERT INTO sessions
       (user_id, tenant_id, refresh_token_hash, token_family, expires_at,
        device_name, device_type, os, browser,
        ip_address, country, city, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     RETURNING *`,
    [
      opts.userId, opts.tenantId, opts.refreshTokenHash, opts.tokenFamily,
      opts.expiresAt, opts.deviceName, opts.deviceType, opts.os, opts.browser,
      opts.ipAddress, opts.country, opts.city, opts.userAgent,
    ]
  )
  return result.rows[0]
}

export async function findSessionByTokenHash(
  tokenHash: string
): Promise<SessionRow | null> {
  const result = await db.query<SessionRow>(
    `SELECT * FROM sessions WHERE refresh_token_hash = $1`,
    [tokenHash]
  )
  return result.rows[0] ?? null
}

export async function rotateSessionToken(
  client: PoolClient,
  opts: {
    sessionId:        string
    newTokenHash:     string
    previousTokenHash: string
    ipAddress?:       string
    userAgent?:       string
  }
): Promise<void> {
  // Update the active token hash
  await client.query(
    `UPDATE sessions
     SET refresh_token_hash = $1, last_used_at = NOW()
     WHERE id = $2`,
    [opts.newTokenHash, opts.sessionId]
  )

  // Record rotation in history (for theft detection)
  await client.query(
    `INSERT INTO token_rotation_history
       (session_id, token_family, previous_token_hash, new_token_hash, ip_address, user_agent)
     SELECT id, token_family, $2, $1, $3, $4
     FROM sessions WHERE id = $5`,
    [opts.newTokenHash, opts.previousTokenHash, opts.ipAddress, opts.userAgent, opts.sessionId]
  )
}

export async function revokeSession(
  sessionId: string,
  reason: string
): Promise<void> {
  await db.query(
    `UPDATE sessions
     SET is_active = FALSE, revoked_at = NOW(), revoked_reason = $1
     WHERE id = $2`,
    [reason, sessionId]
  )
}

export async function revokeAllUserSessions(
  userId:          string,
  reason:          string,
  exceptSessionId?: string
): Promise<number> {
  const result = await db.query<{ count: string }>(
    `SELECT revoke_all_user_sessions($1, $2, $3) as count`,
    [userId, reason, exceptSessionId ?? null]
  )
  return parseInt(result.rows[0].count)
}

export async function revokeAllFamilySessions(
  tokenFamily: string,
  reason:      string
): Promise<void> {
  await db.query(
    `UPDATE sessions
     SET is_active = FALSE, revoked_at = NOW(), revoked_reason = $1
     WHERE token_family = $2 AND is_active = TRUE`,
    [reason, tokenFamily]
  )
}

export async function wasTokenHashUsedBefore(
  tokenFamily: string,
  tokenHash:   string
): Promise<boolean> {
  const result = await db.query<{ count: string }>(
    `SELECT COUNT(*) as count
     FROM token_rotation_history
     WHERE token_family = $1 AND previous_token_hash = $2`,
    [tokenFamily, tokenHash]
  )
  return parseInt(result.rows[0].count) > 0
}

export async function getActiveUserSessions(userId: string): Promise<SessionRow[]> {
  const result = await db.query<SessionRow>(
    `SELECT * FROM v_active_sessions WHERE user_id = $1 ORDER BY last_used_at DESC`,
    [userId]
  )
  return result.rows
}

export async function writeSessionEvent(opts: {
  sessionId:  string
  userId:     string
  tenantId:   string
  eventType:  string
  ipAddress?: string
  userAgent?: string
  metadata?:  Record<string, unknown>
}): Promise<void> {
  await db.query(
    `INSERT INTO session_events
       (session_id, user_id, tenant_id, event_type, ip_address, user_agent, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      opts.sessionId, opts.userId, opts.tenantId, opts.eventType,
      opts.ipAddress ?? null, opts.userAgent ?? null,
      JSON.stringify(opts.metadata ?? {}),
    ]
  )
}
