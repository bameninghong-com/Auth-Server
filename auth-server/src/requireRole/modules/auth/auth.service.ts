import { withTransaction } from '../../../db/pool'
import { writeAuditLog } from '../../../utils/audit'
import {
  hashPassword, verifyPassword, hashToken,
  generateSecureToken, signAccessToken, signRefreshToken,
  parseDeviceInfo, generateId,
} from '../../../utils'
import {
  findUserByEmail, findUserById, createUser,
  markEmailVerified, updatePassword,
  incrementFailedLogins, resetFailedLogins,
  lockUser, getUserRoles,
} from './user.repository'
import {
  createEmailVerificationToken, findEmailVerificationToken,
  markEmailVerificationTokenUsed, createPasswordResetToken,
  findPasswordResetToken, markPasswordResetTokenUsed,
} from './token.repository'
import {
  createSession, findSessionByTokenHash, rotateSessionToken,
  revokeSession, revokeAllUserSessions, revokeAllFamilySessions,
  wasTokenHashUsedBefore, writeSessionEvent,
} from '../sessions/session.repository'
import {
  sendVerificationEmail, sendPasswordResetEmail,
} from '../../../mail/mailer'
import type { TenantRow } from '../../../types'

const MAX_FAILED_LOGINS = 10

// ── Register ──────────────────────────────────────────────────────────────────

export async function registerUser(opts: {
  tenant:    TenantRow
  email:     string
  password:  string
  ipAddress?: string
  userAgent?: string
}) {
  const { tenant, email, password, ipAddress, userAgent } = opts

  // Check if email already taken
  const existing = await findUserByEmail(tenant.id, email)
  if (existing) {
    // Timing-safe: always hash even if user exists to prevent enumeration
    await hashPassword(password)
    throw new AuthError('EMAIL_TAKEN', 'An account with this email already exists')
  }

  const passwordHash = await hashPassword(password)

  const user = await withTransaction(async (client) => {
    const newUser = await createUser(client, {
      tenantId: tenant.id,
      email,
      passwordHash,
    })

    if (tenant.require_email_verification) {
      const rawToken = generateSecureToken()
      const tokenHash = hashToken(rawToken)

      await createEmailVerificationToken(client, {
        userId:   newUser.id,
        tenantId: tenant.id,
        tokenHash,
      })

      // Send email outside transaction — failure doesn't roll back user creation
      setImmediate(async () => {
        try {
          await sendVerificationEmail({ to: email, token: rawToken, tenantSlug: tenant.slug })
        } catch (err) {
          console.error('[mail] Failed to send verification email:', err)
        }
      })
    }

    return newUser
  })

  await writeAuditLog({
    tenantId:    tenant.id,
    userId:      user.id,
    eventType:   'user_registered',
    severity:    'info',
    ipAddress,
    userAgent,
    description: `New user registered: ${email}`,
  })

  return { userId: user.id, emailVerificationRequired: tenant.require_email_verification }
}

// ── Login ─────────────────────────────────────────────────────────────────────

export async function loginUser(opts: {
  tenant:    TenantRow
  email:     string
  password:  string
  ipAddress?: string
  userAgent?: string
}) {
  const { tenant, email, password, ipAddress, userAgent } = opts
  const device = parseDeviceInfo(userAgent)

  const user = await findUserByEmail(tenant.id, email)

  // Always verify a dummy hash if user not found — prevents timing attacks
  if (!user) {
    await verifyPassword('$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy', password).catch(() => {})
    await writeAuditLog({ tenantId: tenant.id, eventType: 'login_failed', severity: 'warn', ipAddress, description: `Unknown email: ${email}` })
    throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password')
  }

  if (user.is_locked) {
    await writeAuditLog({ tenantId: tenant.id, userId: user.id, eventType: 'login_failed_locked', severity: 'warn', ipAddress })
    throw new AuthError('ACCOUNT_LOCKED', 'This account has been locked')
  }

  if (!user.is_active) {
    throw new AuthError('ACCOUNT_INACTIVE', 'This account is inactive')
  }

  const passwordValid = await verifyPassword(user.password_hash, password)

  if (!passwordValid) {
    const failCount = await incrementFailedLogins(user.id)

    if (failCount >= MAX_FAILED_LOGINS) {
      await lockUser(user.id, `Too many failed login attempts (${failCount})`)
      await revokeAllUserSessions(user.id, 'account_locked')
      await writeAuditLog({ tenantId: tenant.id, userId: user.id, eventType: 'account_locked', severity: 'critical', ipAddress, description: `Locked after ${failCount} failed attempts` })
      throw new AuthError('ACCOUNT_LOCKED', 'Too many failed attempts. Account locked.')
    }

    await writeAuditLog({ tenantId: tenant.id, userId: user.id, eventType: 'login_failed', severity: 'warn', ipAddress, description: `Failed attempt ${failCount}/${MAX_FAILED_LOGINS}` })
    throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password')
  }

  if (tenant.require_email_verification && !user.email_verified) {
    throw new AuthError('EMAIL_NOT_VERIFIED', 'Please verify your email before logging in')
  }

  await resetFailedLogins(user.id)

  const roles = await getUserRoles(user.id)
  const tokenFamily = generateId()

  const rawRefreshToken = generateSecureToken()
  const refreshTokenHash = hashToken(rawRefreshToken)
  const expiresAt = new Date(Date.now() + tenant.refresh_token_ttl * 1000)

  const session = await withTransaction(async (client) => {
    const s = await createSession(client, {
      userId:           user.id,
      tenantId:         tenant.id,
      refreshTokenHash,
      tokenFamily,
      expiresAt,
      deviceName:  device.deviceName,
      deviceType:  device.deviceType,
      os:          device.os,
      browser:     device.browser,
      userAgent:   device.userAgent,
      ipAddress,
    })
    return s
  })

  await writeSessionEvent({
    sessionId: session.id,
    userId:    user.id,
    tenantId:  tenant.id,
    eventType: 'login',
    ipAddress,
    userAgent,
  })

  await writeAuditLog({
    tenantId:    tenant.id,
    userId:      user.id,
    sessionId:   session.id,
    eventType:   'login_success',
    severity:    'info',
    ipAddress,
    userAgent,
    description: `Login from ${device.deviceName}`,
  })

  const accessToken = signAccessToken({
    sub:        user.id,
    tenant_id:  tenant.id,
    email:      user.email,
    roles,
    session_id: session.id,
  }, tenant.access_token_ttl)

  return { accessToken, refreshToken: rawRefreshToken, sessionId: session.id }
}

// ── Refresh Token ─────────────────────────────────────────────────────────────

export async function refreshAccessToken(opts: {
  rawRefreshToken: string
  tenant:          TenantRow
  ipAddress?:      string
  userAgent?:      string
}) {
  const { rawRefreshToken, tenant, ipAddress, userAgent } = opts

  const incomingHash = hashToken(rawRefreshToken)
  const session = await findSessionByTokenHash(incomingHash)

  if (!session) {
    // Token not found — check if it was previously rotated (theft detection)
    const wasUsedBefore = await wasTokenHashUsedBefore('', incomingHash)
    if (wasUsedBefore) {
      await writeAuditLog({ eventType: 'token_theft_detected', severity: 'critical', ipAddress, description: 'Rotated refresh token reused' })
    }
    throw new AuthError('INVALID_TOKEN', 'Refresh token not found')
  }

  // Theft detection: token found but already rotated away
  if (!session.is_active) {
    const alreadyRotated = await wasTokenHashUsedBefore(session.token_family, incomingHash)
    if (alreadyRotated) {
      // Revoke the entire family — token was stolen
      await revokeAllFamilySessions(session.token_family, 'token_theft')
      await writeAuditLog({
        tenantId:    session.tenant_id,
        userId:      session.user_id,
        sessionId:   session.id,
        eventType:   'token_theft_detected',
        severity:    'critical',
        ipAddress,
        description: 'Previously rotated refresh token was reused — all sessions revoked',
      })
      throw new AuthError('TOKEN_THEFT', 'Security violation detected. All sessions have been revoked.')
    }
    throw new AuthError('SESSION_REVOKED', 'Session has been revoked')
  }

  if (new Date() > session.expires_at) {
    await revokeSession(session.id, 'expired')
    throw new AuthError('TOKEN_EXPIRED', 'Refresh token has expired')
  }

  if (session.tenant_id !== tenant.id) {
    throw new AuthError('INVALID_TOKEN', 'Token tenant mismatch')
  }

  const user = await findUserById(session.user_id)
  if (!user || !user.is_active || user.is_locked) {
    await revokeSession(session.id, 'account_locked')
    throw new AuthError('ACCOUNT_INACTIVE', 'Account is no longer active')
  }

  const roles = await getUserRoles(user.id)

  // Rotate: issue new refresh token
  const newRawToken = generateSecureToken()
  const newTokenHash = hashToken(newRawToken)

  await withTransaction(async (client) => {
    await rotateSessionToken(client, {
      sessionId:         session.id,
      newTokenHash,
      previousTokenHash: incomingHash,
      ipAddress,
      userAgent,
    })
  })

  await writeSessionEvent({
    sessionId: session.id,
    userId:    user.id,
    tenantId:  tenant.id,
    eventType: 'token_refreshed',
    ipAddress,
    userAgent,
  })

  const accessToken = signAccessToken({
    sub:        user.id,
    tenant_id:  tenant.id,
    email:      user.email,
    roles,
    session_id: session.id,
  }, tenant.access_token_ttl)

  return { accessToken, refreshToken: newRawToken }
}

// ── Logout ────────────────────────────────────────────────────────────────────

export async function logoutUser(opts: {
  sessionId:  string
  userId:     string
  tenantId:   string
  logoutAll:  boolean
  ipAddress?: string
  userAgent?: string
}) {
  const { sessionId, userId, tenantId, logoutAll, ipAddress, userAgent } = opts

  if (logoutAll) {
    await revokeAllUserSessions(userId, 'forced_logout')
  } else {
    await revokeSession(sessionId, 'logout')
  }

  await writeSessionEvent({ sessionId, userId, tenantId, eventType: logoutAll ? 'forced_logout' : 'logout', ipAddress, userAgent })
  await writeAuditLog({ tenantId, userId, sessionId, eventType: logoutAll ? 'logout_all' : 'logout', severity: 'info', ipAddress })
}

// ── Email verification ────────────────────────────────────────────────────────

export async function verifyEmail(opts: { rawToken: string; ipAddress?: string }) {
  const tokenHash = hashToken(opts.rawToken)
  const record = await findEmailVerificationToken(tokenHash)

  if (!record)                        throw new AuthError('INVALID_TOKEN',  'Verification token not found')
  if (record.used_at)                 throw new AuthError('TOKEN_USED',     'Token already used')
  if (new Date() > record.expires_at) throw new AuthError('TOKEN_EXPIRED',  'Verification token has expired')

  await withTransaction(async (client) => {
    await markEmailVerificationTokenUsed(record.id)
    await markEmailVerified(record.user_id)
  })

  await writeAuditLog({ tenantId: record.tenant_id, userId: record.user_id, eventType: 'email_verified', severity: 'info', ipAddress: opts.ipAddress })
}

// ── Password reset ────────────────────────────────────────────────────────────

export async function requestPasswordReset(opts: {
  tenant:     TenantRow
  email:      string
  ipAddress?: string
}) {
  const { tenant, email, ipAddress } = opts
  const user = await findUserByEmail(tenant.id, email)

  // Always respond the same — prevents email enumeration
  if (!user || !user.is_active) return

  const rawToken  = generateSecureToken()
  const tokenHash = hashToken(rawToken)

  await withTransaction(async (client) => {
    await createPasswordResetToken(client, {
      userId:    user.id,
      tenantId:  tenant.id,
      tokenHash,
      ipAddress,
    })
  })

  setImmediate(async () => {
    try {
      await sendPasswordResetEmail({ to: email, token: rawToken, tenantSlug: tenant.slug })
    } catch (err) {
      console.error('[mail] Failed to send password reset email:', err)
    }
  })

  await writeAuditLog({ tenantId: tenant.id, userId: user.id, eventType: 'password_reset_requested', severity: 'warn', ipAddress })
}

export async function resetPassword(opts: {
  rawToken:    string
  newPassword: string
  ipAddress?:  string
}) {
  const tokenHash = hashToken(opts.rawToken)
  const record = await findPasswordResetToken(tokenHash)

  if (!record)                        throw new AuthError('INVALID_TOKEN', 'Reset token not found')
  if (record.used_at)                 throw new AuthError('TOKEN_USED',    'Token already used')
  if (new Date() > record.expires_at) throw new AuthError('TOKEN_EXPIRED', 'Reset token has expired')

  const newHash = await hashPassword(opts.newPassword)

  await withTransaction(async (client) => {
    await markPasswordResetTokenUsed(record.id)
    await updatePassword(record.user_id, newHash)
  })

  // Revoke all sessions — password changed
  await revokeAllUserSessions(record.user_id, 'password_changed')
  await writeAuditLog({ tenantId: record.tenant_id, userId: record.user_id, eventType: 'password_changed', severity: 'info', ipAddress: opts.ipAddress, description: 'Password reset via email token' })
}

// ── AuthError ─────────────────────────────────────────────────────────────────

export class AuthError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message)
    this.name = 'AuthError'
  }
}
