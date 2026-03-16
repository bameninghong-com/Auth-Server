import { Request, Response, NextFunction } from 'express'
import { z } from 'zod'
import {
  registerUser, loginUser, refreshAccessToken,
  logoutUser, verifyEmail, requestPasswordReset,
  resetPassword, AuthError,
} from './auth.service'
import { getActiveUserSessions } from '../sessions/session.repository'
import { findTenantBySlug } from '../tenants/tenant.repository'

// ── Validation schemas ────────────────────────────────────────────────────────

const registerSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters'),
})

const loginSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(1),
})

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
})

const forgotPasswordSchema = z.object({
  email: z.string().email(),
})

const resetPasswordSchema = z.object({
  token:       z.string().min(1),
  newPassword: z.string().min(8),
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function getIp(req: Request): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
    ?? req.socket.remoteAddress
    ?? 'unknown'
}

async function resolveTenant(req: Request, res: Response) {
  const slug = req.params.tenant ?? req.headers['x-tenant-id'] as string
  if (!slug) {
    res.status(400).json({ error: 'TENANT_REQUIRED', message: 'Tenant not specified' })
    return null
  }

  const tenant = await findTenantBySlug(slug)
  if (!tenant) {
    res.status(404).json({ error: 'TENANT_NOT_FOUND', message: 'Tenant not found' })
    return null
  }
  return tenant
}

function handleError(err: unknown, res: Response) {
  if (err instanceof AuthError) {
    const statusMap: Record<string, number> = {
      EMAIL_TAKEN:         409,
      INVALID_CREDENTIALS: 401,
      ACCOUNT_LOCKED:      423,
      ACCOUNT_INACTIVE:    403,
      EMAIL_NOT_VERIFIED:  403,
      INVALID_TOKEN:       401,
      TOKEN_EXPIRED:       401,
      TOKEN_USED:          410,
      TOKEN_THEFT:         401,
      SESSION_REVOKED:     401,
    }
    return res.status(statusMap[err.code] ?? 400).json({
      error:   err.code,
      message: err.message,
    })
  }

  console.error('[auth] Unexpected error:', err)
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' })
}

// ── Controllers ───────────────────────────────────────────────────────────────

export async function register(req: Request, res: Response, _next: NextFunction) {
  try {
    const tenant = await resolveTenant(req, res)
    if (!tenant) return

    const body = registerSchema.safeParse(req.body)
    if (!body.success) {
      return res.status(422).json({ error: 'VALIDATION_ERROR', issues: body.error.issues })
    }

    const result = await registerUser({
      tenant,
      email:     body.data.email,
      password:  body.data.password,
      ipAddress: getIp(req),
      userAgent: req.headers['user-agent'],
    })

    return res.status(201).json({
      message: result.emailVerificationRequired
        ? 'Registration successful. Please verify your email.'
        : 'Registration successful.',
      emailVerificationRequired: result.emailVerificationRequired,
    })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function login(req: Request, res: Response, _next: NextFunction) {
  try {
    const tenant = await resolveTenant(req, res)
    if (!tenant) return

    const body = loginSchema.safeParse(req.body)
    if (!body.success) {
      return res.status(422).json({ error: 'VALIDATION_ERROR', issues: body.error.issues })
    }

    const result = await loginUser({
      tenant,
      email:     body.data.email,
      password:  body.data.password,
      ipAddress: getIp(req),
      userAgent: req.headers['user-agent'],
    })

    // Refresh token goes in httpOnly cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   tenant.refresh_token_ttl * 1000,
      path:     '/auth/refresh',
    })

    return res.json({
      accessToken: result.accessToken,
      sessionId:   result.sessionId,
    })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function refresh(req: Request, res: Response, _next: NextFunction) {
  try {
    const tenant = await resolveTenant(req, res)
    if (!tenant) return

    // Accept from cookie (preferred) or body (for non-browser clients)
    const rawRefreshToken =
      req.cookies?.refreshToken ??
      refreshSchema.safeParse(req.body).data?.refreshToken

    if (!rawRefreshToken) {
      return res.status(401).json({ error: 'NO_TOKEN', message: 'Refresh token not provided' })
    }

    const result = await refreshAccessToken({
      rawRefreshToken,
      tenant,
      ipAddress: getIp(req),
      userAgent: req.headers['user-agent'],
    })

    // Rotate cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   tenant.refresh_token_ttl * 1000,
      path:     '/auth/refresh',
    })

    return res.json({ accessToken: result.accessToken })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function logout(req: Request, res: Response, _next: NextFunction) {
  try {
    const tenant = await resolveTenant(req, res)
    if (!tenant) return

    // auth middleware sets req.auth
    const auth = (req as any).auth
    if (!auth) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Not authenticated' })
    }

    const logoutAll = req.query.all === 'true'

    await logoutUser({
      sessionId:  auth.sessionId,
      userId:     auth.userId,
      tenantId:   auth.tenantId,
      logoutAll,
      ipAddress:  getIp(req),
      userAgent:  req.headers['user-agent'],
    })

    res.clearCookie('refreshToken', { path: '/auth/refresh' })
    return res.json({ message: logoutAll ? 'Logged out from all devices' : 'Logged out successfully' })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function verifyEmailController(req: Request, res: Response, _next: NextFunction) {
  try {
    const token = req.query.token as string
    if (!token) {
      return res.status(400).json({ error: 'TOKEN_REQUIRED', message: 'Token is required' })
    }

    await verifyEmail({ rawToken: token, ipAddress: getIp(req) })
    return res.json({ message: 'Email verified successfully' })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function forgotPassword(req: Request, res: Response, _next: NextFunction) {
  try {
    const tenant = await resolveTenant(req, res)
    if (!tenant) return

    const body = forgotPasswordSchema.safeParse(req.body)
    if (!body.success) {
      return res.status(422).json({ error: 'VALIDATION_ERROR', issues: body.error.issues })
    }

    await requestPasswordReset({
      tenant,
      email:     body.data.email,
      ipAddress: getIp(req),
    })

    // Always return 200 — prevents email enumeration
    return res.json({ message: 'If this email exists, a reset link has been sent.' })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function resetPasswordController(req: Request, res: Response, _next: NextFunction) {
  try {
    const body = resetPasswordSchema.safeParse(req.body)
    if (!body.success) {
      return res.status(422).json({ error: 'VALIDATION_ERROR', issues: body.error.issues })
    }

    await resetPassword({
      rawToken:    body.data.token,
      newPassword: body.data.newPassword,
      ipAddress:   getIp(req),
    })

    return res.json({ message: 'Password reset successfully. Please log in again.' })
  } catch (err) {
    return handleError(err, res)
  }
}

// ── Session overview (Audit log for user) ─────────────────────────────────────

export async function getSessions(req: Request, res: Response, _next: NextFunction) {
  try {
    const auth = (req as any).auth
    if (!auth) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Not authenticated' })
    }

    const sessions = await getActiveUserSessions(auth.userId)

    return res.json({
      sessions: sessions.map(s => ({
        id:          s.id,
        deviceName:  s.device_name,
        deviceType:  s.device_type,
        os:          s.os,
        browser:     s.browser,
        ipAddress:   s.ip_address,
        country:     s.country,
        city:        s.city,
        lastUsedAt:  s.last_used_at,
        createdAt:   s.created_at,
        isCurrent:   s.id === auth.sessionId,
      })),
    })
  } catch (err) {
    return handleError(err, res)
  }
}

export async function revokeSessionController(req: Request, res: Response, _next: NextFunction) {
  try {
    const auth = (req as any).auth
    if (!auth) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Not authenticated' })
    }

    const { sessionId } = req.params
    if (sessionId === auth.sessionId) {
      return res.status(400).json({ error: 'CANNOT_REVOKE_CURRENT', message: 'Use /logout to end your current session' })
    }

    const { revokeSession } = await import('../sessions/session.repository')
    await revokeSession(sessionId, 'forced_logout')

    return res.json({ message: 'Session revoked' })
  } catch (err) {
    return handleError(err, res)
  }
}
