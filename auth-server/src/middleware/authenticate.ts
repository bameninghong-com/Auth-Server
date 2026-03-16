import { Request, Response, NextFunction } from 'express'
import { verifyAccessToken } from '../utils'
import type { AuthContext } from '../types'

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext
    }
  }
}

// Verifies the Authorization: Bearer <token> header.
// Sets req.auth on success — does NOT throw if token missing (use requireAuth for that).
export function authenticate(req: Request, _res: Response, next: NextFunction) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) return next()

  try {
    const token = header.slice(7)
    const payload = verifyAccessToken(token)

    req.auth = {
      userId:    payload.sub,
      tenantId:  payload.tenant_id,
      email:     payload.email,
      roles:     payload.roles,
      sessionId: payload.session_id,
    }
  } catch {
    // Invalid token — req.auth stays undefined, requireAuth will reject
  }

  next()
}

// Use after authenticate() to enforce authentication on a route
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.auth) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' })
  }
  next()
}

// Use after requireAuth() to enforce a specific role
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.auth) {
      return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required' })
    }
    const hasRole = roles.some(role => req.auth!.roles.includes(role))
    if (!hasRole) {
      return res.status(403).json({ error: 'FORBIDDEN', message: `Required role: ${roles.join(' or ')}` })
    }
    next()
  }
}
