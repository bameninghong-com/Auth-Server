import { Router } from 'express'
import rateLimit from 'express-rate-limit'
import {
  register, login, refresh, logout,
  verifyEmailController, forgotPassword, resetPasswordController,
  getSessions, revokeSessionController,
} from './auth.controller'
import { authenticate, requireAuth } from '../../../middleware/authenticate'

const router = Router()

// ── Rate limiters ─────────────────────────────────────────────────────────────

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max:      20,
  message:  { error: 'RATE_LIMITED', message: 'Too many attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders:   false,
})

const passwordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max:      5,
  message:  { error: 'RATE_LIMITED', message: 'Too many password reset attempts' },
  standardHeaders: true,
  legacyHeaders:   false,
})

// ── Routes ────────────────────────────────────────────────────────────────────

// Tenant is passed as a URL param: POST /auth/projekt-alpha/register
// Or via X-Tenant-Id header for flexibility

router.post('/:tenant/register',        authLimiter,     register)
router.post('/:tenant/login',           authLimiter,     login)
router.post('/:tenant/refresh',                          refresh)
router.post('/:tenant/logout',          authenticate,    requireAuth, logout)

router.get('/verify-email',                              verifyEmailController)
router.post('/:tenant/forgot-password', passwordLimiter, forgotPassword)
router.post('/reset-password',          passwordLimiter, resetPasswordController)

// Session management (requires auth)
router.get('/:tenant/sessions',         authenticate, requireAuth, getSessions)
router.delete('/:tenant/sessions/:sessionId', authenticate, requireAuth, revokeSessionController)

export default router
