import crypto from 'crypto'
import * as argon2 from 'argon2'
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import { env } from '../config/env'
import type { AccessTokenPayload, RefreshTokenPayload, DeviceInfo } from '../types'

// ── Password hashing (argon2id) ───────────────────────────────────────────────

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type:        argon2.argon2id,
    memoryCost:  65536,   // 64 MB
    timeCost:    3,
    parallelism: 4,
  })
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  return argon2.verify(hash, password)
}

// ── Token hashing (SHA-256) ───────────────────────────────────────────────────
// Raw tokens are never stored — only their SHA-256 hash

export function hashToken(rawToken: string): string {
  return crypto.createHash('sha256').update(rawToken).digest('hex')
}

export function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex')
}

// ── JWT ───────────────────────────────────────────────────────────────────────

export function signAccessToken(payload: Omit<AccessTokenPayload, 'type'>, ttlSeconds: number): string {
  return jwt.sign(
    { ...payload, type: 'access' },
    env.JWT_SECRET,
    { expiresIn: ttlSeconds }
  )
}

export function signRefreshToken(payload: Omit<RefreshTokenPayload, 'type'>): string {
  // Refresh tokens have no expiry in the JWT itself —
  // expiry is enforced via the sessions table (expires_at column)
  return jwt.sign(
    { ...payload, type: 'refresh' },
    env.JWT_SECRET
  )
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  const payload = jwt.verify(token, env.JWT_SECRET) as AccessTokenPayload
  if (payload.type !== 'access') throw new Error('Invalid token type')
  return payload
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const payload = jwt.verify(token, env.JWT_SECRET) as RefreshTokenPayload
  if (payload.type !== 'refresh') throw new Error('Invalid token type')
  return payload
}

// ── Device info parsing ───────────────────────────────────────────────────────
// Minimal UA parsing without heavy libraries

export function parseDeviceInfo(userAgent: string = ''): DeviceInfo {
  const ua = userAgent.toLowerCase()

  const deviceType: DeviceInfo['deviceType'] =
    /mobile|android|iphone|ipad/.test(ua) ? (
      /ipad|tablet/.test(ua) ? 'tablet' : 'mobile'
    ) : ua ? 'desktop' : 'unknown'

  const os =
    /windows/.test(ua) ? 'Windows' :
    /mac os/.test(ua)  ? 'macOS' :
    /linux/.test(ua)   ? 'Linux' :
    /android/.test(ua) ? 'Android' :
    /ios|iphone|ipad/.test(ua) ? 'iOS' : 'Unknown'

  const browser =
    /edg\//.test(ua)    ? 'Edge' :
    /chrome\//.test(ua) ? 'Chrome' :
    /firefox\//.test(ua)? 'Firefox' :
    /safari\//.test(ua) ? 'Safari' : 'Unknown'

  const version = userAgent.match(/(?:Chrome|Firefox|Safari|Edg)\/(\d+)/)?.[1] ?? ''
  const browserFull = version ? `${browser} ${version}` : browser

  return {
    deviceName: `${browserFull} on ${os}`,
    deviceType,
    os,
    browser: browserFull,
    userAgent,
  }
}

export { uuidv4 as generateId }
