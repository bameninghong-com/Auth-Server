// ── Database row types ────────────────────────────────────────────────────────

export interface TenantRow {
  id:                         string
  name:                       string
  slug:                       string
  access_token_ttl:           number
  refresh_token_ttl:          number
  max_sessions_per_user:      number
  refresh_token_rotation:     boolean
  revoke_all_on_theft:        boolean
  require_email_verification: boolean
  is_active:                  boolean
  created_at:                 Date
  updated_at:                 Date
}

export interface UserRow {
  id:                  string
  tenant_id:           string
  email:               string
  password_hash:       string
  email_verified:      boolean
  email_verified_at:   Date | null
  is_active:           boolean
  is_locked:           boolean
  locked_at:           Date | null
  locked_reason:       string | null
  failed_login_count:  number
  last_failed_login:   Date | null
  last_login_at:       Date | null
  created_at:          Date
  updated_at:          Date
}

export interface SessionRow {
  id:                 string
  user_id:            string
  tenant_id:          string
  refresh_token_hash: string
  token_family:       string
  device_name:        string | null
  device_type:        string | null
  os:                 string | null
  browser:            string | null
  ip_address:         string | null
  country:            string | null
  city:               string | null
  user_agent:         string | null
  is_active:          boolean
  last_used_at:       Date
  created_at:         Date
  expires_at:         Date
  revoked_at:         Date | null
  revoked_reason:     string | null
}

// ── JWT payload ───────────────────────────────────────────────────────────────

export interface AccessTokenPayload {
  sub:       string    // user_id
  tenant_id: string
  email:     string
  roles:     string[]
  session_id: string
  type:      'access'
}

export interface RefreshTokenPayload {
  sub:        string   // user_id
  tenant_id:  string
  session_id: string
  family:     string   // token_family for rotation theft detection
  type:       'refresh'
}

// ── Request context (set by auth middleware) ──────────────────────────────────

export interface AuthContext {
  userId:    string
  tenantId:  string
  email:     string
  roles:     string[]
  sessionId: string
}

// ── Audit event types ─────────────────────────────────────────────────────────

export type AuditSeverity = 'info' | 'warn' | 'critical'

export interface AuditEventInput {
  tenantId?:   string
  userId?:     string
  sessionId?:  string
  eventType:   string
  severity:    AuditSeverity
  ipAddress?:  string
  userAgent?:  string
  country?:    string
  description?: string
  metadata?:   Record<string, unknown>
}

// ── Device info ───────────────────────────────────────────────────────────────

export interface DeviceInfo {
  deviceName:  string
  deviceType:  'desktop' | 'mobile' | 'tablet' | 'unknown'
  os:          string
  browser:     string
  userAgent:   string
}
