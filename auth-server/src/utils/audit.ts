import { db } from '../db/pool'
import type { AuditEventInput } from '../types'

// Writes to security_audit_log — never throws, audit failures must not
// break the main request flow.
export async function writeAuditLog(event: AuditEventInput): Promise<void> {
  try {
    await db.query(
      `INSERT INTO security_audit_log
         (tenant_id, user_id, session_id, event_type, severity,
          ip_address, user_agent, country, description, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        event.tenantId   ?? null,
        event.userId     ?? null,
        event.sessionId  ?? null,
        event.eventType,
        event.severity,
        event.ipAddress  ?? null,
        event.userAgent  ?? null,
        event.country    ?? null,
        event.description ?? null,
        JSON.stringify(event.metadata ?? {}),
      ]
    )
  } catch (err) {
    // Log to console but never throw — audit must not break business logic
    console.error('[audit] Failed to write audit log:', err)
  }
}
