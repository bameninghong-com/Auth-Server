import { db } from '../../../db/pool'
import type { TenantRow } from '../../../types'

export async function findTenantBySlug(slug: string): Promise<TenantRow | null> {
  const result = await db.query<TenantRow>(
    `SELECT * FROM tenants WHERE slug = $1 AND is_active = TRUE`,
    [slug]
  )
  return result.rows[0] ?? null
}

export async function findTenantById(id: string): Promise<TenantRow | null> {
  const result = await db.query<TenantRow>(
    `SELECT * FROM tenants WHERE id = $1 AND is_active = TRUE`,
    [id]
  )
  return result.rows[0] ?? null
}
