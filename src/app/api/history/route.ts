import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

export async function GET() {
  const items = await db.auditHistory.findMany({
    orderBy: { createdAt: 'desc' },
    take: 100,
  })
  return NextResponse.json(
    items.map((i) => ({
      id: i.id,
      action: i.action,
      target: i.target,
      detail: i.detail,
      createdAt: i.createdAt.toISOString(),
    })),
  )
}
