// DIVISION T82 — scheduled ingestion toggle (server-only).
// GET: current schedule state. POST: enable/disable (audited).
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

const PostSchema = z.object({ enabled: z.boolean() })

async function scheduleState(): Promise<{ enabled: boolean; lastIngestAt: string | null }> {
  const setting = await db.applicationSetting.findUnique({ where: { key: 'vulnintel.schedule' } })
  let enabled = false
  if (setting) {
    try {
      enabled = (JSON.parse(setting.value) as { enabled?: boolean }).enabled === true
    } catch {
      enabled = false
    }
  }
  const last = await db.applicationSetting.findUnique({ where: { key: 'vulnintel.lastIngest' } })
  let lastIngestAt: string | null = null
  if (last) {
    try {
      lastIngestAt = (JSON.parse(last.value) as { at?: string }).at ?? null
    } catch {
      lastIngestAt = null
    }
  }
  return { enabled, lastIngestAt }
}

export async function GET() {
  return NextResponse.json(await scheduleState())
}

export async function POST(request: Request) {
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  const parsed = PostSchema.safeParse(body)
  if (!parsed.success) return NextResponse.json({ error: 'invalid payload' }, { status: 400 })

  await db.applicationSetting.upsert({
    where: { key: 'vulnintel.schedule' },
    create: { key: 'vulnintel.schedule', value: JSON.stringify({ enabled: parsed.data.enabled }) },
    update: { value: JSON.stringify({ enabled: parsed.data.enabled }) },
  })
  await db.auditHistory.create({
    data: {
      action: 'vuln.schedule',
      detail: `scheduled ingestion ${parsed.data.enabled ? 'enabled' : 'disabled'} (every 24h)`,
    },
  })
  return NextResponse.json(await scheduleState())
}
