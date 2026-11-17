// DIVISION T82 — remediation task tracking (advisory-only checklist).
// GET: list tasks. POST: create a task from a Hardening Studio proposal.
// Dedupe: at most one OPEN/IN_PROGRESS task per control; re-creating returns
// the existing task instead of duplicating. Nothing here executes system
// changes — statuses record the operator's manual progress only.
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { guardMutation } from '@/lib/api-guard'

export const dynamic = 'force-dynamic'

const CreateSchema = z.object({
  controlId: z.string().min(3).max(32),
  title: z.string().min(1).max(200),
  scanId: z.string().min(1).max(64).optional(),
  payload: z.record(z.string(), z.unknown()).optional(),
})

export async function GET() {
  const rows = await db.remediationTask.findMany({
    orderBy: [{ status: 'asc' }, { updatedAt: 'desc' }],
    take: 200,
  })
  return NextResponse.json(
    rows.map((r) => ({
      id: r.id,
      controlId: r.controlId,
      scanId: r.scanId,
      title: r.title,
      status: r.status,
      createdAt: r.createdAt.toISOString(),
      updatedAt: r.updatedAt.toISOString(),
      closedAt: r.closedAt?.toISOString() ?? null,
    })),
  )
}

export async function POST(request: Request) {
  const denied = guardMutation(request)
  if (denied) return denied
  let body: unknown
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }

  const parsed = CreateSchema.safeParse(body)
  if (!parsed.success) return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  const { controlId, title, scanId, payload } = parsed.data

  const openStates = ['OPEN', 'IN_PROGRESS']
  const existing = await db.remediationTask.findFirst({
    where: { controlId, status: { in: openStates } },
    orderBy: { updatedAt: 'desc' },
  })
  if (existing) {
    return NextResponse.json({ task: existing, created: false })
  }

  const task = await db.remediationTask.create({
    data: {
      controlId,
      scanId: scanId ?? null,
      title: title.slice(0, 200),
      payloadJson: payload ? JSON.stringify(payload).slice(0, 12000) : null,
      status: 'OPEN',
    },
  })

  await db.auditHistory.create({
    data: { action: 'task.create', target: controlId, detail: `remediation task ${task.id}` },
  })

  return NextResponse.json({ task, created: true }, { status: 201 })
}
