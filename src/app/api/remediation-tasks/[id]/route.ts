// DIVISION T82 — single remediation task: update status / delete.
// PATCH: OPEN | IN_PROGRESS | DONE | DISMISSED (sets closedAt on DONE).
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { guardMutation } from '@/lib/api-guard'

export const dynamic = 'force-dynamic'

type RouteContext = { params: Promise<{ id: string }> }

const PatchSchema = z.object({
  status: z.enum(['OPEN', 'IN_PROGRESS', 'DONE', 'DISMISSED']),
})

export async function PATCH(request: Request, ctx: RouteContext) {
  const denied = guardMutation(request)
  if (denied) return denied
  const { id } = await ctx.params

  let body: unknown
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  const parsed = PatchSchema.safeParse(body)
  if (!parsed.success) return NextResponse.json({ error: 'invalid payload' }, { status: 400 })

  const closedAt = parsed.data.status === 'DONE' ? new Date() : null
  try {
    const task = await db.remediationTask.update({
      where: { id },
      data: { status: parsed.data.status, closedAt },
    })
    await db.auditHistory.create({
      data: { action: 'task.update', target: task.controlId, detail: `status=${parsed.data.status}` },
    })
    return NextResponse.json({ task })
  } catch {
    return NextResponse.json({ error: 'not found' }, { status: 404 })
  }
}

export async function DELETE(request: Request, ctx: RouteContext) {
  const denied = guardMutation(request)
  if (denied) return denied
  const { id } = await ctx.params
  try {
    const task = await db.remediationTask.delete({ where: { id } })
    await db.auditHistory.create({
      data: { action: 'task.delete', target: task.controlId, detail: `task ${id} deleted` },
    })
  } catch {
    return NextResponse.json({ error: 'not found' }, { status: 404 })
  }
  return NextResponse.json({ ok: true })
}
