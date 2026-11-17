// DIVISION T82 — single assistant conversation (server-only).
// GET: full conversation for restore. DELETE: remove one conversation (audited).
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

type RouteContext = { params: Promise<{ id: string }> }

export async function GET(_request: Request, ctx: RouteContext) {
  const { id } = await ctx.params
  const row = await db.assistantConversation.findUnique({ where: { id } })
  if (!row) return NextResponse.json({ error: 'not found' }, { status: 404 })

  let messages: { role: 'user' | 'assistant'; content: string }[] = []
  try {
    const parsed = JSON.parse(row.messagesJson) as { role: string; content: string }[]
    messages = parsed
      .filter((m) => (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
      .map((m) => ({ role: m.role as 'user' | 'assistant', content: m.content }))
  } catch {
    messages = []
  }

  return NextResponse.json({
    id: row.id,
    title: row.title,
    grounded: row.grounded,
    score: row.score,
    messages,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  })
}

export async function DELETE(_request: Request, ctx: RouteContext) {
  const { id } = await ctx.params
  try {
    await db.assistantConversation.delete({ where: { id } })
  } catch {
    return NextResponse.json({ error: 'not found' }, { status: 404 })
  }
  await db.auditHistory.create({
    data: { action: 'assistant.delete', detail: `conversation ${id} deleted` },
  })
  return NextResponse.json({ ok: true })
}
