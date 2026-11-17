// DIVISION T82 — assistant conversation history (server-only).
// GET: list recent conversations (metadata only; messages fetched individually).
// DELETE: wipe the whole history (audited).
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const limitParam = Number.parseInt(url.searchParams.get('limit') ?? '30', 10)
  const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 100) : 30

  const rows = await db.assistantConversation.findMany({
    orderBy: { updatedAt: 'desc' },
    take: limit,
  })

  return NextResponse.json(
    rows.map((r) => {
      let count = 0
      try {
        const parsed = JSON.parse(r.messagesJson) as unknown[]
        count = Array.isArray(parsed) ? parsed.length : 0
      } catch {
        count = 0
      }
      return {
        id: r.id,
        title: r.title,
        grounded: r.grounded,
        score: r.score,
        messageCount: count,
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
      }
    }),
  )
}

export async function DELETE() {
  await db.assistantConversation.deleteMany({})
  await db.auditHistory.create({
    data: { action: 'assistant.delete', detail: 'assistant conversation history wiped' },
  })
  return NextResponse.json({ ok: true })
}
