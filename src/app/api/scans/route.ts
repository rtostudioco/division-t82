import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { runScan } from '@/lib/engine/runner'
import { CONTROL_CATEGORIES } from '@/lib/engine/types'

export const dynamic = 'force-dynamic'
export const maxDuration = 60

export async function GET() {
  const scans = await db.scanJob.findMany({
    orderBy: { startedAt: 'desc' },
    take: 50,
    include: { host: true },
  })
  return NextResponse.json(
    scans.map((s) => ({
      id: s.id,
      startedAt: s.startedAt.toISOString(),
      finishedAt: s.finishedAt?.toISOString() ?? null,
      status: s.status,
      score: s.score,
      coverage: s.coverage,
      counts: s.countsJson ? JSON.parse(s.countsJson) : null,
      severityCounts: s.severityJson ? JSON.parse(s.severityJson) : null,
      host: { hostname: s.host.hostname, os: s.host.os, osVersion: s.host.osVersion },
    })),
  )
}

export async function POST(request: Request) {
  let scope: string[] = []
  try {
    const body = await request.json()
    if (Array.isArray(body?.scope)) scope = body.scope.map(String)
  } catch {
    // empty body => full scope
  }
  const validScope = scope.filter((s) => (CONTROL_CATEGORIES as readonly string[]).includes(s))
  try {
    const result = await runScan({ scope: validScope })
    return NextResponse.json(result)
  } catch (e) {
    return NextResponse.json(
      { error: `scan failed: ${String((e as Error).message).slice(0, 400)}` },
      { status: 500 },
    )
  }
}
