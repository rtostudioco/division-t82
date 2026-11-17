import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { detectPlatform } from '@/lib/engine/platform'
import { computeScore } from '@/lib/engine/types'
import type { ControlStatus, Severity } from '@/lib/engine/types'

export const dynamic = 'force-dynamic'

export async function GET() {
  const p = await detectPlatform()
  const scans = await db.scanJob.findMany({
    where: { status: 'completed' },
    orderBy: { startedAt: 'asc' },
    take: 20,
    include: { host: true },
  })
  const last = scans[scans.length - 1] ?? null

  let categoryScores: { category: string; score: number | null; scored: number; total: number }[] = []
  let topFindings: unknown[] = []
  let counts: Record<string, number> | null = null
  let severityCounts: Record<string, number> | null = null

  if (last) {
    const results = await db.controlResult.findMany({ where: { scanId: last.id } })
    const score = computeScore(
      results.map((r) => ({
        controlId: r.controlId,
        severity: r.severity as Severity,
        status: r.status as ControlStatus,
        category: r.category,
      })),
    )
    categoryScores = score.categories.map((c) => ({
      category: c.category, score: c.score, scored: c.scored, total: c.total,
    }))
    counts = score.counts
    severityCounts = score.severityCounts
    const findings = await db.finding.findMany({
      where: { scanId: last.id },
      orderBy: { severity: 'asc' },
      take: 6,
    })
    topFindings = findings.map((f) => ({
      controlId: f.controlId,
      name: JSON.parse(f.controlName),
      severity: f.severity,
      status: f.status,
      category: f.category,
      detail: f.detail,
    }))
  }

  return NextResponse.json({
    engine: {
      platform: p.platform,
      hostname: p.hostname,
      os: p.os,
      osVersion: p.osVersion,
      kernel: p.kernel,
      arch: p.arch,
      isRoot: p.isRoot,
      adapters: [
        { platform: 'linux', status: 'ACTIVE' },
        { platform: 'windows', status: 'DESIGNED_NOT_IMPLEMENTED' },
        { platform: 'macos', status: 'DESIGNED_NOT_IMPLEMENTED' },
      ],
      engineVersion: last?.engineVersion ?? '1.0.0',
    },
    lastScan: last
      ? {
          id: last.id,
          startedAt: last.startedAt.toISOString(),
          finishedAt: last.finishedAt?.toISOString() ?? null,
          score: last.score,
          coverage: last.coverage,
          counts: counts ?? {},
          severityCounts: severityCounts ?? {},
        }
      : null,
    scoreHistory: scans.map((s) => ({
      at: s.finishedAt?.toISOString() ?? s.startedAt.toISOString(),
      score: s.score,
      coverage: s.coverage,
    })),
    categoryScores,
    topFindings,
  })
}
