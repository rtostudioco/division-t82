import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { computeScore } from '@/lib/engine/types'
import type { ControlStatus, Severity } from '@/lib/engine/types'
import { CATALOG } from '@/lib/engine/rules'

const RULE_META = new Map(
  [...CATALOG.linux, ...CATALOG.windows, ...CATALOG.macos].map((r) => [r.id, { implemented: r.implemented, evidenceSource: r.evidenceSource }]),
)

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params
  if (!/^[\w-]{1,64}$/.test(id)) {
    return NextResponse.json({ error: 'invalid scan id' }, { status: 400 })
  }
  const scan = await db.scanJob.findUnique({
    where: { id },
    include: { host: true, results: { orderBy: [{ category: 'asc' }, { controlId: 'asc' }] } },
  })
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 })

  const scoreInputs = scan.results.map((r) => ({
    controlId: r.controlId,
    severity: r.severity as Severity,
    status: r.status as ControlStatus,
    category: r.category,
  }))
  const score = computeScore(scoreInputs)

  return NextResponse.json({
    id: scan.id,
    startedAt: scan.startedAt.toISOString(),
    finishedAt: scan.finishedAt?.toISOString() ?? null,
    status: scan.status,
    score: score.overall,
    coverage: score.coverage,
    counts: score.counts,
    severityCounts: score.severityCounts,
    host: {
      hostname: scan.host.hostname,
      os: scan.host.os,
      osVersion: scan.host.osVersion,
      kernel: scan.host.kernel,
      arch: scan.host.arch,
      isRoot: scan.host.isRoot,
    },
    categories: score.categories,
    formula: score.formula,
    controls: scan.results.map((r) => ({
      id: r.id,
      controlId: r.controlId,
      name: JSON.parse(r.controlName),
      category: r.category,
      severity: r.severity,
      status: r.status,
      reason: r.reason,
      detail: r.detail,
      explanation: r.explanation ? JSON.parse(r.explanation) : null,
      limitations: r.limitations ? JSON.parse(r.limitations) : null,
      evidenceId: r.evidenceId,
      privilegesRequired: r.privilegesRequired,
      durationMs: r.durationMs,
      ...(RULE_META.get(r.controlId) ?? { implemented: false, evidenceSource: '' }),
    })),
  })
}
