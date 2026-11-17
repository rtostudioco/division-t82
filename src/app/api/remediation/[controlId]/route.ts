import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { CATALOG } from '@/lib/engine/rules'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ controlId: string }> },
) {
  const { controlId } = await params
  // strict format validation — the id is used only as a catalog lookup key
  if (!/^VC-(LNX|WIN|MAC)-\d{4}$/.test(controlId)) {
    return NextResponse.json({ error: 'invalid control id format' }, { status: 400 })
  }
  const rule = [...CATALOG.linux, ...CATALOG.windows, ...CATALOG.macos].find((r) => r.id === controlId)
  if (!rule) return NextResponse.json({ error: 'control not found' }, { status: 404 })

  // current finding from latest scan (if any)
  const lastScan = await db.scanJob.findFirst({
    where: { status: 'completed' },
    orderBy: { startedAt: 'desc' },
    select: { id: true },
  })
  let currentFinding: { status: string; detail: string | null } | undefined
  if (lastScan) {
    const result = await db.controlResult.findFirst({
      where: { scanId: lastScan.id, controlId },
      select: { status: true, detail: true },
    })
    if (result) currentFinding = { status: result.status, detail: result.detail }
  }

  return NextResponse.json({
    controlId: rule.id,
    controlName: rule.name,
    severity: rule.severity,
    category: rule.category,
    implemented: rule.implemented,
    evidenceSource: rule.evidenceSource,
    remediation: rule.remediation,
    references: rule.references,
    currentFinding,
  })
}
