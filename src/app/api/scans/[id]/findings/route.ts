import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { CATALOG } from '@/lib/engine/rules'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params
  if (!/^[\w-]{1,64}$/.test(id)) {
    return NextResponse.json({ error: 'invalid scan id' }, { status: 400 })
  }
  const findings = await db.finding.findMany({
    where: { scanId: id },
    orderBy: [{ severity: 'asc' }, { controlId: 'asc' }],
  })

  // join with catalog for explanations/references
  const ruleById = new Map(
    [...CATALOG.linux, ...CATALOG.windows, ...CATALOG.macos].map((r) => [r.id, r]),
  )

  return NextResponse.json(
    findings.map((f) => {
      const rule = ruleById.get(f.controlId)
      return {
        controlId: f.controlId,
        name: JSON.parse(f.controlName),
        severity: f.severity,
        status: f.status,
        category: f.category,
        detail: f.detail,
        explanation: rule?.explanation ?? null,
        references: rule?.references ?? [],
        remediationAvailable: !!rule,
      }
    }),
  )
}
