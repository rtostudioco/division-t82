import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { guardMutation } from '@/lib/api-guard'

export const dynamic = 'force-dynamic'

export async function POST(request: Request) {
  const denied = guardMutation(request)
  if (denied) return denied
  // local data purge — audited. Deletes scans + cascaded results/evidence/findings,
  // vulnerability matches (cascade) and the local vulnerability catalog.
  await db.scanJob.deleteMany({})
  await db.remediationPreview.deleteMany({})
  await db.vulnerabilityMatch.deleteMany({})
  await db.vulnerabilityRecord.deleteMany({})
  await db.applicationSetting.deleteMany({ where: { key: 'vulnintel.lastIngest' } })
  await db.auditHistory.create({
    data: {
      action: 'scan.reset',
      detail: 'All local scans, control results, evidence, findings and the vulnerability catalog were deleted by the operator.',
    },
  })
  return NextResponse.json({ ok: true })
}
