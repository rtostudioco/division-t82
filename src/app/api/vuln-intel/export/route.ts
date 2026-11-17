// DIVISION T82 — CSV export of vulnerability intelligence (server-only).
// GET ?scope=matches  (default): exact-version matches for the latest scan.
// GET ?scope=catalog : the full local CVE catalog.
// Honest header row + proper CSV escaping; audit-logged like report.export.
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

type Cell = string | number | boolean | null

function csvCell(value: Cell): string {
  if (value === null) return ''
  const s = String(value)
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

function csvBody(rows: Cell[][]): string {
  return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n'
}

export async function GET(request: Request) {
  const url = new URL(request.url)
  const scope = url.searchParams.get('scope') === 'catalog' ? 'catalog' : 'matches'

  let rows: Cell[][]
  if (scope === 'catalog') {
    const records = await db.vulnerabilityRecord.findMany({
      orderBy: [{ kev: 'desc' }, { cvssScore: 'desc' }],
      take: 5000,
    })
    rows = [
      ['cveId', 'title', 'cvssScore', 'cvssVector', 'kev', 'source', 'cwes', 'publishedAt', 'modifiedAt'],
      ...records.map((r) => {
        let cwes: string = ''
        try {
          const parsed = JSON.parse(r.cwesJson ?? '[]') as string[]
          cwes = parsed.join(' ')
        } catch {
          cwes = ''
        }
        return [
          r.cveId,
          r.title,
          r.cvssScore?.toFixed(1) ?? null,
          r.cvssVector,
          r.kev,
          r.source,
          cwes,
          r.publishedAt?.toISOString() ?? null,
          r.modifiedAt?.toISOString() ?? null,
        ]
      }),
    ]
  } else {
    const scan = await db.scanJob.findFirst({
      where: { status: 'completed' },
      orderBy: { startedAt: 'desc' },
      include: { host: { select: { hostname: true, os: true, osVersion: true } } },
    })
    if (!scan) {
      return NextResponse.json({ error: 'no completed scan yet' }, { status: 404 })
    }
    const matches = await db.vulnerabilityMatch.findMany({
      where: { scanId: scan.id },
      include: { record: { select: { cvssScore: true, cvssVector: true, kev: true, title: true } } },
      orderBy: { severity: 'asc' },
    })
    rows = [
      ['cveId', 'package', 'packageVersion', 'ecosystem', 'confidence', 'severity', 'cvssScore', 'cvssVector', 'kev', 'title'],
      ...matches.map((m) => [
        m.cveId,
        m.packageName,
        m.packageVersion,
        m.ecosystem,
        m.confidence,
        m.severity,
        m.record?.cvssScore?.toFixed(1) ?? null,
        m.record?.cvssVector ?? null,
        m.record?.kev ?? false,
        m.record?.title ?? '',
      ]),
    ]
  }

  const date = new Date().toISOString().slice(0, 10)
  const filename = scope === 'catalog' ? `t82-vuln-catalog-${date}.csv` : `t82-vuln-matches-${date}.csv`
  await db.auditHistory.create({
    data: { action: 'report.export', target: scope, detail: `vulnerability CSV export (${rows.length - 1} rows)` },
  })

  return new NextResponse(csvBody(rows), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store',
    },
  })
}
