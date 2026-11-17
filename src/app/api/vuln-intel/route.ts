// DIVISION T82 — vulnerability intelligence read endpoint (GET).
// Returns ingestion status, catalog stats, the latest scan's exact-version
// matches (OSV-confirmed) and a browsable slice of the catalog.
import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

export interface VulnRecordItem {
  cveId: string
  title: string
  cvssScore: number | null
  cvssVector: string | null
  cwes: string[]
  kev: boolean
  source: string
  publishedAt: string | null
  modifiedAt: string | null
}

export interface VulnMatchItem {
  cveId: string
  title: string
  packageName: string
  packageVersion: string
  severity: string
  cvssScore: number | null
  kev: boolean
  ecosystem: string
  matchedAt: string
}

export async function GET() {
  const [total, kevCount, highCount, lastIngestSetting, latestScan] = await Promise.all([
    db.vulnerabilityRecord.count(),
    db.vulnerabilityRecord.count({ where: { kev: true } }),
    db.vulnerabilityRecord.count({ where: { cvssScore: { gte: 7 } } }),
    db.applicationSetting.findUnique({ where: { key: 'vulnintel.lastIngest' } }),
    db.scanJob.findFirst({
      where: { status: 'completed' },
      orderBy: { startedAt: 'desc' },
      select: { id: true, startedAt: true, host: { select: { hostname: true, os: true } } },
    }),
  ])

  const matches = latestScan
    ? await db.vulnerabilityMatch.findMany({
        where: { scanId: latestScan.id },
        include: { record: true },
        orderBy: [{ severity: 'asc' }, { packageName: 'asc' }],
        take: 500,
      })
    : []

  const records = await db.vulnerabilityRecord.findMany({
    orderBy: [{ kev: 'desc' }, { cvssScore: 'desc' }],
    take: 400,
  })

  const matchItems: VulnMatchItem[] = matches.map((m) => ({
    cveId: m.cveId,
    title: m.record?.title ?? m.cveId,
    packageName: m.packageName,
    packageVersion: m.packageVersion,
    severity: m.severity,
    cvssScore: m.record?.cvssScore ?? null,
    kev: m.record?.kev ?? false,
    ecosystem: m.ecosystem,
    matchedAt: m.matchedAt.toISOString(),
  }))

  const recordItems: VulnRecordItem[] = records.map((r) => ({
    cveId: r.cveId,
    title: r.title,
    cvssScore: r.cvssScore,
    cvssVector: r.cvssVector,
    cwes: r.cwesJson ? JSON.parse(r.cwesJson) : [],
    kev: r.kev,
    source: r.source,
    publishedAt: r.publishedAt?.toISOString() ?? null,
    modifiedAt: r.modifiedAt?.toISOString() ?? null,
  }))

  return NextResponse.json({
    catalog: { total, kev: kevCount, highOrAbove: highCount },
    lastIngest: lastIngestSetting ? JSON.parse(lastIngestSetting.value) : null,
    latestScan: latestScan
      ? {
          id: latestScan.id,
          startedAt: latestScan.startedAt.toISOString(),
          hostname: latestScan.host.hostname,
          os: latestScan.host.os,
        }
      : null,
    matches: matchItems,
    records: recordItems,
  })
}
