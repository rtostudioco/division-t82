// DIVISION T82 — vulnerability ingestion endpoint (POST).
// Runs OSV exact-version matching against the latest scan inventory + NVD
// recent-CVE ingestion. Both sources report success/failure honestly.
import { NextResponse } from 'next/server'
import { ingestVulnerabilities } from '@/lib/vulnintel/ingest'

export const dynamic = 'force-dynamic'
export const maxDuration = 120

export async function POST() {
  try {
    const result = await ingestVulnerabilities()
    return NextResponse.json(result)
  } catch (e) {
    return NextResponse.json(
      { error: `ingestion failed: ${String((e as Error).message).slice(0, 300)}` },
      { status: 500 },
    )
  }
}
