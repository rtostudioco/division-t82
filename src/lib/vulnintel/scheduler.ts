// DIVISION T82 — scheduled OSV/NVD/KEV ingestion (server-only).
// Started once per server process from src/instrumentation.ts. Checks every 6h
// and actually ingests only when the last run is >= 24h old AND the schedule is
// enabled (ApplicationSetting 'vulnintel.schedule'). Failures are logged to
// AuditHistory (visible in notifications) — never crash the server process.
import { db } from '@/lib/db'
import { ingestVulnerabilities } from './ingest'

const DAY_MS = 24 * 3600 * 1000
const CHECK_INTERVAL_MS = 6 * 3600 * 1000
const FIRST_CHECK_DELAY_MS = 45_000

const g = globalThis as unknown as { __t82IngestScheduler?: boolean }

async function maybeRun(): Promise<void> {
  try {
    const setting = await db.applicationSetting.findUnique({ where: { key: 'vulnintel.schedule' } })
    let enabled = false
    if (setting) {
      try {
        enabled = (JSON.parse(setting.value) as { enabled?: boolean }).enabled === true
      } catch {
        enabled = false
      }
    }
    if (!enabled) return

    const last = await db.applicationSetting.findUnique({ where: { key: 'vulnintel.lastIngest' } })
    let lastAt = 0
    if (last) {
      try {
        lastAt = new Date((JSON.parse(last.value) as { at?: string }).at ?? 0).getTime()
      } catch {
        lastAt = 0
      }
    }
    if (Date.now() - lastAt < DAY_MS) return

    await ingestVulnerabilities()
  } catch (e) {
    try {
      await db.auditHistory.create({
        data: {
          action: 'vuln.schedule',
          detail: `scheduled ingest failed: ${String((e as Error).message).slice(0, 200)}`,
        },
      })
    } catch {
      // DB unavailable — nothing else to do in a background tick
    }
  }
}

export function startIngestScheduler(): void {
  if (g.__t82IngestScheduler) return
  g.__t82IngestScheduler = true
  setTimeout(() => void maybeRun(), FIRST_CHECK_DELAY_MS)
  setInterval(() => void maybeRun(), CHECK_INTERVAL_MS)
}
