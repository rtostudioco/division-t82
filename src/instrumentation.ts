// DIVISION T82 — server instrumentation (runs once when the server boots).
// Node.js runtime only. Two responsibilities:
//   1. Recovery: a scan interrupted by a crash/restart must never stay
//      'running' forever — it is marked 'failed' with an honest reason.
//   2. Starts the scheduled OSV/NVD/KEV ingestion.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  try {
    const { db } = await import('@/lib/db')
    const stale = await db.scanJob.updateMany({
      where: { status: 'running' },
      data: {
        status: 'failed',
        finishedAt: new Date(),
        errorReason: 'interrupted — the server restarted before the scan finished',
      },
    })
    if (stale.count > 0) {
      console.log(`[t82] recovered ${stale.count} interrupted scan(s) at boot → marked failed`)
    }
  } catch {
    // DB may not be ready yet during first boot — never block startup
  }
  try {
    const { startIngestScheduler } = await import('@/lib/vulnintel/scheduler')
    startIngestScheduler()
  } catch {
    // never block server startup on the scheduler
  }
}
