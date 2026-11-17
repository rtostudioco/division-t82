// DIVISION T82 — server instrumentation (runs once when the server boots).
// Only in the Node.js runtime; starts the scheduled OSV/NVD/KEV ingestion.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return
  try {
    const { startIngestScheduler } = await import('@/lib/vulnintel/scheduler')
    startIngestScheduler()
  } catch {
    // never block server startup on the scheduler
  }
}
