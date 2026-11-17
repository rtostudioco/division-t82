// DIVISION T82 — installer download center API.
// GET  → catalog of distributable artifacts in dist/ (with sha256 metadata).
// POST → runs deploy/scripts/make-release.sh (source-only packaging, no
//        compilation happens here: the target machine builds during install).
import { NextResponse } from 'next/server'
import { execFile } from 'child_process'
import { listArtifacts } from '@/lib/downloads'

export const dynamic = 'force-dynamic'
export const maxDuration = 300

// One generation at a time (per process).
let busy = false

export async function GET() {
  const artifacts = await listArtifacts()
  return NextResponse.json({ artifacts, busy })
}

export async function POST() {
  if (busy) {
    return NextResponse.json(
      { error: 'generación ya en curso — espera unos segundos' },
      { status: 409 },
    )
  }
  busy = true
  try {
    const result = await new Promise<{ code: number; out: string }>((resolve) => {
      execFile(
        'bash',
        ['deploy/scripts/make-release.sh'],
        { cwd: process.cwd(), timeout: 240_000, maxBuffer: 4 * 1024 * 1024 },
        (err, stdout, stderr) => {
          const code = err ? ((err as NodeJS.ErrnoException & { code?: number }).code ?? 1) : 0
          const out = `${stdout ?? ''}\n${stderr ?? ''}`.slice(-1500)
          resolve({ code: typeof code === 'number' ? code : 1, out })
        },
      )
    })

    if (result.code !== 0) {
      return NextResponse.json(
        { error: `generación falló (código ${result.code})`, detail: result.out },
        { status: 500 },
      )
    }
    const artifacts = await listArtifacts()
    return NextResponse.json({ artifacts, busy: false })
  } catch (e) {
    return NextResponse.json(
      { error: `generación falló: ${String((e as Error).message).slice(0, 200)}` },
      { status: 500 },
    )
  } finally {
    busy = false
  }
}
