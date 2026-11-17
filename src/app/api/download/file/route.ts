// DIVISION T82 — serves a single release artifact from dist/ as a download.
// GET /api/download/file?name=vulncheck-t82-0.2.1-source-x86_64.tar.gz
// The name is validated against a strict allow-list regex and the resolved
// path is checked to stay inside dist/ (defense in depth vs. traversal).
import { NextResponse } from 'next/server'
import { readArtifact } from '@/lib/downloads'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const name = new URL(request.url).searchParams.get('name') ?? ''
  const buf = await readArtifact(name)
  if (!buf) {
    return NextResponse.json(
      { error: 'artefacto no encontrado — genera los instaladores primero' },
      { status: 404 },
    )
  }
  return new NextResponse(new Uint8Array(buf), {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(buf.byteLength),
      'Content-Disposition': `attachment; filename="${name}"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    },
  })
}
