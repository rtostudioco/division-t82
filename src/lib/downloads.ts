// DIVISION T82 — distributable installer catalog (server-side only).
// Scans the dist/ folder for release artifacts produced by
// deploy/scripts/make-release.sh and computes verification metadata.
// Filesystem is the source of truth — no database rows involved.
import fs from 'fs/promises'
import path from 'path'
import crypto from 'crypto'

export interface ArtifactInfo {
  name: string
  kind: 'portable' | 'deb' | 'windows' | 'macos' | 'checksums'
  size: number
  sha256: string
  generatedAt: string
}

// Strict allow-list of distributable file names (no traversal, no surprises).
// Linux: fuente portable + .deb · Windows: setup NSIS · macOS: .dmg/.pkg.
const ARTIFACT_RE =
  /^vulncheck-t82-\d+\.\d+\.\d+(?:-[\w.]+)?-source-[\w.-]+\.tar\.gz$|^vulncheck-t82_\d+\.\d+\.\d+(?:-[\w.]+)?_[\w.-]+\.deb$|^vulncheck-t82-\d+\.\d+\.\d+(?:-[\w.]+)?-win64-setup\.exe$|^vulncheck-t82-\d+\.\d+\.\d+(?:-[\w.]+)?-macos-(?:arm64|x86_64)\.(?:dmg|pkg)$|^SHA256SUMS$/

function kindOf(name: string): ArtifactInfo['kind'] {
  if (name.endsWith('.tar.gz')) return 'portable'
  if (name.endsWith('.deb')) return 'deb'
  if (name.endsWith('-win64-setup.exe')) return 'windows'
  if (name.endsWith('.dmg') || name.endsWith('.pkg')) return 'macos'
  return 'checksums'
}

export function distDir(): string {
  return path.join(process.cwd(), 'dist')
}

export function isArtifactName(name: string): boolean {
  return ARTIFACT_RE.test(name)
}

export async function listArtifacts(): Promise<ArtifactInfo[]> {
  const dir = distDir()
  let names: string[] = []
  try {
    names = (await fs.readdir(dir)).filter(isArtifactName)
  } catch {
    return []
  }

  const out: ArtifactInfo[] = []
  for (const name of names) {
    try {
      const full = path.join(dir, name)
      const st = await fs.stat(full)
      if (!st.isFile()) continue
      const buf = await fs.readFile(full)
      out.push({
        name,
        kind: kindOf(name),
        size: st.size,
        sha256: crypto.createHash('sha256').update(buf).digest('hex'),
        generatedAt: st.mtime.toISOString(),
      })
    } catch {
      // file vanished mid-scan — skip it
    }
  }
  // checksums last, artifacts newest first
  out.sort((a, b) => {
    const ka = a.kind === 'checksums' ? 1 : 0
    const kb = b.kind === 'checksums' ? 1 : 0
    if (ka !== kb) return ka - kb
    return b.generatedAt.localeCompare(a.generatedAt)
  })
  return out
}

export async function readArtifact(name: string): Promise<Buffer | null> {
  if (!isArtifactName(name)) return null
  const full = path.join(distDir(), name)
  // Defense in depth: resolved path must stay inside dist/.
  if (path.dirname(full) !== distDir()) return null
  try {
    const st = await fs.stat(full)
    if (!st.isFile()) return null
    return await fs.readFile(full)
  } catch {
    return null
  }
}
