import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { detectPlatform } from '@/lib/engine/platform'
import { allRules } from '@/lib/engine/rules'
import { ENGINE_VERSION } from '@/lib/engine/types'

export const dynamic = 'force-dynamic'

export async function GET() {
  const p = await detectPlatform()
  const rules = allRules()
  const lastScan = await db.scanJob.findFirst({
    where: { status: 'completed' },
    orderBy: { startedAt: 'desc' },
    select: { startedAt: true },
  })

  return NextResponse.json({
    platform: p.platform,
    platformLabel:
      p.platform === 'linux' ? 'Linux' : p.platform === 'windows' ? 'Windows' : 'macOS',
    hostname: p.hostname,
    os: p.os,
    osVersion: p.osVersion,
    distro: p.distro,
    kernel: p.kernel,
    arch: p.arch,
    user: p.user,
    isRoot: p.isRoot,
    adapters: [
      { platform: 'linux', status: p.platform === 'linux' ? 'ACTIVE' : 'UNSUPPORTED_HOST' },
      {
        platform: 'windows',
        status: 'DESIGNED_NOT_IMPLEMENTED',
        reason: 'Requires native desktop bridge (Tauri 2 + WMI/CIM collectors) on a Windows host',
      },
      {
        platform: 'macos',
        status: 'DESIGNED_NOT_IMPLEMENTED',
        reason: 'Requires native desktop bridge (Tauri 2 + Apple APIs) on a macOS host',
      },
    ],
    engineVersion: ENGINE_VERSION,
    rulesTotal: rules.length,
    rulesImplementedLinux: rules.filter((r) => r.platforms.includes('linux') && r.implemented).length,
    lastScanAt: lastScan?.startedAt?.toISOString() ?? null,
  })
}
