import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

export async function GET() {
  const lastScan = await db.scanJob.findFirst({
    where: { status: 'completed' },
    orderBy: { startedAt: 'desc' },
    select: { id: true, inventoryJson: true },
  })
  if (!lastScan?.inventoryJson) {
    return NextResponse.json({ error: 'no completed scan available' }, { status: 404 })
  }
  const inv = JSON.parse(lastScan.inventoryJson)
  return NextResponse.json({
    fromScanId: lastScan.id,
    listeners: inv.network?.listeners ?? null,
    interfaces: inv.network?.interfaces ?? null,
    firewall: {
      detected: inv.network?.firewall?.tool != null,
      active: inv.network?.firewall?.active ?? null,
      tool: inv.network?.firewall?.tool ?? null,
      note: inv.network?.firewall?.ufwInstalled
        ? 'ufw config readable'
        : 'no firewall tool/config detected on this host',
    },
    ipForward: inv.network?.ipForward ?? null,
  })
}
