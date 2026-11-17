import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params
  if (!/^[\w-]{1,64}$/.test(id)) {
    return NextResponse.json({ error: 'invalid scan id' }, { status: 400 })
  }
  const scan = await db.scanJob.findUnique({
    where: { id },
    select: { inventoryJson: true },
  })
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 })
  if (!scan.inventoryJson) return NextResponse.json({ error: 'inventory not captured' }, { status: 404 })
  return NextResponse.json(JSON.parse(scan.inventoryJson))
}
