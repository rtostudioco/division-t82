import { NextResponse } from 'next/server'
import { getArticle } from '@/lib/engine/knowledge'

export const dynamic = 'force-dynamic'

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params
  if (!/^[a-z0-9-]{1,80}$/.test(slug)) {
    return NextResponse.json({ error: 'invalid slug' }, { status: 400 })
  }
  const a = getArticle(slug)
  if (!a) return NextResponse.json({ error: 'article not found' }, { status: 404 })
  return NextResponse.json(a)
}
