import { NextResponse } from 'next/server'
import { listArticles } from '@/lib/engine/knowledge'

export const dynamic = 'force-dynamic'

export async function GET(request: Request) {
  const sp = new URL(request.url).searchParams
  const articles = listArticles({
    query: sp.get('query') ?? undefined,
    category: sp.get('category') ?? undefined,
    level: sp.get('level') ?? undefined,
    platform: sp.get('platform') ?? undefined,
    control: sp.get('control') ?? undefined,
  })
  return NextResponse.json(
    articles.map((a) => ({
      slug: a.slug,
      title: a.title,
      summary: a.summary,
      level: a.level,
      category: a.category,
      platforms: a.platforms,
      relatedControls: a.relatedControls,
      mitre: a.mitre,
      reviewedAt: a.reviewedAt,
    })),
  )
}
