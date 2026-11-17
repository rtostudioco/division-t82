// DIVISION T82 — Knowledge Center loader/search (server side)
import { KNOWLEDGE_ARTICLES } from '@/data/knowledge/articles'
import type { KnowledgeArticleData, ArticleLevel, ControlCategory, Platform } from './types'

export interface ArticleQuery {
  query?: string
  category?: string
  level?: string
  platform?: string
  control?: string
}

function scoreArticle(a: KnowledgeArticleData, q: string): number {
  const needle = q.toLowerCase()
  let score = 0
  const hay = [
    a.title.en, a.title.es, a.summary.en, a.summary.es,
    a.technicalDescription.en, a.technicalDescription.es,
    a.rootCause.es, a.howItHappens.es, a.threatContext.es,
    ...a.mitre.map((m) => `${m.id} ${m.name}`),
    ...(a.cve ?? []),
    ...(a.cwe ?? []),
    ...a.relatedControls,
  ].join(' ').toLowerCase()
  for (const term of needle.split(/\s+/).filter(Boolean)) {
    if (hay.includes(term)) score += term.length > 3 ? 2 : 1
  }
  return score
}

export function listArticles(q: ArticleQuery = {}): KnowledgeArticleData[] {
  let items = KNOWLEDGE_ARTICLES
  if (q.category) items = items.filter((a) => a.category === q.category)
  if (q.level) items = items.filter((a) => a.level === q.level)
  if (q.platform) items = items.filter((a) => a.platforms.includes(q.platform as Platform))
  if (q.control) items = items.filter((a) => a.relatedControls.includes(q.control as string))
  if (q.query && q.query.trim()) {
    items = items
      .map((a) => ({ a, s: scoreArticle(a, q.query as string) }))
      .filter((x) => x.s > 0)
      .sort((x, y) => y.s - x.s)
      .map((x) => x.a)
  }
  return items
}

export function getArticle(slug: string): KnowledgeArticleData | null {
  return KNOWLEDGE_ARTICLES.find((a) => a.slug === slug) ?? null
}

export function articleFacets() {
  const levels = new Set<ArticleLevel>()
  const categories = new Set<ControlCategory>()
  const platforms = new Set<Platform>()
  for (const a of KNOWLEDGE_ARTICLES) {
    levels.add(a.level)
    categories.add(a.category)
    for (const p of a.platforms) platforms.add(p)
  }
  return {
    levels: [...levels],
    categories: [...categories],
    platforms: [...platforms],
    total: KNOWLEDGE_ARTICLES.length,
  }
}
