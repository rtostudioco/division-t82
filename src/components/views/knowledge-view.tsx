'use client'
// DIVISION T82 — Module 9/13: Knowledge Center. Learning library linked to engine controls.
import { useEffect, useState } from 'react'
import {
  ArrowLeft, BookOpen, ExternalLink, GraduationCap, TriangleAlert,
} from 'lucide-react'
import { useArticles, useArticle, type ArticleMeta, type LocStr } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n, localized } from '@/lib/i18n'
import { CATEGORY_LABELS } from '@/lib/engine/types'
import { SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

function catLabel(cat: string, lang: Lang): string {
  const v = (CATEGORY_LABELS as Record<string, LocStr> | undefined)?.[cat]
  return v ? localized(v, lang) : cat
}

const LEVELS = ['BEGINNER', 'INTERMEDIATE', 'ADVANCED'] as const
const LEVEL_TKEY: Record<(typeof LEVELS)[number], Parameters<ReturnType<typeof useI18n>['t']>[0]> = {
  BEGINNER: 'common.beginner',
  INTERMEDIATE: 'common.intermediate',
  ADVANCED: 'common.advanced',
}
const LEVEL_CLS: Record<(typeof LEVELS)[number], string> = {
  BEGINNER: 'border-t82-green/40 bg-t82-green/10 text-t82-green',
  INTERMEDIATE: 'border-t82-cyan/40 bg-t82-cyan/10 text-t82-cyan',
  ADVANCED: 'border-t82-warning/40 bg-t82-warning/10 text-t82-warning',
}
const PLATFORMS = ['linux', 'windows', 'macos'] as const

type SectionKey =
  | 'technicalDescription' | 'rootCause' | 'howItHappens' | 'threatContext'
  | 'indicators' | 'detection' | 'prevention' | 'mitigation' | 'verification'

const SECTION_LABELS: Record<SectionKey, { es: string; en: string }> = {
  technicalDescription: { es: 'Descripción técnica', en: 'Technical description' },
  rootCause: { es: 'Causa raíz', en: 'Root cause' },
  howItHappens: { es: 'Cómo ocurre', en: 'How it happens' },
  threatContext: { es: 'Contexto de amenaza', en: 'Threat context' },
  indicators: { es: 'Indicadores', en: 'Indicators' },
  detection: { es: 'Detección', en: 'Detection' },
  prevention: { es: 'Prevención', en: 'Prevention' },
  mitigation: { es: 'Mitigación', en: 'Mitigation' },
  verification: { es: 'Verificación', en: 'Verification' },
}

function LevelBadge({ level, className }: { level: string; className?: string }) {
  const { t } = useI18n()
  const lv = (LEVELS as readonly string[]).includes(level) ? (level as (typeof LEVELS)[number]) : null
  if (!lv) {
    return <Badge variant="outline" className={cn('font-mono text-[10px] t82-caps', className)}>{level}</Badge>
  }
  return (
    <Badge variant="outline" className={cn('font-mono text-[10px] t82-caps', LEVEL_CLS[lv], className)}>
      {t(LEVEL_TKEY[lv])}
    </Badge>
  )
}

function ArticleCard({ a, lang, onOpen }: { a: ArticleMeta; lang: Lang; onOpen: (slug: string) => void }) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpen(a.slug)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen(a.slug)
        }
      }}
      className="flex min-h-[44px] cursor-pointer flex-col gap-2 rounded-xl border bg-card p-4 text-left shadow-sm transition-colors hover:border-ring focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
    >
      <div className="flex items-start justify-between gap-2">
        <h3 className="min-w-0 flex-1 text-sm font-semibold leading-snug">{localized(a.title, lang)}</h3>
        <LevelBadge level={a.level} />
      </div>
      <p className="line-clamp-3 text-xs leading-relaxed text-muted-foreground">{localized(a.summary, lang)}</p>
      <div className="mt-auto flex flex-wrap items-center gap-1.5 pt-1">
        <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] t82-caps text-muted-foreground">
          {catLabel(a.category, lang)}
        </span>
        {a.platforms.map((p) => (
          <span key={p} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{p}</span>
        ))}
      </div>
      <div className="flex flex-wrap gap-1">
        {a.relatedControls.map((c) => (
          <span key={c} className="rounded bg-t82-cyan/10 px-1.5 py-0.5 font-mono text-[10px] text-t82-cyan">{c}</span>
        ))}
      </div>
    </div>
  )
}

export function KnowledgeView() {
  const { t, lang } = useI18n()
  const selectedArticle = useAppStore((s) => s.selectedArticle)
  const openArticle = useAppStore((s) => s.openArticle)
  const setView = useAppStore((s) => s.setView)
  const setSelectedControl = useAppStore((s) => s.setSelectedControl)

  // list-mode filters (debounced query, 300 ms)
  const [searchInput, setSearchInput] = useState('')
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState('all')
  const [platform, setPlatform] = useState('all')
  const [category, setCategory] = useState('all')

  useEffect(() => {
    const id = setTimeout(() => setQuery(searchInput), 300)
    return () => clearTimeout(id)
  }, [searchInput])

  const articles = useArticles({
    query: query.trim().length >= 2 ? query.trim() : undefined,
    level: level === 'all' ? undefined : level,
    platform: platform === 'all' ? undefined : platform,
    category: category === 'all' ? undefined : category,
  })
  const article = useArticle(selectedArticle)

  const goHardening = (controlId: string) => {
    setSelectedControl(controlId)
    setView('hardening')
  }

  // ── Reader mode ─────────────────────────────────────────────────────────────
  if (selectedArticle) {
    if (article.isPending) {
      return (
        <div className="mx-auto max-w-3xl space-y-4" role="status" aria-label={t('common.loading')}>
          <Skeleton className="h-10 w-40" />
          <Skeleton className="h-6 w-3/4" />
          <LoadingRows rows={6} />
        </div>
      )
    }
    if (article.isError || !article.data) {
      return (
        <div className="mx-auto max-w-3xl space-y-4 py-10">
          <Button variant="ghost" size="sm" className="min-h-11" onClick={() => openArticle(null)}>
            <ArrowLeft className="size-4" aria-hidden />
            {t('knowledge.back')}
          </Button>
          <EmptyState
            icon={<BookOpen className="size-8" />}
            title={t('common.error')}
            description={article.error?.message}
            action={<Button onClick={() => void article.refetch()}>{t('common.retry')}</Button>}
          />
        </div>
      )
    }
    const a = article.data
    const locale = lang === 'es' ? 'es-ES' : 'en-US'

    const sections: [SectionKey, LocStr][] = [
      ['technicalDescription', a.technicalDescription],
      ['rootCause', a.rootCause],
      ['howItHappens', a.howItHappens],
      ['threatContext', a.threatContext],
      ['indicators', a.indicators],
      ['detection', a.detection],
      ['prevention', a.prevention],
      ['mitigation', a.mitigation],
      ['verification', a.verification],
    ]

    return (
      <article className="mx-auto max-w-3xl space-y-4">
        <div>
          <Button variant="ghost" size="sm" className="min-h-11 -ml-2" onClick={() => openArticle(null)}>
            <ArrowLeft className="size-4" aria-hidden />
            {t('knowledge.back')}
          </Button>
        </div>

        <header className="space-y-3">
          <h1 className="text-xl font-bold leading-tight">{localized(a.title, lang)}</h1>
          <p className="text-sm italic leading-relaxed text-muted-foreground">{localized(a.summary, lang)}</p>
          <div className="flex flex-wrap items-center gap-2">
            <LevelBadge level={a.level} />
            <span className="rounded border border-border bg-muted px-2 py-0.5 text-[10px] t82-caps text-muted-foreground">
              {catLabel(a.category, lang)}
            </span>
            {a.platforms.map((p) => (
              <span key={p} className="rounded border border-border px-2 py-0.5 font-mono text-[10px] text-muted-foreground">{p}</span>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold t82-caps text-muted-foreground">{t('knowledge.related')}:</span>
            {a.relatedControls.map((c) => (
              <button
                key={c}
                onClick={() => goHardening(c)}
                className="rounded bg-t82-cyan/10 px-2 py-0.5 font-mono text-[10px] text-t82-cyan transition-colors hover:bg-t82-cyan/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
                aria-label={`${t('findings.viewRemediation')}: ${c}`}
              >
                {c}
              </button>
            ))}
          </div>
          {a.mitre.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-semibold t82-caps text-muted-foreground">{t('knowledge.mitre')}:</span>
              {a.mitre.map((m) => (
                <span key={m.id} className="rounded border border-t82-cyan/40 px-2 py-0.5 font-mono text-[10px] text-t82-cyan">
                  {m.id} · {m.name}
                </span>
              ))}
            </div>
          )}
          {(a.cve?.length || a.cwe?.length) ? (
            <div className="flex flex-wrap items-center gap-2">
              {a.cve?.map((c) => (
                <span key={c} className="rounded border border-t82-critical/40 px-2 py-0.5 font-mono text-[10px] text-t82-critical">{c}</span>
              ))}
              {a.cwe?.map((c) => (
                <span key={c} className="rounded border border-t82-warning/40 px-2 py-0.5 font-mono text-[10px] text-t82-warning">{c}</span>
              ))}
            </div>
          ) : null}
        </header>

        <div className="space-y-5 rounded-xl border bg-card p-4 md:p-6">
          {sections.map(([key, value]) => (
            <section key={key}>
              <h2 className="text-[11px] font-semibold t82-caps tracking-wide text-muted-foreground">
                {SECTION_LABELS[key][lang]}
              </h2>
              <p className="mt-1.5 text-sm leading-relaxed">{localized(value, lang)}</p>
            </section>
          ))}

          {a.secureConfigExample && (
            <section>
              <h2 className="text-[11px] font-semibold t82-caps tracking-wide text-t82-green">
                {a.secureConfigExample.label} · {a.secureConfigExample.language}
              </h2>
              <pre className="mt-1.5 overflow-x-auto rounded-md bg-muted p-3 font-mono text-[11px] leading-relaxed">
                {a.secureConfigExample.code}
              </pre>
            </section>
          )}

          {a.defensiveCodeExample && (
            <section>
              <h2 className="text-[11px] font-semibold t82-caps tracking-wide text-t82-cyan">
                {a.defensiveCodeExample.label} · {a.defensiveCodeExample.language}
              </h2>
              <pre className="mt-1.5 overflow-x-auto rounded-md bg-muted p-3 font-mono text-[11px] leading-relaxed">
                {a.defensiveCodeExample.code}
              </pre>
            </section>
          )}

          {a.labScenario && (
            <section className="rounded-lg border border-t82-cyan/30 bg-t82-cyan/5 p-4">
              <h2 className="text-[11px] font-semibold t82-caps tracking-wide text-t82-cyan">
                {t('knowledge.lab')} — {localized(a.labScenario.title, lang)}
              </h2>
              <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-sm leading-relaxed">
                {a.labScenario.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
              <p className="mt-3 flex items-start gap-2 text-xs font-medium text-t82-warning">
                <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                {localized(a.labScenario.safetyNote, lang)}
              </p>
            </section>
          )}

          {a.references.length > 0 && (
            <section>
              <h2 className="text-[11px] font-semibold t82-caps tracking-wide text-muted-foreground">{t('common.references')}</h2>
              <ul className="mt-1.5 space-y-1">
                {a.references.map((r) => (
                  <li key={r.url}>
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-t82-cyan underline-offset-2 hover:underline"
                    >
                      {r.label}
                      <ExternalLink className="size-3" aria-hidden />
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}

          <footer className="border-t pt-3 text-[11px] text-muted-foreground">
            {t('knowledge.reviewed')}: <span className="font-mono">{new Date(a.reviewedAt).toLocaleDateString(locale)}</span>
          </footer>
        </div>
      </article>
    )
  }

  // ── List mode ───────────────────────────────────────────────────────────────
  return (
    <div className="space-y-4">
      <div className="mb-1">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('knowledge.title')}</h1>
        <p className="mt-0.5 text-xs text-muted-foreground">{t('knowledge.subtitle')}</p>
      </div>

      <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
        <Input
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder={t('knowledge.search')}
          aria-label={t('knowledge.search')}
          className="h-11 lg:max-w-xs"
        />
        <div className="grid grid-cols-3 gap-2 lg:flex">
          <Select value={level} onValueChange={setLevel}>
            <SelectTrigger className="min-h-[44px] w-full lg:w-36" aria-label={t('knowledge.level')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('common.all')}</SelectItem>
              {LEVELS.map((lv) => (
                <SelectItem key={lv} value={lv}>{t(LEVEL_TKEY[lv])}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={platform} onValueChange={setPlatform}>
            <SelectTrigger className="min-h-[44px] w-full lg:w-32" aria-label="Platform">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('common.all')}</SelectItem>
              {PLATFORMS.map((p) => (
                <SelectItem key={p} value={p}>
                  <span className="font-mono text-xs">{p}</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={category} onValueChange={setCategory}>
            <SelectTrigger className="min-h-[44px] w-full lg:w-52" aria-label={t('common.category')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t('common.all')}</SelectItem>
              {Object.entries(CATEGORY_LABELS as Record<string, LocStr>).map(([key, label]) => (
                <SelectItem key={key} value={key}>{localized(label, lang)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {articles.isPending ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3" role="status" aria-label={t('common.loading')}>
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      ) : articles.isError ? (
        <EmptyState
          icon={<GraduationCap className="size-8" />}
          title={t('common.error')}
          description={articles.error?.message}
          action={<Button onClick={() => void articles.refetch()}>{t('common.retry')}</Button>}
        />
      ) : (articles.data ?? []).length === 0 ? (
        <EmptyState icon={<GraduationCap className="size-8" />} title={t('common.noData')} description={t('knowledge.search')} />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {(articles.data ?? []).map((a) => (
            <ArticleCard key={a.slug} a={a} lang={lang} onOpen={openArticle} />
          ))}
        </div>
      )}
    </div>
  )
}

export default KnowledgeView
