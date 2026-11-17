'use client'
// DIVISION T82 — Module 3/13: Security Assessment. Per-category evidence-backed results.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, Info, Loader2, ListChecks, RefreshCw } from 'lucide-react'
import { useOverview, useScan, useRunScan, type LocStr, type ScanDetail } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n, localized } from '@/lib/i18n'
import { CATEGORY_LABELS } from '@/lib/engine/types'
import { StatusBadge, SeverityBadge, SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Accordion, AccordionContent, AccordionItem, AccordionTrigger,
} from '@/components/ui/accordion'
import {
  Collapsible, CollapsibleContent, CollapsibleTrigger,
} from '@/components/ui/collapsible'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'
type StatusT = Parameters<typeof StatusBadge>[0]['status']
type SeverityT = Parameters<typeof SeverityBadge>[0]['severity']

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const STATUS_ORDER = ['PASS', 'FAIL', 'WARNING', 'NOT_APPLICABLE', 'NOT_ASSESSED', 'ERROR'] as const
const STATUS_TKEY: Record<(typeof STATUS_ORDER)[number], Parameters<ReturnType<typeof useI18n>['t']>[0]> = {
  PASS: 'common.pass',
  FAIL: 'common.fail',
  WARNING: 'common.warning',
  NOT_APPLICABLE: 'common.na',
  NOT_ASSESSED: 'common.nAssessed',
  ERROR: 'common.errorState',
}

function catLabel(cat: string, lang: Lang): string {
  const v = (CATEGORY_LABELS as Record<string, LocStr> | undefined)?.[cat]
  return v ? localized(v, lang) : cat
}

function countOf(counts: Record<string, number> | undefined | null, key: string): number {
  if (!counts) return 0
  const lower = key.toLowerCase()
  let sum = 0
  for (const [k, v] of Object.entries(counts)) if (k.toLowerCase() === lower) sum += v ?? 0
  return sum
}

function scoreTone(score: number | null): string {
  if (score === null) return 'text-muted-foreground'
  if (score >= 80) return 'text-t82-green'
  if (score >= 55) return 'text-t82-warning'
  return 'text-t82-critical'
}

interface CatalogRule {
  id: string
  name: LocStr
  category: string
  severity: string
  platforms: string[]
  implemented: boolean
  evidenceSource: string
  explanation: LocStr | null
}
interface CatalogResponse {
  categories: { key: string; en: string; es: string }[]
  rules: CatalogRule[]
}

export function AssessmentView() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const setView = useAppStore((s) => s.setView)
  const ov = useOverview()
  const lastScanId = ov.data?.lastScan?.id ?? null
  const scan = useScan(lastScanId)
  const runScan = useRunScan()
  const [statusFilter, setStatusFilter] = useState<string>('all')

  const catalog = useQuery({
    queryKey: ['t82-rules-catalog'],
    queryFn: async (): Promise<CatalogResponse> => {
      const res = await fetch('/api/rules/catalog', { cache: 'no-store' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return res.json() as Promise<CatalogResponse>
    },
  })

  const designedByPlatform = useMemo(() => {
    const map = new Map<string, CatalogRule[]>()
    for (const r of catalog.data?.rules ?? []) {
      if (r.implemented) continue
      for (const p of r.platforms) {
        const arr = map.get(p) ?? []
        arr.push(r)
        map.set(p, arr)
      }
    }
    return [...map.entries()]
  }, [catalog.data])

  const rescan = async () => {
    try {
      await runScan.mutateAsync([])
      toast({ title: lang === 'es' ? 'Evaluación completada' : 'Assessment completed' })
    } catch (err) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: err instanceof Error ? err.message : String(err),
      })
    }
  }

  const controlsByCategory = useMemo(() => {
    const map = new Map<string, ScanDetail['controls']>()
    if (scan.data) {
      for (const c of scan.data.controls) {
        const arr = map.get(c.category) ?? []
        arr.push(c)
        map.set(c.category, arr)
      }
    }
    return map
  }, [scan.data])

  if (ov.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-72" />
        <LoadingRows rows={6} />
      </div>
    )
  }

  if (ov.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<ListChecks className="size-8" />}
          title={t('common.error')}
          description={ov.error?.message}
          action={<Button onClick={() => void ov.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  if (!lastScanId) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<ListChecks className="size-8" />}
          title={t('assessment.title')}
          description={t('assessment.runHint')}
          action={<Button onClick={() => setView('overview')}>{t('overview.startScan')}</Button>}
        />
      </div>
    )
  }

  if (scan.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-72" />
        <LoadingRows rows={6} />
      </div>
    )
  }

  if (scan.isError || !scan.data) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<ListChecks className="size-8" />}
          title={t('common.error')}
          description={scan.error?.message}
          action={<Button onClick={() => void scan.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  const s = scan.data

  const filtered = (cat: string) => {
    const items = controlsByCategory.get(cat) ?? []
    return statusFilter === 'all' ? items : items.filter((c) => c.status === statusFilter)
  }

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-bold t82-caps tracking-wide">{t('assessment.title')}</h1>
          <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
            {s.host.hostname} · {s.host.os} · {s.id}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="ghost" size="icon" className="size-9" aria-label={t('assessment.formula')}>
                <Info className="size-4" aria-hidden />
              </Button>
            </PopoverTrigger>
            <PopoverContent align="end" className="w-96">
              <p className="text-xs font-semibold t82-caps text-muted-foreground">{t('assessment.formula')}</p>
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded-md bg-muted p-3 font-mono text-[11px] leading-relaxed">
                {s.formula}
              </pre>
            </PopoverContent>
          </Popover>
          <Button variant="outline" className="min-h-11" onClick={() => void rescan()} disabled={runScan.isPending}>
            {runScan.isPending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <RefreshCw className="size-4" aria-hidden />
            )}
            {runScan.isPending ? t('common.scanning') : t('common.rescan')}
          </Button>
        </div>
      </div>

      {/* Status summary chips */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card p-4">
        {STATUS_ORDER.map((st) => (
          <span key={st} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1">
            <StatusBadge status={st as StatusT} lang={lang} />
            <span className="font-mono text-xs font-bold tabular-nums">{countOf(s.counts, st)}</span>
          </span>
        ))}
        <span className="ml-auto font-mono text-xs text-muted-foreground">
          {t('common.score')}: <span className={`font-bold ${scoreTone(s.score)}`}>{s.score === null ? '—' : s.score.toFixed(1)}</span>
          {' · '}
          {t('common.coverage')}: <span className="font-bold text-t82-cyan">{s.coverage.toFixed(1)}%</span>
        </span>
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2">
        <span className="text-xs t82-caps text-muted-foreground">{t('common.filter')}</span>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="min-h-[44px] w-52" aria-label={t('common.status')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('common.all')}</SelectItem>
            {STATUS_ORDER.map((st) => (
              <SelectItem key={st} value={st}>{t(STATUS_TKEY[st])}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Categories */}
      <Accordion type="multiple" className="rounded-xl border bg-card px-4">
        {s.categories.map((cat) => {
          const items = filtered(cat.category)
          if (items.length === 0) return null
          return (
            <AccordionItem key={cat.category} value={cat.category}>
              <AccordionTrigger className="gap-3 hover:no-underline">
                <span className="flex min-w-0 flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold">{catLabel(cat.category, lang)}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">{cat.category}</span>
                  <span className={cn('ml-auto shrink-0 font-mono text-sm font-bold tabular-nums', scoreTone(cat.score))}>
                    {cat.score === null ? '—' : `${cat.score.toFixed(1)}`}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                    {cat.scored}/{cat.total}
                  </span>
                </span>
              </AccordionTrigger>
              <AccordionContent className="pt-1">
                <div className="space-y-2">
                  {items.map((c) => {
                    const honest = c.status === 'NOT_ASSESSED' || c.status === 'NOT_APPLICABLE'
                    return (
                      <Collapsible key={c.id} className="rounded-lg border">
                        <CollapsibleTrigger asChild>
                          <button className="flex min-h-[52px] w-full flex-wrap items-center gap-2 rounded-lg px-3 py-2 text-left transition-colors hover:bg-accent/60 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring">
                            <StatusBadge status={c.status as StatusT} lang={lang} />
                            <SeverityBadge severity={c.severity as SeverityT} />
                            <span className="font-mono text-[11px] text-muted-foreground">{c.controlId}</span>
                            <span className="min-w-0 flex-1 truncate text-sm">{localized(c.name, lang)}</span>
                            {c.implemented ? (
                              <span className="hidden rounded border border-t82-green/30 bg-t82-green/10 px-1.5 py-0.5 text-[9px] font-semibold t82-caps text-t82-green sm:inline">
                                {t('common.implemented')}
                              </span>
                            ) : (
                              <span className="hidden rounded border border-border bg-muted px-1.5 py-0.5 text-[9px] font-semibold t82-caps text-muted-foreground sm:inline">
                                {t('common.designed')}
                              </span>
                            )}
                            <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform [[data-state=open]>&]:rotate-180" aria-hidden />
                          </button>
                        </CollapsibleTrigger>
                        <CollapsibleContent>
                          <div className="space-y-2 border-t px-3 py-3 text-xs">
                            {c.reason && (
                              <p className={cn(honest ? 'text-t82-critical' : 'text-muted-foreground')}>
                                <span className="font-semibold t82-caps">{t('common.reason')}: </span>
                                {c.reason}
                              </p>
                            )}
                            {c.detail && (
                              <div>
                                <p className="font-semibold t82-caps text-muted-foreground">{t('common.detail')}</p>
                                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-muted p-2 font-mono text-[11px]">
                                  {c.detail}
                                </pre>
                              </div>
                            )}
                            {c.explanation && (
                              <p className="leading-relaxed text-muted-foreground">
                                <span className="font-semibold text-foreground">{bi(lang, 'Explicación', 'Explanation')}: </span>
                                {localized(c.explanation, lang)}
                              </p>
                            )}
                            {c.limitations && (
                              <p className="leading-relaxed text-muted-foreground">
                                <span className="font-semibold text-foreground">{t('common.limitations')}: </span>
                                {localized(c.limitations, lang)}
                              </p>
                            )}
                            {c.evidenceSource && (
                              <p className="text-muted-foreground">
                                <span className="font-semibold t82-caps">{t('common.source')}: </span>
                                <span className="font-mono">{c.evidenceSource}</span>
                              </p>
                            )}
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    )
                  })}
                </div>
              </AccordionContent>
            </AccordionItem>
          )
        })}
      </Accordion>

      {/* Designed catalog */}
      <SectionCard
        title={t('assessment.designed')}
        description={bi(
          lang,
          'Reglas declaradas para otras plataformas. Nunca se evalúan ni generan resultados en este entorno.',
          'Rules declared for other platforms. They are never evaluated or produce results in this environment.',
        )}
      >
        {catalog.isPending ? (
          <LoadingRows rows={2} />
        ) : catalog.isError ? (
          <div className="flex flex-col items-start gap-2">
            <p className="text-xs text-muted-foreground">{t('common.error')}: {catalog.error.message}</p>
            <Button variant="outline" size="sm" className="min-h-11" onClick={() => void catalog.refetch()}>
              {t('common.retry')}
            </Button>
          </div>
        ) : designedByPlatform.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
        ) : (
          <div className="space-y-4">
            {designedByPlatform.map(([platform, rules]) => (
              <div key={platform}>
                <p className="mb-2 font-mono text-xs font-bold t82-caps text-t82-cyan">{platform}</p>
                <ul className="max-h-96 space-y-1.5 overflow-y-auto pr-1">
                  {rules.map((r) => (
                    <li key={`${platform}-${r.id}`} className="flex flex-wrap items-center gap-2 rounded-md border px-3 py-2">
                      <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[9px] font-semibold t82-caps text-muted-foreground">
                        {t('common.designed')}
                      </span>
                      <span className="font-mono text-[11px] text-muted-foreground">{r.id}</span>
                      <span className="min-w-0 flex-1 truncate text-sm">{localized(r.name, lang)}</span>
                      <span className="w-full font-mono text-[10px] text-muted-foreground sm:w-auto">
                        {r.evidenceSource} — {bi(lang, 'no implementado en este entorno', 'not implemented in this environment')}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  )
}

export default AssessmentView
