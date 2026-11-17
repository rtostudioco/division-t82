'use client'
// DIVISION T82 — Module 1/13: Security Overview.
// Explainable score with separate coverage, score history and priority findings.
import { useState } from 'react'
import {
  AlertTriangle, ChevronRight, Loader2, RefreshCw, ScanLine, ShieldCheck, TrendingUp,
} from 'lucide-react'
import { useOverview, useRunScan, type LocStr } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n, localized } from '@/lib/i18n'
import { CATEGORY_LABELS, CONTROL_CATEGORIES } from '@/lib/engine/types'
import {
  ScoreRing, CoverageBar, SectionCard, StatCard, EmptyState, LoadingRows,
  SeverityBadge, statusIcon,
} from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/hooks/use-toast'
import {
  LineChart, Line, XAxis, YAxis, Tooltip as ChartTooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'

type Lang = 'es' | 'en'
type SeverityT = Parameters<typeof SeverityBadge>[0]['severity']
type StatusIconT = Parameters<typeof statusIcon>[0]

const ALL_CATEGORIES: string[] = Array.isArray(CONTROL_CATEGORIES)
  ? (CONTROL_CATEGORIES as readonly string[]).slice()
  : Object.keys(CATEGORY_LABELS as Record<string, unknown>)

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

const CHART_TT = {
  contentStyle: {
    background: 'var(--popover)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    fontSize: 12,
    color: 'var(--popover-foreground)',
  },
  labelStyle: { color: 'var(--muted-foreground)' },
  itemStyle: { color: 'var(--popover-foreground)' },
}

function scoreTone(score: number | null): string {
  if (score === null) return 'text-muted-foreground'
  if (score >= 80) return 'text-t82-green'
  if (score >= 55) return 'text-t82-warning'
  return 'text-t82-critical'
}

export function OverviewView() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const setView = useAppStore((s) => s.setView)
  const setSelectedControl = useAppStore((s) => s.setSelectedControl)
  const ov = useOverview()
  const runScan = useRunScan()
  const [scope, setScope] = useState<string[]>(ALL_CATEGORIES)

  const openHardening = (controlId: string) => {
    setSelectedControl(controlId)
    setView('hardening')
  }

  const runAssessment = async (categories: string[]) => {
    try {
      await runScan.mutateAsync(categories)
      toast({ title: lang === 'es' ? 'Evaluación completada' : 'Assessment completed' })
    } catch (err) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: err instanceof Error ? err.message : String(err),
      })
    }
  }

  if (ov.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-72" />
        <div className="grid gap-4 lg:grid-cols-2">
          <Skeleton className="h-56" />
          <Skeleton className="h-56" />
        </div>
        <LoadingRows rows={3} />
      </div>
    )
  }

  if (ov.isError || !ov.data) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<ScanLine className="size-8" />}
          title={t('common.error')}
          description={ov.error?.message ?? t('common.noData')}
          action={<Button onClick={() => void ov.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  const data = ov.data
  const lastScan = data.lastScan

  // ── First launch ──────────────────────────────────────────────────────────
  if (!lastScan) {
    return (
      <div className="mx-auto max-w-3xl space-y-4">
        <SectionCard
          title={t('overview.firstLaunch')}
          description={t('overview.firstLaunchText')}
          right={<ShieldCheck className="size-5 text-t82-green" aria-hidden />}
        >
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-lg border bg-muted/30 p-4">
              <p className="text-xs font-semibold t82-caps text-t82-cyan">{t('overview.compat')}</p>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{t('overview.compatText')}</p>
            </div>
            <div className="rounded-lg border bg-muted/30 p-4">
              <p className="text-xs font-semibold t82-caps text-t82-cyan">{t('overview.permissions')}</p>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{t('overview.permissionsText')}</p>
            </div>
          </div>

          <div className="mt-4 rounded-lg border p-4">
            <p className="text-xs font-semibold t82-caps text-muted-foreground">{t('overview.scope')}</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {ALL_CATEGORIES.map((cat) => (
                <label
                  key={cat}
                  className="flex min-h-[44px] cursor-pointer items-center gap-2.5 rounded-md border px-3 text-sm transition-colors hover:bg-accent"
                >
                  <Checkbox
                    checked={scope.includes(cat)}
                    onCheckedChange={() =>
                      setScope((s) => (s.includes(cat) ? s.filter((x) => x !== cat) : [...s, cat]))
                    }
                    aria-label={catLabel(cat, lang)}
                  />
                  <span className="min-w-0 truncate">{catLabel(cat, lang)}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3">
            <Button
              onClick={() => void runAssessment(scope)}
              disabled={runScan.isPending || scope.length === 0}
              className="min-h-11 px-6"
            >
              {runScan.isPending ? (
                <>
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  {t('common.scanning')}
                </>
              ) : (
                <>
                  <ShieldCheck className="size-4" aria-hidden />
                  {t('overview.startScan')}
                </>
              )}
            </Button>
            <p className="font-mono text-xs text-muted-foreground">
              {scope.length}/{ALL_CATEGORIES.length} {lang === 'es' ? 'categorías' : 'categories'}
            </p>
          </div>
        </SectionCard>
      </div>
    )
  }

  // ── With last scan ────────────────────────────────────────────────────────
  const counts = lastScan.counts ?? {}
  const sev = lastScan.severityCounts ?? {}
  const notScored = countOf(counts, 'NOT_ASSESSED') + countOf(counts, 'NOT_APPLICABLE')
  const pending = countOf(counts, 'FAIL') + countOf(counts, 'WARNING')
  const locale = lang === 'es' ? 'es-ES' : 'en-US'
  const chartData = data.scoreHistory.map((d) => ({
    name: new Date(d.at).toLocaleDateString(locale, { month: 'short', day: 'numeric' }),
    score: d.score ?? undefined,
    coverage: d.coverage,
  }))

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-bold t82-caps tracking-wide">{t('overview.title')}</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('overview.subtitle')}</p>
        </div>
        <Button
          variant="outline"
          className="min-h-11"
          onClick={() => void runAssessment([])}
          disabled={runScan.isPending}
        >
          {runScan.isPending ? (
            <Loader2 className="size-4 animate-spin" aria-hidden />
          ) : (
            <RefreshCw className="size-4" aria-hidden />
          )}
          {runScan.isPending ? t('common.scanning') : t('common.rescan')}
        </Button>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title={t('common.lastScan')}
          description={new Date(lastScan.startedAt).toLocaleString(locale)}
        >
          <div className="flex flex-col items-center gap-6 sm:flex-row">
            <ScoreRing value={lastScan.score} label={t('common.score')} />
            <div className="min-w-0 flex-1 space-y-3">
              <div>
                <p className="mb-1.5 text-xs t82-caps text-muted-foreground">{t('common.coverage')}</p>
                <CoverageBar value={lastScan.coverage} />
              </div>
              {notScored > 0 && <p className="text-xs leading-relaxed text-muted-foreground">{t('status.notAssessedNote')}</p>}
              {lastScan.coverage < 85 && (
                <p className="flex items-start gap-2 text-xs font-medium text-t82-warning">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                  {t('overview.coverageWarn')}
                </p>
              )}
            </div>
          </div>
        </SectionCard>

        <SectionCard
          title={t('overview.history')}
          right={<TrendingUp className="size-4 text-muted-foreground" aria-hidden />}
        >
          {chartData.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <div className="w-full" role="img" aria-label={t('overview.history')}>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: 'var(--muted-foreground)', fontSize: 10 }}
                    tickLine={false}
                    axisLine={{ stroke: 'var(--border)' }}
                  />
                  <YAxis
                    domain={[0, 100]}
                    width={32}
                    tick={{ fill: 'var(--muted-foreground)', fontSize: 10 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <ChartTooltip {...CHART_TT} />
                  <Line
                    type="monotone"
                    dataKey="score"
                    name={t('common.score')}
                    stroke="var(--t82-green)"
                    strokeWidth={2}
                    dot={{ r: 2 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="coverage"
                    name={t('common.coverage')}
                    stroke="var(--t82-cyan)"
                    strokeWidth={2}
                    strokeDasharray="6 4"
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionCard>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label={t('overview.risksCritical')} value={countOf(sev, 'critical')} tone="bad" />
        <StatCard label={t('overview.risksHigh')} value={countOf(sev, 'high')} tone="bad" />
        <StatCard
          label={t('overview.pending')}
          value={pending}
          tone="warn"
          sub={`FAIL ${countOf(counts, 'fail')} · WARNING ${countOf(counts, 'warning')}`}
        />
        <StatCard label={t('common.coverage')} value={`${lastScan.coverage.toFixed(1)}%`} tone="info" />
      </div>

      <SectionCard title={t('overview.categories')}>
        <div className="max-h-96 space-y-3 overflow-y-auto pr-1">
          {data.categoryScores.map((c) => (
            <div key={c.category} className="grid gap-1 sm:flex sm:items-center sm:gap-3">
              <span className="min-w-0 flex-1 truncate text-xs font-medium sm:max-w-44">{catLabel(c.category, lang)}</span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                {c.score !== null && (
                  <div
                    className="h-full rounded-full bg-t82-green transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.max(0, c.score))}%` }}
                  />
                )}
              </div>
              <span className={`shrink-0 text-right font-mono text-xs tabular-nums sm:w-32 ${scoreTone(c.score)}`}>
                {c.score === null ? '—' : `${c.score.toFixed(1)}%`} · {c.scored}/{c.total}
              </span>
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title={t('overview.priority')}>
        {(data.topFindings ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('findings.empty')}</p>
        ) : (
          <ul className="max-h-96 divide-y overflow-y-auto rounded-lg border">
            {data.topFindings.map((f) => (
              <li key={f.controlId}>
                <button
                  onClick={() => openHardening(f.controlId)}
                  className="flex min-h-[52px] w-full items-center gap-3 px-3 py-2 text-left transition-colors hover:bg-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
                >
                  {statusIcon(f.status as StatusIconT)}
                  <span className="shrink-0">
                    <SeverityBadge severity={f.severity as SeverityT} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{localized(f.name, lang)}</span>
                    {f.detail && (
                      <span className="block truncate font-mono text-[11px] text-muted-foreground">{f.detail}</span>
                    )}
                  </span>
                  <span className="hidden shrink-0 font-mono text-[10px] text-muted-foreground sm:block">
                    {f.controlId}
                  </span>
                  <ChevronRight className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                </button>
              </li>
            ))}
          </ul>
        )}
      </SectionCard>
    </div>
  )
}

export default OverviewView
