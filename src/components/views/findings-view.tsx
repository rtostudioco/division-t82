'use client'
// DIVISION T82 — Module 4/13: Findings. Open FAIL/WARNING items with remediation link.
import { useState } from 'react'
import { ExternalLink, Flag, Hammer, ScanSearch } from 'lucide-react'
import { useOverview, useFindings, type FindingItem } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n, localized } from '@/lib/i18n'
import { SectionCard, EmptyState, LoadingRows, SeverityBadge, statusIcon } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'
type SeverityT = Parameters<typeof SeverityBadge>[0]['severity']
type StatusIconT = Parameters<typeof statusIcon>[0]

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

interface FindingWithRefs extends FindingItem {
  references?: { label: string; url: string }[]
}

export function FindingsView() {
  const { t, lang } = useI18n()
  const setView = useAppStore((s) => s.setView)
  const setSelectedControl = useAppStore((s) => s.setSelectedControl)
  const ov = useOverview()
  const lastScanId = ov.data?.lastScan?.id ?? null
  const findings = useFindings(lastScanId)
  const [sevFilter, setSevFilter] = useState<string>('all')

  const openHardening = (controlId: string) => {
    setSelectedControl(controlId)
    setView('hardening')
  }

  if (ov.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-56" />
        <LoadingRows rows={4} />
      </div>
    )
  }

  if (ov.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<Flag className="size-8" />}
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
          icon={<ScanSearch className="size-8" />}
          title={t('findings.title')}
          description={bi(lang, 'Ejecuta una evaluación para generar hallazgos.', 'Run an assessment to generate findings.')}
          action={<Button onClick={() => setView('overview')}>{t('common.scan')}</Button>}
        />
      </div>
    )
  }

  if (findings.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-56" />
        <LoadingRows rows={4} />
      </div>
    )
  }

  if (findings.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<Flag className="size-8" />}
          title={t('common.error')}
          description={findings.error?.message}
          action={<Button onClick={() => void findings.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  const items = findings.data ?? []
  const counts = new Map<string, number>()
  for (const f of items) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1)
  const visible = sevFilter === 'all' ? items : items.filter((f) => f.severity === sevFilter)

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold t82-caps tracking-wide">{t('findings.title')}</h1>

      {items.length === 0 ? (
        <EmptyState icon={<Flag className="size-8" />} title={t('findings.empty')} />
      ) : (
        <>
          {/* Severity filter chips */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setSevFilter('all')}
              aria-pressed={sevFilter === 'all'}
              className={cn(
                'inline-flex min-h-[36px] items-center gap-1.5 rounded-full border px-3 text-xs font-medium transition-colors',
                sevFilter === 'all' ? 'border-ring bg-accent text-foreground' : 'text-muted-foreground hover:bg-accent',
              )}
            >
              {t('common.all')}
              <span className="font-mono text-[10px] tabular-nums">{items.length}</span>
            </button>
            {SEV_ORDER.filter((sev) => counts.has(sev)).map((sev) => (
              <button
                key={sev}
                onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}
                aria-pressed={sevFilter === sev}
                className={cn(
                  'inline-flex min-h-[36px] items-center gap-1.5 rounded-full border px-3 font-mono text-[11px] font-semibold transition-colors',
                  sevFilter === sev
                    ? sev === 'CRITICAL' || sev === 'HIGH'
                      ? 'border-t82-critical bg-t82-critical/10 text-t82-critical'
                      : sev === 'MEDIUM'
                        ? 'border-t82-warning bg-t82-warning/10 text-t82-warning'
                        : 'border-t82-cyan bg-t82-cyan/10 text-t82-cyan'
                    : 'border-border text-muted-foreground hover:bg-accent',
                )}
              >
                {sev}
                <span className="text-[10px] tabular-nums">{counts.get(sev)}</span>
              </button>
            ))}
          </div>

          {/* Finding cards */}
          <div className="grid gap-4 lg:grid-cols-2">
            {visible.map((f) => {
              const fw = f as FindingWithRefs
              return (
                <SectionCard
                  key={f.controlId}
                  title={
                    <span className="flex flex-wrap items-center gap-2">
                      {statusIcon(f.status as StatusIconT)}
                      <span className="text-sm font-semibold normal-case">{localized(f.name, lang)}</span>
                    </span>
                  }
                  description={undefined}
                  right={<SeverityBadge severity={f.severity as SeverityT} />}
                >
                  <div className="space-y-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[11px] text-muted-foreground">{f.controlId}</span>
                      <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] t82-caps text-muted-foreground">
                        {f.category}
                      </span>
                    </div>
                    {f.detail && (
                      <div>
                        <p className="mb-1 text-[10px] font-semibold t82-caps text-muted-foreground">{t('common.detail')}</p>
                        <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-muted p-2 font-mono text-[11px] leading-relaxed">
                          {f.detail}
                        </pre>
                      </div>
                    )}
                    {f.explanation && (
                      <p className="text-xs leading-relaxed text-muted-foreground">
                        <span className="font-semibold text-foreground">{bi(lang, 'Explicación', 'Explanation')}: </span>
                        {localized(f.explanation, lang)}
                      </p>
                    )}
                    {fw.references && fw.references.length > 0 && (
                      <div>
                        <p className="mb-1 text-[10px] font-semibold t82-caps text-muted-foreground">{t('common.references')}</p>
                        <ul className="space-y-1">
                          {fw.references.map((r) => (
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
                      </div>
                    )}
                    <Button variant="outline" size="sm" className="min-h-11 w-full sm:w-auto" onClick={() => openHardening(f.controlId)}>
                      <Hammer className="size-3.5" aria-hidden />
                      {t('findings.viewRemediation')}
                    </Button>
                  </div>
                </SectionCard>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

export default FindingsView
