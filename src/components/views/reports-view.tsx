'use client'
// DIVISION T82 — Module 10/13: Reports. Executive summary + JSON/CSV/PDF export.
import { useState } from 'react'
import { FileJson, FileSpreadsheet, FileText, Loader2, ScanSearch } from 'lucide-react'
import { useScans, useScan } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n } from '@/lib/i18n'
import { StatusBadge, ScoreRing, CoverageBar, SectionCard, EmptyState, LoadingRows, StatCard } from '@/components/t82/shared'
import { DownloadsCard } from '@/components/t82/downloads-card'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'
type StatusT = Parameters<typeof StatusBadge>[0]['status']

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const STATUS_ORDER = ['PASS', 'FAIL', 'WARNING', 'NOT_APPLICABLE', 'NOT_ASSESSED', 'ERROR'] as const
const SEV_TONES: { key: string; tone: 'bad' | 'warn' | 'info' | 'default' }[] = [
  { key: 'critical', tone: 'bad' },
  { key: 'high', tone: 'bad' },
  { key: 'medium', tone: 'warn' },
  { key: 'low', tone: 'info' },
  { key: 'info', tone: 'default' },
]
const SEV_LABEL: Record<string, { es: string; en: string }> = {
  critical: { es: 'Crítica', en: 'Critical' },
  high: { es: 'Alta', en: 'High' },
  medium: { es: 'Media', en: 'Medium' },
  low: { es: 'Baja', en: 'Low' },
  info: { es: 'Informativa', en: 'Info' },
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

export function ReportsView() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const setView = useAppStore((s) => s.setView)
  const scans = useScans()
  const [userPick, setUserPick] = useState<string>('')
  const [pdfBusy, setPdfBusy] = useState(false)
  const items = scans.data ?? []
  // Derived selection: user's explicit pick when still valid, else newest scan.
  const selectedId = userPick && items.some((s) => s.id === userPick) ? userPick : (items[0]?.id ?? '')
  const detail = useScan(selectedId || null)

  const selected = items.find((s) => s.id === selectedId) ?? null
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  const download = (format: 'json' | 'csv') => {
    if (!selectedId) return
    window.location.href = `/api/scans/${selectedId}/report?format=${format}`
  }

  const printReport = () => {
    if (!selectedId) return
    setPdfBusy(true)
    fetch(`/api/scans/${selectedId}/report?format=pdf`, { cache: 'no-store' })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.blob()
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `t82-posture-${new Date().toISOString().slice(0, 10)}.pdf`
        document.body.appendChild(a)
        a.click()
        a.remove()
        URL.revokeObjectURL(url)
        toast({
          title: bi(lang, 'Informe PDF generado', 'PDF report generated'),
          description: bi(lang, 'Descarga iniciada — archivo PDF nativo con resumen ejecutivo y resultados.', 'Download started — native PDF with executive summary and results.'),
        })
      })
      .catch((e) => {
        toast({
          title: bi(lang, 'Error generando PDF', 'PDF generation failed'),
          description: String(e.message),
          variant: 'destructive',
        })
      })
      .finally(() => setPdfBusy(false))
  }

  if (scans.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-56" />
        <LoadingRows rows={4} />
      </div>
    )
  }

  if (scans.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<FileText className="size-8" />}
          title={t('common.error')}
          description={scans.error?.message}
          action={<Button onClick={() => void scans.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('reports.title')}</h1>
        <div className="flex items-center gap-2">
          {items.length > 0 && (
            <Select value={selectedId} onValueChange={setUserPick}>
              <SelectTrigger className="min-h-[44px] w-64" aria-label={t('common.lastScan')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {items.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    <span className="font-mono text-xs">
                      {new Date(s.startedAt).toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' })}
                      {' · '}
                      {s.score === null ? '—' : s.score.toFixed(1)}
                      {' · '}
                      {s.coverage.toFixed(1)}%
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </div>
      </div>

      <DownloadsCard />

      {items.length === 0 ? (
        <EmptyState
          icon={<ScanSearch className="size-8" />}
          title={t('reports.title')}
          description={bi(lang, 'Ejecuta una evaluación para generar informes.', 'Run an assessment to generate reports.')}
          action={<Button onClick={() => setView('overview')}>{t('common.scan')}</Button>}
        />
      ) : !selected ? null : (
        <>
          <SectionCard
            title={t('reports.executive')}
            description={`${selected.host.hostname} · ${selected.host.os} ${selected.host.osVersion}`}
            right={
              <div className="flex flex-wrap gap-2">
                <Button variant="outline" size="sm" className="min-h-11" onClick={() => download('json')} aria-label={t('reports.json')}>
                  <FileJson className="size-3.5" aria-hidden />
                  {t('reports.json')}
                </Button>
                <Button variant="outline" size="sm" className="min-h-11" onClick={() => download('csv')} aria-label={t('reports.csv')}>
                  <FileSpreadsheet className="size-3.5" aria-hidden />
                  {t('reports.csv')}
                </Button>
                <Button variant="outline" size="sm" className="min-h-11" onClick={printReport} disabled={pdfBusy} aria-label={t('reports.pdf')}>
                  {pdfBusy ? (
                    <Loader2 className="size-3.5 animate-spin" aria-hidden />
                  ) : (
                    <FileText className="size-3.5" aria-hidden />
                  )}
                  {t('reports.pdf')}
                </Button>
              </div>
            }
          >
            <div className="flex flex-col gap-6 sm:flex-row sm:items-start">
              <div className="shrink-0 self-center">
                <ScoreRing value={selected.score} label={t('common.score')} />
              </div>
              <div className="min-w-0 flex-1 space-y-4">
                <div>
                  <p className="mb-1.5 text-xs t82-caps text-muted-foreground">{t('common.coverage')}</p>
                  <CoverageBar value={selected.coverage} />
                </div>
                <div className="flex flex-wrap gap-2">
                  {STATUS_ORDER.map((st) => (
                    <span key={st} className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1">
                      <StatusBadge status={st as StatusT} lang={lang} />
                      <span className="font-mono text-xs font-bold tabular-nums">{countOf(selected.counts, st)}</span>
                    </span>
                  ))}
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                  {SEV_TONES.map(({ key, tone }) => (
                    <StatCard
                      key={key}
                      label={lang === 'es' ? SEV_LABEL[key].es : SEV_LABEL[key].en}
                      value={countOf(selected.severityCounts, key)}
                      tone={tone}
                    />
                  ))}
                </div>
                <div>
                  <p className="mb-1 text-[10px] font-semibold t82-caps text-muted-foreground">{t('assessment.formula')}</p>
                  <pre className="overflow-x-auto rounded-md bg-muted p-2 font-mono text-[10px] leading-relaxed">
                    {detail.data?.formula ?? '…'}
                  </pre>
                </div>
              </div>
            </div>
          </SectionCard>

          <SectionCard title={t('common.limitations')}>
            <p className="text-sm leading-relaxed text-muted-foreground">{t('reports.hint')}</p>
            <p className={cn('mt-2 text-sm font-medium leading-relaxed text-foreground')}>
              {bi(
                lang,
                'Auditoría de solo lectura. Controles con privilegios elevados requeridos se reportan NO_EVALUADO.',
                'Read-only audit. Controls requiring elevated privileges are reported NOT_ASSESSED.',
              )}
            </p>
          </SectionCard>
        </>
      )}
    </div>
  )
}

export default ReportsView
