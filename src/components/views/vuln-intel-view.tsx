'use client'
// DIVISION T82 — Module 6/13: Vulnerability Intelligence (ACTIVE).
// OSV exact-version matching against the latest scan inventory + NVD recent CVEs
// (with CISA KEV flags). Honest per-source status; no fabricated matches.
import { useMemo, useState } from 'react'
import { Bug, CalendarClock, Database, Download, ExternalLink, Info, Loader2, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState, SeverityBadge } from '@/components/t82/shared'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { useToast } from '@/hooks/use-toast'
import {
  useVulnIntel, useIngestVulns, useVulnSchedule, useSetVulnSchedule,
  type VulnMatchItem, type VulnRecordItem,
} from '@/hooks/t82-queries'

type Lang = 'es' | 'en'
const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const SOURCES: { name: string; url: string; desc: { es: string; en: string } }[] = [
  {
    name: 'OSV.dev (Google)',
    url: 'https://osv.dev/',
    desc: { es: 'Coincidencia exacta por versión contra el inventario de paquetes.', en: 'Exact version matching against the package inventory.' },
  },
  {
    name: 'NVD — NIST',
    url: 'https://nvd.nist.gov/',
    desc: { es: 'CVEs modificados recientemente (ventana de 3 días).', en: 'Recently modified CVEs (3-day window).' },
  },
  {
    name: 'CISA KEV',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    desc: { es: 'Barrido completo del catálogo KEV vía NVD (filtro hasKev), independiente de la ventana de CVEs recientes.', en: 'Full KEV catalog sweep via NVD (hasKev filter), independent of the recent-CVE window.' },
  },
  {
    name: 'CVE Program',
    url: 'https://www.cve.org/',
    desc: { es: 'Registro oficial de identificadores CVE.', en: 'Official registry of CVE identifiers.' },
  },
]

function sevRank(s: string): number {
  const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 }
  return order[s] ?? 4
}

function IngestStatusLine({ label, st, lang }: { label: string; st: { ok: boolean; skipped?: string; matches?: number; recordsUpserted?: number; packagesQueried?: number; matchedPackages?: number; kevMarked?: number; error?: string } | undefined; lang: Lang }) {
  if (!st) {
    return (
      <li className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-xs">
        <span className="font-medium">{label}</span>
        <span className="text-muted-foreground">{bi(lang, 'sin datos', 'no data')}</span>
      </li>
    )
  }
  const detail = st.ok
    ? st.skipped
      ? st.skipped
      : [
          st.packagesQueried != null ? `${st.packagesQueried} pkg` : null,
          st.matchedPackages != null ? `${st.matchedPackages} ${bi(lang, 'con avisos', 'with advisories')}` : null,
          st.matches != null ? `${st.matches} matches` : null,
          st.recordsUpserted != null ? `${st.recordsUpserted} CVEs` : null,
          st.kevMarked != null && st.kevMarked > 0 ? `${st.kevMarked} KEV` : null,
        ]
          .filter(Boolean)
          .join(' · ')
    : `${bi(lang, 'fallo', 'failed')}: ${st.error ?? 'unknown'}`
  return (
    <li className="flex items-start justify-between gap-3 rounded-md border px-3 py-2 text-xs">
      <div className="min-w-0">
        <p className="font-semibold">{label}</p>
        <p className="text-[11px] leading-relaxed text-muted-foreground">{detail}</p>
      </div>
      <span className={`shrink-0 font-mono text-[10px] t82-caps ${st.ok ? 'text-t82-green' : 'text-destructive'}`}>
        {st.ok ? (st.skipped ? 'SKIPPED' : 'OK') : 'ERROR'}
      </span>
    </li>
  )
}

function MatchRow({ m }: { m: VulnMatchItem }) {
  return (
    <li className="flex items-start gap-3 rounded-md border border-l-2 border-l-t82-warning px-3 py-2">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${m.cveId}`}
            target="_blank"
            rel="noreferrer"
            className="font-mono text-xs font-bold text-t82-cyan hover:underline"
          >
            {m.cveId}
            <ExternalLink className="ml-1 inline size-3" aria-hidden />
          </a>
          {m.kev ? (
            <Badge variant="destructive" className="t82-caps text-[10px]">KEV</Badge>
          ) : null}
          {m.severity && m.severity !== 'UNKNOWN' ? (
            <SeverityBadge severity={m.severity as never} />
          ) : null}
          {m.cvssScore != null ? (
            <span className="font-mono text-[10px] text-muted-foreground">CVSS {m.cvssScore.toFixed(1)}</span>
          ) : null}
        </div>
        <p className="line-clamp-2 text-xs text-muted-foreground">{m.title}</p>
        <p className="font-mono text-[10px] text-muted-foreground">
          {m.packageName} {m.packageVersion}
        </p>
      </div>
    </li>
  )
}

function RecordRow({ r, lang }: { r: VulnRecordItem; lang: Lang }) {
  return (
    <li className="flex items-start justify-between gap-3 rounded-md border px-3 py-2">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${r.cveId}`}
            target="_blank"
            rel="noreferrer"
            className="font-mono text-xs font-bold text-t82-cyan hover:underline"
          >
            {r.cveId}
            <ExternalLink className="ml-1 inline size-3" aria-hidden />
          </a>
          {r.kev ? (
            <Badge variant="destructive" className="t82-caps text-[10px]">KEV</Badge>
          ) : null}
          {r.cvssScore != null ? (
            <span className={`font-mono text-[10px] ${r.cvssScore >= 7 ? 'text-destructive' : 'text-muted-foreground'}`}>
              CVSS {r.cvssScore.toFixed(1)}
            </span>
          ) : null}
          <Badge variant="outline" className="font-mono text-[9px] t82-caps text-muted-foreground">
            {r.source}
          </Badge>
        </div>
        <p className="line-clamp-2 text-xs text-muted-foreground">{r.title}</p>
      </div>
      <span className="shrink-0 text-right text-[10px] text-muted-foreground" title={bi(lang, 'publicado', 'published')}>
        {r.publishedAt ? r.publishedAt.slice(0, 10) : '—'}
      </span>
    </li>
  )
}

export function VulnIntelView() {
  const { t, lang } = useI18n()
  const langKey = (lang === 'es' ? 'es' : 'en') as Lang
  const { toast } = useToast()
  const { data, isLoading } = useVulnIntel()
  const ingest = useIngestVulns()
  const schedule = useVulnSchedule()
  const setSchedule = useSetVulnSchedule()
  const [query, setQuery] = useState('')

  const filteredMatches = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = data?.matches ?? []
    if (!q) return list
    return list.filter(
      (m) =>
        m.cveId.toLowerCase().includes(q) ||
        m.packageName.toLowerCase().includes(q) ||
        m.title.toLowerCase().includes(q),
    )
  }, [data?.matches, query])

  const filteredRecords = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = data?.records ?? []
    if (!q) return list.slice(0, 120)
    return list
      .filter(
        (r) =>
          r.cveId.toLowerCase().includes(q) ||
          r.title.toLowerCase().includes(q),
      )
      .slice(0, 120)
  }, [data?.records, query])

  const hasCatalog = (data?.catalog.total ?? 0) > 0

  const startIngest = () => {
    ingest.mutate(undefined, {
      onSuccess: (res) => {
        const failed = !res?.osv?.ok || !res?.nvd?.ok || !res?.cisa?.ok
        toast({
          title: failed ? t('vulnintel.ingestError') : t('vulnintel.ingestDone'),
          description: failed ? `${res?.osv?.error ?? res?.osv?.skipped ?? 'ok'} | ${res?.nvd?.error ?? 'ok'} | ${res?.cisa?.error ?? 'ok'}` : undefined,
          variant: failed ? 'destructive' : 'default',
        })
      },
      onError: (e) => {
        toast({ title: t('vulnintel.ingestError'), description: String(e.message), variant: 'destructive' })
      },
    })
  }

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-start justify-between gap-3">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('vulnintel.title')}</h1>
        <Badge
          variant="outline"
          className={`font-mono text-[10px] t82-caps ${hasCatalog ? 'border-t82-green/40 text-t82-green' : 'border-border bg-muted text-muted-foreground'}`}
        >
          {hasCatalog ? 'ACTIVE — OSV + NVD + CISA KEV' : 'READY — RUN INGESTION'}
        </Badge>
      </div>

      {/* Ingestion control + status */}
      <SectionCard
        title={t('vulnintel.status')}
        description={bi(
          langKey,
          'La ingesta consulta OSV por cada paquete instalado (versión exacta), NVD por los CVEs modificados en los últimos 3 días y el catálogo completo CISA KEV vía el filtro hasKev de NVD.',
          'Ingestion queries OSV for every installed package (exact version), NVD for CVEs modified in the last 3 days, and the full CISA KEV catalog via NVD\'s hasKev filter.',
        )}
        right={
          <Button onClick={startIngest} disabled={ingest.isPending} size="sm" className="min-h-9">
            {ingest.isPending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <RefreshCw className="size-4" aria-hidden />
            )}
            <span className="ml-2 t82-caps text-[11px]">
              {ingest.isPending ? t('vulnintel.ingesting') : t('vulnintel.ingest')}
            </span>
          </Button>
        }
      >
        {isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : data?.lastIngest ? (
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground">
              {bi(langKey, 'Última ingesta:', 'Last ingestion:')}{' '}
              <span className="font-mono">{new Date(data.lastIngest.at).toLocaleString()}</span>
            </p>
            <ul className="space-y-2">
              <IngestStatusLine label={t('vulnintel.osvStatus')} st={data.lastIngest.osv} lang={langKey} />
              <IngestStatusLine label={t('vulnintel.nvdStatus')} st={data.lastIngest.nvd} lang={langKey} />
              <IngestStatusLine label={t('vulnintel.cisaStatus')} st={data.lastIngest.cisa} lang={langKey} />
            </ul>
          </div>
        ) : (
          <EmptyState
            icon={<Database className="size-8" />}
            title={t('vulnintel.never')}
            description={t('vulnintel.empty')}
          />
        )}
      </SectionCard>

      {/* Scheduled ingestion + CSV export */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title={t('vulnintel.schedule')}
          description={t('vulnintel.scheduleHint')}
          right={<CalendarClock className="size-4 text-muted-foreground" aria-hidden />}
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="text-sm font-medium">
                {schedule.data?.enabled ? (
                  <span className="text-t82-green">{t('vulnintel.scheduleOn')}</span>
                ) : (
                  <span className="text-muted-foreground">{t('vulnintel.scheduleOff')}</span>
                )}
              </p>
              {schedule.data?.lastIngestAt && (
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {bi(langKey, 'última:', 'last:')} {new Date(schedule.data.lastIngestAt).toLocaleString()}
                </p>
              )}
            </div>
            <Switch
              checked={schedule.data?.enabled ?? false}
              onCheckedChange={(v) => setSchedule.mutate(v)}
              disabled={schedule.isPending || setSchedule.isPending}
              aria-label={t('vulnintel.schedule')}
            />
          </div>
        </SectionCard>

        <SectionCard
          title={bi(langKey, 'Exportación', 'Export')}
          description={bi(
            langKey,
            'Descarga el detalle de coincidencias de la última evaluación o el catálogo local completo.',
            'Download the latest assessment matches or the full local catalog.',
          )}
          right={<Download className="size-4 text-muted-foreground" aria-hidden />}
        >
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              className="min-h-11"
              onClick={() => { window.location.href = '/api/vuln-intel/export?scope=matches' }}
              disabled={!data?.latestScan || data.matches.length === 0}
              aria-label={t('vulnintel.exportMatches')}
            >
              <Download className="size-3.5" aria-hidden />
              {t('vulnintel.exportMatches')}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="min-h-11"
              onClick={() => { window.location.href = '/api/vuln-intel/export?scope=catalog' }}
              disabled={!hasCatalog}
              aria-label={t('vulnintel.exportCatalog')}
            >
              <Download className="size-3.5" aria-hidden />
              {t('vulnintel.exportCatalog')}
            </Button>
          </div>
        </SectionCard>
      </div>

      {/* Catalog stats */}
      {hasCatalog ? (
        <div className="grid gap-4 sm:grid-cols-3">
          <SectionCard title={t('vulnintel.records')} right={<Database className="size-4 text-muted-foreground" aria-hidden />}>
            <p className="font-mono text-2xl font-bold">{data?.catalog.total}</p>
          </SectionCard>
          <SectionCard title={t('vulnintel.highOrAbove')} right={<ShieldAlert className="size-4 text-destructive" aria-hidden />}>
            <p className="font-mono text-2xl font-bold text-destructive">{data?.catalog.highOrAbove}</p>
          </SectionCard>
          <SectionCard title={t('vulnintel.kev')} right={<ShieldAlert className="size-4 text-destructive" aria-hidden />}>
            <p className="font-mono text-2xl font-bold">{data?.catalog.kev}</p>
          </SectionCard>
        </div>
      ) : null}

      {/* Host exposure — exact-version matches */}
      <SectionCard
        title={t('vulnintel.exposure')}
        description={
          data?.latestScan
            ? `${data.latestScan.hostname} · ${data.latestScan.os} · ${new Date(data.latestScan.startedAt).toLocaleString()}`
            : undefined
        }
        right={<ShieldCheck className="size-4 text-t82-green" aria-hidden />}
      >
        {isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : !data?.latestScan ? (
          <EmptyState icon={<Bug className="size-8" />} title={t('vulnintel.noScan')} />
        ) : data.matches.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="size-8 text-t82-green" />}
            title={t('vulnintel.noMatches')}
            description={t('vulnintel.advisoryNote')}
          />
        ) : (
          <div className="space-y-3">
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t('vulnintel.search')}
              className="max-w-md"
              aria-label={t('vulnintel.search')}
            />
            <p className="text-[11px] text-muted-foreground">
              <Info className="mr-1 inline size-3" aria-hidden />
              {t('vulnintel.advisoryNote')}
            </p>
            <ul className="max-h-96 space-y-2 overflow-y-auto pr-1">
              {filteredMatches.slice(0, 100).map((m) => (
                <MatchRow key={`${m.cveId}-${m.packageName}`} m={m} />
              ))}
            </ul>
            <p className="text-[11px] text-muted-foreground">
              {bi(langKey, 'mostrando', 'showing')} {Math.min(filteredMatches.length, 100)} / {data.matches.length}
            </p>
          </div>
        )}
      </SectionCard>

      {/* Catalog browser */}
      {hasCatalog ? (
        <SectionCard
          title={bi(langKey, 'Catálogo local (búsqueda)', 'Local catalog (search)')}
          right={<Download className="size-4 text-muted-foreground" aria-hidden />}
        >
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('vulnintel.search')}
            className="max-w-md"
            aria-label={t('vulnintel.search')}
          />
          <ul className="mt-3 max-h-96 space-y-2 overflow-y-auto pr-1">
            {filteredRecords.map((r) => (
              <RecordRow key={r.cveId} r={r} lang={langKey} />
            ))}
            {filteredRecords.length === 0 ? (
              <li className="py-6 text-center text-xs text-muted-foreground">{t('vulnintel.noMatches')}</li>
            ) : null}
          </ul>
        </SectionCard>
      ) : null}

      {/* Policy + sources (structure preserved from the honest module) */}
      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title={t('vulnintel.policy')}
          description={t('vulnintel.policyText')}
          right={<ShieldCheck className="size-4 text-t82-green" aria-hidden />}
        >
          <ul className="space-y-2 text-xs leading-relaxed text-muted-foreground">
            <li className="flex gap-2">
              <span className="font-mono font-bold text-t82-cyan">01</span>
              {bi(langKey, 'Coincidencia solo por versión exacta del paquete (nombre + versión vía OSV).', 'Matching only on exact package version (name + version via OSV).')}
            </li>
            <li className="flex gap-2">
              <span className="font-mono font-bold text-t82-cyan">02</span>
              {bi(langKey, 'Una coincidencia aproximada de nombre nunca se presenta como vulnerabilidad confirmada.', 'Approximate name matching is never presented as a confirmed vulnerability.')}
            </li>
            <li className="flex gap-2">
              <span className="font-mono font-bold text-t82-cyan">03</span>
              {bi(langKey, 'Toda vulnerabilidad reportada enlaza su identificador CVE y su referencia oficial (NVD).', 'Every reported vulnerability links its CVE identifier and its official reference (NVD).')}
            </li>
          </ul>
        </SectionCard>

        <SectionCard
          title={bi(langKey, 'Fuentes oficiales activas', 'Active official sources')}
          right={<Database className="size-4 text-muted-foreground" aria-hidden />}
        >
          <ul className="space-y-2">
            {SOURCES.map((s) => (
              <li key={s.name} className="flex items-start justify-between gap-3 rounded-md border px-3 py-2">
                <div className="min-w-0">
                  <p className="text-xs font-semibold">{s.name}</p>
                  <p className="truncate text-[11px] text-muted-foreground">{s.desc[langKey]}</p>
                </div>
                <a
                  href={s.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex size-9 shrink-0 items-center justify-center rounded-md text-t82-cyan hover:bg-accent"
                  aria-label={s.name}
                >
                  <ExternalLink className="size-3.5" aria-hidden />
                </a>
              </li>
            ))}
          </ul>
        </SectionCard>
      </div>
    </div>
  )
}

export default VulnIntelView
