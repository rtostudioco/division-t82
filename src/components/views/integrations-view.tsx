'use client'
// DIVISION T82 — Module 12/13: Integrations. Universal MCP is LIVE (local
// read-only server on :3030); the rest remain defined contracts (honest).
import { Blocks, BookOpenCheck, FileOutput, MonitorSmartphone } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { SectionCard } from '@/components/t82/shared'
import { Badge } from '@/components/ui/badge'
import { McpCard } from '@/components/t82/mcp-card'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const CARDS: {
  key: string
  icon: React.ComponentType<{ className?: string }>
  es: string
  en: string
}[] = [
  {
    key: 'Universal RAG',
    icon: BookOpenCheck,
    es: 'Indexación de los artículos del Centro de Conocimiento para recuperación aumentada (RAG). Contrato de ingesta y esquema de chunks definidos; sin conexión activa en este entorno.',
    en: 'Indexing of Knowledge Center articles for retrieval-augmented generation. Ingestion contract and chunk schema defined; no active connection in this environment.',
  },
  {
    key: 'Sentinel Desk',
    icon: MonitorSmartphone,
    es: 'Panel de operaciones para agregación multi-host, correlación y supervisión continua. Diseñado como puente de escritorio nativo (Tauri 2); requiere autorización explícita del operador.',
    en: 'Operations dashboard for multi-host aggregation, correlation and continuous monitoring. Designed as a native desktop bridge (Tauri 2); requires explicit operator authorization.',
  },
  {
    key: 'External audit tools',
    icon: FileOutput,
    es: 'Exportación de informes JSON/CSV y evidencia vc.evidence/v1 para herramientas de auditoría externas (CIS-CAT, OpenSCAP, SIEM). Formatos estables y versionados.',
    en: 'Export of JSON/CSV reports and vc.evidence/v1 evidence for external audit tools (CIS-CAT, OpenSCAP, SIEM). Stable, versioned formats.',
  },
]

export function IntegrationsView() {
  const { t, lang } = useI18n()
  const langKey = (lang === 'es' ? 'es' : 'en') as Lang

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-bold t82-caps tracking-wide">{t('integrations.title')}</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('integrations.hint')}</p>
        </div>
        <Blocks className="size-5 shrink-0 text-muted-foreground" aria-hidden />
      </div>

      <McpCard />

      <div className="grid gap-4 md:grid-cols-2">
        {CARDS.map((c) => (
          <SectionCard
            key={c.key}
            title={c.key}
            right={<c.icon className="size-4 text-muted-foreground" aria-hidden />}
          >
            <p className="text-sm leading-relaxed text-muted-foreground">{langKey === 'es' ? c.es : c.en}</p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="font-mono text-[10px] t82-caps border-border bg-muted text-muted-foreground">
                CONTRATO DEFINIDO — SIN CONEXIÓN ACTIVA
              </Badge>
            </div>
            <p className="mt-3 font-mono text-[10px] text-muted-foreground" title="docs/ARCHITECTURE_PROPOSAL.md">
              docs/ARCHITECTURE_PROPOSAL.md · §6
            </p>
          </SectionCard>
        ))}
      </div>

      <p className="text-xs leading-relaxed text-muted-foreground">
        {bi(
          langKey,
          'El MCP local es de solo lectura y de solo asesoría. Las demás integraciones no se activan sin autorización explícita; sus contratos son estables y versionados.',
          'The local MCP is read-only and advisory-only. Other integrations are not activated without explicit authorization; their contracts are stable and versioned.',
        )}
      </p>
    </div>
  )
}

export default IntegrationsView
