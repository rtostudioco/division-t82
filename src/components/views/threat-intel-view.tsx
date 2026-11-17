'use client'
// DIVISION T82 — Module 8/13: Threat Intelligence. Consent-gated by design; no fabricated data.
import { ExternalLink, Fingerprint, Globe, Radar, ShieldOff } from 'lucide-react'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState } from '@/components/t82/shared'
import { Badge } from '@/components/ui/badge'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

const IOC_FORMATS: { label: string; example: string; desc: { es: string; en: string } }[] = [
  {
    label: 'HASH',
    example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    desc: { es: 'SHA-256 / SHA-1 / MD5 de un archivo o binario.', en: 'SHA-256 / SHA-1 / MD5 of a file or binary.' },
  },
  {
    label: 'IP',
    example: '203.0.113.9 · 2001:db8::1',
    desc: { es: 'Dirección IPv4 o IPv6 (documentación RFC 5737/3849).', en: 'IPv4 or IPv6 address (RFC 5737/3849 documentation).' },
  },
  {
    label: 'DOMAIN',
    example: 'malicioso.ejemplo.com',
    desc: { es: 'Nombre de dominio o subdominio sospechoso.', en: 'Suspicious domain or subdomain name.' },
  },
  {
    label: 'URL',
    example: 'https://malicioso.ejemplo.com/payload',
    desc: { es: 'URL completa de entrega o C2.', en: 'Full delivery or C2 URL.' },
  },
]

export function ThreatIntelView() {
  const { t, lang } = useI18n()
  const langKey = (lang === 'es' ? 'es' : 'en') as Lang

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-start justify-between gap-3">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('threatintel.title')}</h1>
        <Badge variant="outline" className="font-mono text-[10px] t82-caps border-border bg-muted text-muted-foreground">
          CONSENT-GATED — DISABLED BY DESIGN
        </Badge>
      </div>

      <SectionCard title={t('threatintel.title')} right={<Radar className="size-4 text-muted-foreground" aria-hidden />}>
        <EmptyState icon={<Radar className="size-8" />} title={t('threatintel.empty')} />
      </SectionCard>

      <div className="grid gap-4 lg:grid-cols-2">
        <SectionCard
          title={bi(langKey, 'Validación de formato IOC', 'IOC format validation')}
          right={<Fingerprint className="size-4 text-muted-foreground" aria-hidden />}
        >
          <ul className="space-y-2">
            {IOC_FORMATS.map((f) => (
              <li key={f.label} className="rounded-md border px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] font-bold t82-caps text-t82-cyan">{f.label}</span>
                  <span className="min-w-0 truncate font-mono text-[11px] text-muted-foreground" title={f.example}>{f.example}</span>
                </div>
                <p className="mt-1 text-[11px] text-muted-foreground">{f.desc[langKey]}</p>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
            {bi(
              langKey,
              'Todo IOC se valida por formato antes de cualquier consulta externa; los formatos inválidos se rechazan localmente.',
              'Every IOC is format-validated before any external lookup; invalid formats are rejected locally.',
            )}
          </p>
        </SectionCard>

        <SectionCard
          title={bi(langKey, 'Consentimiento y fuentes oficiales', 'Consent and official sources')}
          right={<ShieldOff className="size-4 text-muted-foreground" aria-hidden />}
        >
          <p className="text-xs leading-relaxed text-muted-foreground">
            {bi(
              langKey,
              'La consulta de IOCs requiere consentimiento explícito del operador y conectividad externa estable. Permanece deshabilitada por diseño: la app no realiza llamadas salientes sin autorización y nunca presenta datos de amenazas inventados.',
              'IOC lookups require explicit operator consent and stable external connectivity. It remains disabled by design: the app makes no outbound calls without authorization and never presents fabricated threat data.',
            )}
          </p>
          <ul className="mt-4 space-y-2">
            <li>
              <a
                href="https://attack.mitre.org/"
                target="_blank"
                rel="noreferrer"
                className="flex min-h-[44px] items-center justify-between gap-2 rounded-md border px-3 text-sm text-t82-cyan transition-colors hover:bg-accent"
              >
                MITRE ATT&CK
                <ExternalLink className="size-3.5 shrink-0" aria-hidden />
              </a>
            </li>
            <li>
              <a
                href="https://www.cisa.gov/"
                target="_blank"
                rel="noreferrer"
                className="flex min-h-[44px] items-center justify-between gap-2 rounded-md border px-3 text-sm text-t82-cyan transition-colors hover:bg-accent"
              >
                CISA
                <ExternalLink className="size-3.5 shrink-0" aria-hidden />
              </a>
            </li>
          </ul>
          <p className="mt-4 flex items-center gap-2 text-[11px] text-muted-foreground">
            <Globe className="size-3 shrink-0" aria-hidden />
            {bi(langKey, 'Sin telemetría · sin llamadas externas por defecto · datos 100% locales.', 'No telemetry · no outbound calls by default · 100% local data.')}
          </p>
        </SectionCard>
      </div>
    </div>
  )
}

export default ThreatIntelView
