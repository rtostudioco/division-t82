'use client'
// DIVISION T82 — Module 5/13: Network Exposure. Firewall, listeners, interfaces.
import { Globe, Network, RadioTower, ScanSearch, ShieldCheck } from 'lucide-react'
import { useNetwork, type NetworkInfo } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

function Chip({ tone = 'muted', className, children }: { tone?: 'good' | 'warn' | 'bad' | 'muted' | 'info'; className?: string; children: React.ReactNode }) {
  const cls =
    tone === 'good' ? 'bg-t82-green/12 text-t82-green border-t82-green/30' :
    tone === 'warn' ? 'bg-t82-warning/12 text-t82-warning border-t82-warning/30' :
    tone === 'bad' ? 'bg-t82-critical/12 text-t82-critical border-t82-critical/30' :
    tone === 'info' ? 'bg-t82-cyan/12 text-t82-cyan border-t82-cyan/30' :
    'bg-muted text-muted-foreground border-border'
  return (
    <span className={cn(`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-semibold t82-caps ${cls}`, className)}>
      {children}
    </span>
  )
}

function isExternal(address: string): boolean {
  return address === '0.0.0.0' || address === '::' || address === '*' || address === '[::]'
}

function FirewallCard({ lang, fw }: { lang: Lang; fw: NetworkInfo['firewall'] }) {
  return (
    <SectionCard title={bi(lang, 'Firewall del host', 'Host firewall')} right={<ShieldCheck className="size-4 text-muted-foreground" aria-hidden />}>
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone={fw.detected ? 'info' : 'muted'}>
          {fw.detected && fw.tool ? fw.tool : bi(lang, 'no detectado', 'not detected')}
        </Chip>
        {fw.active === true && <Chip tone="good">{bi(lang, 'activo', 'active')}</Chip>}
        {fw.active === false && <Chip tone="bad">{bi(lang, 'no activo', 'not active')}</Chip>}
        {fw.active === null && fw.detected && <Chip>{bi(lang, 'no verificable (requiere root)', 'not verifiable (requires root)')}</Chip>}
        {fw.active === null && !fw.detected && <Chip>{bi(lang, 'sin herramienta detectada', 'no tool detected')}</Chip>}
      </div>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
        {fw.note ??
          bi(
            lang,
            'El estado del firewall se verifica de forma read-only. Un estado null significa que no se pudo confirmar sin privilegios.',
            'Firewall state is verified read-only. A null state means it could not be confirmed without privileges.',
          )}
      </p>
    </SectionCard>
  )
}

function IpForwardCard({ lang, ipForward }: { lang: Lang; ipForward: number | null }) {
  return (
    <SectionCard title={bi(lang, 'Reenvío IPv4', 'IPv4 forwarding')} right={<Globe className="size-4 text-muted-foreground" aria-hidden />}>
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone="good" className={ipForward === 0 ? '' : 'hidden'}>
          {bi(lang, 'desactivado', 'disabled')}
        </Chip>
        <Chip tone="warn" className={ipForward === 1 ? '' : 'hidden'}>
          {bi(lang, 'activado', 'enabled')}
        </Chip>
        <Chip className={ipForward == null ? '' : 'hidden'}>
          {bi(lang, 'desconocido', 'unknown')}
        </Chip>
        <span className="font-mono text-xs text-muted-foreground">net.ipv4.ip_forward = {ipForward ?? '—'}</span>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        {ipForward === 1
          ? bi(lang, 'El host reenvía paquetes entre interfaces — revisa si debe actuar como router.', 'Host forwards packets between interfaces — verify it should act as a router.')
          : ipForward === 0
            ? bi(lang, 'Reenvío de paquetes deshabilitado (postura de host estándar).', 'Packet forwarding disabled (standard host posture).')
            : bi(lang, 'No se pudo leer el sysctl en este entorno.', 'The sysctl could not be read in this environment.')}
      </p>
    </SectionCard>
  )
}

export function NetworkView() {
  const { t, lang } = useI18n()
  const setView = useAppStore((s) => s.setView)
  const net = useNetwork()

  if (net.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-64" />
        <div className="grid gap-4 md:grid-cols-2">
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
        <LoadingRows rows={3} />
      </div>
    )
  }

  if (net.isError || !net.data || !net.data.fromScanId) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<ScanSearch className="size-8" />}
          title={t('network.title')}
          description={
            net.isError
              ? net.error?.message
              : bi(lang, 'Ejecuta una evaluación para analizar la superficie de red del host.', 'Run an assessment to analyze the host network surface.')
          }
          action={
            <Button onClick={() => (net.isError ? void net.refetch() : setView('overview'))}>
              {net.isError ? t('common.retry') : t('common.scan')}
            </Button>
          }
        />
      </div>
    )
  }

  const d = net.data
  const listeners = d.listeners ?? []
  const interfaces = d.interfaces ?? []
  const externalCount = listeners.filter((l) => isExternal(l.address)).length
  const localCount = listeners.length - externalCount

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('network.title')}</h1>
        <p className="font-mono text-[11px] text-muted-foreground">scan: {d.fromScanId}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <FirewallCard lang={lang} fw={d.firewall} />
        <IpForwardCard lang={lang} ipForward={d.ipForward} />
      </div>

      <SectionCard title={t('assets.interfaces')} right={<Network className="size-4 text-muted-foreground" aria-hidden />}>
        {interfaces.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
        ) : (
          <div className="max-h-64 overflow-y-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="t82-caps">{bi(lang, 'Interfaz', 'Interface')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Dirección', 'Address')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Ámbito', 'Scope')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {interfaces.map((i, idx) => (
                  <TableRow key={`${i.name}-${i.address}-${idx}`}>
                    <TableCell className="font-mono text-xs">{i.name}</TableCell>
                    <TableCell className="font-mono text-xs">{i.address}</TableCell>
                    <TableCell>
                      <Chip tone={i.internal ? 'muted' : 'info'}>{i.internal ? bi(lang, 'interna', 'internal') : bi(lang, 'externa', 'external')}</Chip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      <SectionCard
        title={t('network.listeners')}
        description={bi(
          lang,
          'Filas marcadas escuchan en todas las interfaces (0.0.0.0/::/*) — revisa si la exposición es intencional.',
          'Highlighted rows listen on all interfaces (0.0.0.0/::/*) — verify the exposure is intentional.',
        )}
        right={<RadioTower className="size-4 text-muted-foreground" aria-hidden />}
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Chip tone="warn">{t('network.external')}: <span className="font-mono">{externalCount}</span></Chip>
          <Chip tone="info">{t('network.localOnly')}: <span className="font-mono">{localCount}</span></Chip>
        </div>
        {listeners.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
        ) : (
          <div className="max-h-96 overflow-y-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="t82-caps">Proto</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Dirección:Puerto', 'Address:Port')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Exposición', 'Exposure')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listeners.map((l, idx) => {
                  const ext = isExternal(l.address)
                  return (
                    <TableRow key={`${l.proto}-${l.address}-${l.port}-${idx}`} className={cn(ext && 'border-l-2 border-l-t82-warning bg-t82-warning/5')}>
                      <TableCell className="font-mono text-xs t82-caps">{l.proto}</TableCell>
                      <TableCell className="font-mono text-xs">{l.address}:{l.port}</TableCell>
                      <TableCell>
                        <Chip tone={ext ? 'warn' : 'info'}>{ext ? 'EXTERNAL' : 'LOCAL'}</Chip>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>
    </div>
  )
}

export default NetworkView
