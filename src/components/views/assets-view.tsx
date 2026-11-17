'use client'
// DIVISION T82 — Module 2/13: Asset Inventory. Read-only system snapshot.
import {
  Boxes, Cpu, HardDrive, ListChecks, MonitorSmartphone, Package, ScanSearch,
  Server, ShieldAlert, Users,
} from 'lucide-react'
import { useOverview, useInventory } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

function KV({ label, value, mono = true }: { label: React.ReactNode; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 py-1.5 last:border-b-0">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className={`min-w-0 truncate text-right text-xs ${mono ? 'font-mono' : ''}`} title={typeof value === 'string' ? value : undefined}>
        {value}
      </span>
    </div>
  )
}

function Chip({ tone = 'muted', children }: { tone?: 'good' | 'warn' | 'bad' | 'muted' | 'info'; children: React.ReactNode }) {
  const cls =
    tone === 'good' ? 'bg-t82-green/12 text-t82-green border-t82-green/30' :
    tone === 'warn' ? 'bg-t82-warning/12 text-t82-warning border-t82-warning/30' :
    tone === 'bad' ? 'bg-t82-critical/12 text-t82-critical border-t82-critical/30' :
    tone === 'info' ? 'bg-t82-cyan/12 text-t82-cyan border-t82-cyan/30' :
    'bg-muted text-muted-foreground border-border'
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-semibold t82-caps ${cls}`}>
      {children}
    </span>
  )
}

function sysctlTone(name: string, v: number | null): 'good' | 'warn' | 'muted' {
  if (v === null) return 'muted'
  if (name === 'randomize_va_space') return v === 2 ? 'good' : 'warn'
  if (name === 'suid_dumpable') return v === 0 ? 'good' : 'warn'
  return v >= 1 ? 'good' : 'warn'
}

export function AssetsView() {
  const { t, lang } = useI18n()
  const setView = useAppStore((s) => s.setView)
  const ov = useOverview()
  const lastScanId = ov.data?.lastScan?.id ?? null
  const inv = useInventory(lastScanId)

  if (ov.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-64" />
        <div className="grid gap-4 md:grid-cols-2">
          <Skeleton className="h-52" />
          <Skeleton className="h-52" />
        </div>
        <LoadingRows rows={3} />
      </div>
    )
  }

  if (ov.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<Boxes className="size-8" />}
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
          title={t('assets.title')}
          description={bi(lang, 'Ejecuta una evaluación para construir el inventario del sistema.', 'Run an assessment to build the system inventory.')}
          action={<Button onClick={() => setView('overview')}>{t('common.scan')}</Button>}
        />
      </div>
    )
  }

  if (inv.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-64" />
        <LoadingRows rows={6} />
      </div>
    )
  }

  if (inv.isError || !inv.data) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<Boxes className="size-8" />}
          title={t('common.error')}
          description={inv.error?.message}
          action={<Button onClick={() => void inv.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  const d = inv.data
  const locale = lang === 'es' ? 'es-ES' : 'en-US'
  const systemdRunning = d.hardening.systemdRunning

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-bold t82-caps tracking-wide">{t('assets.title')}</h1>
        <p className="font-mono text-[11px] text-muted-foreground">
          {bi(lang, 'Recogido', 'Collected')}: {new Date(d.collectedAt).toLocaleString(locale)}
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* OS */}
        <SectionCard title={t('assets.os')} right={<Server className="size-4 text-muted-foreground" aria-hidden />}>
          <KV label={bi(lang, 'Sistema', 'System')} value={d.os?.prettyName ?? t('common.noData')} mono={false} />
          <KV label="ID / VERSION_ID" value={d.os ? `${d.os.id} · ${d.os.versionId}` : '—'} />
          <KV label={bi(lang, 'Kernel', 'Kernel')} value={d.kernel ?? '—'} />
          <KV label={bi(lang, 'Arquitectura', 'Architecture')} value={d.platform.arch} />
          <KV label={bi(lang, 'Nombre de host', 'Hostname')} value={d.platform.hostname} />
          <div className="flex items-center justify-between gap-3 pt-2">
            <span className="text-xs text-muted-foreground">{bi(lang, 'Usuario', 'User')}</span>
            <span className="flex items-center gap-2">
              <span className="font-mono text-xs">{d.platform.user}</span>
              <Chip tone={d.platform.isRoot ? 'warn' : 'muted'}>
                {d.platform.isRoot ? 'root' : bi(lang, 'sin root', 'non-root')}
              </Chip>
            </span>
          </div>
        </SectionCard>

        {/* Hardware */}
        <SectionCard title={t('assets.hardware')} right={<Cpu className="size-4 text-muted-foreground" aria-hidden />}>
          <KV label="CPU" value={d.hardware.cpuModel ?? '—'} mono={false} />
          <KV label={bi(lang, 'Núcleos', 'Cores')} value={d.hardware.cpuCores ?? '—'} />
          <KV label={bi(lang, 'Memoria total', 'Total memory')} value={d.hardware.memoryTotalMB != null ? `${d.hardware.memoryTotalMB} MB` : '—'} />
          <KV label={t('assets.uptime')} value={d.hardware.uptimeHours != null ? `${d.hardware.uptimeHours} h` : '—'} />
        </SectionCard>

        {/* Packages */}
        <SectionCard title={t('assets.packages')} right={<Package className="size-4 text-muted-foreground" aria-hidden />}>
          <p className="font-mono text-3xl font-bold tabular-nums text-t82-cyan">{d.packages.count ?? '—'}</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {d.packages.count != null
              ? bi(lang, 'paquetes instalados (dpkg)', 'installed packages (dpkg)')
              : bi(lang, 'contador no disponible', 'count not available')}
          </p>
        </SectionCard>

        {/* Updates */}
        <SectionCard title={bi(lang, 'Actualizaciones', 'Updates')} right={<ListChecks className="size-4 text-muted-foreground" aria-hidden />}>
          <KV label={bi(lang, 'Actualizaciones pendientes', 'Pending updates')} value={d.updates.pendingUpdates ?? '—'} />
          <KV label={bi(lang, 'Actualizaciones de seguridad', 'Security updates')} value={d.updates.pendingSecurityUpdates ?? '—'} />
          <div className="flex flex-wrap gap-2 pt-2">
            {d.updates.aptCacheFresh === false && <Chip tone="warn">{bi(lang, 'caché APT obsoleta', 'APT cache stale')}</Chip>}
            {d.updates.aptCacheFresh === true && <Chip tone="good">{bi(lang, 'caché APT al día', 'APT cache fresh')}</Chip>}
            {d.updates.aptCacheFresh == null && <Chip>{bi(lang, 'caché APT desconocida', 'APT cache unknown')}</Chip>}
            {d.updates.unattendedUpgradesEnabled === true && <Chip tone="good">unattended-upgrades ON</Chip>}
            {d.updates.unattendedUpgradesEnabled === false && (
              <Chip tone={d.updates.unattendedInstalled ? 'warn' : 'muted'}>
                {d.updates.unattendedInstalled
                  ? 'unattended-upgrades OFF'
                  : bi(lang, 'unattended-upgrades no instalado', 'unattended-upgrades not installed')}
              </Chip>
            )}
          </div>
        </SectionCard>

        {/* Users */}
        <SectionCard className="md:col-span-2" title={t('assets.users')} right={<Users className="size-4 text-muted-foreground" aria-hidden />}>
          {d.users.human.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <div className="max-h-40 overflow-y-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="t82-caps">{bi(lang, 'Usuario', 'User')}</TableHead>
                    <TableHead className="t82-caps">UID</TableHead>
                    <TableHead className="t82-caps">Shell</TableHead>
                    <TableHead className="t82-caps">Home</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.users.human.map((u) => (
                    <TableRow key={`${u.name}-${u.uid}`}>
                      <TableCell className="font-mono text-xs">{u.name}</TableCell>
                      <TableCell className="font-mono text-xs">{u.uid}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{u.shell}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{u.home}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Chip>{bi(lang, 'Cuentas de sistema', 'System accounts')}: <span className="font-mono">{d.users.systemCount}</span></Chip>
            {d.users.rootOnlyUid0.length > 1 && (
              <Chip tone="warn">
                <ShieldAlert className="size-3" aria-hidden />
                {bi(lang, 'Múltiples cuentas con UID 0', 'Multiple UID 0 accounts')}:
                <span className="font-mono">{d.users.rootOnlyUid0.join(', ')}</span>
              </Chip>
            )}
          </div>
        </SectionCard>

        {/* Interfaces */}
        <SectionCard title={t('assets.interfaces')} right={<MonitorSmartphone className="size-4 text-muted-foreground" aria-hidden />}>
          {!d.network.interfaces || d.network.interfaces.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <ul className="space-y-1.5">
              {d.network.interfaces.map((i) => (
                <li key={`${i.name}-${i.address}`} className="flex items-center justify-between gap-3 rounded-md border px-3 py-1.5">
                  <span className="min-w-0 truncate font-mono text-xs">{i.address}</span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-[11px] text-muted-foreground">{i.name}</span>
                    <Chip tone={i.internal ? 'muted' : 'info'}>{i.internal ? 'interna' : 'externa'}</Chip>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        {/* Listeners */}
        <SectionCard title={bi(lang, 'Puertos en escucha', 'Listening ports')} right={<HardDrive className="size-4 text-muted-foreground" aria-hidden />}>
          <p className="font-mono text-3xl font-bold tabular-nums text-t82-cyan">
            {d.network.listeners ? d.network.listeners.length : '—'}
          </p>
          {!d.network.listeners || d.network.listeners.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto pr-1">
              {d.network.listeners.map((l, idx) => (
                <li key={`${l.proto}-${l.address}-${l.port}-${idx}`} className="flex items-center justify-between gap-2 text-[11px]">
                  <span className="font-mono text-muted-foreground">{l.proto}</span>
                  <span className="min-w-0 truncate font-mono">{l.address}:{l.port}</span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        {/* Services */}
        <SectionCard className="md:col-span-2" title={t('assets.services')} right={<Server className="size-4 text-muted-foreground" aria-hidden />}>
          {systemdRunning === true ? (
            d.hardening.runningServices && d.hardening.runningServices.length > 0 ? (
              <ul className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
                {d.hardening.runningServices.map((s) => (
                  <li key={s} className="rounded-md border bg-muted/40 px-2 py-1 font-mono text-[11px]">{s}</li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
            )
          ) : (
            <p className="text-sm text-muted-foreground">
              {systemdRunning === false
                ? 'systemd no disponible en este entorno (contenedor).'
                : bi(lang, 'Estado de systemd desconocido en este entorno.', 'systemd state unknown in this environment.')}
            </p>
          )}
          {d.hardening.initComm && (
            <p className="mt-2 text-xs text-muted-foreground">
              init: <span className="font-mono text-foreground">{d.hardening.initComm}</span>
            </p>
          )}
        </SectionCard>

        {/* Kernel hardening */}
        <SectionCard title={bi(lang, 'Endurecimiento del kernel', 'Kernel hardening')}>
          <ul className="space-y-2">
            {Object.entries(d.hardening.sysctls).map(([name, value]) => (
              <li key={name} className="flex items-center justify-between gap-3">
                <span className="min-w-0 truncate font-mono text-xs">{name}</span>
                <Chip tone={sysctlTone(name, value)}>{value === null ? '—' : String(value)}</Chip>
              </li>
            ))}
          </ul>
        </SectionCard>

        {/* AppArmor / LSM */}
        <SectionCard title={bi(lang, 'Módulo LSM / AppArmor', 'LSM / AppArmor')}>
          <div className="flex flex-wrap gap-2">
            {d.hardening.apparmorLsmActive === true && <Chip tone="good">AppArmor {bi(lang, 'activo', 'active')}</Chip>}
            {d.hardening.apparmorLsmActive === false && <Chip>AppArmor {bi(lang, 'inactivo', 'inactive')}</Chip>}
            {d.hardening.apparmorLsmActive == null && <Chip>AppArmor {bi(lang, 'no verificable', 'not verifiable')}</Chip>}
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            {bi(
              lang,
              'Estado del módulo de seguridad de Linux (LSM) reportado por el kernel.',
              'Linux Security Module (LSM) state reported by the kernel.',
            )}
          </p>
        </SectionCard>

        {/* File permissions */}
        <SectionCard className="md:col-span-2" title={bi(lang, 'Permisos de archivos sensibles', 'Sensitive file permissions')}>
          {d.hardening.filePerms.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <div className="max-h-48 overflow-y-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="t82-caps">Path</TableHead>
                    <TableHead className="t82-caps">Mode</TableHead>
                    <TableHead className="t82-caps">{t('common.error')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.hardening.filePerms.map((f) => (
                    <TableRow key={f.path}>
                      <TableCell className="font-mono text-xs">{f.path}</TableCell>
                      <TableCell className="font-mono text-xs">{f.mode}</TableCell>
                      <TableCell className="text-xs text-t82-critical">{f.error ?? '—'}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </SectionCard>

        {/* Evidence notes */}
        <SectionCard className="md:col-span-2" title={t('assets.notes')}>
          {d.evidenceNotes.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('common.noData')}</p>
          ) : (
            <ul className="space-y-1.5">
              {d.evidenceNotes.map((n, i) => (
                <li key={i} className="flex gap-2 text-xs text-muted-foreground">
                  <span className="font-mono text-t82-cyan">{String(i + 1).padStart(2, '0')}</span>
                  <span className="min-w-0">{n}</span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
      </div>
    </div>
  )
}

export default AssetsView
