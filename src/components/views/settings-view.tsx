'use client'
// DIVISION T82 — Module 13/13: Settings. Appearance, engine status, internal security, local data.
import { Bot, Loader2, Moon, ShieldCheck, Sun, Trash2 } from 'lucide-react'
import { useTheme } from 'next-themes'
import { useEngineStatus, useResetData } from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

function KV({ label, value }: { label: React.ReactNode; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 py-1.5 last:border-b-0">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <span className="min-w-0 truncate text-right font-mono text-xs" title={typeof value === 'string' ? value : undefined}>
        {value}
      </span>
    </div>
  )
}

const SECURITY_ITEMS: { es: string; en: string }[] = [
  {
    es: 'Allowlist cerrada de comandos (ss, dpkg-query, apt-get -s, systemctl…) y rutas fijas (/etc/*, /proc/sys/*) — sin shell, sin interpolación de usuario.',
    en: 'Closed command allowlist (ss, dpkg-query, apt-get -s, systemctl…) and fixed paths (/etc/*, /proc/sys/*) — no shell, no user interpolation.',
  },
  {
    es: 'execFile con timeout (≤6 s) y límite de salida (256 KB).',
    en: 'execFile with timeout (≤6 s) and output limit (256 KB).',
  },
  {
    es: 'Sin endpoints administrativos; sin ejecución de comandos del usuario o de un LLM.',
    en: 'No administrative endpoints; no execution of user or LLM commands.',
  },
  {
    es: 'Evidencia redactada: usuarios listados sin hashes; nunca se leen ni almacenan secretos.',
    en: 'Redacted evidence: users listed without hashes; secrets are never read or stored.',
  },
  {
    es: 'Auditoría de operaciones en AuditHistory (scan.run, scan.reset, settings.update).',
    en: 'Operation audit in AuditHistory (scan.run, scan.reset, settings.update).',
  },
  {
    es: 'El frontend solo habla HTTP con /api/** — frontera única, sin acceso directo al sistema.',
    en: 'The frontend only speaks HTTP with /api/** — single boundary, no direct system access.',
  },
  {
    es: 'El Asistente T82 (IA interna) es solo consultivo: envía el resumen agregado de la última evaluación al modelo interno — nunca evidencia cruda, hashes ni secretos — y no ejecuta comandos.',
    en: 'The T82 Assistant (internal AI) is advisory-only: it sends the aggregated summary of the latest assessment to the internal model — never raw evidence, hashes or secrets — and executes no commands.',
  },
  {
    es: 'Sin telemetría — todos los datos permanecen en SQLite local.',
    en: 'No telemetry — all data stays in local SQLite.',
  },
]

export function SettingsView() {
  const { t, lang, setLang } = useI18n()
  const { toast } = useToast()
  const { theme, setTheme } = useTheme()
  const engine = useEngineStatus()
  const reset = useResetData()

  const doReset = () => {
    reset.mutate(undefined, {
      onSuccess: () => toast({ title: bi(lang, 'Datos locales borrados', 'Local data deleted') }),
      onError: (err) =>
        toast({ variant: 'destructive', title: t('common.error'), description: err.message }),
    })
  }

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold t82-caps tracking-wide">{t('settings.title')}</h1>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Appearance */}
        <SectionCard title={t('settings.themeMode')}>
          <div className="space-y-4">
            <div>
              <p className="mb-2 text-xs text-muted-foreground">{t('settings.themeMode')}</p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  className={cn('min-h-11 flex-1', theme === 'light' && 'border-ring bg-accent')}
                  onClick={() => setTheme('light')}
                  aria-pressed={theme === 'light'}
                >
                  <Sun className="size-4" aria-hidden />
                  {bi(lang, 'Claro', 'Light')}
                </Button>
                <Button
                  variant="outline"
                  className={cn('min-h-11 flex-1', theme === 'dark' && 'border-ring bg-accent')}
                  onClick={() => setTheme('dark')}
                  aria-pressed={theme === 'dark'}
                >
                  <Moon className="size-4" aria-hidden />
                  {bi(lang, 'Oscuro', 'Dark')}
                </Button>
              </div>
            </div>
            <div>
              <p className="mb-2 text-xs text-muted-foreground">{t('settings.language')}</p>
              <Select value={lang} onValueChange={(v) => setLang(v as 'es' | 'en')}>
                <SelectTrigger className="min-h-[44px] w-48" aria-label={t('settings.language')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="es">Español</SelectItem>
                  <SelectItem value="en">English</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </SectionCard>

        {/* Local data */}
        <SectionCard title={t('settings.data')} description={bi(lang, 'Los datos viven solo en este equipo (SQLite local).', 'Data lives only on this machine (local SQLite).')}>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" className="min-h-11" disabled={reset.isPending}>
                {reset.isPending ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Trash2 className="size-4" aria-hidden />}
                {t('settings.reset')}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>{t('settings.reset')}</AlertDialogTitle>
                <AlertDialogDescription>{t('settings.resetConfirm')}</AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>{t('common.close')}</AlertDialogCancel>
                <AlertDialogAction onClick={doReset}>{t('common.close') === 'Cerrar' ? 'Confirmar' : 'Confirm'}</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </SectionCard>

        {/* Engine + adapters */}
        <SectionCard className="lg:col-span-2" title={t('settings.engine')}>
          {engine.isPending ? (
            <LoadingRows rows={4} />
          ) : engine.isError || !engine.data ? (
            <EmptyState
              icon={<ShieldCheck className="size-8" />}
              title={t('common.error')}
              description={engine.error?.message}
              action={<Button onClick={() => void engine.refetch()}>{t('common.retry')}</Button>}
            />
          ) : (
            <div className="grid gap-6 md:grid-cols-2">
              <div>
                <KV label={bi(lang, 'Plataforma', 'Platform')} value={engine.data.platform} />
                <KV label="OS" value={`${engine.data.os} ${engine.data.osVersion}`} />
                <KV label={bi(lang, 'Kernel', 'Kernel')} value={engine.data.kernel} />
                <KV label={bi(lang, 'Usuario', 'User')} value={`${engine.data.user}${engine.data.isRoot ? ' (root)' : ''}`} />
                <KV label="engineVersion" value={engine.data.engineVersion} />
                <KV label={bi(lang, 'Reglas totales', 'Total rules')} value={engine.data.rulesTotal} />
                <KV label={bi(lang, 'Reglas implementadas (Linux)', 'Implemented rules (Linux)')} value={engine.data.rulesImplementedLinux} />
              </div>
              <div>
                <p className="mb-2 text-[10px] font-semibold t82-caps text-muted-foreground">{bi(lang, 'Adaptadores', 'Adapters')}</p>
                <ul className="space-y-2">
                  {engine.data.adapters.map((a) => {
                    const active = a.status === 'ACTIVE'
                    return (
                      <li key={a.platform} className="rounded-md border px-3 py-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-xs font-semibold t82-caps">{a.platform}</span>
                          <Badge
                            variant="outline"
                            className={cn(
                              'font-mono text-[10px] t82-caps',
                              active
                                ? 'border-t82-green/30 bg-t82-green/12 text-t82-green'
                                : 'border-border bg-muted text-muted-foreground',
                            )}
                          >
                            {a.status}
                          </Badge>
                        </div>
                        {a.reason && <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">{a.reason}</p>}
                      </li>
                    )
                  })}
                </ul>
              </div>
            </div>
          )}
        </SectionCard>

        {/* Internal security */}
        <SectionCard className="lg:col-span-2" title={t('settings.security')}>
          <ul className="space-y-2.5">
            {SECURITY_ITEMS.map((item, i) => (
              <li key={i} className="flex gap-3">
                <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full bg-t82-green/10 font-mono text-[10px] font-bold text-t82-green">
                  {String(i + 1).padStart(2, '0')}
                </span>
                <p className="text-xs leading-relaxed text-muted-foreground">{lang === 'es' ? item.es : item.en}</p>
              </li>
            ))}
          </ul>
        </SectionCard>

        {/* About + authorship */}
        <SectionCard className="lg:col-span-2" title={t('settings.about')}>
          <p className="text-sm leading-relaxed text-muted-foreground">{t('settings.aboutText')}</p>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-t82-green/30 bg-t82-green/10 px-4 py-3">
            <div className="min-w-0">
              <p className="text-[10px] font-semibold t82-caps text-muted-foreground">{t('settings.credit')}</p>
              <p className="font-mono text-sm font-bold text-t82-green">{t('footer.by')}</p>
            </div>
            <Bot className="size-8 shrink-0 text-t82-green/40" aria-hidden />
          </div>
        </SectionCard>
      </div>
    </div>
  )
}

export default SettingsView
