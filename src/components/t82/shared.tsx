'use client'
// DIVISION T82 — shared UI primitives (NEO CYBER)
import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { AlertTriangle, CheckCircle2, CircleSlash, HelpCircle, ShieldX, XCircle, Loader2 } from 'lucide-react'
import type { ControlStatus, Severity, Loc } from '@/lib/engine/types'

const STATUS_STYLE: Record<ControlStatus, { cls: string; labelEs: string; labelEn: string }> = {
  PASS: { cls: 'bg-t82-green/12 text-t82-green border-t82-green/30', labelEs: 'APTO', labelEn: 'PASS' },
  FAIL: { cls: 'bg-t82-critical/12 text-t82-critical border-t82-critical/30', labelEs: 'FALLO', labelEn: 'FAIL' },
  WARNING: { cls: 'bg-t82-warning/12 text-t82-warning border-t82-warning/30', labelEs: 'ADVERTENCIA', labelEn: 'WARNING' },
  NOT_APPLICABLE: { cls: 'bg-muted text-muted-foreground border-border', labelEs: 'NO APLICABLE', labelEn: 'NOT APPLICABLE' },
  NOT_ASSESSED: { cls: 'bg-muted text-muted-foreground border-border', labelEs: 'NO EVALUADO', labelEn: 'NOT ASSESSED' },
  ERROR: { cls: 'bg-t82-critical/8 text-t82-critical/80 border-t82-critical/25', labelEs: 'ERROR', labelEn: 'ERROR' },
}

export function StatusBadge({ status, lang = 'es', className }: { status: ControlStatus; lang?: 'es' | 'en'; className?: string }) {
  const s = STATUS_STYLE[status]
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold t82-caps font-mono', s.cls, className)}>
      {status === 'PASS' && <CheckCircle2 className="size-3" aria-hidden />}
      {status === 'FAIL' && <XCircle className="size-3" aria-hidden />}
      {status === 'WARNING' && <AlertTriangle className="size-3" aria-hidden />}
      {(status === 'NOT_ASSESSED' || status === 'NOT_APPLICABLE') && <CircleSlash className="size-3" aria-hidden />}
      {status === 'ERROR' && <ShieldX className="size-3" aria-hidden />}
      <span className="sr-only">status:</span>
      {lang === 'es' ? s.labelEs : s.labelEn}
    </span>
  )
}

const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: 'bg-t82-critical text-white border-transparent',
  HIGH: 'bg-t82-critical/75 text-white border-transparent',
  MEDIUM: 'bg-t82-warning/80 text-white border-transparent',
  LOW: 'bg-t82-cyan/70 text-white border-transparent',
  INFO: 'bg-muted text-muted-foreground border-border',
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge variant="outline" className={cn('font-mono text-[10px] t82-caps', SEVERITY_STYLE[severity], className)}>
      {severity}
    </Badge>
  )
}

export function ScoreRing({ value, size = 132, label }: { value: number | null; size?: number; label?: string }) {
  const v = value ?? 0
  const stroke = 10
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const color = value === null ? 'var(--muted-foreground)' : v >= 80 ? 'var(--t82-green)' : v >= 55 ? 'var(--t82-warning)' : 'var(--t82-critical)'
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} className="stroke-muted" fill="none" />
        <circle
          cx={size / 2} cy={size / 2} r={r} strokeWidth={stroke} fill="none"
          stroke={color} strokeDasharray={c} strokeDashoffset={c - (c * v) / 100}
          strokeLinecap="round" className="transition-all duration-500"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-2xl font-bold tabular-nums" style={{ color }}>
          {value === null ? '—' : v.toFixed(1)}
        </span>
        {label && <span className="text-[10px] text-muted-foreground t82-caps">{label}</span>}
      </div>
    </div>
  )
}

export function CoverageBar({ value, className }: { value: number; className?: string }) {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div className="h-2 flex-1 rounded-full bg-muted overflow-hidden" role="progressbar" aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full bg-t82-cyan transition-all duration-500" style={{ width: `${Math.min(100, Math.max(0, value))}%` }} />
      </div>
      <span className="font-mono text-xs tabular-nums text-muted-foreground">{value.toFixed(1)}%</span>
    </div>
  )
}

export function SectionCard({ title, description, right, children, className, id }: {
  title: React.ReactNode
  description?: React.ReactNode
  right?: React.ReactNode
  children: React.ReactNode
  className?: string
  id?: string
}) {
  return (
    <section id={id} className={cn('rounded-xl border bg-card text-card-foreground shadow-sm', className)} aria-label={typeof title === 'string' ? title : undefined}>
      <div className="flex flex-wrap items-start justify-between gap-3 border-b px-4 py-3 md:px-6">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold t82-caps tracking-wide">{title}</h2>
          {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        </div>
        {right && <div className="shrink-0">{right}</div>}
      </div>
      <div className="p-4 md:p-6">{children}</div>
    </section>
  )
}

export function StatCard({ label, value, sub, tone }: {
  label: React.ReactNode
  value: React.ReactNode
  sub?: React.ReactNode
  tone?: 'default' | 'good' | 'warn' | 'bad' | 'info'
}) {
  const toneCls =
    tone === 'good' ? 'text-t82-green' :
    tone === 'warn' ? 'text-t82-warning' :
    tone === 'bad' ? 'text-t82-critical' :
    tone === 'info' ? 'text-t82-cyan' : 'text-foreground'
  return (
    <div className="rounded-xl border bg-card p-4 shadow-sm">
      <p className="text-[11px] t82-caps text-muted-foreground">{label}</p>
      <p className={cn('mt-1 font-mono text-2xl font-bold tabular-nums', toneCls)}>{value}</p>
      {sub && <p className="mt-0.5 text-xs text-muted-foreground">{sub}</p>}
    </div>
  )
}

export function EmptyState({ icon, title, description, action }: {
  icon?: React.ReactNode
  title: React.ReactNode
  description?: React.ReactNode
  action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed bg-muted/30 px-6 py-10 text-center">
      {icon && <div className="text-muted-foreground" aria-hidden>{icon}</div>}
      <p className="text-sm font-medium">{title}</p>
      {description && <p className="max-w-md text-xs text-muted-foreground">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function LoadingRows({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2" role="status" aria-label="loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
      <span className="sr-only"><Loader2 className="animate-spin" /></span>
    </div>
  )
}

export function LocText({ value, lang }: { value: Loc | null | undefined; lang: 'es' | 'en' }) {
  if (!value) return null
  return <>{value[lang] ?? value.en}</>
}

export function statusIcon(status: ControlStatus) {
  switch (status) {
    case 'PASS': return <CheckCircle2 className="size-4 text-t82-green" aria-hidden />
    case 'FAIL': return <XCircle className="size-4 text-t82-critical" aria-hidden />
    case 'WARNING': return <AlertTriangle className="size-4 text-t82-warning" aria-hidden />
    case 'ERROR': return <ShieldX className="size-4 text-t82-critical/80" aria-hidden />
    default: return <HelpCircle className="size-4 text-muted-foreground" aria-hidden />
  }
}
