'use client'
// DIVISION T82 — Module 7/13: Hardening Studio. ADVISORY-ONLY remediation proposals.
// The app never executes system changes; every step is a manual, copyable proposal.
import { useEffect, useState } from 'react'
import {
  AlertTriangle, Check, ChevronRight, Copy, FileCode2, Hammer, ListTodo, Loader2, Play, Plus, RotateCcw, ShieldAlert, X,
} from 'lucide-react'
import {
  useOverview, useFindings, useRemediation, useRemediationTasks,
  useCreateRemediationTask, useUpdateRemediationTask, useDeleteRemediationTask,
  type RemediationTaskItem,
} from '@/hooks/t82-queries'
import { useAppStore } from '@/lib/store'
import { useI18n, localized } from '@/lib/i18n'
import {
  SectionCard, EmptyState, LoadingRows, SeverityBadge, StatusBadge,
} from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/hooks/use-toast'
import { cn } from '@/lib/utils'

type Lang = 'es' | 'en'
type SeverityT = Parameters<typeof SeverityBadge>[0]['severity']
type StatusT = Parameters<typeof StatusBadge>[0]['status']

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

function SubHead({ children }: { children: React.ReactNode }) {
  return <p className="text-[10px] font-semibold t82-caps tracking-wide text-muted-foreground">{children}</p>
}

function CodeBlock({ code, onCopy, label, lang }: { code: string; onCopy: (cmd: string) => void; label?: string; lang: Lang }) {
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-md bg-muted p-3 pr-12 font-mono text-[11px] leading-relaxed" aria-label={label}>
        {code}
      </pre>
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-1.5 top-1.5 size-8 opacity-70 transition-opacity hover:opacity-100"
        onClick={() => onCopy(code)}
        aria-label={bi(lang, 'Copiar comando', 'Copy command')}
      >
        <Copy className="size-3.5" aria-hidden />
      </Button>
    </div>
  )
}

const TASK_BADGE: Record<RemediationTaskItem['status'], string> = {
  OPEN: 'border-border bg-muted text-muted-foreground',
  IN_PROGRESS: 'border-t82-cyan/40 bg-t82-cyan/10 text-t82-cyan',
  DONE: 'border-t82-green/40 bg-t82-green/12 text-t82-green',
  DISMISSED: 'border-border bg-muted text-muted-foreground',
}

export function HardeningView() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const setView = useAppStore((s) => s.setView)
  const selectedControl = useAppStore((s) => s.selectedControl)
  const setSelectedControl = useAppStore((s) => s.setSelectedControl)
  const ov = useOverview()
  const lastScanId = ov.data?.lastScan?.id ?? null
  const findings = useFindings(lastScanId)
  const rem = useRemediation(selectedControl)
  const tasks = useRemediationTasks()
  const createTask = useCreateRemediationTask()
  const updateTask = useUpdateRemediationTask()
  const deleteTask = useDeleteRemediationTask()

  // Auto-select the first finding when nothing is selected yet.
  useEffect(() => {
    const items = findings.data ?? []
    if (!selectedControl && items.length > 0) setSelectedControl(items[0].controlId)
  }, [selectedControl, findings.data, setSelectedControl])

  const copyCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd)
      toast({ title: t('common.copied') })
    } catch {
      toast({ variant: 'destructive', title: t('common.error'), description: bi(lang, 'No se pudo copiar', 'Copy failed') })
    }
  }

  const items = findings.data ?? []
  const taskItems = tasks.data ?? []
  const openTaskIds = new Set(
    taskItems.filter((x) => x.status === 'OPEN' || x.status === 'IN_PROGRESS').map((x) => x.controlId),
  )

  const addTask = () => {
    if (!rem.data) return
    createTask.mutate(
      {
        controlId: rem.data.controlId,
        title: localized(rem.data.controlName, lang),
        scanId: lastScanId ?? undefined,
        payload: { priority: rem.data.remediation.priority, category: rem.data.category },
      },
      {
        onSuccess: (res) =>
          toast({
            title: res.created ? t('hardening.taskCreated') : t('hardening.taskExists'),
          }),
        onError: (e) =>
          toast({ variant: 'destructive', title: t('common.error'), description: e.message }),
      },
    )
  }

  const setTaskStatus = (task: RemediationTaskItem, status: RemediationTaskItem['status']) => {
    updateTask.mutate(
      { id: task.id, status },
      {
        onError: (e) =>
          toast({ variant: 'destructive', title: t('common.error'), description: e.message }),
      },
    )
  }

  const removeTask = (task: RemediationTaskItem) => {
    deleteTask.mutate(task.id, {
      onError: (e) =>
        toast({ variant: 'destructive', title: t('common.error'), description: e.message }),
    })
  }

  return (
    <div className="space-y-4">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-bold t82-caps tracking-wide">{t('hardening.title')}</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('hardening.subtitle')}</p>
        </div>
        <Hammer className="size-5 shrink-0 text-muted-foreground" aria-hidden />
      </div>

      {/* Advisory banner */}
      <div
        role="note"
        className="flex items-start gap-2.5 rounded-lg border border-t82-warning/40 bg-t82-warning/10 px-4 py-3"
      >
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-t82-warning" aria-hidden />
        <p className="text-xs font-semibold t82-caps tracking-wide text-t82-warning">{t('hardening.advisory')}</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(280px,340px)_1fr]">
        {/* Findings list (left) */}
        <SectionCard title={t('findings.title')} className="self-start">
          {findings.isPending ? (
            <LoadingRows rows={4} />
          ) : findings.isError ? (
            <div className="flex flex-col gap-2">
              <p className="text-xs text-muted-foreground">{t('common.error')}: {findings.error?.message}</p>
              <Button variant="outline" size="sm" className="min-h-11" onClick={() => void findings.refetch()}>
                {t('common.retry')}
              </Button>
            </div>
          ) : items.length === 0 ? (
            <EmptyState
              icon={<ShieldAlert className="size-6" />}
              title={t('findings.empty')}
              description={bi(lang, 'Sin hallazgos abiertos: no hay remediaciones que mostrar.', 'No open findings: no remediations to show.')}
            />
          ) : (
            <ul className="max-h-[480px] space-y-1.5 overflow-y-auto pr-1" aria-label={t('findings.title')}>
              {items.map((f) => {
                const active = selectedControl === f.controlId
                return (
                  <li key={f.controlId}>
                    <button
                      onClick={() => setSelectedControl(f.controlId)}
                      aria-current={active ? 'true' : undefined}
                      className={cn(
                        'flex min-h-[52px] w-full flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring',
                        active ? 'border-t82-cyan bg-t82-cyan/10' : 'border-border hover:bg-accent',
                      )}
                    >
                      <span className="flex w-full items-center gap-2">
                        <span className="min-w-0 flex-1 truncate text-sm font-medium">{localized(f.name, lang)}</span>
                        <SeverityBadge severity={f.severity as SeverityT} />
                      </span>
                      <span className="flex w-full items-center gap-2">
                        <span className="font-mono text-[10px] text-muted-foreground">{f.controlId}</span>
                        <ChevronRight className={cn('ml-auto size-3.5 shrink-0 transition-transform', active ? 'text-t82-cyan' : 'text-muted-foreground')} aria-hidden />
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </SectionCard>

        {/* Remediation detail (right) */}
        <div className="min-w-0">
          {!selectedControl ? (
            <EmptyState icon={<Hammer className="size-8" />} title={t('hardening.select')} />
          ) : rem.isPending ? (
            <div className="space-y-3" role="status" aria-label={t('common.loading')}>
              <Skeleton className="h-12 w-full" />
              <LoadingRows rows={6} />
            </div>
          ) : rem.isError || !rem.data ? (
            <EmptyState
              icon={<Hammer className="size-8" />}
              title={t('common.error')}
              description={rem.error?.message}
              action={<Button onClick={() => void rem.refetch()}>{t('common.retry')}</Button>}
            />
          ) : !rem.data.implemented ? (
            <SectionCard title={`Remediación — ${rem.data.controlId}`} right={<SeverityBadge severity={rem.data.severity as SeverityT} />}>
              <EmptyState
                icon={<ShieldAlert className="size-8" />}
                title={bi(lang, 'Control no implementado en este entorno.', 'Control not implemented in this environment.')}
                description={bi(
                  lang,
                  'No hay remediación aplicable aquí. Este control forma parte del catálogo diseñado y requiere el puente nativo de plataforma.',
                  'No applicable remediation here. This control is part of the designed catalog and requires the native platform bridge.',
                )}
              />
            </SectionCard>
          ) : (
            (() => {
              const r = rem.data.remediation
              return (
                <SectionCard
                  title={`Remediación — ${rem.data.controlId}`}
                  description={localized(rem.data.controlName, lang)}
                  right={
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="text-[10px] font-semibold t82-caps text-muted-foreground">
                        {bi(lang, 'Prioridad', 'Priority')}
                      </span>
                      <SeverityBadge severity={r.priority as SeverityT} />
                      <Button
                        variant="outline"
                        size="sm"
                        className="min-h-9 text-xs"
                        onClick={addTask}
                        disabled={createTask.isPending || openTaskIds.has(rem.data.controlId)}
                        aria-label={t('hardening.addTask')}
                        title={openTaskIds.has(rem.data.controlId) ? t('hardening.taskExists') : t('hardening.addTask')}
                      >
                        {createTask.isPending ? (
                          <Loader2 className="size-3.5 animate-spin" aria-hidden />
                        ) : (
                          <Plus className="size-3.5" aria-hidden />
                        )}
                        {t('hardening.addTask')}
                      </Button>
                    </span>
                  }
                >
                  <div className="space-y-4">
                    {/* Current finding status */}
                    {rem.data.currentFinding && (
                      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-3 py-2">
                        <StatusBadge status={rem.data.currentFinding.status as StatusT} lang={lang} />
                        {rem.data.currentFinding.detail && (
                          <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground" title={rem.data.currentFinding.detail}>
                            {rem.data.currentFinding.detail}
                          </span>
                        )}
                      </div>
                    )}

                    <div>
                      <SubHead>{bi(lang, 'Problema', 'Problem')}</SubHead>
                      <p className="mt-1 text-sm font-medium leading-relaxed">{localized(r.problemSummary, lang)}</p>
                    </div>

                    <div>
                      <SubHead>{bi(lang, 'Causa raíz', 'Root cause')}</SubHead>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{localized(r.rootCause, lang)}</p>
                    </div>

                    <div>
                      <SubHead>{bi(lang, 'Riesgo', 'Risk')}</SubHead>
                      <p className="mt-1 text-sm leading-relaxed text-t82-critical">{localized(r.risk, lang)}</p>
                    </div>

                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="rounded-md border bg-muted/30 p-3">
                        <SubHead>{t('hardening.current')}</SubHead>
                        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{localized(r.currentStateNote, lang)}</p>
                      </div>
                      <div className="rounded-md border border-t82-green/30 bg-t82-green/5 p-3">
                        <SubHead>{t('hardening.recommended')}</SubHead>
                        <p className="mt-1 text-xs leading-relaxed text-foreground">{localized(r.recommendedState, lang)}</p>
                      </div>
                    </div>

                    {/* Steps */}
                    <div>
                      <SubHead>{t('hardening.steps')}</SubHead>
                      <ol className="mt-2 space-y-3">
                        {r.steps.map((step, i) => (
                          <li key={i} className="rounded-lg border p-3">
                            <p className="flex items-start gap-2 text-sm font-medium">
                              <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full bg-muted font-mono text-[10px]">
                                {i + 1}
                              </span>
                              {localized(step.title, lang)}
                            </p>
                            {step.command && (
                              <div className="mt-2">
                                <CodeBlock code={step.command} onCopy={(cmd) => void copyCommand(cmd)} label={step.command} lang={lang} />
                              </div>
                            )}
                            {step.note && <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{localized(step.note, lang)}</p>}
                          </li>
                        ))}
                        {r.steps.length === 0 && (
                          <li className="text-xs text-muted-foreground">
                            {bi(lang, 'Sin pasos definidos para este control.', 'No steps defined for this control.')}
                          </li>
                        )}
                      </ol>
                    </div>

                    {r.affectedFiles && r.affectedFiles.length > 0 && (
                      <div>
                        <SubHead>{t('hardening.affected')}</SubHead>
                        <ul className="mt-2 flex flex-wrap gap-1.5">
                          {r.affectedFiles.map((f) => (
                            <li key={f} className="rounded-md border bg-muted/50 px-2 py-1 font-mono text-[11px]">{f}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div>
                      <SubHead>{t('hardening.risks')}</SubHead>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{localized(r.sideEffects, lang)}</p>
                    </div>

                    <div>
                      <SubHead>{t('hardening.prereq')}</SubHead>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{localized(r.prerequisites, lang)}</p>
                    </div>

                    <div>
                      <SubHead>{t('hardening.rollback')}</SubHead>
                      <p className="mt-1 text-sm leading-relaxed text-muted-foreground">{localized(r.rollback, lang)}</p>
                    </div>

                    <div>
                      <SubHead>{t('hardening.verify')}</SubHead>
                      <p className="mt-1 flex items-start gap-2 text-sm leading-relaxed text-t82-green">
                        <Check className="mt-0.5 size-3.5 shrink-0" aria-hidden />
                        {localized(r.verify, lang)}
                      </p>
                    </div>

                    {rem.data.references.length > 0 && (
                      <div>
                        <SubHead>{t('common.references')}</SubHead>
                        <ul className="mt-2 space-y-1">
                          {rem.data.references.map((ref) => (
                            <li key={ref.url}>
                              <a
                                href={ref.url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 text-xs text-t82-cyan underline-offset-2 hover:underline"
                              >
                                {ref.label}
                                <FileCode2 className="size-3" aria-hidden />
                              </a>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </SectionCard>
              )
            })()
          )}
        </div>
      </div>

      {/* Remediation task tracking (advisory checklist) */}
      <SectionCard
        title={t('hardening.tasks')}
        description={t('hardening.tasksHint')}
        right={<ListTodo className="size-4 text-muted-foreground" aria-hidden />}
      >
        {tasks.isPending ? (
          <LoadingRows rows={2} />
        ) : tasks.isError ? (
          <EmptyState
            icon={<ListTodo className="size-6" />}
            title={t('common.error')}
            description={tasks.error?.message}
            action={<Button onClick={() => void tasks.refetch()}>{t('common.retry')}</Button>}
          />
        ) : taskItems.length === 0 ? (
          <EmptyState icon={<ListTodo className="size-8" />} title={t('hardening.noTasks')} />
        ) : (
          <ul className="max-h-96 space-y-2 overflow-y-auto pr-1" aria-label={t('hardening.tasks')}>
            {taskItems.map((task) => (
              <li
                key={task.id}
                className={cn(
                  'flex flex-wrap items-start gap-2 rounded-md border px-3 py-2',
                  task.status === 'DISMISSED' && 'opacity-60',
                )}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-t82-cyan">{task.controlId}</span>
                    <Badge variant="outline" className={cn('t82-caps text-[10px]', TASK_BADGE[task.status])}>
                      {task.status}
                    </Badge>
                    {task.status === 'DONE' && task.closedAt && (
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {t('hardening.closedAt')}: {new Date(task.closedAt).toLocaleDateString()}
                      </span>
                    )}
                  </div>
                  <p className={cn('mt-0.5 truncate text-xs text-muted-foreground', task.status === 'DONE' && 'line-through')}>
                    {task.title}
                  </p>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                  {(task.status === 'OPEN' || task.status === 'DISMISSED') && (
                    <Button variant="outline" size="sm" className="min-h-9 text-xs" onClick={() => setTaskStatus(task, 'IN_PROGRESS')}>
                      <Play className="size-3" aria-hidden />
                      {t('hardening.start')}
                    </Button>
                  )}
                  {(task.status === 'OPEN' || task.status === 'IN_PROGRESS') && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="min-h-9 border-t82-green/40 text-xs text-t82-green"
                      onClick={() => setTaskStatus(task, 'DONE')}
                    >
                      <Check className="size-3" aria-hidden />
                      {t('hardening.done')}
                    </Button>
                  )}
                  {(task.status === 'DONE' || task.status === 'DISMISSED') && (
                    <Button variant="outline" size="sm" className="min-h-9 text-xs" onClick={() => setTaskStatus(task, 'OPEN')}>
                      <RotateCcw className="size-3" aria-hidden />
                      {t('hardening.reopen')}
                    </Button>
                  )}
                  {(task.status === 'IN_PROGRESS' || task.status === 'OPEN') && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="min-h-9 text-xs"
                      onClick={() => setTaskStatus(task, 'DISMISSED')}
                    >
                      {t('hardening.dismiss')}
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-8 text-muted-foreground hover:text-destructive"
                    onClick={() => removeTask(task)}
                    aria-label={`${t('common.close')} ${task.controlId}`}
                  >
                    <X className="size-3.5" aria-hidden />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </SectionCard>
    </div>
  )
}

export default HardeningView
