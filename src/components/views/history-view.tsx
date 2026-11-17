'use client'
// DIVISION T82 — Module 11/13: Activity History. Local audit trail (AuditHistory).
import { History } from 'lucide-react'
import { useHistory } from '@/hooks/t82-queries'
import { useI18n } from '@/lib/i18n'
import { SectionCard, EmptyState, LoadingRows } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

type Lang = 'es' | 'en'

const bi = (lang: Lang, es: string, en: string) => (lang === 'es' ? es : en)

export function HistoryView() {
  const { t, lang } = useI18n()
  const history = useHistory()
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  if (history.isPending) {
    return (
      <div className="space-y-4" role="status" aria-label={t('common.loading')}>
        <Skeleton className="h-10 w-64" />
        <LoadingRows rows={5} />
      </div>
    )
  }

  if (history.isError) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <EmptyState
          icon={<History className="size-8" />}
          title={t('common.error')}
          description={history.error?.message}
          action={<Button onClick={() => void history.refetch()}>{t('common.retry')}</Button>}
        />
      </div>
    )
  }

  const items = history.data ?? []

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-bold t82-caps tracking-wide">{t('history.title')}</h1>

      <SectionCard
        title={t('history.title')}
        description={bi(lang, 'Registro de auditoría local — cada operación queda trazada.', 'Local audit log — every operation is traced.')}
        right={<span className="font-mono text-xs text-muted-foreground">{items.length}</span>}
      >
        {items.length === 0 ? (
          <EmptyState icon={<History className="size-8" />} title={t('common.noData')} />
        ) : (
          <div className="max-h-96 overflow-y-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="t82-caps">{bi(lang, 'Acción', 'Action')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Destino', 'Target')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Detalle', 'Detail')}</TableHead>
                  <TableHead className="t82-caps">{bi(lang, 'Fecha', 'Date')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((h) => (
                  <TableRow key={h.id}>
                    <TableCell className="whitespace-nowrap font-mono text-xs text-t82-cyan">{h.action}</TableCell>
                    <TableCell className="max-w-40 truncate font-mono text-xs text-muted-foreground" title={h.target ?? undefined}>
                      {h.target ?? '—'}
                    </TableCell>
                    <TableCell className="max-w-72 break-words text-xs text-muted-foreground" title={h.detail ?? undefined}>
                      {h.detail ?? '—'}
                    </TableCell>
                    <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                      {new Date(h.createdAt).toLocaleString(locale)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>
    </div>
  )
}

export default HistoryView
