'use client'
// DIVISION T82 — internal AI assistant dock (advisory-only).
// Floating action button + right-side chat panel. The conversation history is
// kept client-side AND persisted server-side (aggregated posture data only —
// never raw evidence), so past conversations can be restored from the panel.
import { useEffect, useRef, useState } from 'react'
import { Bot, History, Loader2, RotateCcw, Send, Trash2, X } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import { Sheet, SheetContent, SheetTitle } from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { useI18n } from '@/lib/i18n'
import { useToast } from '@/hooks/use-toast'
import {
  useAssistantConversations,
  fetchAssistantConversation,
  type AssistantConversationMeta,
} from '@/hooks/t82-queries'
import { cn } from '@/lib/utils'

type ChatMsg = { role: 'user' | 'assistant'; content: string }

const MAX_HISTORY = 12

function Markdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      components={{
        p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
        ul: ({ children }) => <ul className="mb-2 list-disc space-y-1 pl-4 last:mb-0">{children}</ul>,
        ol: ({ children }) => <ol className="mb-2 list-decimal space-y-1 pl-4 last:mb-0">{children}</ol>,
        li: ({ children }) => <li className="leading-relaxed">{children}</li>,
        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
        code: ({ children }) => (
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">{children}</code>
        ),
        a: ({ children, href }) => (
          <a href={href} target="_blank" rel="noreferrer" className="text-t82-cyan underline">
            {children}
          </a>
        ),
      }}
    >
      {content}
    </ReactMarkdown>
  )
}

export function AssistantDock() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [conversationId, setConversationId] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const listRef = useRef<HTMLDivElement | null>(null)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const history = useAssistantConversations()

  useEffect(() => {
    const el = listRef.current
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' })
  }, [messages, busy, showHistory])

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 150)
  }, [open])

  const send = async (text: string) => {
    const content = text.trim()
    if (!content || busy) return
    const next = [...messages, { role: 'user' as const, content }]
    setMessages(next.slice(-MAX_HISTORY))
    setInput('')
    setBusy(true)
    try {
      const res = await fetch('/api/assistant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: next.slice(-MAX_HISTORY),
          lang,
          ...(conversationId ? { conversationId } : {}),
        }),
      })
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null
        throw new Error(body?.error ?? `HTTP ${res.status}`)
      }
      const data = (await res.json()) as { reply: string; conversationId: string | null }
      setMessages((cur) => [...cur, { role: 'assistant', content: data.reply }])
      if (data.conversationId) setConversationId(data.conversationId)
    } catch (e) {
      toast({
        variant: 'destructive',
        title: t('assistant.error'),
        description: String((e as Error).message).slice(0, 180),
      })
      setInput(content) // restore so the user can retry without retyping
    } finally {
      setBusy(false)
    }
  }

  const clear = () => {
    if (busy) return
    setMessages([])
    setConversationId(null)
    setInput('')
  }

  const toggleHistory = () => {
    if (!showHistory) void history.refetch()
    setShowHistory((v) => !v)
  }

  const restore = async (meta: AssistantConversationMeta) => {
    if (busy) return
    try {
      const full = await fetchAssistantConversation(meta.id)
      setMessages(full.messages)
      setConversationId(full.id)
      setShowHistory(false)
      toast({ title: t('assistant.restored') })
    } catch (e) {
      toast({ variant: 'destructive', title: t('common.error'), description: String((e as Error).message).slice(0, 160) })
    }
  }

  const deleteAll = async () => {
    try {
      await fetch('/api/assistant/conversations', { method: 'DELETE' })
      setMessages([])
      setConversationId(null)
      setShowHistory(false)
      toast({ title: t('assistant.deleted') })
    } catch (e) {
      toast({ variant: 'destructive', title: t('common.error'), description: String((e as Error).message).slice(0, 160) })
    }
  }

  const deleteOne = async (id: string) => {
    try {
      await fetch(`/api/assistant/conversations/${id}`, { method: 'DELETE' })
      if (conversationId === id) {
        setMessages([])
        setConversationId(null)
      }
      void history.refetch()
    } catch {
      /* keep panel state */
    }
  }

  const suggestions = [t('assistant.suggest1'), t('assistant.suggest2'), t('assistant.suggest3')]
  const items = history.data ?? []

  return (
    <>
      {/* Floating action button — floats above the footer, safe-area friendly */}
      <Button
        size="icon"
        onClick={() => setOpen(true)}
        aria-label={t('assistant.open')}
        title={t('assistant.open')}
        className={cn(
          'fixed right-4 z-50 size-12 rounded-full border border-t82-green/40 bg-t82-green/12 text-t82-green',
          'shadow-[0_4px_16px_rgba(0,0,0,0.35)] hover:bg-t82-green/20',
          'bottom-[calc(5rem+env(safe-area-inset-bottom))] md:right-6 md:bottom-[4.75rem]',
        )}
      >
        <Bot className="size-5" aria-hidden />
      </Button>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="right"
          className="flex w-full flex-col gap-0 p-0 pb-[max(0px,env(safe-area-inset-bottom))] sm:max-w-md"
        >
          {/* Header */}
          <div className="flex items-center justify-between gap-2 border-b px-4 py-3">
            <div className="flex min-w-0 items-center gap-2.5">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-t82-green/40 bg-t82-green/10">
                <Bot className="size-4.5 text-t82-green" aria-hidden />
              </div>
              <div className="min-w-0">
                <SheetTitle className="truncate text-sm font-bold t82-caps tracking-wide">
                  {t('assistant.title')}
                </SheetTitle>
                <p className="truncate text-[11px] text-muted-foreground">{t('assistant.subtitle')}</p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <Button
                variant="ghost"
                size="icon"
                className="size-9"
                onClick={toggleHistory}
                aria-label={t('assistant.history')}
                title={t('assistant.history')}
                aria-expanded={showHistory}
              >
                <History className="size-4" aria-hidden />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="size-9"
                onClick={clear}
                disabled={messages.length === 0 || busy}
                aria-label={t('assistant.clear')}
                title={t('assistant.clear')}
              >
                <RotateCcw className="size-4" aria-hidden />
              </Button>
            </div>
          </div>

          {/* Conversation history panel */}
          {showHistory && (
            <div className="border-b bg-muted/30 px-3 py-3">
              <div className="mb-2 flex items-center justify-between gap-2 px-1">
                <p className="text-[10px] font-semibold t82-caps text-muted-foreground">{t('assistant.historyTitle')}</p>
                {history.isFetching && <Loader2 className="size-3 animate-spin text-muted-foreground" aria-hidden />}
              </div>
              <ul className="max-h-56 space-y-1.5 overflow-y-auto pr-1">
                {items.length === 0 && !history.isFetching && (
                  <li className="px-1 py-3 text-xs text-muted-foreground">{t('assistant.historyEmpty')}</li>
                )}
                {items.map((c) => (
                  <li key={c.id} className="flex items-center gap-1.5">
                    <button
                      onClick={() => void restore(c)}
                      className="min-w-0 flex-1 rounded-md border px-2.5 py-2 text-left transition-colors hover:bg-accent"
                      aria-label={`${t('assistant.restore')}: ${c.title}`}
                    >
                      <span className="block truncate text-xs font-medium">{c.title}</span>
                      <span className="mt-0.5 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                        <span>{new Date(c.updatedAt).toLocaleString()}</span>
                        <span>· {c.messageCount} msg</span>
                        {c.score != null && <span>· score {c.score.toFixed(1)}</span>}
                        {c.grounded && (
                          <Badge variant="outline" className="border-t82-green/40 px-1 py-0 text-[9px] text-t82-green">
                            GROUNDED
                          </Badge>
                        )}
                      </span>
                    </button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                      onClick={() => void deleteOne(c.id)}
                      aria-label={`${t('common.close')}: ${c.title}`}
                    >
                      <X className="size-3.5" aria-hidden />
                    </Button>
                  </li>
                ))}
              </ul>
              {items.length > 0 && (
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button variant="outline" size="sm" className="mt-2 min-h-9 w-full text-xs text-destructive">
                      <Trash2 className="size-3.5" aria-hidden />
                      {t('assistant.deleteAll')}
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>{t('assistant.deleteAll')}</AlertDialogTitle>
                      <AlertDialogDescription>{t('assistant.disclaimer')}</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>{t('common.close')}</AlertDialogCancel>
                      <AlertDialogAction onClick={() => void deleteAll()}>{t('common.close') === 'Cerrar' ? 'Confirmar' : 'Confirm'}</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              )}
            </div>
          )}

          {/* Advisory-only disclosure */}
          <p className="border-b bg-muted/40 px-4 py-2 text-[10px] leading-relaxed text-muted-foreground">
            {t('assistant.disclaimer')}
          </p>

          {/* Messages */}
          <div ref={listRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-4">
            <div className="mr-auto max-w-[94%] rounded-lg rounded-bl-sm border bg-card px-3 py-2.5 text-sm leading-relaxed">
              <Markdown content={t('assistant.greeting')} />
            </div>

            {messages.length === 0 && !busy && (
              <div className="flex flex-wrap gap-2 pt-1">
                {suggestions.map((s) => (
                  <Button
                    key={s}
                    variant="outline"
                    size="sm"
                    className="min-h-9 text-xs"
                    onClick={() => void send(s)}
                  >
                    {s}
                  </Button>
                ))}
              </div>
            )}

            {messages.map((m, i) =>
              m.role === 'user' ? (
                <div
                  key={i}
                  className="ml-auto max-w-[85%] rounded-lg rounded-br-sm border border-t82-green/30 bg-t82-green/12 px-3 py-2 text-sm leading-relaxed"
                >
                  {m.content}
                </div>
              ) : (
                <div
                  key={i}
                  className="mr-auto max-w-[94%] rounded-lg rounded-bl-sm border bg-card px-3 py-2.5 text-sm leading-relaxed"
                >
                  <Markdown content={m.content} />
                </div>
              ),
            )}

            {busy && (
              <div className="mr-auto flex items-center gap-2 rounded-lg rounded-bl-sm border bg-card px-3 py-2.5 text-sm text-muted-foreground">
                <Loader2 className="size-3.5 animate-spin" aria-hidden />
                <span aria-live="polite" className="font-mono text-xs t82-caps">
                  T82…
                </span>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="flex items-center gap-2 border-t px-3 py-3">
            <Input
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  void send(input)
                }
              }}
              placeholder={t('assistant.placeholder')}
              aria-label={t('assistant.placeholder')}
              className="min-h-11"
              maxLength={4000}
              disabled={busy}
            />
            <Button
              size="icon"
              className="size-11 shrink-0"
              onClick={() => void send(input)}
              disabled={busy || input.trim().length === 0}
              aria-label={t('assistant.send')}
            >
              <Send className="size-4" aria-hidden />
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}

export default AssistantDock
