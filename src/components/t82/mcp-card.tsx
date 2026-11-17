'use client'
// DIVISION T82 — Universal MCP live card (client).
// Shows the state of the local MCP server (port 3030 via gateway), its tools,
// a live JSON-RPC tools/call demo and the connection snippet for MCP clients.
// The MCP server itself is a read-only mini-service — the UI never mutates.
import { useCallback, useEffect, useState } from 'react'
import { Activity, Loader2, Play, Waypoints } from 'lucide-react'
import { SectionCard } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'

interface McpTool {
  name: string
  description: string
}

interface McpHealth {
  status?: string
  service?: string
  version?: string
  transport?: string
  tools?: McpTool[]
}

const MCP_FETCH = { headers: { Accept: 'application/json, text/event-stream' } } as const

export function McpCard() {
  const { t, lang } = useI18n()
  const [health, setHealth] = useState<McpHealth | null>(null)
  const [online, setOnline] = useState<boolean | null>(null)
  const [tool, setTool] = useState<string>('t82_latest_posture')
  const [query, setQuery] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<string>('')

  const ping = useCallback(async () => {
    try {
      const res = await fetch('/health?XTransformPort=3030', { cache: 'no-store' })
      const data = (await res.json()) as McpHealth
      setHealth(data)
      setOnline(res.ok && data.status === 'ok')
    } catch {
      setOnline(false)
    }
  }, [])

  useEffect(() => {
    void ping()
  }, [ping])

  const tools = health?.tools ?? []
  const needsQuery = tool === 't82_ask' || tool === 't82_knowledge_search'
  const optionalQuery = tool === 't82_control_search' || tool === 't82_top_cves'

  const run = async () => {
    if (running) return
    setRunning(true)
    setResult('')
    try {
      const args: Record<string, string> = {}
      const q = query.trim()
      if (needsQuery && q) args[tool === 't82_ask' ? 'question' : 'query'] = q
      if (optionalQuery && q) args[tool === 't82_top_cves' ? 'package' : 'query'] = q
      if (tool === 't82_ask') args.lang = lang

      const res = await fetch('/mcp?XTransformPort=3030', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...MCP_FETCH.headers },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: { name: tool, arguments: args },
        }),
      })
      const data = (await res.json()) as {
        result?: { content?: { type: string; text?: string }[] }
        error?: { message?: string }
      }
      if (data.error) {
        setResult(`MCP error: ${data.error.message ?? 'unknown'}`)
      } else {
        const text = (data.result?.content ?? [])
          .map((c) => (c.type === 'text' ? c.text : JSON.stringify(c)))
          .join('\n')
        setResult(text || t('mcp.resultEmpty'))
      }
    } catch (e) {
      setResult(`fetch error: ${String((e as Error).message).slice(0, 200)}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <SectionCard
      title="Universal MCP — servidor local"
      description={t('mcp.desc')}
      right={<Waypoints className="size-4 text-muted-foreground" aria-hidden />}
    >
      <div className="space-y-3">
        {/* Status */}
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            variant="outline"
            className={cn(
              'gap-1.5 px-2 py-0.5 font-mono text-[10px] t82-caps',
              online === true && 'border-t82-green/50 bg-t82-green/10 text-t82-green',
              online === false && 'border-destructive/50 bg-destructive/10 text-destructive',
              online === null && 'border-border bg-muted text-muted-foreground',
            )}
          >
            {online === true ? (
              <>
                <Activity className="size-3" aria-hidden />
                {t('mcp.online')}
              </>
            ) : online === false ? (
              t('mcp.offline')
            ) : (
              t('common.loading')
            )}
          </Badge>
          {health?.transport && (
            <span className="font-mono text-[10px] text-muted-foreground">{health.transport}</span>
          )}
        </div>

        {/* Tool list */}
        {tools.length > 0 && (
          <ul className="space-y-1.5">
            {tools.map((tl) => (
              <li key={tl.name} className="rounded-md border bg-card/50 px-2.5 py-2">
                <p className="font-mono text-[11px] font-semibold text-t82-green">{tl.name}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{tl.description}</p>
              </li>
            ))}
          </ul>
        )}

        {/* Live demo */}
        <div className="rounded-md border bg-muted/40 p-3">
          <p className="mb-2 text-[10px] font-semibold t82-caps text-muted-foreground">{t('mcp.demoTitle')}</p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <select
              value={tool}
              onChange={(e) => {
                setTool(e.target.value)
                setQuery('')
                setResult('')
              }}
              aria-label={t('mcp.demoTitle')}
              className="min-h-11 flex-1 rounded-md border bg-background px-3 font-mono text-xs"
            >
              {tools.map((tl) => (
                <option key={tl.name} value={tl.name}>
                  {tl.name}
                </option>
              ))}
            </select>
            <Button size="sm" className="min-h-11 shrink-0 sm:w-32" onClick={() => void run()} disabled={running || tools.length === 0}>
              {running ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : (
                <Play className="size-4" aria-hidden />
              )}
              {running ? t('mcp.running') : t('mcp.run')}
            </Button>
          </div>
          {(needsQuery || optionalQuery) && (
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void run()
              }}
              placeholder={needsQuery ? t('mcp.queryRequired') : t('mcp.queryOptional')}
              className="mt-2 min-h-11 font-mono text-xs"
              maxLength={1000}
            />
          )}
          {result && (
            <pre className="mt-2 max-h-64 overflow-y-auto whitespace-pre-wrap break-words rounded-md border bg-background p-2.5 font-mono text-[10px] leading-relaxed">
              {result}
            </pre>
          )}
        </div>

        {/* Connect snippet */}
        <div className="rounded-md border bg-muted/40 p-3">
          <p className="mb-1.5 text-[10px] font-semibold t82-caps text-muted-foreground">{t('mcp.connectTitle')}</p>
          <pre className="overflow-x-auto rounded-md border bg-background p-2.5 font-mono text-[10px] leading-relaxed">
            {`{\n  "mcpServers": {\n    "vulncheck-t82": {\n      "url": "http://localhost:3030/mcp"\n    }\n  }\n}`}
          </pre>
          <p className="mt-2 text-[10px] leading-relaxed text-muted-foreground">{t('mcp.connectNote')}</p>
        </div>
      </div>
    </SectionCard>
  )
}

export default McpCard
