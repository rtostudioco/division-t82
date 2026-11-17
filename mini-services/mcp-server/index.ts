// DIVISION T82 — Universal MCP server (local, read-only, advisory-only).
// Exposes the platform's assessment data and internal AI assistant over the
// Model Context Protocol (streamable HTTP, stateless) so any local MCP client
// (Claude Desktop, Cursor, scripts, agents) can call it as a local process.
//
//   port       : 3030
//   endpoint   : POST /mcp   (MCP JSON-RPC, streamable HTTP, stateless)
//   health     : GET  /health
//   upstream   : main app API at http://127.0.0.1:3000 (single source of truth)
//
// Honesty rules inherited from the platform: every tool is read-only and
// grounded in the latest completed assessment; nothing is mutated, no raw
// evidence or secrets are exposed — aggregated posture data only.
import express from 'express'
import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'

const PORT = 3030
const UPSTREAM = 'http://127.0.0.1:3000'

// ─── Upstream helpers ────────────────────────────────────────────────────────

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${UPSTREAM}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(120_000),
  })
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`upstream ${path} → HTTP ${res.status} ${body.slice(0, 200)}`)
  }
  return (await res.json()) as T
}

interface ScanRow {
  id: string
  startedAt: string
  status: string
  score: number | null
  coverage: number | null
  host?: { hostname: string; os: string; osVersion: string }
}

async function latestScanId(): Promise<string> {
  const scans = await api<ScanRow[]>('/api/scans')
  const completed = scans.filter((s) => s.status === 'completed')
  if (completed.length === 0) throw new Error('no completed assessment yet — run one in the platform UI')
  return completed[0].id
}

// ─── MCP server definition ───────────────────────────────────────────────────

function buildServer(): McpServer {
  const server = new McpServer(
    { name: 'vulncheck-t82', version: '1.0.0' },
    { instructions: 'DIVISION T82: local-first security posture platform. All tools are read-only and advisory-only, grounded in the latest completed assessment. Answer in the user language.' },
  )

  // 1 — Latest assessment summary.
  server.tool(
    't82_latest_posture',
    'Summary of the latest completed security assessment: score, coverage, status counts, severity counts and top findings.',
    {},
    async () => {
      const scans = await api<ScanRow[]>('/api/scans')
      const last = scans.find((s) => s.status === 'completed')
      if (!last) {
        return { content: [{ type: 'text', text: 'No completed assessment yet. Open the platform and run "Iniciar evaluación".' }] }
      }
      const o = await api<{ lastScan: { counts: Record<string, number> | null; severityCounts: Record<string, number> | null }; topFindings: { controlId?: string; name?: { en?: string; es?: string }; severity?: string; status?: string; category?: string; detail?: string }[] }>(
        '/api/overview',
      )
      const lines: string[] = [
        `Assessment ${last.startedAt.slice(0, 16).replace('T', ' ')} UTC — host ${last.host?.hostname ?? '?'} (${last.host?.os ?? ''} ${last.host?.osVersion ?? ''})`,
        `score: ${last.score?.toFixed(1) ?? 'n/a'}/100 | coverage: ${last.coverage?.toFixed(1) ?? 'n/a'}%`,
        `status counts: ${JSON.stringify(o.lastScan?.counts ?? {})}`,
        `severity counts: ${JSON.stringify(o.lastScan?.severityCounts ?? {})}`,
        'top findings:',
        ...o.topFindings.slice(0, 8).map((f) => {
          const name = f.name?.es || f.name?.en || ''
          return `- [${f.severity}/${f.status}] ${f.controlId ?? ''} ${name} (${f.category ?? ''}): ${(f.detail ?? '').slice(0, 120)}`
        }),
      ]
      return { content: [{ type: 'text', text: lines.join('\n') }] }
    },
  )

  // 2 — Control search over the latest assessment.
  server.tool(
    't82_control_search',
    'Search security controls of the latest assessment by free text, status (PASS, FAIL, WARNING, NOT_APPLICABLE, NOT_ASSESSED, ERROR) and severity (CRITICAL, HIGH, MEDIUM, LOW).',
    {
      query: z.string().max(120).optional().describe('free text in control id, name or detail'),
      status: z.enum(['PASS', 'FAIL', 'WARNING', 'NOT_APPLICABLE', 'NOT_ASSESSED', 'ERROR']).optional(),
      severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
      limit: z.number().int().min(1).max(40).optional().describe('max controls returned (default 12)'),
    },
    async ({ query, status, severity, limit }) => {
      const id = await latestScanId()
      const d = await api<{
        controls: { controlId: string; name: { en: string; es: string }; category: string; severity: string; status: string; reason?: string; detail?: string }[]
      }>(`/api/scans/${id}`)
      const q = (query ?? '').toLowerCase()
      const out: string[] = []
      const lim = limit ?? 12
      for (const c of d.controls ?? []) {
        if (status && c.status !== status) continue
        if (severity && c.severity !== severity) continue
        const hay = `${c.controlId} ${c.name.en} ${c.name.es} ${c.reason ?? ''} ${c.detail ?? ''}`.toLowerCase()
        if (q && !hay.includes(q)) continue
        out.push(`- ${c.controlId} [${c.severity}/${c.status}] (${c.category}) ${c.name.es} — ${(c.detail || c.reason || '').slice(0, 140)}`)
        if (out.length >= lim) break
      }
      return { content: [{ type: 'text', text: out.length ? out.join('\n') : 'No controls matched the filters.' }] }
    },
  )

  // 3 — Top vulnerability matches (KEV first).
  server.tool(
    't82_top_cves',
    'Vulnerability matches of the latest assessment (OSV-confirmed exact-version matches), KEV / highest CVSS first.',
    {
      limit: z.number().int().min(1).max(40).optional().describe('max CVEs returned (default 12)'),
      package: z.string().max(80).optional().describe('filter by package name substring'),
    },
    async ({ limit, package: pkg }) => {
      const v = await api<{ matches: { cveId: string; packageName: string; packageVersion: string; severity: string; cvssScore: number | null; kev: boolean }[] }>(
        '/api/vuln-intel',
      )
      const rows = (v.matches ?? [])
        .filter((m) => !pkg || m.packageName.toLowerCase().includes(pkg.toLowerCase()))
        .sort((a, b) => {
          const kev = Number(b.kev) - Number(a.kev)
          if (kev !== 0) return kev
          const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
          const r = (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4)
          if (r !== 0) return r
          return (b.cvssScore ?? 0) - (a.cvssScore ?? 0)
        })
        .slice(0, limit ?? 12)
      const text = rows.length
        ? rows
            .map(
              (m) =>
                `- ${m.cveId} | ${m.packageName} ${m.packageVersion} | ${m.severity} cvss ${m.cvssScore?.toFixed(1) ?? '?'}${m.kev ? ' | KEV (actively exploited)' : ''}`,
            )
            .join('\n')
        : 'No vulnerability matches recorded for the latest assessment.'
      return { content: [{ type: 'text', text }] }
    },
  )

  // 4 — Knowledge base search (retrieval layer).
  server.tool(
    't82_knowledge_search',
    'Keyword search over the Knowledge Center articles (hardening guidance, control explanations). Returns title, level, platform, category and summary.',
    {
      query: z.string().min(1).max(120).describe('keywords, e.g. ssh, firewall, sysctl, passwords'),
      limit: z.number().int().min(1).max(10).optional(),
    },
    async ({ query, limit }) => {
      const arts = await api<{ slug: string; title: { es: string; en: string }; summary: { es: string; en: string }; level: string; category: string; platforms: string[] }[]>(
        `/api/knowledge/articles?query=${encodeURIComponent(query)}`,
      )
      const rows = (arts ?? []).slice(0, limit ?? 5)
      const text = rows.length
        ? rows.map((a) => `- ${a.title.es} (${a.level}, ${a.category}, ${a.platforms.join('/')}) — ${a.summary.es.slice(0, 160)} [slug: ${a.slug}]`).join('\n')
        : `No knowledge articles matched "${query}".`
      return { content: [{ type: 'text', text }] }
    },
  )

  // 5 — Ask the internal T82 AI assistant (grounded, advisory-only).
  server.tool(
    't82_ask',
    'Ask the T82 internal AI assistant. It answers grounded in the latest assessment data (score, controls, CVEs) with an advisory-only security analyst persona. Spanish or English.',
    {
      question: z.string().min(1).max(1000).describe('the question, e.g. "¿Cuál es mi riesgo más urgente?"'),
      lang: z.enum(['es', 'en']).optional().describe('language hint (default es)'),
    },
    async ({ question, lang }) => {
      const r = await api<{ reply: string; grounded: boolean }>('/api/assistant', {
        method: 'POST',
        body: JSON.stringify({ messages: [{ role: 'user', content: question }], lang: lang ?? 'es' }),
      })
      const tag = r.grounded ? '[grounded in latest assessment]' : '[no assessment data yet]'
      return { content: [{ type: 'text', text: `${r.reply}\n\n${tag}` }] }
    },
  )

  return server
}

// ─── Stateless streamable HTTP transport ─────────────────────────────────────

const app = express()

// ─── Local-first transport hardening (P0) ────────────────────────────────
// The MCP server is a loopback-only service for local clients (Claude
// Desktop, Cursor, local scripts). It must never accept traffic presenting
// a non-local Host header (DNS-rebinding shape) or a cross-origin Origin
// header, and abusive request rates are rejected.

function parseHostname(h?: string): string {
  const v = (h ?? '').trim()
  if (!v) return ''
  if (v.startsWith('[')) {
    const end = v.indexOf(']')
    return end === -1 ? v.toLowerCase() : v.slice(1, end).toLowerCase()
  }
  return v.split(':')[0].trim().toLowerCase()
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname.endsWith('.localhost')
}

function trustedHosts(): string[] {
  return (process.env.MCP_TRUSTED_HOSTS ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
}

// 1) Host allowlist: loopback only (or explicitly trusted via MCP_TRUSTED_HOSTS).
app.use((req, res, next) => {
  const hostName = parseHostname(req.headers.host)
  if (!isLoopback(hostName) && !trustedHosts().includes(hostName)) {
    res.status(403).json({ error: 't82-mcp: non-local Host header rejected — loopback-only service' })
    return
  }
  // 2) Origin validation when present (MCP streamable-HTTP spec recommendation)
  const origin = req.headers.origin
  if (origin) {
    try {
      const o = new URL(origin)
      if (!isLoopback(o.hostname) && o.hostname !== hostName) {
        res.status(403).json({ error: 't82-mcp: cross-origin request rejected' })
        return
      }
    } catch {
      res.status(403).json({ error: 't82-mcp: malformed Origin header' })
      return
    }
  }
  next()
})

// 3) Best-effort rate limit: fixed window, 60 requests/minute — protects the
//    read-only tools against abusive loops (upstream calls carry timeouts).
const RATE_WINDOW_MS = 60_000
const RATE_MAX = 60
let rateWindowStart = Date.now()
let rateCount = 0
app.use((_req, res, next) => {
  const now = Date.now()
  if (now - rateWindowStart > RATE_WINDOW_MS) {
    rateWindowStart = now
    rateCount = 0
  }
  rateCount++
  if (rateCount > RATE_MAX) {
    res.status(429).json({ error: `t82-mcp: rate limit exceeded (${RATE_MAX} req/min)` })
    return
  }
  next()
})

app.use(express.json({ limit: '256kb' }))

app.post('/mcp', async (req, res) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless: no session persistence
      enableJsonResponse: true,
    })
    res.on('close', () => {
      transport.close()
    })
    const server = buildServer()
    await server.connect(transport)
    await transport.handleRequest(req, res, req.body)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: '2.0',
        id: (req.body as { id?: unknown })?.id ?? randomUUID(),
        error: { code: -32603, message: `t82-mcp internal error: ${msg.slice(0, 200)}` },
      })
    }
  }
})

// Reject legacy SSE endpoints (not used in stateless JSON mode).
app.get('/mcp', (_req, res) => {
  res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed (stateless JSON mode: use POST).' } })
})

app.get('/health', async (_req, res) => {
  res.json({
    status: 'ok',
    service: 'vulncheck-t82-mcp',
    version: '1.0.0',
    transport: 'streamable-http (stateless JSON)',
    endpoint: '/mcp',
    upstream: UPSTREAM,
    tools: [
      { name: 't82_latest_posture', description: 'Latest assessment summary (score, coverage, counts, top findings)' },
      { name: 't82_control_search', description: 'Search controls by text/status/severity' },
      { name: 't82_top_cves', description: 'Top vulnerability matches, KEV first' },
      { name: 't82_knowledge_search', description: 'Keyword search over Knowledge Center articles' },
      { name: 't82_ask', description: 'Ask the internal T82 AI assistant (grounded, advisory-only)' },
    ],
  })
})

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[t82-mcp] listening on http://127.0.0.1:${PORT}/mcp (stateless streamable HTTP, loopback-only) → upstream ${UPSTREAM}`)
})
