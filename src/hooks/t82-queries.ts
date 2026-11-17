'use client'
// DIVISION T82 — typed client data layer. The ONLY way views talk to the engine.
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', ...init })
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      if (body?.error) detail = body.error
    } catch { /* keep status code */ }
    throw new Error(detail)
  }
  return res.json() as Promise<T>
}

export interface EngineStatus {
  platform: 'linux' | 'windows' | 'macos'
  platformLabel: string
  hostname: string
  os: string
  osVersion: string
  distro: string | null
  kernel: string
  arch: string
  user: string
  isRoot: boolean
  adapters: { platform: string; status: string; reason?: string }[]
  engineVersion: string
  rulesTotal: number
  rulesImplementedLinux: number
  lastScanAt: string | null
}

export interface LocStr { en: string; es: string }

export interface ScanListItem {
  id: string
  startedAt: string
  finishedAt: string | null
  status: string
  score: number | null
  coverage: number
  counts: Record<string, number>
  severityCounts: Record<string, number>
  host: { hostname: string; os: string; osVersion: string }
}

export interface ControlResultItem {
  id: string
  controlId: string
  name: LocStr
  category: string
  severity: string
  status: string
  reason: string | null
  detail: string | null
  explanation: LocStr | null
  limitations: LocStr | null
  evidenceSource?: string
  implemented: boolean
  evidence?: { method: string; source: string; confidence: string; privilegesRequired: string | null }[]
  durationMs?: number
}

export interface CategoryScoreItem {
  category: string
  score: number | null
  scored: number
  total: number
  notScored: string[]
}

export interface ScanDetail {
  id: string
  startedAt: string
  finishedAt: string | null
  status: string
  score: number | null
  coverage: number
  counts: Record<string, number>
  severityCounts: Record<string, number>
  host: { hostname: string; os: string; osVersion: string; kernel: string; arch: string; isRoot: boolean }
  categories: CategoryScoreItem[]
  controls: ControlResultItem[]
  formula: string
}

export interface FindingItem {
  controlId: string
  name: LocStr
  severity: string
  status: string
  category: string
  detail: string | null
  explanation: LocStr | null
}

export interface Inventory {
  os: { prettyName: string; id: string; versionId: string } | null
  kernel: string | null
  platform: { hostname: string; arch: string; user: string; isRoot: boolean }
  hardware: { cpuModel: string | null; cpuCores: number | null; memoryTotalMB: number | null; uptimeHours: number | null }
  packages: { count: number | null; list?: { name: string; version: string }[] | null }
  users: { human: { name: string; uid: number; shell: string; home: string }[]; systemCount: number; rootOnlyUid0: string[] }
  network: {
    interfaces: { name: string; address: string; internal: boolean }[] | null
    listeners: { proto: string; address: string; port: number }[] | null
    ipForward: number | null
    firewall: { ufwInstalled: boolean; ufwEnabled: boolean | null; nftablesInstalled: boolean; nftablesConfExists: boolean; iptablesInstalled: boolean; tool: string | null; active: boolean | null }
  }
  identity: { shadowReadable: boolean; sudoersReadable: boolean; sudoersFiles: string[]; passwordMaxDays: string | null; sshdPresent: boolean }
  hardening: {
    sysctls: { randomize_va_space: number | null; kptr_restrict: number | null; dmesg_restrict: number | null; suid_dumpable: number | null }
    sysctlsNet?: {
      accept_redirects: number | null
      send_redirects: number | null
      accept_source_route: number | null
      icmp_echo_ignore_broadcasts: number | null
      icmp_ignore_bogus_error_responses: number | null
      tcp_syncookies: number | null
      log_martians: number | null
      rp_filter: number | null
    }
    systemdRunning: boolean | null
    runningServices: string[] | null
    initComm: string | null
    apparmorLsmActive: boolean | null
    filePerms: { path: string; mode: string; error?: string }[]
  }
  encryption: { crypttabExists: boolean; cryptsetupInstalled: boolean }
  endpoint: { clamavInstalled: boolean; gccInstalled: boolean }
  swap?: { devices: { name: string; size: string; type: string; mountpoint: string }[] | null }
  updates: { aptCacheFresh: boolean | null; pendingUpdates: number | null; pendingSecurityUpdates: number | null; unattendedUpgradesEnabled: boolean | null; unattendedInstalled: boolean }
  evidenceNotes: string[]
  collectedAt: string
}

export interface NetworkInfo {
  fromScanId: string | null
  listeners: { proto: string; address: string; port: number }[] | null
  interfaces: { name: string; address: string; internal: boolean }[] | null
  firewall: { detected: boolean; active: boolean | null; tool: string | null; note?: string }
  ipForward: number | null
}

export interface ArticleMeta {
  slug: string
  title: LocStr
  summary: LocStr
  level: string
  category: string
  platforms: string[]
  relatedControls: string[]
  mitre: { id: string; name: string }[]
}

export interface ArticleFull extends ArticleMeta {
  technicalDescription: LocStr
  rootCause: LocStr
  howItHappens: LocStr
  threatContext: LocStr
  cve?: string[]
  cwe?: string[]
  indicators: LocStr
  detection: LocStr
  prevention: LocStr
  mitigation: LocStr
  verification: LocStr
  secureConfigExample?: { label: string; language: string; code: string }
  defensiveCodeExample?: { label: string; language: string; code: string }
  labScenario?: { title: LocStr; steps: string[]; safetyNote: LocStr }
  references: { label: string; url: string }[]
  reviewedAt: string
}

export interface RemediationPreview {
  controlId: string
  controlName: LocStr
  severity: string
  category: string
  implemented: boolean
  remediation: {
    problemSummary: LocStr
    rootCause: LocStr
    risk: LocStr
    priority: string
    currentStateNote: LocStr
    recommendedState: LocStr
    steps: { title: LocStr; command?: string; note?: LocStr }[]
    affectedFiles?: string[]
    sideEffects: LocStr
    prerequisites: LocStr
    rollback: LocStr
    verify: LocStr
    advisoryOnly: boolean
  }
  references: { label: string; url: string }[]
  currentFinding?: { status: string; detail: string | null }
}

export interface HistoryItem {
  id: string
  action: string
  target: string | null
  detail: string | null
  createdAt: string
}

export interface VulnRecordItem {
  cveId: string
  title: string
  cvssScore: number | null
  cvssVector: string | null
  cwes: string[]
  kev: boolean
  source: string
  publishedAt: string | null
  modifiedAt: string | null
}

export interface VulnMatchItem {
  cveId: string
  title: string
  packageName: string
  packageVersion: string
  severity: string
  cvssScore: number | null
  kev: boolean
  ecosystem: string
  matchedAt: string
}

export interface IngestSourceStatus {
  ok: boolean
  skipped?: string
  packagesQueried?: number
  matchedPackages?: number
  matches?: number
  recordsUpserted?: number
  kevMarked?: number
  error?: string
}

export interface VulnIntelData {
  catalog: { total: number; kev: number; highOrAbove: number }
  lastIngest: { at: string; osv: IngestSourceStatus; nvd: IngestSourceStatus; cisa?: IngestSourceStatus } | null
  latestScan: { id: string; startedAt: string; hostname: string; os: string } | null
  matches: VulnMatchItem[]
  records: VulnRecordItem[]
}

export interface OverviewData {
  engine: {
    platform: string
    hostname: string
    os: string
    osVersion: string
    kernel: string
    arch: string
    isRoot: boolean
    adapters: { platform: string; status: string; reason?: string }[]
    engineVersion: string
  }
  lastScan: {
    id: string
    startedAt: string
    finishedAt: string | null
    score: number | null
    coverage: number
    counts: Record<string, number>
    severityCounts: Record<string, number>
  } | null
  scoreHistory: { at: string; score: number | null; coverage: number }[]
  categoryScores: { category: string; score: number | null; scored: number; total: number }[]
  topFindings: FindingItem[]
}

export const t82Keys = {
  engineStatus: ['engine-status'] as const,
  overview: ['overview'] as const,
  scans: ['scans'] as const,
  scan: (id: string) => ['scan', id] as const,
  findings: (id: string) => ['findings', id] as const,
  inventory: (id: string) => ['inventory', id] as const,
  network: ['network'] as const,
  articles: (q: string) => ['articles', q] as const,
  article: (slug: string) => ['article', slug] as const,
  remediation: (c: string) => ['remediation', c] as const,
  history: ['history'] as const,
  vulnIntel: ['vuln-intel'] as const,
  vulnSchedule: ['vuln-schedule'] as const,
  remTasks: ['remediation-tasks'] as const,
  assistantConversations: ['assistant-conversations'] as const,
}

export function useEngineStatus() {
  return useQuery({
    queryKey: t82Keys.engineStatus,
    queryFn: () => fetchJson<EngineStatus>('/api/engine/status'),
    staleTime: 30_000,
  })
}

export function useOverview() {
  return useQuery({ queryKey: t82Keys.overview, queryFn: () => fetchJson<OverviewData>('/api/overview') })
}

export function useScans() {
  return useQuery({ queryKey: t82Keys.scans, queryFn: () => fetchJson<ScanListItem[]>('/api/scans') })
}

export function useScan(id: string | null) {
  return useQuery({
    queryKey: t82Keys.scan(id ?? 'none'),
    queryFn: () => fetchJson<ScanDetail>(`/api/scans/${id}`),
    enabled: !!id,
  })
}

export function useFindings(scanId: string | null) {
  return useQuery({
    queryKey: t82Keys.findings(scanId ?? 'none'),
    queryFn: () => fetchJson<FindingItem[]>(`/api/scans/${scanId}/findings`),
    enabled: !!scanId,
  })
}

export function useInventory(scanId: string | null) {
  return useQuery({
    queryKey: t82Keys.inventory(scanId ?? 'none'),
    queryFn: () => fetchJson<Inventory>(`/api/scans/${scanId}/inventory`),
    enabled: !!scanId,
  })
}

export function useNetwork() {
  return useQuery({ queryKey: t82Keys.network, queryFn: () => fetchJson<NetworkInfo>('/api/network') })
}

export function useArticles(q: { query?: string; category?: string; level?: string; platform?: string }) {
  const params = new URLSearchParams()
  if (q.query) params.set('query', q.query)
  if (q.category) params.set('category', q.category)
  if (q.level) params.set('level', q.level)
  if (q.platform) params.set('platform', q.platform)
  return useQuery({
    queryKey: t82Keys.articles(params.toString()),
    queryFn: () => fetchJson<ArticleMeta[]>(`/api/knowledge/articles?${params.toString()}`),
  })
}

export function useArticle(slug: string | null) {
  return useQuery({
    queryKey: t82Keys.article(slug ?? 'none'),
    queryFn: () => fetchJson<ArticleFull>(`/api/knowledge/articles/${slug}`),
    enabled: !!slug,
  })
}

export function useRemediation(controlId: string | null) {
  return useQuery({
    queryKey: t82Keys.remediation(controlId ?? 'none'),
    queryFn: () => fetchJson<RemediationPreview>(`/api/remediation/${controlId}`),
    enabled: !!controlId,
  })
}

export function useHistory() {
  return useQuery({ queryKey: t82Keys.history, queryFn: () => fetchJson<HistoryItem[]>('/api/history') })
}

export function useRunScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (scope: string[]) =>
      fetchJson<{ scanId: string }>('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries()
    },
  })
}

export function useResetData() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => fetchJson<{ ok: boolean }>('/api/settings/reset', { method: 'POST' }),
    onSuccess: () => {
      void qc.invalidateQueries()
    },
  })
}

export function useVulnIntel() {
  return useQuery({
    queryKey: t82Keys.vulnIntel,
    queryFn: () => fetchJson<VulnIntelData>('/api/vuln-intel'),
  })
}

export function useIngestVulns() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () =>
      fetchJson<IngestSourceStatus & { at: string; osv: IngestSourceStatus; nvd: IngestSourceStatus; cisa: IngestSourceStatus }>(
        '/api/vuln-intel/ingest',
        { method: 'POST' },
      ),
    onSuccess: () => {
      void qc.invalidateQueries()
    },
  })
}

// ─── Scheduled ingestion ────────────────────────────────────────────────────

export interface VulnScheduleState {
  enabled: boolean
  lastIngestAt: string | null
}

export function useVulnSchedule() {
  return useQuery({
    queryKey: t82Keys.vulnSchedule,
    queryFn: () => fetchJson<VulnScheduleState>('/api/vuln-intel/schedule'),
  })
}

export function useSetVulnSchedule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (enabled: boolean) =>
      fetchJson<VulnScheduleState>('/api/vuln-intel/schedule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: t82Keys.vulnSchedule })
      void qc.invalidateQueries({ queryKey: t82Keys.history })
    },
  })
}

// ─── Remediation tasks (advisory checklist) ─────────────────────────────────

export interface RemediationTaskItem {
  id: string
  controlId: string
  scanId: string | null
  title: string
  status: 'OPEN' | 'IN_PROGRESS' | 'DONE' | 'DISMISSED'
  createdAt: string
  updatedAt: string
  closedAt: string | null
}

export function useRemediationTasks() {
  return useQuery({
    queryKey: t82Keys.remTasks,
    queryFn: () => fetchJson<RemediationTaskItem[]>('/api/remediation-tasks'),
  })
}

export function useCreateRemediationTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { controlId: string; title: string; scanId?: string; payload?: Record<string, unknown> }) =>
      fetchJson<{ task: RemediationTaskItem; created: boolean }>('/api/remediation-tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: t82Keys.remTasks })
      void qc.invalidateQueries({ queryKey: t82Keys.history })
    },
  })
}

export function useUpdateRemediationTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: { id: string; status: RemediationTaskItem['status'] }) =>
      fetchJson<{ task: RemediationTaskItem }>(`/api/remediation-tasks/${input.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: input.status }),
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: t82Keys.remTasks })
      void qc.invalidateQueries({ queryKey: t82Keys.history })
    },
  })
}

export function useDeleteRemediationTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => fetchJson<{ ok: boolean }>(`/api/remediation-tasks/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: t82Keys.remTasks })
      void qc.invalidateQueries({ queryKey: t82Keys.history })
    },
  })
}

// ─── Assistant conversation history ────────────────────────────────────────

export interface AssistantConversationMeta {
  id: string
  title: string
  grounded: boolean
  score: number | null
  messageCount: number
  createdAt: string
  updatedAt: string
}

export interface AssistantConversationFull extends AssistantConversationMeta {
  messages: { role: 'user' | 'assistant'; content: string }[]
}

export function useAssistantConversations() {
  return useQuery({
    queryKey: t82Keys.assistantConversations,
    queryFn: () => fetchJson<AssistantConversationMeta[]>('/api/assistant/conversations'),
    enabled: false, // fetched on demand when the history panel opens
  })
}

export async function fetchAssistantConversation(id: string): Promise<AssistantConversationFull> {
  return fetchJson<AssistantConversationFull>(`/api/assistant/conversations/${id}`)
}
