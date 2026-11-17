'use client'
// DIVISION T82 — app shell: sidebar (13 modules), header, view router, sticky footer.
import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useTheme } from 'next-themes'
import {
  ShieldCheck, Boxes, ListChecks, Flag, Network, Bug, Hammer, Radar,
  GraduationCap, FileText, History, Blocks, Settings, Menu, Sun, Moon,
  Search, Bell, Languages, Activity,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTrigger, SheetTitle } from '@/components/ui/sheet'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useAppStore, type ViewKey } from '@/lib/store'
import { useI18n } from '@/lib/i18n'
import { useEngineStatus, useHistory, useArticles, t82Keys } from '@/hooks/t82-queries'
import { AssistantDock } from '@/components/t82/assistant'
import { cn } from '@/lib/utils'
import { useEffect } from 'react'

const NAV: { key: ViewKey; icon: React.ComponentType<{ className?: string }>; tKey: Parameters<ReturnType<typeof useI18n>['t']>[0] }[] = [
  { key: 'overview', icon: ShieldCheck, tKey: 'nav.overview' },
  { key: 'assets', icon: Boxes, tKey: 'nav.assets' },
  { key: 'assessment', icon: ListChecks, tKey: 'nav.assessment' },
  { key: 'findings', icon: Flag, tKey: 'nav.findings' },
  { key: 'network', icon: Network, tKey: 'nav.network' },
  { key: 'vulnintel', icon: Bug, tKey: 'nav.vulnintel' },
  { key: 'hardening', icon: Hammer, tKey: 'nav.hardening' },
  { key: 'threatintel', icon: Radar, tKey: 'nav.threatintel' },
  { key: 'knowledge', icon: GraduationCap, tKey: 'nav.knowledge' },
  { key: 'reports', icon: FileText, tKey: 'nav.reports' },
  { key: 'history', icon: History, tKey: 'nav.history' },
  { key: 'integrations', icon: Blocks, tKey: 'nav.integrations' },
  { key: 'settings', icon: Settings, tKey: 'nav.settings' },
]

function SidebarContent() {
  const { t } = useI18n()
  const view = useAppStore((s) => s.view)
  const setView = useAppStore((s) => s.setView)
  return (
    <nav aria-label="Modules" className="flex h-full flex-col gap-0.5 overflow-y-auto p-3">
      <div className="mb-4 flex items-center gap-2 px-2 pt-1">
        <div className="flex size-8 items-center justify-center rounded-lg border border-t82-green/40 bg-t82-green/10">
          <ShieldCheck className="size-4.5 text-t82-green" aria-hidden />
        </div>
        <div className="min-w-0">
          <p className="truncate text-sm font-bold t82-caps tracking-wider">{t('app.name')}</p>
          <p className="truncate text-[10px] text-muted-foreground">{t('app.tagline')}</p>
        </div>
      </div>
      {NAV.map((item) => {
        const active = view === item.key
        return (
          <button
            key={item.key}
            onClick={() => setView(item.key)}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex min-h-[44px] items-center gap-2.5 rounded-lg px-3 text-left text-[13px] font-medium transition-colors duration-150',
              active
                ? 'bg-t82-green/10 text-t82-green shadow-[inset_2px_0_0_var(--t82-green)]'
                : 'text-muted-foreground hover:bg-accent hover:text-foreground',
            )}
          >
            <item.icon className="size-4 shrink-0" aria-hidden />
            <span className="truncate">{t(item.tKey)}</span>
          </button>
        )
      })}
      <div className="mt-auto px-2 pb-1 pt-4">
        <p className="text-[10px] leading-relaxed text-muted-foreground font-mono">v1.1.0 · vc.evidence/v1</p>
      </div>
    </nav>
  )
}

function HeaderSearch() {
  const { t, lang } = useI18n()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const setView = useAppStore((s) => s.setView)
  const openArticle = useAppStore((s) => s.openArticle)
  const articles = useArticles({ query: query.length >= 2 ? query : undefined })

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    document.addEventListener('keydown', down)
    return () => document.removeEventListener('keydown', down)
  }, [])

  return (
    <>
      <Button variant="outline" size="sm" className="h-9 gap-2 text-muted-foreground md:w-64 md:justify-start" onClick={() => setOpen(true)}>
        <Search className="size-3.5" aria-hidden />
        <span className="hidden md:inline text-xs">{t('header.search')}</span>
        <kbd className="ml-auto hidden rounded border bg-muted px-1 font-mono text-[10px] md:inline">⌘K</kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput value={query} onValueChange={setQuery} placeholder={t('knowledge.search')} />
        <CommandList>
          <CommandEmpty>—</CommandEmpty>
          <CommandGroup heading={t('nav.overview') === 'Resumen de Seguridad' ? 'Módulos' : 'Modules'}>
            {NAV.map((item) => (
              <CommandItem key={item.key} onSelect={() => { setView(item.key); setOpen(false) }}>
                <item.icon className="size-4" aria-hidden />
                {t(item.tKey)}
              </CommandItem>
            ))}
          </CommandGroup>
          {articles.data && articles.data.length > 0 && (
            <CommandGroup heading={t('knowledge.title')}>
              {articles.data.slice(0, 8).map((a) => (
                <CommandItem key={a.slug} onSelect={() => { setView('knowledge'); openArticle(a.slug); setOpen(false) }}>
                  <GraduationCap className="size-4" aria-hidden />
                  {a.title[lang] ?? a.title.en}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
      </CommandDialog>
    </>
  )
}

function HeaderNotifications() {
  const { t } = useI18n()
  const history = useHistory()
  const items = (history.data ?? []).slice(0, 6)
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="size-9" aria-label={t('header.notifications')}>
          <Bell className="size-4" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-2">
        <p className="px-2 pb-1 text-xs font-semibold t82-caps text-muted-foreground">{t('history.title')}</p>
        {items.length === 0 && <p className="px-2 py-3 text-xs text-muted-foreground">{t('common.noData')}</p>}
        <ul className="max-h-64 space-y-1 overflow-y-auto">
          {items.map((h) => (
            <li key={h.id} className="rounded-md px-2 py-1.5 text-xs hover:bg-accent">
              <span className="font-mono text-t82-cyan">{h.action}</span>
              {h.detail && <span className="block text-muted-foreground">{h.detail}</span>}
              <span className="block text-[10px] text-muted-foreground">{new Date(h.createdAt).toLocaleString()}</span>
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  )
}

function Header() {
  const { t, lang, setLang } = useI18n()
  const { theme, setTheme } = useTheme()
  const status = useEngineStatus()
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <header className="sticky top-0 z-40 border-b bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
      <div className="flex h-14 items-center gap-2 px-3 md:px-5">
        <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" className="size-9 md:hidden" aria-label="Menu">
              <Menu className="size-4" aria-hidden />
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="w-72 p-0">
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SidebarContent />
          </SheetContent>
        </Sheet>

        <div className="flex min-w-0 items-center gap-2">
          <span className="rounded-md border border-t82-green/40 bg-t82-green/10 px-2 py-0.5 font-mono text-[10px] font-bold t82-caps text-t82-green">
            T82
          </span>
          <span className="hidden truncate text-xs text-muted-foreground sm:inline">
            {status.data ? `${status.data.os} · ${status.data.osVersion}` : t('header.os')}
          </span>
        </div>

        <div className="mx-auto hidden md:block">
          <HeaderSearch />
        </div>
        <div className="md:hidden">
          <HeaderSearch />
        </div>

        <div className="flex items-center gap-1">
          <div className="mr-1 hidden items-center gap-1.5 rounded-md border px-2 py-1 sm:flex" title={t('header.engine')}>
            <Activity className={cn('size-3.5', status.data?.lastScanAt ? 'text-t82-green' : 'text-muted-foreground')} aria-hidden />
            <span className="text-[10px] font-mono t82-caps text-muted-foreground">
              {status.data?.lastScanAt ? t('header.engine.on') : t('header.engine.idle')}
            </span>
          </div>
          <HeaderNotifications />
          <Button variant="ghost" size="icon" className="size-9" onClick={() => setLang(lang === 'es' ? 'en' : 'es')} aria-label={t('settings.language')}>
            <Languages className="size-4" aria-hidden />
            <span className="ml-0.5 font-mono text-[10px] font-bold">{lang.toUpperCase()}</span>
          </Button>
          <Button variant="ghost" size="icon" className="size-9" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={t('header.theme')}>
            <Sun className="size-4 dark:hidden" aria-hidden />
            <Moon className="hidden size-4 dark:block" aria-hidden />
          </Button>
        </div>
      </div>
    </header>
  )
}

function LazyView({ view }: { view: ViewKey }) {
  switch (view) {
    case 'overview': return <OverviewView />
    case 'assets': return <AssetsView />
    case 'assessment': return <AssessmentView />
    case 'findings': return <FindingsView />
    case 'network': return <NetworkView />
    case 'vulnintel': return <VulnIntelView />
    case 'hardening': return <HardeningView />
    case 'threatintel': return <ThreatIntelView />
    case 'knowledge': return <KnowledgeView />
    case 'reports': return <ReportsView />
    case 'history': return <HistoryView />
    case 'integrations': return <IntegrationsView />
    case 'settings': return <SettingsView />
  }
}

export default function Page() {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
  }))
  const view = useAppStore((s) => s.view)
  const { t } = useI18n()

  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={200}>
        <div className="flex min-h-screen">
          <aside className="sticky top-0 hidden h-screen w-60 shrink-0 border-r bg-sidebar md:block" aria-label="Sidebar">
            <SidebarContent />
          </aside>
          <div className="flex min-w-0 flex-1 flex-col">
            <Header />
            <main id="main" className="flex-1 px-4 py-5 md:px-6 md:py-6" aria-live="polite">
              <LazyView view={view} />
            </main>
            <footer className="mt-auto border-t bg-card/50 px-4 py-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] md:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-muted-foreground">
                <span className="font-mono">{t('footer.note')}</span>
                <span className="flex flex-wrap items-center gap-2 font-mono">
                  <span
                    className="rounded-md border border-t82-green/30 bg-t82-green/10 px-2 py-0.5 font-semibold text-t82-green"
                    title="Ramón Taboada Olivella — RTO Studio"
                  >
                    {t('footer.by')}
                  </span>
                  <span>{t('app.name')} · {new Date().getFullYear()}</span>
                </span>
              </div>
            </footer>
            <AssistantDock />
          </div>
        </div>
      </TooltipProvider>
    </QueryClientProvider>
  )
}

import { OverviewView } from '@/components/views/overview-view'
import { AssetsView } from '@/components/views/assets-view'
import { AssessmentView } from '@/components/views/assessment-view'
import { FindingsView } from '@/components/views/findings-view'
import { NetworkView } from '@/components/views/network-view'
import { VulnIntelView } from '@/components/views/vuln-intel-view'
import { HardeningView } from '@/components/views/hardening-view'
import { ThreatIntelView } from '@/components/views/threat-intel-view'
import { KnowledgeView } from '@/components/views/knowledge-view'
import { ReportsView } from '@/components/views/reports-view'
import { HistoryView } from '@/components/views/history-view'
import { IntegrationsView } from '@/components/views/integrations-view'
import { SettingsView } from '@/components/views/settings-view'
