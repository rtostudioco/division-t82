'use client'
// DIVISION T82 — installer download center (client).
// Lists distributable artifacts from dist/ (via /api/download), triggers
// server-side generation (source packaging only — no compilation here) and
// serves the files with checksum verification.
import { useCallback, useEffect, useState } from 'react'
import { AppWindow, AppWindowMac, Download, FileArchive, Loader2, Package, PackageOpen, ShieldCheck } from 'lucide-react'
import { SectionCard } from '@/components/t82/shared'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { useI18n } from '@/lib/i18n'
import { useToast } from '@/hooks/use-toast'

interface ArtifactInfo {
  name: string
  kind: 'portable' | 'deb' | 'windows' | 'macos' | 'checksums'
  size: number
  sha256: string
  generatedAt: string
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function kindIcon(kind: ArtifactInfo['kind'], cls: string) {
  if (kind === 'portable') return <Package className={cls} aria-hidden />
  if (kind === 'deb') return <FileArchive className={cls} aria-hidden />
  if (kind === 'windows') return <AppWindow className={cls} aria-hidden />
  if (kind === 'macos') return <AppWindowMac className={cls} aria-hidden />
  return <ShieldCheck className={cls} aria-hidden />
}

export function DownloadsCard() {
  const { t, lang } = useI18n()
  const { toast } = useToast()
  const [artifacts, setArtifacts] = useState<ArtifactInfo[]>([])
  const [loaded, setLoaded] = useState(false)
  const [generating, setGenerating] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/download', { cache: 'no-store' })
      const data = (await res.json()) as { artifacts?: ArtifactInfo[] }
      setArtifacts(data.artifacts ?? [])
    } catch {
      /* catalog refresh is non-critical */
    } finally {
      setLoaded(true)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const generate = async () => {
    if (generating) return
    setGenerating(true)
    try {
      const res = await fetch('/api/download', { method: 'POST' })
      const data = (await res.json()) as { artifacts?: ArtifactInfo[]; error?: string }
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`)
      setArtifacts(data.artifacts ?? [])
      toast({ title: t('downloads.generatedOk'), description: t('downloads.generatedDesc') })
    } catch (e) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: String((e as Error).message).slice(0, 180),
      })
    } finally {
      setGenerating(false)
    }
  }

  const download = (name: string) => {
    window.location.href = `/api/download/file?name=${encodeURIComponent(name)}`
  }

  const portable = artifacts.find((a) => a.kind === 'portable')
  const deb = artifacts.find((a) => a.kind === 'deb')
  const win = artifacts.find((a) => a.kind === 'windows')
  const mac = artifacts.find((a) => a.kind === 'macos')
  const locale = lang === 'es' ? 'es-ES' : 'en-US'

  return (
    <SectionCard title={t('downloads.title')} description={t('downloads.hint')}>
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            className="min-h-11"
            onClick={() => void generate()}
            disabled={generating}
          >
            {generating ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <PackageOpen className="size-4" aria-hidden />
            )}
            {generating ? t('downloads.generating') : t('downloads.generate')}
          </Button>
          {artifacts.length > 0 && (
            <span className="text-xs text-muted-foreground">
              {new Date(artifacts[0].generatedAt).toLocaleString(locale, {
                dateStyle: 'short',
                timeStyle: 'short',
              })}
            </span>
          )}
        </div>

        {loaded && artifacts.length === 0 && (
          <p className="rounded-md border border-dashed px-3 py-3 text-sm text-muted-foreground">
            {t('downloads.empty')} — {t('downloads.emptyHint')}
          </p>
        )}

        {artifacts.map((a) => (
          <div
            key={a.name}
            className="flex flex-col gap-2 rounded-md border bg-card/50 px-3 py-2.5 sm:flex-row sm:items-center"
          >
            <div className="flex min-w-0 flex-1 items-center gap-2.5">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-md border bg-background">
                {kindIcon(a.kind, 'size-4 text-t82-green')}
              </div>
              <div className="min-w-0">
                <p className="truncate font-mono text-xs font-medium" title={a.name}>
                  {a.name}
                </p>
                <p className="mt-0.5 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-muted-foreground">
                  <span>{formatSize(a.size)}</span>
                  <span title={a.sha256}>· sha256 {a.sha256.slice(0, 12)}…</span>
                </p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              className="min-h-9 shrink-0"
              onClick={() => download(a.name)}
            >
              <Download className="size-3.5" aria-hidden />
              {t('downloads.download')}
            </Button>
          </div>
        ))}

        {(portable || deb || win || mac) && (
          <div className="grid gap-2 sm:grid-cols-2">
            {portable && (
              <div className="rounded-md border bg-muted/40 p-2.5">
                <Badge variant="outline" className="mb-1.5 text-[9px]">
                  {t('downloads.installPortable')}
                </Badge>
                <pre className="overflow-x-auto font-mono text-[10px] leading-relaxed text-muted-foreground">
                  {`tar -xzf ${portable.name}\ncd vulncheck-t82\nsudo ./install.sh`}
                </pre>
              </div>
            )}
            {deb && (
              <div className="rounded-md border bg-muted/40 p-2.5">
                <Badge variant="outline" className="mb-1.5 text-[9px]">
                  {t('downloads.installDeb')}
                </Badge>
                <pre className="overflow-x-auto font-mono text-[10px] leading-relaxed text-muted-foreground">
                  {`sudo dpkg -i ${deb.name}\nsudo systemctl enable --now vulncheck-t82`}
                </pre>
              </div>
            )}
            {win && (
              <div className="rounded-md border bg-muted/40 p-2.5">
                <Badge variant="outline" className="mb-1.5 text-[9px]">
                  {t('downloads.installWindows')}
                </Badge>
                <pre className="overflow-x-auto font-mono text-[10px] leading-relaxed text-muted-foreground">
                  {`${win.name}\n# Ejecutar como administrador (UAC)\n# Servicio 'VulncheckT82' · http://127.0.0.1:3000`}
                </pre>
              </div>
            )}
            {mac && (
              <div className="rounded-md border bg-muted/40 p-2.5">
                <Badge variant="outline" className="mb-1.5 text-[9px]">
                  {t('downloads.installMacos')}
                </Badge>
                <pre className="overflow-x-auto font-mono text-[10px] leading-relaxed text-muted-foreground">
                  {`${mac.name}\n# .dmg: abrir y copiar la .app a Aplicaciones\n# .pkg: sudo installer -pkg <file> -target /`}
                </pre>
              </div>
            )}
          </div>
        )}

        <p className="text-[10px] leading-relaxed text-muted-foreground">{t('downloads.note')}</p>
        <p className="text-[10px] leading-relaxed text-muted-foreground">{t('downloads.nativeNote')}</p>
      </div>
    </SectionCard>
  )
}

export default DownloadsCard
