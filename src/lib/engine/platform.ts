// DIVISION T82 — platform detection (read-only, os-api + /etc/os-release)
import os from 'node:os'
import { safeRead, parseKeyValueFile } from './util/paths'
import type { OsReleaseInfo, PlatformInfo } from './collectors/linux/bag'
import type { Platform } from './types'

export async function detectOsRelease(): Promise<OsReleaseInfo | null> {
  const res = await safeRead('/etc/os-release')
  if (!res.ok) return null
  const kv = parseKeyValueFile(res.content)
  return {
    prettyName: kv.PRETTY_NAME ?? kv.NAME ?? 'Unknown',
    name: kv.NAME ?? 'Unknown',
    versionId: kv.VERSION_ID ?? 'unknown',
    id: (kv.ID ?? 'unknown').toLowerCase(),
    idLike: (kv.ID_LIKE ?? '').toLowerCase().split(/\s+/).filter(Boolean),
  }
}

export function familyOf(osRelease: OsReleaseInfo | null): PlatformInfo['distroFamily'] {
  if (!osRelease) return null
  if (osRelease.id === 'ubuntu' || osRelease.idLike.includes('ubuntu')) return 'ubuntu'
  if (osRelease.id === 'debian' || osRelease.idLike.includes('debian')) return 'debian'
  return 'other'
}

export async function detectPlatform(): Promise<PlatformInfo> {
  const cpus = os.cpus()
  const osRelease = await detectOsRelease()
  const isWindows = process.platform === 'win32'
  const isMac = process.platform === 'darwin'
  const platform: Platform = isWindows ? 'windows' : isMac ? 'macos' : 'linux'
  return {
    platform,
    hostname: os.hostname(),
    os: osRelease?.prettyName ?? (isWindows ? 'Windows' : isMac ? 'macOS' : 'Linux'),
    osVersion: osRelease?.versionId ?? os.version?.() ?? '',
    distro: osRelease?.id ?? null,
    distroFamily: familyOf(osRelease),
    kernel: os.release(),
    arch: process.arch,
    user: process.env.USER ?? process.env.USERNAME ?? String(process.getuid?.() ?? 'unknown'),
    isRoot: process.getuid ? process.getuid() === 0 : false,
    ...(cpus.length > 0 ? {} : {}),
  }
}
