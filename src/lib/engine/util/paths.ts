// DIVISION T82 — guarded file access.
// Only fixed, whitelisted paths may be read. No user input ever reaches this module.
// This is the anti path-traversal boundary (docs/ARCHITECTURE_PROPOSAL.md §4).
import { readFile, readdir, stat } from 'node:fs/promises'
import path from 'node:path'

export type ReadResult =
  | { ok: true; content: string }
  | { ok: false; error: string; kind: 'NOT_ALLOWED' | 'NOT_FOUND' | 'NO_PERMISSION' | 'TOO_LARGE' | 'FAILED' }

const MAX_BYTES = 256 * 1024

/** Exact paths the engine is allowed to read (evidence sources). */
const READABLE_FILES = new Set([
  '/etc/os-release',
  '/etc/passwd',
  '/etc/shadow',
  '/etc/group',
  '/etc/login.defs',
  '/etc/ssh/sshd_config',
  '/etc/ssh/sshd_config.d',
  '/etc/sudoers',
  '/etc/sudoers.d',
  '/etc/crypttab',
  '/etc/default/ufw',
  '/etc/ufw/ufw.conf',
  '/etc/nftables.conf',
  '/etc/apparmor.d',
  '/etc/apt/apt.conf.d/20auto-upgrades',
  '/etc/apt/apt.conf.d/10periodic',
  '/proc/sys/kernel/randomize_va_space',
  '/proc/sys/kernel/kptr_restrict',
  '/proc/sys/kernel/dmesg_restrict',
  '/proc/sys/fs/suid_dumpable',
  '/proc/sys/net/ipv4/ip_forward',
  '/proc/sys/net/ipv6/conf/all/forwarding',
  '/proc/sys/net/ipv4/tcp_syncookies',
  '/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts',
  '/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses',
  '/proc/sys/net/ipv4/conf/all/accept_redirects',
  '/proc/sys/net/ipv4/conf/all/send_redirects',
  '/proc/sys/net/ipv4/conf/all/accept_source_route',
  '/proc/sys/net/ipv4/conf/all/log_martians',
  '/proc/sys/net/ipv4/conf/all/rp_filter',
  '/sys/kernel/security/lsm',
  '/sys/module/apparmor/parameters/enabled',
  '/var/lib/apt/lists', // directory listing only — used to verify APT cache freshness
  '/proc/1/comm',
])

function resolveAllowed(p: string): string | null {
  // allow fixed path, or a direct child of an allowed directory entry
  if (READABLE_FILES.has(p)) return p
  for (const dir of ['/etc/ssh/sshd_config.d', '/etc/sudoers.d', '/etc/apparmor.d']) {
    if (p.startsWith(dir + '/')) {
      const rel = p.slice(dir.length + 1)
      // Drop-ins are named by convention WITHOUT a leading dot
      // (sshd_config.d/10-custom.conf, apparmor.d/usr.bin.firefox, sudoers.d/admin);
      // requiring a dot-prefix silently skipped real evidence (fixed 0.3.0).
      // The boundary stays closed: single segment, no traversal, no suffix games.
      if (
        rel.length > 0 &&
        !rel.includes('/') &&
        !rel.includes('..') &&
        !rel.endsWith('~') &&
        !rel.endsWith('#')
      ) {
        return p
      }
    }
  }
  return null
}

export async function safeRead(p: string): Promise<ReadResult> {
  const allowed = resolveAllowed(p)
  if (!allowed) return { ok: false, error: `path not in engine read allowlist: ${p}`, kind: 'NOT_ALLOWED' }
  try {
    const st = await stat(p)
    if (st.isDirectory()) {
      const names = await readdir(p)
      return { ok: true, content: names.join('\n') }
    }
    if (st.size > MAX_BYTES) return { ok: false, error: 'file exceeds 256KB limit', kind: 'TOO_LARGE' }
    const content = await readFile(p, 'utf8')
    return { ok: true, content }
  } catch (e) {
    const err = e as { code?: string }
    if (err.code === 'ENOENT') return { ok: false, error: `${p}: not found`, kind: 'NOT_FOUND' }
    if (err.code === 'EACCES') return { ok: false, error: `${p}: permission denied (root required)`, kind: 'NO_PERMISSION' }
    return { ok: false, error: `${p}: ${String(err.code ?? 'error')}`, kind: 'FAILED' }
  }
}

export async function safeStat(p: string): Promise<
  | { ok: true; mode: string; owner: string; group: string; path: string }
  | { ok: false; error: string }
> {
  // B2 hardening: stat obeys the SAME allowlist as reads — a bare
  // `p.startsWith('/etc/')` accepted metadata probing of ANY /etc file.
  const allowed = resolveAllowed(p) !== null
  if (!allowed) return { ok: false, error: `path not allowed for stat: ${p}` }
  try {
    const st = await stat(p)
    const mode = (st.mode & 0o777).toString(8).padStart(3, '0')
    return { ok: true, mode, owner: String(st.uid), group: String(st.gid), path: p }
  } catch (e) {
    return { ok: false, error: `${p}: ${(e as { code?: string }).code ?? 'error'}` }
  }
}

export function parseKeyValueFile(content: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
    if (m) out[m[1]] = m[2].trim().replace(/^"(.*)"$/, '$1')
  }
  return out
}

export function parseSimpleOptions(content: string): Record<string, string> {
  // sshd_config-style: Key value [# comment] — last value wins (mirrors sshd semantics)
  const out: Record<string, string> = {}
  for (const line of content.split('\n')) {
    const trimmed = line.replace(/#.*$/, '').trim()
    if (!trimmed) continue
    const m = trimmed.match(/^([A-Za-z][A-Za-z0-9]*)\s+(.+)$/)
    if (m) out[m[1]] = m[2].trim()
  }
  return out
}
