// DIVISION T82 — Linux evidence collectors (read-only, one function per domain).
// Security rules (docs/ARCHITECTURE_PROPOSAL.md §4):
//   - every collector runs inside its own try/catch: a failing collector NEVER
//     breaks the scan — it sets the bag's *Error field and leaves data null/default
//   - ONLY safeExec (closed allowlist) + safeRead/safeStat (fixed path allowlist)
//   - no shell, no user input, no secrets: /etc/shadow HASHES are never stored —
//     only per-account lock/empty/set statuses
import os from 'node:os'
import { emptyBag } from './bag'
import type { LinuxEvidenceBag, PlatformInfo } from './bag'
import { safeExec } from '../../util/exec'
import { safeRead, safeStat, parseKeyValueFile } from '../../util/paths'

// ─── Runtime-only bag extensions (contract-compatible) ──────────────────────
// The bag type is fixed, but derived (non-secret) shadow statuses must reach the
// rules. LinuxEvidenceBag consumers tolerate the extra optional property at
// runtime; both sides use this typed view instead of `any`.

export type ShadowAccountStatus = 'locked' | 'EMPTY' | 'SET'

export interface ShadowStatusEntry {
  name: string
  status: ShadowAccountStatus
}

export interface LinuxEvidenceBagWithShadow extends LinuxEvidenceBag {
  /** Derived per-account status ONLY (never hash strings). Runtime property. */
  shadowStatuses?: ShadowStatusEntry[]
}

// ─── Small parse helpers ─────────────────────────────────────────────────────

function errorMessage(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e)
  return msg.slice(0, 300)
}

/** Parse /etc/passwd lines: name:x:uid:gid:gecos:home:shell */
function parsePasswd(content: string): LinuxEvidenceBag['passwd'] {
  const users: NonNullable<LinuxEvidenceBag['passwd']> = []
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const f = trimmed.split(':')
    if (f.length < 7) continue
    const uid = Number(f[2])
    const gid = Number(f[3])
    if (!Number.isInteger(uid) || !Number.isInteger(gid)) continue
    users.push({ name: f[0], uid, gid, home: f[5] ?? '', shell: f[6] ?? '' })
  }
  return users
}

/**
 * Parse per-account STATUS from /etc/shadow field 2 — never the hash itself:
 *   starts with '!' or '*' → 'locked'   |   empty → 'EMPTY'   |   anything else → 'SET'
 * (e.g. '$6$...' or '$y$...'). The resulting array contains only names+statuses.
 */
function parseShadowStatuses(content: string): ShadowStatusEntry[] {
  const out: ShadowStatusEntry[] = []
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('!')) continue
    const f = trimmed.split(':')
    if (f.length < 2 || !f[0]) continue
    const field2 = f[1]
    let status: ShadowAccountStatus
    if (field2.startsWith('!') || field2.startsWith('*')) status = 'locked'
    else if (field2 === '') status = 'EMPTY'
    else status = 'SET'
    out.push({ name: f[0], status })
  }
  return out
}

/**
 * sshd_config parser with FIRST-OCCURRENCE-WINS semantics, mirroring sshd(8):
 * "the first obtained value for each keyword is used". util/paths
 * parseSimpleOptions() is last-wins, so sshd files are parsed here instead.
 */
function parseSshdFirstWins(content: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of content.split('\n')) {
    const trimmed = line.replace(/#.*$/, '').trim()
    if (!trimmed) continue
    const m = trimmed.match(/^([A-Za-z][A-Za-z0-9]*)\s+(.+)$/)
    if (m && !(m[1] in out)) out[m[1]] = m[2].trim()
  }
  return out
}

/** Un-commented `Include <args>` directives of the main sshd_config. */
function sshdIncludeArgs(content: string): string[] {
  const args: string[] = []
  for (const line of content.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const m = trimmed.match(/^Include\s+(.+)$/i)
    if (m) args.push(...m[1].trim().split(/\s+/))
  }
  return args
}

/**
 * Merge sshd options following sshd(8) semantics:
 *  1. If the main config has an Include directive pointing at sshd_config.d
 *     (e.g. "/etc/ssh/sshd_config.d/*.conf"), options from the included files
 *     are applied FIRST — files sorted by name, each file's first occurrence
 *     wins, and across files the first file that sets a key wins.
 *  2. Then main-file options are applied ONLY where the key is not already set
 *     (first obtained value wins globally).
 * If there is no Include directive, the main file is used alone.
 */
async function collectSshdMerged(): Promise<{
  present: boolean
  merged: Record<string, string>
  error?: string
}> {
  const main = await safeRead('/etc/ssh/sshd_config')
  if (!main.ok) {
    return { present: false, merged: {}, error: main.error }
  }
  const merged: Record<string, string> = {}
  const includes = sshdIncludeArgs(main.content)
  const includesSshdDir = includes.some((a) => a.includes('sshd_config.d'))
  if (includesSshdDir) {
    const dir = await safeRead('/etc/ssh/sshd_config.d')
    if (dir.ok) {
      const files = dir.content
        .split('\n')
        .map((s) => s.trim())
        .filter((n) => n.length > 0 && n !== '.' && n !== '..' && n.endsWith('.conf'))
        .sort()
      for (const file of files) {
        // Drop-ins carry conventional names (10-custom.conf, 50-cloud-init.conf);
        // the path boundary admits any single-segment name (fixed 0.3.0).
        const res = await safeRead(`/etc/ssh/sshd_config.d/${file}`)
        if (!res.ok) continue
        const opts = parseSshdFirstWins(res.content)
        for (const [k, v] of Object.entries(opts)) {
          if (!(k in merged)) merged[k] = v
        }
      }
    }
  }
  const mainOpts = parseSshdFirstWins(main.content)
  for (const [k, v] of Object.entries(mainOpts)) {
    if (!(k in merged)) merged[k] = v
  }
  return { present: true, merged }
}

/**
 * Parse `ss -tulnH` output. Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port
 * e.g. "udp UNCONN 0 0 127.0.0.1:323 0.0.0.0:*" → local is column index 4.
 * '[::]:22' → address '::'; '*:81' → address '*' (wildcard); '0.0.0.0:22' → '0.0.0.0'.
 */
function parseSsListeners(stdout: string): NonNullable<LinuxEvidenceBag['listeners']> {
  const out: NonNullable<LinuxEvidenceBag['listeners']> = []
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const cols = trimmed.split(/\s+/)
    if (cols.length < 5) continue
    const netid = cols[0]
    const local = cols[4]
    if (netid !== 'tcp' && netid !== 'udp' && netid !== 'tcp6' && netid !== 'udp6') continue
    const idx = local.lastIndexOf(':')
    if (idx <= 0) continue
    const port = Number(local.slice(idx + 1))
    if (!Number.isInteger(port) || port < 0 || port > 65535) continue
    let address = local.slice(0, idx)
    if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1)
    const isV6 = netid.endsWith('6') || address.includes(':')
    out.push({
      proto: netid.startsWith('tcp') ? (isV6 ? 'tcp6' : 'tcp') : isV6 ? 'udp6' : 'udp',
      address,
      port,
    })
  }
  return out
}

/** Binary presence via the allowlisted `stat -c '%a %U %G %n' <path>`. */
async function binaryPresent(path: string): Promise<boolean> {
  const res = await safeExec('stat', ['-c', '%a %U %G %n', path])
  return res.ok
}

function parseProcNumber(content: string): number | null {
  const n = Number(content.trim())
  return Number.isFinite(n) ? n : null
}

// ─── Main collector ──────────────────────────────────────────────────────────

export async function collectLinuxEvidence(platform: PlatformInfo): Promise<LinuxEvidenceBag> {
  const bag = emptyBag(platform)

  // ── os-release ────────────────────────────────────────────────────────────
  try {
    const res = await safeRead('/etc/os-release')
    if (res.ok) {
      const kv = parseKeyValueFile(res.content)
      bag.osRelease = {
        prettyName: kv.PRETTY_NAME ?? kv.NAME ?? 'Unknown',
        name: kv.NAME ?? 'Unknown',
        versionId: kv.VERSION_ID ?? 'unknown',
        id: (kv.ID ?? 'unknown').toLowerCase(),
        idLike: (kv.ID_LIKE ?? '').toLowerCase().split(/\s+/).filter(Boolean),
      }
    } else {
      bag.osReleaseError = res.error
    }
  } catch (e) {
    bag.osReleaseError = errorMessage(e)
  }

  // ── kernel release (uname -r; fallback to detected platform.kernel) ───────
  try {
    const res = await safeExec('uname', ['-r'])
    bag.kernelRelease = res.ok ? res.stdout.trim() || platform.kernel : platform.kernel
  } catch {
    bag.kernelRelease = platform.kernel // platform detection data is honest fallback
  }

  // ── /etc/passwd ───────────────────────────────────────────────────────────
  try {
    const res = await safeRead('/etc/passwd')
    if (res.ok) {
      bag.passwd = parsePasswd(res.content)
    } else {
      bag.passwdError = res.error
    }
  } catch (e) {
    bag.passwdError = errorMessage(e)
  }

  // ── /etc/shadow → statuses ONLY (hashes never stored) ─────────────────────
  try {
    const res = await safeRead('/etc/shadow')
    if (res.ok) {
      bag.shadowReadable = true
      const statuses = parseShadowStatuses(res.content)
      ;(bag as LinuxEvidenceBagWithShadow).shadowStatuses = statuses
    } else {
      bag.shadowReadable = false
      bag.shadowError = res.error
    }
  } catch (e) {
    bag.shadowReadable = false
    bag.shadowError = errorMessage(e)
  }

  // ── /etc/sudoers (+ /etc/sudoers.d listing) ───────────────────────────────
  try {
    const res = await safeRead('/etc/sudoers')
    if (res.ok) {
      bag.sudoersReadable = true
      bag.sudoersContent = res.content
    } else {
      bag.sudoersReadable = false
      bag.sudoersError = res.error
    }
  } catch (e) {
    bag.sudoersReadable = false
    bag.sudoersError = errorMessage(e)
  }
  try {
    const res = await safeRead('/etc/sudoers.d')
    if (res.ok) {
      bag.sudoersFiles = res.content
        .split('\n')
        .map((s) => s.trim())
        .filter((n) => n.length > 0 && n !== '.' && n !== '..')
        // sudoers(5) ignores drop-ins containing '.' or ending in '~'/'#' —
        // listing only files sudoers actually reads keeps the evidence honest.
        .filter((n) => /^[A-Za-z0-9_-]+$/.test(n))
    }
  } catch {
    // sudoers.d listing is optional evidence; leave [] on failure
  }

  // ── /etc/login.defs ───────────────────────────────────────────────────────
  try {
    const res = await safeRead('/etc/login.defs')
    if (res.ok) {
      bag.loginDefs = parseKeyValueFile(res.content)
    } else {
      bag.loginDefsError = res.error
    }
  } catch (e) {
    bag.loginDefsError = errorMessage(e)
  }

  // ── sshd config (merged with sshd_config.d when Include is present) ───────
  try {
    const sshd = await collectSshdMerged()
    bag.sshdConfigPresent = sshd.present
    bag.sshdConfigMerged = sshd.merged
    if (!sshd.present) bag.sshdError = sshd.error
  } catch (e) {
    bag.sshdConfigPresent = false
    bag.sshdError = errorMessage(e)
  }

  // ── listening sockets (ss -tulnH) ─────────────────────────────────────────
  try {
    const res = await safeExec('ss', ['-tulnH'])
    if (res.ok) {
      bag.listeners = parseSsListeners(res.stdout)
    } else {
      bag.listenersError = res.error
    }
  } catch (e) {
    bag.listenersError = errorMessage(e)
  }

  // ── network interfaces (node:os API) ──────────────────────────────────────
  try {
    const raw = os.networkInterfaces()
    const flat: NonNullable<LinuxEvidenceBag['interfaces']> = []
    for (const [name, infos] of Object.entries(raw)) {
      for (const info of infos ?? []) {
        flat.push({ name, address: info.address, internal: info.internal })
      }
    }
    bag.interfaces = flat
  } catch {
    bag.interfaces = null
  }

  // ── IPv4 forwarding sysctl ────────────────────────────────────────────────
  try {
    const res = await safeRead('/proc/sys/net/ipv4/ip_forward')
    if (res.ok) {
      bag.ipForward = parseProcNumber(res.content)
    } else {
      bag.ipForwardError = res.error
    }
  } catch (e) {
    bag.ipForwardError = errorMessage(e)
  }

  // ── firewall tooling (binaries via allowlisted stat; configs via safeRead;
  //    runtime state probed read-only, honest null when the probe needs root) ─
  try {
    bag.firewall.ufwInstalled = await binaryPresent('/usr/sbin/ufw')
    bag.firewall.nftablesInstalled = await binaryPresent('/usr/sbin/nft')
    bag.firewall.iptablesInstalled = await binaryPresent('/usr/sbin/iptables')

    const ufwConf = await safeRead('/etc/ufw/ufw.conf')
    if (ufwConf.ok) {
      const kv = parseKeyValueFile(ufwConf.content)
      bag.firewall.ufwEnabled = kv.ENABLED === 'yes' ? true : kv.ENABLED === 'no' ? false : null
    } else {
      bag.firewall.ufwEnabled = null // file missing → unknown, honest
    }
    bag.firewall.nftablesConfExists = (await safeRead('/etc/nftables.conf')).ok

    // Runtime probes (real enforcement state, preferred over config inference):
    const ufwStatus = await safeExec('ufw', ['status'])
    bag.firewall.ufwRuntime = ufwStatus.ok ? /status:\s*active/i.test(ufwStatus.stdout) : null
    const nftRuleset = await safeExec('nft', ['list', 'ruleset'])
    // An empty ruleset prints nothing → safeExec reports EMPTY_OUTPUT; a non-empty
    // stdout means loaded rules exist in the kernel.
    bag.firewall.nftRulesetLoaded = nftRuleset.ok ? nftRuleset.stdout.trim().length > 0 : null

    bag.firewall.tool = bag.firewall.ufwInstalled
      ? 'ufw'
      : bag.firewall.nftablesInstalled
        ? 'nftables'
        : bag.firewall.iptablesInstalled
          ? 'iptables'
          : null
    bag.firewall.active =
      bag.firewall.ufwRuntime ??
      (bag.firewall.nftRulesetLoaded === true
        ? true
        : bag.firewall.ufwEnabled === true
          ? true
          : bag.firewall.ufwEnabled === false
            ? false
            : bag.firewall.tool === null
              ? false
              : null)
  } catch {
    // firewall block: defaults from emptyBag stand on failure
  }

  // ── installed packages (dpkg-query -W lists ALL known packages; used as an
  //    inventory approximation + vulnerability matching input) ───────────────
  try {
    const res = await safeExec('dpkg-query', ['-W', '-f=${Package}\\t${Version}\\n'])
    if (res.ok) {
      const lines = res.stdout.split('\n').filter((l) => l.trim().length > 0)
      bag.packagesCount = lines.length
      const MAX_PACKAGES = 2500
      bag.packages = lines
        .slice(0, MAX_PACKAGES)
        .map((l) => {
          const idx = l.indexOf('\t')
          return idx > 0
            ? { name: l.slice(0, idx).trim(), version: l.slice(idx + 1).trim() }
            : { name: l.trim(), version: '' }
        })
        .filter((p) => p.name.length > 0)
    } else {
      bag.packagesError = res.error
    }
  } catch (e) {
    bag.packagesError = errorMessage(e)
  }

  // ── APT cache freshness (/var/lib/apt/lists directory listing) ────────────
  try {
    const res = await safeRead('/var/lib/apt/lists')
    if (res.ok) {
      const entries = res.content
        .split('\n')
        .map((s) => s.trim())
        .filter((n) => n.length > 0 && n !== 'lock' && n !== 'partial' && n !== 'auxstorage')
      bag.aptCacheFresh = entries.length > 2
    } else {
      bag.aptCacheFresh = null
    }
  } catch {
    bag.aptCacheFresh = null
  }

  // ── pending updates (simulated upgrade — never applied) ───────────────────
  try {
    if (bag.aptCacheFresh) {
      const res = await safeExec('apt-get', ['-s', 'upgrade'])
      if (res.ok) {
        const instLines = res.stdout
          .split('\n')
          .filter((l) => l.startsWith('Inst '))
        bag.pendingUpdates = instLines.length
        bag.pendingSecurityUpdates = instLines.filter((l) => /security/i.test(l.slice(5))).length
      } else {
        bag.pendingError = res.error
      }
    } else {
      bag.pendingError = 'APT cache empty/stale or unreadable — apt-get -s upgrade skipped'
    }
  } catch (e) {
    bag.pendingError = errorMessage(e)
  }

  // ── unattended-upgrades (config presence + binary) ────────────────────────
  try {
    const candidates = [
      '/etc/apt/apt.conf.d/20auto-upgrades',
      '/etc/apt/apt.conf.d/10periodic',
    ]
    let enabled = false
    for (const p of candidates) {
      const res = await safeRead(p)
      if (res.ok && /APT::Periodic::Unattended-Upgrade\s+"1"/.test(res.content)) enabled = true
    }
    bag.unattendedUpgradesEnabled = enabled // both files missing → false (honest)
    bag.unattendedInstalled = await binaryPresent('/usr/bin/unattended-upgrade')
  } catch {
    bag.unattendedUpgradesEnabled = null
    bag.unattendedInstalled = false
  }

  // ── kernel hardening sysctls ──────────────────────────────────────────────
  try {
    const readNum = async (p: string): Promise<number | null> => {
      const res = await safeRead(p)
      return res.ok ? parseProcNumber(res.content) : null
    }
    bag.sysctls.randomize_va_space = await readNum('/proc/sys/kernel/randomize_va_space')
    bag.sysctls.kptr_restrict = await readNum('/proc/sys/kernel/kptr_restrict')
    bag.sysctls.dmesg_restrict = await readNum('/proc/sys/kernel/dmesg_restrict')
    bag.sysctls.suid_dumpable = await readNum('/proc/sys/fs/suid_dumpable')
  } catch {
    bag.sysctls = {
      randomize_va_space: null,
      kptr_restrict: null,
      dmesg_restrict: null,
      suid_dumpable: null,
    }
  }

  // ── network-hardening sysctls (CIS "Network Parameters") ─────────────────
  try {
    const readNum = async (p: string): Promise<number | null> => {
      const res = await safeRead(p)
      return res.ok ? parseProcNumber(res.content) : null
    }
    bag.sysctlsNet.accept_redirects = await readNum('/proc/sys/net/ipv4/conf/all/accept_redirects')
    bag.sysctlsNet.send_redirects = await readNum('/proc/sys/net/ipv4/conf/all/send_redirects')
    bag.sysctlsNet.accept_source_route = await readNum('/proc/sys/net/ipv4/conf/all/accept_source_route')
    bag.sysctlsNet.icmp_echo_ignore_broadcasts = await readNum('/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts')
    bag.sysctlsNet.icmp_ignore_bogus_error_responses = await readNum('/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses')
    bag.sysctlsNet.tcp_syncookies = await readNum('/proc/sys/net/ipv4/tcp_syncookies')
    bag.sysctlsNet.log_martians = await readNum('/proc/sys/net/ipv4/conf/all/log_martians')
    bag.sysctlsNet.rp_filter = await readNum('/proc/sys/net/ipv4/conf/all/rp_filter')
  } catch {
    // leave all-null → network sysctl rules report NOT_ASSESSED honestly
  }

  // ── systemd operational state + running services ──────────────────────────
  try {
    const res = await safeExec('systemctl', ['is-system-running'])
    if (res.ok) {
      const state = res.stdout.trim().toLowerCase()
      // 'running' → healthy; 'degraded' → operational with failed units (still systemd)
      bag.systemdRunning = state.includes('running') || state.includes('degraded')
      if (!bag.systemdRunning) bag.systemdError = `systemd state: ${state}`
    } else {
      bag.systemdRunning = false
      bag.systemdError = res.error // typical in containers: "System has not been booted..." / offline
    }
    if (bag.systemdRunning) {
      const svc = await safeExec('systemctl', [
        'list-units',
        '--type=service',
        '--state=running',
        '--no-pager',
        '--no-legend',
      ])
      if (svc.ok) {
        bag.runningServices = svc.stdout
          .split('\n')
          .map((l) => l.trim().split(/\s+/)[0] ?? '')
          .filter((name) => name.length > 0)
      } else {
        bag.runningServices = null
        bag.systemdError = svc.error
      }
    } else {
      bag.runningServices = null
    }
  } catch (e) {
    bag.systemdRunning = false
    bag.runningServices = null
    bag.systemdError = errorMessage(e)
  }

  // ── PID 1 (init) ──────────────────────────────────────────────────────────
  try {
    const res = await safeRead('/proc/1/comm')
    bag.initComm = res.ok && res.content.trim().length > 0 ? res.content.trim() : null
  } catch {
    bag.initComm = null
  }

  // ── LSM / AppArmor ────────────────────────────────────────────────────────
  try {
    const res = await safeRead('/sys/kernel/security/lsm')
    bag.apparmorLsmActive = res.ok ? res.content.toLowerCase().includes('apparmor') : null
  } catch {
    bag.apparmorLsmActive = null
  }
  try {
    bag.apparmorProfilesDirExists = (await safeRead('/etc/apparmor.d')).ok
  } catch {
    bag.apparmorProfilesDirExists = false
  }

  // ── endpoint protection binaries ──────────────────────────────────────────
  try {
    bag.clamavInstalled =
      (await binaryPresent('/usr/bin/clamscan')) || (await binaryPresent('/usr/sbin/clamd'))
    // Real enforcement state: clamav-daemon among the running systemd services
    // (collected earlier; null when systemd is offline, e.g. containers).
    bag.clamavDaemonRunning =
      bag.runningServices === null
        ? null
        : bag.runningServices.some((s) => s.startsWith('clamav-daemon'))
    bag.gccInstalled = await binaryPresent('/usr/bin/gcc')
  } catch {
    bag.clamavInstalled = false
    bag.clamavDaemonRunning = null
    bag.gccInstalled = false
  }

  // ── disk encryption ───────────────────────────────────────────────────────
  try {
    bag.crypttabExists = (await safeRead('/etc/crypttab')).ok
    bag.cryptsetupInstalled = await binaryPresent('/usr/sbin/cryptsetup')
  } catch {
    bag.crypttabExists = false
    bag.cryptsetupInstalled = false
  }

  // ── block devices / swap inventory (lsblk, read-only) ────────────────────
  try {
    const res = await safeExec('lsblk', ['-P', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT'])
    if (res.ok) {
      const parseField = (line: string, key: string): string => {
        const m = line.match(new RegExp(`${key}="([^"]*)"`))
        return m ? m[1] : ''
      }
      const devices: NonNullable<LinuxEvidenceBag['swapDevices']> = []
      const luks: string[] = []
      for (const line of res.stdout.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed) continue
        const name = parseField(trimmed, 'NAME')
        if (!name) continue
        const entry = {
          name,
          size: parseField(trimmed, 'SIZE'),
          type: parseField(trimmed, 'TYPE'),
          mountpoint: parseField(trimmed, 'MOUNTPOINT'),
        }
        // Runtime data-at-rest evidence: lsblk reports mapped LUKS containers as TYPE=crypt.
        if (entry.type === 'crypt') luks.push(entry.name)
        const isSwap =
          entry.type === 'swap' ||
          entry.mountpoint === '[SWAP]' ||
          /^zram/.test(entry.name)
        if (isSwap) devices.push(entry)
      }
      bag.swapDevices = devices
      bag.luksVolumes = luks
    } else {
      bag.swapDevices = null
      bag.luksVolumes = null
    }
  } catch {
    bag.swapDevices = null
    bag.luksVolumes = null
  }

  // ── sensitive file permissions (stat — readable without root) ─────────────
  try {
    const paths = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/login.defs']
    for (const p of paths) {
      const res = await safeStat(p)
      if (res.ok) {
        bag.filePerms.push({ path: p, mode: res.mode })
      } else {
        bag.filePerms.push({ path: p, mode: '', error: res.error })
      }
    }
  } catch {
    // filePerms stays [] → rules report NOT_ASSESSED honestly
  }

  // ── hardware inventory (node:os API) ──────────────────────────────────────
  try {
    const cpus = os.cpus()
    bag.cpuModel = cpus[0]?.model ?? null
    bag.cpuCores = cpus.length > 0 ? cpus.length : null
    bag.memoryTotalMB = Math.round(os.totalmem() / 1048576)
    bag.uptimeHours = Math.round(os.uptime() / 3600)
  } catch {
    bag.cpuModel = null
    bag.cpuCores = null
    bag.memoryTotalMB = null
    bag.uptimeHours = null
  }

  // ── process count (ps axo pid,user,comm — header line excluded) ───────────
  try {
    const res = await safeExec('ps', ['axo', 'pid,user,comm'])
    if (res.ok) {
      bag.processCount = res.stdout
        .split('\n')
        .filter((l) => l.trim().length > 0 && !l.trim().startsWith('PID')).length
    } else {
      bag.processCount = null
    }
  } catch {
    bag.processCount = null
  }

  return bag
}
