// DIVISION T82 — Linux evidence bag contract + platform detection
// The collectors populate this bag ONCE per scan; rules evaluate over it (pure functions).
import type { Confidence, Platform } from '../../types'

// ─── Platform detection ─────────────────────────────────────────────────────

export interface OsReleaseInfo {
  prettyName: string
  name: string
  versionId: string
  id: string // debian | ubuntu | ...
  idLike: string[]
}

export interface PlatformInfo {
  platform: Platform
  hostname: string
  os: string // pretty name
  osVersion: string
  distro: string | null
  distroFamily: 'debian' | 'ubuntu' | 'other' | null
  kernel: string
  arch: string
  user: string
  isRoot: boolean
}

// ─── Linux evidence bag (every field optional: collectors degrade honestly) ─

export interface SshOption {
  key: string
  value: string
}

export interface LinuxEvidenceBag {
  // identity
  osRelease: OsReleaseInfo | null
  osReleaseError?: string
  kernelRelease: string | null
  platform: PlatformInfo

  // users & identity
  passwd: { name: string; uid: number; gid: number; home: string; shell: string }[] | null
  passwdError?: string
  shadowReadable: boolean
  shadowError?: string
  sudoersReadable: boolean
  sudoersFiles: string[] // filenames listed in /etc/sudoers.d (contents may be unreadable)
  sudoersContent?: string // only when readable (root)
  sudoersError?: string
  loginDefs: Record<string, string> | null
  loginDefsError?: string

  // ssh
  sshdConfigPresent: boolean
  sshdConfigMerged: Record<string, string> // merged main + sshd_config.d (last-wins semantics)
  sshdError?: string

  // network
  listeners: { proto: 'tcp' | 'tcp6' | 'udp' | 'udp6'; address: string; port: number }[] | null
  listenersError?: string
  interfaces: { name: string; address: string; internal: boolean }[] | null
  ipForward: number | null
  ipForwardError?: string

  // firewall
  firewall: {
    ufwInstalled: boolean
    ufwEnabled: boolean | null // from /etc/ufw/ufw.conf ENABLED
    nftablesInstalled: boolean
    nftablesConfExists: boolean
    iptablesInstalled: boolean
    tool: 'ufw' | 'nftables' | 'iptables' | null
    active: boolean | null
  }

  // packages & patches
  packagesCount: number | null
  packagesError?: string
  aptCacheFresh: boolean | null // /var/lib/apt/lists non-empty
  pendingUpdates: number | null
  pendingSecurityUpdates: number | null
  pendingError?: string
  unattendedUpgradesEnabled: boolean | null // 20auto-upgrades / 10periodic
  unattendedInstalled: boolean // dpkg has unattended-upgrades package

  // kernel hardening
  sysctls: {
    randomize_va_space: number | null
    kptr_restrict: number | null
    dmesg_restrict: number | null
    suid_dumpable: number | null
  }
  /** Network-hardening sysctls (CIS "Network Parameters"); null → /proc/sys unreadable. */
  sysctlsNet: {
    accept_redirects: number | null
    send_redirects: number | null
    accept_source_route: number | null
    icmp_echo_ignore_broadcasts: number | null
    icmp_ignore_bogus_error_responses: number | null
    tcp_syncookies: number | null
    log_martians: number | null
    rp_filter: number | null
  }

  // services
  systemdRunning: boolean | null // null => offline/unknown (container)
  systemdError?: string
  runningServices: string[] | null
  initComm: string | null // /proc/1/comm

  // endpoint protection / LSM
  apparmorLsmActive: boolean | null
  apparmorProfilesDirExists: boolean
  clamavInstalled: boolean
  gccInstalled: boolean

  // encryption
  crypttabExists: boolean
  cryptsetupInstalled: boolean

  /** Installed package inventory (name+version, capped) — powers vulnerability matching. */
  packages: { name: string; version: string }[] | null
  /** Swap-capable block devices from lsblk (null → lsblk unavailable). */
  swapDevices: { name: string; size: string; type: string; mountpoint: string }[] | null

  // sensitive file permissions (stat, readable without root)
  filePerms: { path: string; mode: string; error?: string }[]

  // hardware inventory (os-api)
  cpuModel: string | null
  cpuCores: number | null
  memoryTotalMB: number | null
  uptimeHours: number | null

  // processes sample (read-only inventory)
  processCount: number | null
}

export type BagField = keyof LinuxEvidenceBag

export function emptyBag(platform: PlatformInfo): LinuxEvidenceBag {
  return {
    osRelease: null,
    kernelRelease: null,
    platform,
    passwd: null,
    shadowReadable: false,
    sudoersReadable: false,
    sudoersFiles: [],
    loginDefs: null,
    sshdConfigPresent: false,
    sshdConfigMerged: {},
    listeners: null,
    interfaces: null,
    ipForward: null,
    firewall: {
      ufwInstalled: false,
      ufwEnabled: null,
      nftablesInstalled: false,
      nftablesConfExists: false,
      iptablesInstalled: false,
      tool: null,
      active: null,
    },
    packagesCount: null,
    aptCacheFresh: null,
    pendingUpdates: null,
    pendingSecurityUpdates: null,
    unattendedUpgradesEnabled: null,
    unattendedInstalled: false,
    sysctls: {
      randomize_va_space: null,
      kptr_restrict: null,
      dmesg_restrict: null,
      suid_dumpable: null,
    },
    sysctlsNet: {
      accept_redirects: null,
      send_redirects: null,
      accept_source_route: null,
      icmp_echo_ignore_broadcasts: null,
      icmp_ignore_bogus_error_responses: null,
      tcp_syncookies: null,
      log_martians: null,
      rp_filter: null,
    },
    systemdRunning: null,
    runningServices: null,
    initComm: null,
    apparmorLsmActive: null,
    apparmorProfilesDirExists: false,
    clamavInstalled: false,
    gccInstalled: false,
    crypttabExists: false,
    cryptsetupInstalled: false,
    packages: null,
    swapDevices: null,
    filePerms: [],
    cpuModel: null,
    cpuCores: null,
    memoryTotalMB: null,
    uptimeHours: null,
    processCount: null,
  }
}

export function confidenceOf(ok: boolean, degraded = false): Confidence {
  if (ok && !degraded) return 'HIGH'
  if (ok) return 'MEDIUM'
  return 'LOW'
}
