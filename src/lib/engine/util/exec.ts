// DIVISION T82 — hardened process execution.
// Security rules (docs/ARCHITECTURE_PROPOSAL.md §4):
//   - NO shell (no shell=True equivalent, no string concatenation)
//   - closed allowlist of (binary, args-prefix) pairs
//   - timeouts + output size limits + minimal env
import { execFile } from 'node:child_process'

interface AllowEntry {
  argv0: string
  /** args must start with exactly this prefix (fixed strings only) */
  prefix: string[]
  timeoutMs: number
  maxBuffer: number
}

const ALLOWLIST: AllowEntry[] = [
  { argv0: 'ss', prefix: ['-tulnH'], timeoutMs: 4000, maxBuffer: 256 * 1024 },
  { argv0: 'dpkg-query', prefix: ['-W', '-f=${Package}\\t${Version}\\n'], timeoutMs: 8000, maxBuffer: 512 * 1024 },
  { argv0: 'apt-get', prefix: ['-s', 'upgrade'], timeoutMs: 8000, maxBuffer: 512 * 1024 },
  { argv0: 'systemctl', prefix: ['is-system-running'], timeoutMs: 3000, maxBuffer: 8 * 1024 },
  { argv0: 'systemctl', prefix: ['list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'], timeoutMs: 5000, maxBuffer: 256 * 1024 },
  { argv0: 'stat', prefix: ['-c', '%a %U %G %n'], timeoutMs: 3000, maxBuffer: 8 * 1024 },
  { argv0: 'lsblk', prefix: ['-P', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT'], timeoutMs: 4000, maxBuffer: 64 * 1024 },
  { argv0: 'ps', prefix: ['axo', 'pid,user,comm'], timeoutMs: 4000, maxBuffer: 256 * 1024 },
  { argv0: 'uname', prefix: ['-r'], timeoutMs: 2000, maxBuffer: 4 * 1024 },
  // Firewall runtime-state probes (read-only). As non-root these usually fail
  // with a permission error — the honest result is then `null` (unknown) and
  // the firewall rule falls back to config-file inference.
  { argv0: 'ufw', prefix: ['status'], timeoutMs: 4000, maxBuffer: 64 * 1024 },
  { argv0: 'nft', prefix: ['list', 'ruleset'], timeoutMs: 4000, maxBuffer: 256 * 1024 },
  { argv0: 'iptables', prefix: ['-S'], timeoutMs: 4000, maxBuffer: 256 * 1024 },
]

export type ExecResult =
  | { ok: true; stdout: string }
  | { ok: false; error: string; kind: 'NOT_ALLOWED' | 'NOT_FOUND' | 'TIMEOUT' | 'FAILED' | 'EMPTY_OUTPUT' }

function findAllowEntry(binary: string, args: string[]): AllowEntry | undefined {
  return ALLOWLIST.find(
    (e) => e.argv0 === binary && e.prefix.length <= args.length && e.prefix.every((p, i) => args[i] === p),
  )
}

export function safeExec(binary: string, args: string[]): Promise<ExecResult> {
  const entry = findAllowEntry(binary, args)
  if (!entry) {
    return Promise.resolve({
      ok: false as const,
      error: `command not in engine allowlist: ${binary} ${args.join(' ')}`,
      kind: 'NOT_ALLOWED' as const,
    })
  }
  return new Promise((resolve) => {
    execFile(
      entry.argv0,
      args,
      {
        timeout: entry.timeoutMs,
        maxBuffer: entry.maxBuffer,
        killSignal: 'SIGKILL',
        windowsHide: true,
        env: { NODE_ENV: 'production', PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL: 'C' },
      },
      (err, stdout, stderr) => {
        if (err) {
          const msg = `${err.name ?? 'Error'}: ${String(err.message ?? '').slice(0, 300)}${stderr ? ` | ${String(stderr).slice(0, 200)}` : ''}`
          const killed = (err as { killed?: boolean }).killed === true
          resolve({ ok: false as const, error: msg, kind: killed ? ('TIMEOUT' as const) : ('FAILED' as const) })
          return
        }
        const out = String(stdout ?? '')
        if (out.trim().length === 0) {
          resolve({ ok: false as const, error: 'empty output', kind: 'EMPTY_OUTPUT' as const })
          return
        }
        resolve({ ok: true as const, stdout: out })
      },
    )
  })
}
