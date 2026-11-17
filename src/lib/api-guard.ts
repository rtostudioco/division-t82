// DIVISION T82 — local-first API mutation guard (P0 hardening).
//
// Threat model: the platform binds to loopback, but a loopback-bound service is
// still reachable by (a) classic cross-site CSRF from any website the user
// visits and (b) DNS-rebinding pages that resolve an attacker domain to
// 127.0.0.1. This guard defends every state-changing API route:
//
//   1. Custom header `x-t82-client: t82-web` is REQUIRED on mutations.
//      Cross-site JS cannot attach custom headers without a successful CORS
//      preflight (which the app never grants) → classic CSRF is dead.
//   2. If an `Origin` header is present (browsers always send it on POSTs),
//      its host must match the `Host` header, be loopback, or be explicitly
//      trusted via T82_TRUSTED_HOSTS (reverse proxies rewrite Host to
//      127.0.0.1) — any other origin is rejected.
//   3. Origin-less (non-browser) calls are only accepted when the `Host`
//      header is loopback or explicitly trusted via T82_TRUSTED_HOSTS
//      (comma-separated hostnames) — kills DNS rebinding, which always
//      presents a non-loopback Host.
//
// Reads (GET/HEAD/OPTIONS) are never blocked: the platform exposes no secrets
// beyond the local assessment the operator already owns.
import { NextResponse } from 'next/server'

const CLIENT_HEADER = 'x-t82-client'
const CLIENT_VALUE = 't82-web'

function parseHostname(header: string | null): string {
  const v = (header ?? '').trim()
  if (!v) return ''
  if (v.startsWith('[')) {
    const end = v.indexOf(']')
    return end === -1 ? v.toLowerCase() : v.slice(1, end).toLowerCase()
  }
  return v.split(':')[0].trim().toLowerCase()
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.endsWith('.localhost')
  )
}

function trustedHosts(): string[] {
  return (process.env.T82_TRUSTED_HOSTS ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
}

/**
 * Returns a 403 NextResponse when the mutating request must be rejected,
 * or null when it may proceed. Apply as the first statement of every
 * POST/PUT/PATCH/DELETE API handler.
 */
export function guardMutation(request: Request): Response | null {
  const method = request.method.toUpperCase()
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return null

  // 1) custom header — the anti-CSRF core
  if (request.headers.get(CLIENT_HEADER) !== CLIENT_VALUE) {
    return NextResponse.json(
      { error: 'mutating request rejected: missing x-t82-client header' },
      { status: 403 },
    )
  }

  const hostName = parseHostname(request.headers.get('host'))
  const origin = request.headers.get('origin')

  if (origin) {
    // 2) Origin validation. Accepted only when the Origin host matches the
    //    request Host, is loopback, or is explicitly trusted
    //    (T82_TRUSTED_HOSTS — reverse proxies legitimately rewrite Host to
    //    loopback). Anything else (attacker.site) is rejected even when the
    //    request Host is loopback: rule 1 already stops real browsers, this
    //    closes the synthetic non-browser gap too.
    try {
      const originHost = new URL(origin).hostname.toLowerCase()
      const trusted = isLoopback(originHost) || trustedHosts().includes(originHost)
      if (originHost !== hostName && !trusted) {
        return NextResponse.json(
          { error: 'mutating request rejected: cross-origin Origin header' },
          { status: 403 },
        )
      }
    } catch {
      return NextResponse.json(
        { error: 'mutating request rejected: malformed Origin header' },
        { status: 403 },
      )
    }
  } else if (!isLoopback(hostName) && !trustedHosts().includes(hostName)) {
    // 3) non-browser call to a non-local host → reject (DNS rebinding shape)
    return NextResponse.json(
      { error: 'mutating request rejected: non-local Host header without Origin' },
      { status: 403 },
    )
  }

  return null
}
