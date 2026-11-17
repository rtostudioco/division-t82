'use client'
// DIVISION T82 — client fetch shim (pairs with src/lib/api-guard.ts).
// Marks every same-origin /api/ request with the `x-t82-client` header so the
// server-side mutation guard can tell genuine UI calls apart from cross-site
// CSRF / DNS-rebinding attempts. Patched at module scope (not in an effect) so
// it is active before any component or TanStack Query fires a request.
if (typeof window !== 'undefined') {
  const w = window as typeof window & { __t82FetchPatched?: boolean }
  if (!w.__t82FetchPatched) {
    w.__t82FetchPatched = true
    const originalFetch = window.fetch.bind(window)
    window.fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      try {
        const url =
          typeof input === 'string'
            ? input
            : input instanceof URL
              ? input.href
              : input.url
        const isApiCall = url.startsWith('/api/') || new URL(url, window.location.origin).pathname.startsWith('/api/')
        if (isApiCall) {
          const baseHeaders =
            init?.headers ?? (typeof input === 'object' && !(input instanceof URL) && 'headers' in input ? input.headers : undefined)
          const headers = new Headers(baseHeaders ?? undefined)
          headers.set('x-t82-client', 't82-web')
          init = { ...init, headers }
        }
      } catch {
        // never break a UI request because of the shim itself
      }
      return originalFetch(input as RequestInfo, init)
    }
  }
}

// Renderless client marker: importing + mounting this component keeps the shim
// in the client bundle even when every route is statically prerendered.
export function FetchGuard() {
  return null
}
