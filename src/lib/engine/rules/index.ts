// DIVISION T82 — rule registry. Agent-implemented platform catalogs plug in here.
// v1.1.0: core catalog (VC-LNX-0101..0601) + extended catalog (util/extended.ts).
import type { Platform, SecurityControl } from '../types'
import { MACOS_DESIGNED, WINDOWS_DESIGNED } from './designed'
// implemented catalogs:
import { LINUX_RULES } from './linux'
import { EXTENDED_LINUX_RULES } from './linux/extended'

export const CATALOG: Record<Platform, SecurityControl[]> = {
  linux: [...LINUX_RULES, ...EXTENDED_LINUX_RULES],
  windows: WINDOWS_DESIGNED,
  macos: MACOS_DESIGNED,
}

export function rulesFor(platform: Platform, scope?: string[]): SecurityControl[] {
  const rules = CATALOG[platform] ?? []
  if (!scope || scope.length === 0) return rules
  return rules.filter((r) => scope.includes(r.category))
}

export function designedRules(platform: Platform): SecurityControl[] {
  if (platform === 'linux') return [...WINDOWS_DESIGNED, ...MACOS_DESIGNED]
  if (platform === 'windows') return MACOS_DESIGNED
  return WINDOWS_DESIGNED
}

export function allRules(): SecurityControl[] {
  return [...CATALOG.linux, ...CATALOG.windows, ...CATALOG.macos]
}
