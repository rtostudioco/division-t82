// DIVISION T82 — designed (not-implemented) catalogs for Windows & macOS.
// Honesty rule: these controls are DECLARED so the UI can show the roadmap,
// but they are NEVER evaluated in this build and never produce fake results.

import type { SecurityControl } from '../types'

function designed(
  id: string,
  name: { en: string; es: string },
  category: SecurityControl['category'],
  severity: SecurityControl['severity'],
  description: { en: string; es: string },
  evidenceSource: string,
  platforms: SecurityControl['platforms'],
): SecurityControl {
  return {
    id,
    version: '0.1.0',
    name,
    description,
    category,
    severity,
    platforms,
    implemented: false,
    evidenceSource,
    evaluate: () => ({
      status: 'NOT_ASSESSED',
      reason: 'Adapter designed but not implemented in this build (requires native platform bridge)',
    }),
    explanation: {
      en: 'This control is part of the cross-platform roadmap. It requires the native desktop bridge (Tauri 2 + platform collectors) to gather real evidence on Windows or macOS hosts.',
      es: 'Este control forma parte del roadmap multiplataforma. Requiere el puente nativo de escritorio (Tauri 2 + colectores por plataforma) para recolectar evidencia real en hosts Windows o macOS.',
    },
    references: [],
    remediation: {
      problemSummary: { en: 'Designed control — no local evaluation available yet.', es: 'Control diseñado — aún sin evaluación local disponible.' },
      rootCause: { en: 'Adapter not implemented in this build.', es: 'Adaptador no implementado en este build.' },
      risk: { en: 'Unknown until assessed on the native platform.', es: 'Desconocido hasta evaluarlo en la plataforma nativa.' },
      priority: severity,
      currentStateNote: { en: 'Not assessed on this host.', es: 'No evaluado en este host.' },
      recommendedState: { en: 'Defined by the control specification when implemented.', es: 'Definido por la especificación del control cuando se implemente.' },
      steps: [],
      sideEffects: { en: 'None — advisory only.', es: 'Ninguno — solo advisory.' },
      prerequisites: { en: 'Native platform bridge.', es: 'Puente nativo de plataforma.' },
      rollback: { en: 'Not applicable.', es: 'No aplicable.' },
      verify: { en: 'Control will report with evidence once the adapter ships.', es: 'El control reportará con evidencia cuando el adaptador esté disponible.' },
      advisoryOnly: true,
    },
  }
}

export const WINDOWS_DESIGNED: SecurityControl[] = [
  designed('VC-WIN-0101', { en: 'UAC properly configured', es: 'UAC correctamente configurado' }, 'IDENTITY_ACCESS', 'HIGH',
    { en: 'User Account Control elevation policy (ConsentPromptBehaviorAdmin, EnableLUA).', es: 'Política de elevación de UAC (ConsentPromptBehaviorAdmin, EnableLUA).' },
    'Registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System (read)', ['windows']),
  designed('VC-WIN-0102', { en: 'Microsoft Defender real-time protection', es: 'Protección en tiempo real de Microsoft Defender' }, 'ENDPOINT_PROTECTION', 'CRITICAL',
    { en: 'Real-time protection, antivirus signatures and tamper protection status.', es: 'Estado de protección en tiempo real, firmas y tamper protection.' },
    'Get-MpComputerStatus (documented cmdlet)', ['windows']),
  designed('VC-WIN-0103', { en: 'Firewall profiles active', es: 'Perfiles de firewall activos' }, 'FIREWALL', 'HIGH',
    { en: 'Domain/Private/Public firewall profiles enabled state.', es: 'Estado de los perfiles Domain/Private/Public del firewall.' },
    'Get-NetFirewallProfile (documented cmdlet)', ['windows']),
  designed('VC-WIN-0104', { en: 'BitLocker volume encryption', es: 'Cifrado de volumen BitLocker' }, 'ENCRYPTION', 'CRITICAL',
    { en: 'BitLocker protection status of OS and fixed volumes.', es: 'Estado de protección BitLocker del SO y volúmenes fijos.' },
    'Get-BitLockerVolume', ['windows']),
  designed('VC-WIN-0105', { en: 'TPM 2.0 + Secure Boot', es: 'TPM 2.0 + Arranque seguro' }, 'OS_SECURITY', 'HIGH',
    { en: 'TPM presence/initialization and UEFI Secure Boot state.', es: 'Presencia/inicialización de TPM y estado de Arranque seguro UEFI.' },
    'Get-Tpm / Confirm-SecureBootUEFI', ['windows']),
  designed('VC-WIN-0106', { en: 'Windows Update operational', es: 'Windows Update operativo' }, 'PATCH_MANAGEMENT', 'MEDIUM',
    { en: 'Pending updates and last successful update time.', es: 'Actualizaciones pendientes y fecha del último update exitoso.' },
    'Windows Update Agent API (read)', ['windows']),
]

export const MACOS_DESIGNED: SecurityControl[] = [
  designed('VC-MAC-0101', { en: 'FileVault enabled', es: 'FileVault habilitado' }, 'ENCRYPTION', 'CRITICAL',
    { en: 'Full disk encryption status via fdesetup (read-only).', es: 'Estado de cifrado completo vía fdesetup (solo lectura).' },
    'fdesetup status', ['macos']),
  designed('VC-MAC-0102', { en: 'Gatekeeper assessment enabled', es: 'Gatekeeper habilitado' }, 'APPLICATION_SECURITY', 'HIGH',
    { en: 'Gatekeeper evaluation of downloaded applications.', es: 'Evaluación Gatekeeper de aplicaciones descargadas.' },
    'spctl --status', ['macos']),
  designed('VC-MAC-0103', { en: 'System Integrity Protection (SIP)', es: 'Protección de Integridad del Sistema (SIP)' }, 'OS_SECURITY', 'CRITICAL',
    { en: 'SIP must remain enabled on production systems.', es: 'SIP debe permanecer habilitado en sistemas de producción.' },
    'csrutil status', ['macos']),
  designed('VC-MAC-0104', { en: 'Application firewall enabled', es: 'Firewall de aplicaciones habilitado' }, 'FIREWALL', 'MEDIUM',
    { en: 'macOS application firewall state (socketfilterfw).', es: 'Estado del firewall de aplicaciones (socketfilterfw).' },
    '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate', ['macos']),
  designed('VC-MAC-0105', { en: 'Software Update current', es: 'Actualizaciones de software al día' }, 'PATCH_MANAGEMENT', 'MEDIUM',
    { en: 'Pending macOS updates.', es: 'Actualizaciones pendientes de macOS.' },
    'softwareupdate -l (read)', ['macos']),
  designed('VC-MAC-0106', { en: 'Administrator accounts reviewed', es: 'Cuentas de administrador revisadas' }, 'IDENTITY_ACCESS', 'MEDIUM',
    { en: 'Users in the admin group reviewed for necessity.', es: 'Usuarios del grupo admin revisados por necesidad.' },
    'dscl . -read /Groups/admin (read)', ['macos']),
]
