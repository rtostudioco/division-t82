// DIVISION T82 — Extended Linux security controls (VC-LNX-0107..0701, v1.1.0 catalog).
// Same contract as the core catalog: PURE evaluators over the evidence bag,
// honest NOT_ASSESSED/NOT_APPLICABLE, advisory-only remediation.
import type { SecurityControl, Loc } from '../../types'
import type { LinuxEvidenceBagWithShadow } from '../../collectors/linux'
import {
  frag,
  rem,
  NO_SSHD,
  MANUAL,
  GENERIC_STATE,
  GENERIC_PREREQ,
  GENERIC_SIDE_EFFECTS,
  REF_DEBIAN,
  REF_OPENSSH,
  REF_CIS,
  REF_NIST,
  REF_MITRE,
} from './util'

const GENERIC_ROLLBACK: Loc = {
  en: 'Restore the backup copy of the modified file and reload the affected service.',
  es: 'Restaure la copia de seguridad del archivo modificado y recargue el servicio afectado.',
}

const GENERIC_VERIFY_SSHD: Loc = {
  en: 'sshd -T | grep <option> shows the effective value; restart sshd and confirm sessions still work before closing the current one.',
  es: 'sshd -T | grep <opción> muestra el valor efectivo; reinicie sshd y confirme que las sesiones siguen funcionando antes de cerrar la actual.',
}

const SSH_RELOAD_STEPS = (title: Loc, setting: string): { title: Loc; command: string; note: Loc }[] => [
  {
    title: { en: 'Edit /etc/ssh/sshd_config (or a drop-in under /etc/ssh/sshd_config.d)', es: 'Edite /etc/ssh/sshd_config (o un drop-in en /etc/ssh/sshd_config.d)' },
    command: `sudo nano /etc/ssh/sshd_config   # set: ${setting}`,
    note: MANUAL,
  },
  {
    title: { en: 'Validate syntax and reload sshd (do not close your session yet)', es: 'Valide la sintaxis y recargue sshd (no cierre aún su sesión)' },
    command: 'sudo sshd -t && sudo systemctl reload ssh',
    note: MANUAL,
  },
]

// ─── IDENTITY_ACCESS (0107–0111) ─────────────────────────────────────────────

const SSHD_X11: SecurityControl = {
  id: 'VC-LNX-0107',
  version: '1.0.0',
  name: { en: 'SSH X11 forwarding disabled', es: 'Reenvío X11 por SSH deshabilitado' },
  description: {
    en: 'X11Forwarding should be disabled: it exposes the X session to the server and enables keylogging/trojan attacks against administrators.',
    es: 'X11Forwarding debe estar deshabilitado: expone la sesión X al servidor y permite ataques de keylogging/troyanos contra administradores.',
  },
  category: 'IDENTITY_ACCESS',
  severity: 'MEDIUM',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/etc/ssh/sshd_config',
  evaluate(bag) {
    if (!bag.sshdConfigPresent) {
      return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
    }
    const v = (bag.sshdConfigMerged['X11Forwarding'] ?? '').toLowerCase()
    const evidence = [
      frag('file-read', '/etc/ssh/sshd_config', { X11Forwarding: v || '(unset — sshd default: no)' }, 'HIGH'),
    ]
    if (v === 'yes') {
      return { status: 'FAIL', detail: 'X11Forwarding yes', evidence }
    }
    if (v === '' || v === 'no') {
      return {
        status: 'PASS',
        detail: v === '' ? 'not set — sshd default is no (effective)' : 'X11Forwarding no',
        evidence,
      }
    }
    return { status: 'WARNING', detail: `unexpected value: ${v}`, evidence }
  },
  explanation: {
    en: 'X11 forwarding tunnels the remote X session through the server. On a hardened server it is pure attack surface: an attacker on the server can capture keystrokes and screenshots of the admin desktop.',
    es: 'El reenvío X11 tuneliza la sesión X remota a través del servidor. En un servidor endurecido es superficie de ataque pura: un atacante en el servidor puede capturar pulsaciones y pantallas del escritorio del administrador.',
  },
  references: [REF_OPENSSH, REF_CIS, REF_DEBIAN],
  remediation: rem(
    'MEDIUM',
    { en: 'SSH X11 forwarding is enabled or left to an unintended value.', es: 'El reenvío X11 por SSH está habilitado o con un valor no previsto.' },
    { en: 'Default hardening not applied to the sshd configuration.', es: 'Endurecimiento por defecto no aplicado a la configuración de sshd.' },
    { en: 'Session hijacking, keylogging and clipboard theft against remote administrators.', es: 'Secuestro de sesión, keylogging y robo de portapapeles contra administradores remotos.' },
    GENERIC_STATE,
    { en: 'X11Forwarding no (explicit) in sshd_config.', es: 'X11Forwarding no (explícito) en sshd_config.' },
    SSH_RELOAD_STEPS({ en: 'Disable X11 forwarding', es: 'Deshabilitar el reenvío X11' }, 'X11Forwarding no'),
    ['/etc/ssh/sshd_config'],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    GENERIC_VERIFY_SSHD,
  ),
}

const SSHD_EMPTY_PWD: SecurityControl = {
  id: 'VC-LNX-0108',
  version: '1.0.0',
  name: { en: 'SSH empty passwords prohibited', es: 'Contraseñas vacías por SSH prohibidas' },
  description: {
    en: 'PermitEmptyPasswords must be no: combined with an account that has an empty password it allows passwordless remote login.',
    es: 'PermitEmptyPasswords debe ser no: combinado con una cuenta de contraseña vacía permite inicio remoto sin contraseña.',
  },
  category: 'IDENTITY_ACCESS',
  severity: 'HIGH',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/etc/ssh/sshd_config',
  evaluate(bag) {
    if (!bag.sshdConfigPresent) {
      return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
    }
    const v = (bag.sshdConfigMerged['PermitEmptyPasswords'] ?? '').toLowerCase()
    const evidence = [
      frag('file-read', '/etc/ssh/sshd_config', { PermitEmptyPasswords: v || '(unset — sshd default: no)' }, 'HIGH'),
    ]
    if (v === 'yes') return { status: 'FAIL', detail: 'PermitEmptyPasswords yes', evidence }
    if (v === '' || v === 'no') {
      return {
        status: 'PASS',
        detail: v === '' ? 'not set — sshd default is no (effective)' : 'PermitEmptyPasswords no',
        evidence,
      }
    }
    return { status: 'WARNING', detail: `unexpected value: ${v}`, evidence }
  },
  explanation: {
    en: 'If empty passwords are permitted and any account has one (e.g. service accounts), anyone can log in remotely without credentials.',
    es: 'Si se permiten contraseñas vacías y alguna cuenta tiene una (p.ej. cuentas de servicio), cualquiera puede iniciar sesión remota sin credenciales.',
  },
  references: [REF_OPENSSH, REF_CIS, REF_NIST],
  remediation: rem(
    'HIGH',
    { en: 'SSH permits empty passwords.', es: 'SSH permite contraseñas vacías.' },
    { en: 'PermitEmptyPasswords yes in the effective sshd configuration.', es: 'PermitEmptyPasswords yes en la configuración efectiva de sshd.' },
    { en: 'Unauthenticated remote access to accounts with empty passwords.', es: 'Acceso remoto no autenticado a cuentas con contraseña vacía.' },
    GENERIC_STATE,
    { en: 'PermitEmptyPasswords no (explicit).', es: 'PermitEmptyPasswords no (explícito).' },
    SSH_RELOAD_STEPS({ en: 'Prohibit empty passwords', es: 'Prohibir contraseñas vacías' }, 'PermitEmptyPasswords no'),
    ['/etc/ssh/sshd_config'],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    GENERIC_VERIFY_SSHD,
  ),
}

const SSHD_MAX_AUTH: SecurityControl = {
  id: 'VC-LNX-0109',
  version: '1.0.0',
  name: { en: 'SSH MaxAuthTries bounded', es: 'SSH MaxAuthTries acotado' },
  description: {
    en: 'MaxAuthTries should be 4 or less to shorten the brute-force window per connection.',
    es: 'MaxAuthTries debe ser 4 o menos para acortar la ventana de fuerza bruta por conexión.',
  },
  category: 'IDENTITY_ACCESS',
  severity: 'MEDIUM',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/etc/ssh/sshd_config',
  evaluate(bag) {
    if (!bag.sshdConfigPresent) {
      return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
    }
    const raw = bag.sshdConfigMerged['MaxAuthTries'] ?? ''
    const evidence = [
      frag('file-read', '/etc/ssh/sshd_config', { MaxAuthTries: raw || '(unset — sshd default: 6)' }, 'HIGH'),
    ]
    if (raw === '') {
      return { status: 'FAIL', detail: 'not set — sshd default is 6 (> 4)', evidence }
    }
    const n = Number(raw)
    if (!Number.isInteger(n)) {
      return { status: 'WARNING', detail: `unparseable MaxAuthTries: ${raw}`, evidence }
    }
    return n <= 4
      ? { status: 'PASS', detail: `MaxAuthTries ${n}`, evidence }
      : { status: 'FAIL', detail: `MaxAuthTries ${n} > 4`, evidence }
  },
  explanation: {
    en: 'Each connection allows MaxAuthTries authentication attempts; a high value widens the brute-force window before the connection is dropped.',
    es: 'Cada conexión permite MaxAuthTries intentos de autenticación; un valor alto amplía la ventana de fuerza bruta antes de cortar la conexión.',
  },
  references: [REF_OPENSSH, REF_CIS, REF_MITRE],
  remediation: rem(
    'MEDIUM',
    { en: 'MaxAuthTries above 4 (or unset, default 6).', es: 'MaxAuthTries mayor que 4 (o sin definir, por defecto 6).' },
    { en: 'Hardening baseline never applied to sshd.', es: 'La línea base de endurecimiento nunca se aplicó a sshd.' },
    { en: 'Online password guessing against every exposed SSH listener.', es: 'Adivinación de contraseñas en línea contra cada listener SSH expuesto.' },
    GENERIC_STATE,
    { en: 'MaxAuthTries 4 (or lower).', es: 'MaxAuthTries 4 (o menor).' },
    SSH_RELOAD_STEPS({ en: 'Bound authentication attempts', es: 'Acotar los intentos de autenticación' }, 'MaxAuthTries 4'),
    ['/etc/ssh/sshd_config'],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    GENERIC_VERIFY_SSHD,
  ),
  limitations: {
    en: 'Value detection uses the merged sshd config (first occurrence wins). sshd -T is not executed to confirm the runtime value.',
    es: 'La detección usa la configuración sshd fusionada (primera aparición gana). No se ejecuta sshd -T para confirmar el valor en ejecución.',
  },
}

const SSHD_KEEPALIVE: SecurityControl = {
  id: 'VC-LNX-0111',
  version: '1.0.0',
  name: { en: 'SSH keepalive bounded', es: 'SSH ClientAliveInterval acotado' },
  description: {
    en: 'ClientAliveInterval should be set between 1 and 900 so idle/hung sessions are detected and closed.',
    es: 'ClientAliveInterval debe estar entre 1 y 900 para detectar y cerrar sesiones inactivas/colgadas.',
  },
  category: 'IDENTITY_ACCESS',
  severity: 'LOW',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/etc/ssh/sshd_config',
  evaluate(bag) {
    if (!bag.sshdConfigPresent) {
      return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
    }
    const raw = bag.sshdConfigMerged['ClientAliveInterval'] ?? ''
    const evidence = [
      frag('file-read', '/etc/ssh/sshd_config', { ClientAliveInterval: raw || '(unset — default: never)' }, 'HIGH'),
    ]
    if (raw === '') {
      return { status: 'FAIL', detail: 'not set — idle sessions are never terminated', evidence }
    }
    const n = Number(raw)
    if (!Number.isInteger(n) || n < 0) {
      return { status: 'WARNING', detail: `unparseable ClientAliveInterval: ${raw}`, evidence }
    }
    return n >= 1 && n <= 900
      ? { status: 'PASS', detail: `ClientAliveInterval ${n}`, evidence }
      : { status: 'FAIL', detail: `ClientAliveInterval ${n} outside 1..900`, evidence }
  },
  explanation: {
    en: 'Without server-side keepalives, abandoned/hung SSH sessions stay authenticated indefinitely (e.g. laptop asleep, NAT mapping expired).',
    es: 'Sin keepalives del servidor, las sesiones SSH abandonadas/colgadas permanecen autenticadas indefinidamente (p.ej. portátil suspendido, NAT expirado).',
  },
  references: [REF_OPENSSH, REF_CIS, REF_NIST],
  remediation: rem(
    'LOW',
    { en: 'ClientAliveInterval unset or outside 1..900.', es: 'ClientAliveInterval sin definir o fuera de 1..900.' },
    { en: 'Hardening baseline never applied to sshd.', es: 'La línea base de endurecimiento nunca se aplicó a sshd.' },
    { en: 'Stale authenticated sessions accumulate; abandoned sessions are never reaped.', es: 'Se acumulan sesiones autenticadas obsoletas; las sesiones abandonadas nunca se recogen.' },
    GENERIC_STATE,
    { en: 'ClientAliveInterval 300 and ClientAliveCountMax 3 (example).', es: 'ClientAliveInterval 300 y ClientAliveCountMax 3 (ejemplo).' },
    SSH_RELOAD_STEPS({ en: 'Set bounded keepalives', es: 'Definir keepalives acotados' }, 'ClientAliveInterval 300'),
    ['/etc/ssh/sshd_config'],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    GENERIC_VERIFY_SSHD,
  ),
}

const DUP_UID: SecurityControl = {
  id: 'VC-LNX-0110',
  version: '1.0.0',
  name: { en: 'No duplicate UIDs', es: 'Sin UIDs duplicados' },
  description: {
    en: 'Every account must have a unique UID: shared UIDs break accountability and allow permission confusion.',
    es: 'Cada cuenta debe tener un UID único: UIDs compartidos rompen la trazabilidad y generan confusión de permisos.',
  },
  category: 'IDENTITY_ACCESS',
  severity: 'MEDIUM',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/etc/passwd',
  evaluate(bag) {
    if (!bag.passwd) {
      return { status: 'NOT_ASSESSED', reason: bag.passwdError ?? '/etc/passwd unavailable' }
    }
    const byUid = new Map<number, string[]>()
    for (const u of bag.passwd) {
      const arr = byUid.get(u.uid) ?? []
      arr.push(u.name)
      byUid.set(u.uid, arr)
    }
    const dupes = [...byUid.entries()].filter(([, names]) => names.length > 1)
    const evidence = [
      frag('file-read', '/etc/passwd', { accounts: bag.passwd.length, duplicateUids: dupes.map(([uid, names]) => ({ uid, names })) }, 'HIGH'),
    ]
    if (dupes.length === 0) {
      return { status: 'PASS', detail: `${bag.passwd.length} accounts, no duplicate UIDs`, evidence }
    }
    const shown = dupes
      .slice(0, 5)
      .map(([uid, names]) => `uid ${uid}: ${names.join(', ')}`)
      .join('; ')
    return { status: 'FAIL', detail: `duplicate UIDs — ${shown}`, evidence }
  },
  explanation: {
    en: 'Two accounts with the same UID are indistinguishable to the kernel: audit trails attribute actions to the UID, not the name, so accountability collapses.',
    es: 'Dos cuentas con el mismo UID son indistinguibles para el kernel: las pistas de auditoría atribuyen acciones al UID, no al nombre, colapsando la trazabilidad.',
  },
  references: [REF_DEBIAN, REF_CIS, REF_NIST],
  remediation: rem(
    'MEDIUM',
    { en: 'Accounts share the same UID.', es: 'Cuentas comparten el mismo UID.' },
    { en: 'Manual account creation without useradd/usermod.', es: 'Creación manual de cuentas sin useradd/usermod.' },
    { en: 'Audit records cannot distinguish the real actor behind shared UIDs.', es: 'Los registros de auditoría no distinguen al actor real tras UIDs compartidos.' },
    GENERIC_STATE,
    { en: 'One UID per account; shared access delegated to groups (e.g. sudo, docker).', es: 'Un UID por cuenta; el acceso compartido se delega a grupos (p.ej. sudo, docker).' },
    [
      {
        title: { en: 'Identify duplicate UIDs', es: 'Identificar UIDs duplicados' },
        command: "awk -F: '{print $3}' /etc/passwd | sort | uniq -d",
        note: MANUAL,
      },
      {
        title: { en: 'Assign a unique UID to the secondary account (picks the next free one)', es: 'Asignar un UID único a la cuenta secundaria (elige el siguiente libre)' },
        command: 'sudo usermod -u <new-uid> <account>',
        note: MANUAL,
      },
      {
        title: { en: 'Re-own the moved files (find them by old UID before changing it)', es: 'Reasignar los archivos movidos (búyelos por el UID viejo antes de cambiarlo)' },
        command: 'sudo find / -xdev -uid <old-uid> -exec chown <account> {} +',
        note: MANUAL,
      },
    ],
    ['/etc/passwd'],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    { en: 'Re-run the duplicate-UID detection command: it must return nothing.', es: 'Reejecute el comando de detección: no debe devolver nada.' },
  ),
}

// ─── NETWORK_SECURITY (0304–0309) ────────────────────────────────────────────

const LEGACY_SERVICES: SecurityControl = {
  id: 'VC-LNX-0304',
  version: '1.0.0',
  name: { en: 'Legacy insecure services not listening', es: 'Servicios heredados inseguros sin escucha' },
  description: {
    en: 'FTP, telnet, TFTP, rlogin and rsh ports must not be listening: they transmit credentials and data in plaintext.',
    es: 'Los puertos FTP, telnet, TFTP, rlogin y rsh no deben estar en escucha: transmiten credenciales y datos en claro.',
  },
  category: 'NETWORK_SECURITY',
  severity: 'HIGH',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: 'ss -tulnH',
  evaluate(bag) {
    if (!bag.listeners) {
      return { status: 'NOT_ASSESSED', reason: bag.listenersError ?? 'listening sockets unavailable (ss unavailable)' }
    }
    const legacy: Record<number, string> = {
      21: 'ftp',
      23: 'telnet',
      69: 'tftp',
      513: 'rlogin',
      514: 'rsh/syslog-udp',
    }
    const hits = bag.listeners.filter((l) => legacy[l.port]).map((l) => `${l.proto} ${l.address}:${l.port} (${legacy[l.port]})`)
    const evidence = [
      frag('execFile:ss', 'ss -tulnH', { legacyPorts: hits }, hits.length === 0 ? 'HIGH' : 'MEDIUM'),
    ]
    if (hits.length === 0) {
      return { status: 'PASS', detail: 'no legacy plaintext service ports listening', evidence }
    }
    return { status: 'FAIL', detail: `listening — ${hits.slice(0, 4).join('; ')}`, evidence }
  },
  explanation: {
    en: 'These protocols pre-date modern security: everything (including passwords) travels in cleartext and can be captured on any path segment.',
    es: 'Estos protocolos son anteriores a la seguridad moderna: todo (incluidas contraseñas) viaja en claro y puede capturarse en cualquier tramo de la ruta.',
  },
  references: [REF_DEBIAN, REF_CIS, REF_NIST],
  remediation: rem(
    'HIGH',
    { en: 'Legacy plaintext services are listening.', es: 'Servicios heredados en claro están en escucha.' },
    { en: 'Obsolete packages still installed/enabled on the host.', es: 'Paquetes obsoletos aún instalados/habilitados en el host.' },
    { en: 'Credential and data interception on the wire; unauthenticated access.', es: 'Intercepción de credenciales y datos en la red; acceso sin autenticación.' },
    GENERIC_STATE,
    { en: 'No listeners on ports 21/23/69/513/514; SSH (22) and encrypted alternatives only.', es: 'Sin listeners en puertos 21/23/69/513/514; solo SSH (22) y alternativas cifradas.' },
    [
      {
        title: { en: 'Identify the owning process for the port', es: 'Identificar el proceso dueño del puerto' },
        command: 'sudo ss -tulnp | grep -E ":21|:23|:69|:513|:514"',
        note: MANUAL,
      },
      {
        title: { en: 'Disable and mask the service', es: 'Deshabilitar y enmascarar el servicio' },
        command: 'sudo systemctl disable --now <service> && sudo systemctl mask <service>',
        note: MANUAL,
      },
      {
        title: { en: 'Remove the package if not needed', es: 'Eliminar el paquete si no es necesario' },
        command: 'sudo apt purge telnetd inetutils-tftpd vsftpd rsh-server',
        note: MANUAL,
      },
    ],
    [],
    GENERIC_SIDE_EFFECTS,
    GENERIC_PREREQ,
    GENERIC_ROLLBACK,
    { en: 'ss -tulnH shows no listeners on those ports after the change.', es: 'ss -tulnH no muestra listeners en esos puertos tras el cambio.' },
  ),
}

function netRule(
  id: string,
  field: keyof LinuxEvidenceBagWithShadow['sysctlsNet'] & string,
  expected: number,
  nameEn: string,
  nameEs: string,
  descEn: string,
  descEs: string,
  riskEn: string,
  riskEs: string,
  severity: 'MEDIUM' | 'LOW',
  sysctlPath: string,
): SecurityControl {
  return {
    id,
    version: '1.0.0',
    name: { en: nameEn, es: nameEs },
    description: { en: descEn, es: descEs },
    category: 'NETWORK_SECURITY',
    severity,
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: sysctlPath,
    evaluate(bag) {
      const v = bag.sysctlsNet?.[field] ?? null
      const evidence = [frag('proc-read', sysctlPath, { [field]: v }, v === null ? 'LOW' : 'HIGH')]
      if (v === null) {
        return {
          status: 'NOT_ASSESSED',
          reason: `${sysctlPath} unreadable (non-Linux runtime or hardened container without /proc/sys)`,
          evidence,
        }
      }
      return v === expected
        ? { status: 'PASS', detail: `${field} = ${v}`, evidence }
        : { status: 'FAIL', detail: `${field} = ${v} (expected ${expected})`, evidence }
    },
    explanation: { en: riskEn, es: riskEs },
    references: [REF_CIS, REF_DEBIAN, REF_NIST],
    remediation: rem(
      severity,
      { en: `${nameEn}: current value deviates from the recommended one.`, es: `${nameEs}: el valor actual se desvía del recomendado.` },
      { en: 'Kernel network parameter left at default; no sysctl hardening applied.', es: 'Parámetro de red del kernel en su valor por defecto; sin endurecimiento sysctl aplicado.' },
      { en: riskEn, es: riskEs },
      GENERIC_STATE,
      { en: `Persist ${field} = ${expected} via /etc/sysctl.d.`, es: `Persistir ${field} = ${expected} vía /etc/sysctl.d.` },
      [
        {
          title: { en: 'Apply immediately (runtime)', es: 'Aplicar de inmediato (runtime)' },
          command: `sudo sysctl -w ${field}=${expected}`,
          note: MANUAL,
        },
        {
          title: { en: 'Persist across reboots', es: 'Persistir entre reinicios' },
          command: `echo '${field}=${expected}' | sudo tee /etc/sysctl.d/60-t82-hardening.conf && sudo sysctl --system`,
          note: MANUAL,
        },
      ],
      ['/etc/sysctl.d/60-t82-hardening.conf'],
      {
        en: 'Network sysctls can break routing/proxy scenarios (e.g. disabling send_redirects/accept_redirects on a router). Apply only to hosts, verify connectivity afterwards.',
        es: 'Los sysctls de red pueden romper escenarios de enrutamiento/proxy (p.ej. deshabilitar redirects en un router). Aplique solo a hosts y verifique conectividad después.',
      },
      GENERIC_PREREQ,
      { en: 'Remove the sysctl.d drop-in and run sysctl --system to restore defaults.', es: 'Elimine el drop-in sysctl.d y ejecute sysctl --system para restaurar los valores por defecto.' },
      { en: `sysctl ${field} prints ${expected}.`, es: `sysctl ${field} imprime ${expected}.` },
    ),
    limitations: {
      en: '/proc/sys reflects the whole kernel: in containers it is the host namespace and may be masked or read-only.',
      es: '/proc/sys refleja todo el kernel: en contenedores es el namespace del host y puede estar enmascarado o ser de solo lectura.',
    },
  }
}

const NET_RULES: SecurityControl[] = [
  netRule(
    'VC-LNX-0305',
    'accept_redirects',
    0,
    'ICMP redirects not accepted',
    'Redirecciones ICMP no aceptadas',
    'The host must ignore ICMP redirect messages (accept_redirects = 0) so attackers cannot alter its routing table on the fly.',
    'El host debe ignorar mensajes de redirección ICMP (accept_redirects = 0) para que atacantes no alteren su tabla de enrutamiento al vuelo.',
    'A forged ICMP redirect silently reroutes traffic through the attacker, enabling MITM of every subsequent connection.',
    'Una redirección ICMP falsificada redirige silenciosamente el tráfico por el atacante, habilitando MITM de cada conexión posterior.',
    'MEDIUM',
    '/proc/sys/net/ipv4/conf/all/accept_redirects',
  ),
  netRule(
    'VC-LNX-0306',
    'accept_source_route',
    0,
    'Source-routed packets rejected',
    'Paquetes con ruta de origen rechazados',
    'The host must drop source-routed packets (accept_source_route = 0): they let the sender pick the path, defeating routing controls.',
    'El host debe descartar paquetes con ruta de origen (accept_source_route = 0): permiten al emisor elegir la ruta y burlar los controles de enrutamiento.',
    'Source routing is a reconnaissance and spoofing primitive that almost never has a legitimate use on hosts.',
    'El source routing es una primitiva de reconocimiento y suplantación que casi nunca tiene uso legítimo en hosts.',
    'MEDIUM',
    '/proc/sys/net/ipv4/conf/all/accept_source_route',
  ),
  netRule(
    'VC-LNX-0307',
    'tcp_syncookies',
    1,
    'TCP SYN cookies enabled',
    'Cookies TCP SYN habilitadas',
    'tcp_syncookies = 1 lets the kernel survive SYN flood attacks without exhausting the connection table.',
    'tcp_syncookies = 1 permite al kernel sobrevivir ataques de inundación SYN sin agotar la tabla de conexiones.',
    'Without SYN cookies, a trivial SYN flood exhausts the backlog and the service stops accepting connections.',
    'Sin cookies SYN, una inundación SYN trivial agota el backlog y el servicio deja de aceptar conexiones.',
    'MEDIUM',
    '/proc/sys/net/ipv4/tcp_syncookies',
  ),
  netRule(
    'VC-LNX-0308',
    'send_redirects',
    0,
    'ICMP redirects not sent',
    'Redirecciones ICMP no enviadas',
    'A host (not a router) must not send ICMP redirects (send_redirects = 0): sending them leaks topology and can mislead peers.',
    'Un host (no un router) no debe enviar redirecciones ICMP (send_redirects = 0): enviarlas filtra la topología y puede confundir a los pares.',
    'Sending redirects reveals internal topology and can push peers into suboptimal/attacker-chosen paths.',
    'Enviar redirecciones revela la topología interna y puede empujar a los pares hacia rutas subóptimas o elegidas por el atacante.',
    'LOW',
    '/proc/sys/net/ipv4/conf/all/send_redirects',
  ),
  netRule(
    'VC-LNX-0309',
    'icmp_echo_ignore_broadcasts',
    1,
    'ICMP broadcast echo ignored',
    'Eco ICMP de broadcast ignorado',
    'icmp_echo_ignore_broadcasts = 1 prevents the host from answering broadcast pings, a component of smurf-amplification attacks.',
    'icmp_echo_ignore_broadcasts = 1 impide que el host responda pings de broadcast, componente de ataques de amplificación smurf.',
    'Answering broadcast ICMP turns the host into an amplification cannon against third parties and floods the local segment.',
    'Responder ICMP de broadcast convierte al host en un cañón de amplificación contra terceros e inunda el segmento local.',
    'LOW',
    '/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts',
  ),
]

// ─── SERVICES_PROCESSES (0402) ───────────────────────────────────────────────

const TIME_SYNC: SecurityControl = {
  id: 'VC-LNX-0402',
  version: '1.0.0',
  name: { en: 'Time synchronization active', es: 'Sincronización de tiempo activa' },
  description: {
    en: 'A time-synchronization daemon (chrony/systemd-timesyncd/ntp/openntpd) must be running so logs, certificates and Kerberos work.',
    es: 'Un demonio de sincronización de tiempo (chrony/systemd-timesyncd/ntp/openntpd) debe estar en ejecución para que logs, certificados y Kerberos funcionen.',
  },
  category: 'SERVICES_PROCESSES',
  severity: 'MEDIUM',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: 'systemctl list-units --type=service --state=running',
  evaluate(bag) {
    if (bag.systemdRunning !== true || !bag.runningServices) {
      return {
        status: 'NOT_ASSESSED',
        reason: 'systemd service list unavailable (container/offline runtime) — time sync cannot be verified honestly',
      }
    }
    const re = /^(chrony|chronyd|systemd-timesyncd|ntp|ntpd|openntpd)\b/
    const hits = bag.runningServices.filter((s) => re.test(s))
    const evidence = [
      frag('execFile:systemctl', 'systemctl list-units --type=service --state=running', { timeSyncUnits: hits }, 'HIGH'),
    ]
    if (hits.length === 0) {
      return { status: 'FAIL', detail: `no time-sync service running (${bag.runningServices.length} running services scanned)`, evidence }
    }
    return { status: 'PASS', detail: `time sync via ${hits[0]}`, evidence }
  },
  explanation: {
    en: 'Drifted clocks break TLS validation, corrupt audit timelines and break Kerberos/2FA. Time is a security dependency, not a convenience.',
    es: 'Los relojes desincronizados rompen la validación TLS, corrompen la línea temporal de auditoría y rompen Kerberos/2FA. El tiempo es una dependencia de seguridad, no una comodidad.',
  },
  references: [REF_DEBIAN, REF_CIS, REF_NIST],
  remediation: rem(
    'MEDIUM',
    { en: 'No time synchronization service running.', es: 'Ningún servicio de sincronización de tiempo en ejecución.' },
    { en: 'NTP client package not installed or its unit not enabled.', es: 'El paquete cliente NTP no está instalado o su unidad no está habilitada.' },
    { en: 'Certificate validation failures, unusable audit trails, broken SSO/Kerberos authentication.', es: 'Fallos de validación de certificados, pistas de auditoría inservibles, autenticación SSO/Kerberos rota.' },
    GENERIC_STATE,
    { en: 'chrony (or systemd-timesyncd) running and enabled at boot.', es: 'chrony (o systemd-timesyncd) en ejecución y habilitado al arranque.' },
    [
      {
        title: { en: 'Install and enable chrony', es: 'Instalar y habilitar chrony' },
        command: 'sudo apt install chrony && sudo systemctl enable --now chrony',
        note: MANUAL,
      },
      {
        title: { en: 'Verify synchronization', es: 'Verificar la sincronización' },
        command: 'chronyc tracking   # or: timedatectl show-timesync',
        note: MANUAL,
      },
    ],
    ['/etc/chrony/chrony.conf'],
    {
      en: 'A wrong NTP source or sudden step changes can break services that require monotonic progress; prefer slew (chrony default) over step.',
      es: 'Una fuente NTP incorrecta o saltos bruscos pueden romper servicios que exigen progreso monótono; prefiera slew (por defecto en chrony) sobre saltos.',
    },
    GENERIC_PREREQ,
    { en: 'sudo systemctl disable --now chrony restores the previous state (verify another sync source exists first).', es: 'sudo systemctl disable --now chrony restaura el estado previo (verifique antes que exista otra fuente de sync).' },
    { en: 'chronyc tracking shows "Leap status : Normal" and timedatectl shows synchronized: yes.', es: 'chronyc tracking muestra "Leap status : Normal" y timedatectl muestra synchronized: yes.' },
  ),
  limitations: {
    en: 'Detected only when systemd is operational: containers without systemd report NOT_ASSESSED even if time is synced by the host.',
    es: 'Solo se detecta con systemd operativo: contenedores sin systemd reportan NOT_ASSESSED aunque el tiempo lo sincronice el host.',
  },
}

// ─── DATA_PROTECTION (0602) ──────────────────────────────────────────────────

const SWAP_PROTECTION: SecurityControl = {
  id: 'VC-LNX-0602',
  version: '1.0.0',
  name: { en: 'Swap protection reviewed', es: 'Protección de swap revisada' },
  description: {
    en: 'If the host has swap, it should be encrypted (LUKS/crypttab) or avoided: swap pages contain passwords and keys in plaintext.',
    es: 'Si el host tiene swap, debe estar cifrado (LUKS/crypttab) o evitarse: las páginas de swap contienen contraseñas y claves en claro.',
  },
  category: 'DATA_PROTECTION',
  severity: 'MEDIUM',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: 'lsblk -P -o NAME,SIZE,TYPE,MOUNTPOINT',
  evaluate(bag) {
    if (!bag.swapDevices) {
      return { status: 'NOT_ASSESSED', reason: 'lsblk unavailable — block devices cannot be inventoried' }
    }
    const evidence = [
      frag('execFile:lsblk', 'lsblk -P -o NAME,SIZE,TYPE,MOUNTPOINT', { swapDevices: bag.swapDevices }, 'MEDIUM'),
      frag('file-read', '/etc/crypttab', { exists: bag.crypttabExists }, bag.crypttabExists ? 'HIGH' : 'MEDIUM'),
    ]
    if (bag.swapDevices.length === 0) {
      return { status: 'NOT_APPLICABLE', reason: 'no swap device detected (zram/none) — nothing to encrypt', evidence }
    }
    if (bag.crypttabExists) {
      return {
        status: 'PASS',
        detail: `swap present (${bag.swapDevices.map((s) => s.name).join(', ')}) and /etc/crypttab exists — config-presence only`,
        evidence,
      }
    }
    return {
      status: 'WARNING',
      detail: `swap present (${bag.swapDevices.map((s) => `${s.name} ${s.size}`).join(', ')}) without /etc/crypttab — likely unencrypted`,
      evidence,
    }
  },
  explanation: {
    en: 'The kernel writes memory pages — including passwords, session tokens and private keys — to swap unencrypted. Whoever takes the disk reads them.',
    es: 'El kernel escribe páginas de memoria —incluidas contraseñas, tokens de sesión y claves privadas— en el swap sin cifrar. Quien tome el disco las lee.',
  },
  references: [REF_DEBIAN, REF_NIST, REF_CIS],
  remediation: rem(
    'MEDIUM',
    { en: 'Swap device without encryption evidence.', es: 'Dispositivo de swap sin evidencia de cifrado.' },
    { en: 'System installed without encrypted swap (no crypttab mapping).', es: 'Sistema instalado sin swap cifrado (sin mapeo en crypttab).' },
    { en: 'Secrets from RAM persist on disk after shutdown/power loss and survive "deleted" files.', es: 'Secretos de RAM persisten en disco tras el apagado y sobreviven a archivos "borrados".' },
    GENERIC_STATE,
    { en: 'Encrypted swap (crypttab) or swap disabled where RAM suffices.', es: 'Swap cifrado (crypttab) o swap deshabilitado si la RAM basta.' },
    [
      {
        title: { en: 'Check current swap usage first', es: 'Verificar primero el uso actual del swap' },
        command: 'swapon --show && free -h',
        note: MANUAL,
      },
      {
        title: { en: 'If RAM suffices: disable swap cleanly', es: 'Si la RAM basta: deshabilitar el swap limpiamente' },
        command: 'sudo swapoff -a && sudo sed -i "/\\bswap\\b/s/^/#/" /etc/fstab',
        note: MANUAL,
      },
      {
        title: { en: 'If swap is needed: migrate it to a LUKS mapping (documented, destructive to that volume)', es: 'Si se necesita swap: migrarlo a un mapeo LUKS (documentado, destructivo para ese volumen)' },
        command: 'sudo cryptsetup luksFormat /dev/<swap-part> && # then register it in /etc/crypttab as swap with /dev/urandom key',
        note: MANUAL,
      },
    ],
    ['/etc/crypttab', '/etc/fstab'],
    {
      en: 'Disabling swap changes OOM behavior (more OOM-kills under pressure). Re-encrypting swap is destructive to the existing swap volume — plan a maintenance window.',
      es: 'Deshabilitar swap cambia el comportamiento OOM (más OOM-kills bajo presión). Recifrar swap es destructivo para el volumen existente — planifique ventana de mantenimiento.',
    },
    GENERIC_PREREQ,
    { en: 'Re-enable the fstab swap line and run swapon -a; or restore the previous crypttab/fstab from backup.', es: 'Rehabilite la línea de swap en fstab y ejecute swapon -a; o restaure crypttab/fstab previos desde backup.' },
    { en: 'swapon --show shows the /dev/mapper/<luks-swap> mapping; crypttab entry present.', es: 'swapon --show muestra el mapeo /dev/mapper/<luks-swap>; entrada crypttab presente.' },
  ),
  limitations: {
    en: 'Config-presence heuristic: crypttab existence does not prove THIS swap device is mapped. zram (RAM-backed) is reported but needs no encryption.',
    es: 'Heurística por presencia de configuración: la existencia de crypttab no prueba que ESTE swap esté mapeado. zram (en RAM) se reporta pero no requiere cifrado.',
  },
}

// ─── APPLICATION_SECURITY (0701) ─────────────────────────────────────────────

const DEV_TOOLS: SecurityControl = {
  id: 'VC-LNX-0701',
  version: '1.0.0',
  name: { en: 'Development tooling reviewed', es: 'Herramientas de desarrollo revisadas' },
  description: {
    en: 'Compilers and build tooling (gcc) should be absent on dedicated servers: they ease post-exploitation (rootkit/kernel module builds).',
    es: 'Compiladores y herramientas de compilación (gcc) deberían ausentarse en servidores dedicados: facilitan la post-explotación (rootkits/módulos del kernel).',
  },
  category: 'APPLICATION_SECURITY',
  severity: 'LOW',
  platforms: ['linux'],
  distros: ['debian', 'ubuntu'],
  implemented: true,
  evidenceSource: '/usr/bin/gcc (stat)',
  evaluate(bag) {
    const evidence = [
      frag('execFile:stat', '/usr/bin/gcc (stat)', { gccInstalled: bag.gccInstalled }, 'MEDIUM'),
    ]
    if (bag.gccInstalled) {
      return {
        status: 'WARNING',
        detail: 'gcc present — acceptable for build hosts; remove on dedicated servers where possible',
        evidence,
      }
    }
    return { status: 'PASS', detail: 'gcc not installed', evidence }
  },
  explanation: {
    en: 'After initial access, attackers commonly compile exploits or load build chains. Every unnecessary build tool removes a free post-exploitation primitive.',
    es: 'Tras el acceso inicial, los atacantes suelen compilar exploits o cargar cadenas de build. Cada herramienta de compilación innecesaria elimina una primitiva de post-explotación gratuita.',
  },
  references: [REF_DEBIAN, REF_CIS, REF_MITRE],
  remediation: rem(
    'LOW',
    { en: 'Compiler toolchain installed on a server role.', es: 'Cadena de compilación instalada en un rol de servidor.' },
    { en: 'Development packages pulled in by another install (e.g. native modules) and never removed.', es: 'Paquetes de desarrollo arrastrados por otra instalación (p.ej. módulos nativos) y nunca eliminados.' },
    { en: 'Speeds up post-exploitation: exploit compilation, rootkit building, privilege escalation tooling.', es: 'Acelera la post-explotación: compilación de exploits, construcción de rootkits, herramientas de escalada.' },
    GENERIC_STATE,
    { en: 'No compiler on dedicated servers; builds happen in CI or dedicated build images.', es: 'Sin compilador en servidores dedicados; los builds ocurren en CI o imágenes dedicadas.' },
    [
      {
        title: { en: 'Check reverse dependencies BEFORE removing', es: 'Verificar dependencias inversas ANTES de eliminar' },
        command: 'apt why gcc   # and: dpkg -l | grep build-essential',
        note: MANUAL,
      },
      {
        title: { en: 'Remove the toolchain if nothing depends on it', es: 'Eliminar la cadena si nada depende de ella' },
        command: 'sudo apt purge gcc g++ make build-essential && sudo apt autoremove',
        note: MANUAL,
      },
    ],
    [],
    {
      en: 'Removing build tools breaks runtimes that compile native extensions at deploy time (node-gyp, Python wheels). Verify your deployment process first.',
      es: 'Eliminar las herramientas de build rompe runtimes que compilan extensiones nativas al desplegar (node-gyp, wheels de Python). Verifique primero su proceso de despliegue.',
    },
    GENERIC_PREREQ,
    { en: 'sudo apt install gcc restores the previous state.', es: 'sudo apt install gcc restaura el estado previo.' },
    { en: 'command -v gcc returns nothing after removal.', es: 'command -v gcc no devuelve nada tras la eliminación.' },
  ),
  limitations: {
    en: 'Only gcc is probed (allowlisted stat). Other compilers (clang, go, rustc) are not inventoried in this build.',
    es: 'Solo se sondea gcc (stat en allowlist). Otros compiladores (clang, go, rustc) no se inventarían en esta build.',
  },
}

export const EXTENDED_LINUX_RULES: SecurityControl[] = [
  SSHD_X11,
  SSHD_EMPTY_PWD,
  SSHD_MAX_AUTH,
  DUP_UID,
  SSHD_KEEPALIVE,
  LEGACY_SERVICES,
  ...NET_RULES,
  TIME_SYNC,
  SWAP_PROTECTION,
  DEV_TOOLS,
]
