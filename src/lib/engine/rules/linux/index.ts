// DIVISION T82 — Linux security controls (VC-LNX-xxxx), 20 implemented rules.
// Evaluators are PURE functions of the LinuxEvidenceBag (no I/O inside evaluate).
// Honesty rules: no permissions → NOT_ASSESSED (with reason); feature absent →
// NOT_APPLICABLE; never PASS without evidence. /etc/shadow hashes are NEVER
// stored — only per-account statuses. Remediation is advisoryOnly (manual steps).
import type {
  SecurityControl,
  ControlEvaluation,
  EvidenceFragment,
  EvidenceMethod,
  Confidence,
  Severity,
  Loc,
  Remediation,
  RemediationStep,
  SecurityReference,
} from '../../types'
import type { LinuxEvidenceBagWithShadow } from '../../collectors/linux'
import {
  frag,
  rem,
  modeWithin,
  NO_SSHD,
  SHADOW_NO_ROOT,
  SUDOERS_NO_ROOT,
  MANUAL,
  GENERIC_STATE,
  GENERIC_PREREQ,
  GENERIC_SIDE_EFFECTS,
  REF_DEBIAN,
  REF_UBUNTU,
  REF_OPENSSH,
  REF_CIS,
  REF_NIST,
  REF_MITRE,
} from './util'

export { frag, rem, modeWithin }

const GENERIC_ROLLBACK: Loc = {
  en: 'Restore the backup copy of the modified file and reload the affected service.',
  es: 'Restaure la copia de seguridad del archivo modificado y recargue el servicio afectado.',
}

// ─── Control catalog ─────────────────────────────────────────────────────────

export const LINUX_RULES: SecurityControl[] = [
  // ── IDENTITY_ACCESS ────────────────────────────────────────────────────────
  {
    id: 'VC-LNX-0101',
    version: '1.0.0',
    name: { en: 'SSH root login prohibited', es: 'Inicio de sesión root por SSH prohibido' },
    description: {
      en: 'PermitRootLogin must be "no" in /etc/ssh/sshd_config (or its sshd_config.d includes) so the root account cannot be reached directly over SSH.',
      es: 'PermitRootLogin debe ser "no" en /etc/ssh/sshd_config (o sus includes de sshd_config.d) para que la cuenta root no sea alcanzable directamente por SSH.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/ssh/sshd_config (+ sshd_config.d)',
    evaluate(bag): ControlEvaluation {
      if (!bag.sshdConfigPresent) {
        return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
      }
      const value = bag.sshdConfigMerged['PermitRootLogin']
      const evidence = [
        frag(
          'file-read',
          '/etc/ssh/sshd_config',
          { sshdConfigPresent: true, option: 'PermitRootLogin', effectiveValue: value ?? null, mergedOptionsCount: Object.keys(bag.sshdConfigMerged).length },
          value !== undefined ? 'MEDIUM' : 'HIGH',
        ),
      ]
      if (value === 'no') {
        return { status: 'PASS', detail: 'PermitRootLogin no — direct root SSH login is disabled', evidence }
      }
      if (value === 'prohibit-password') {
        return {
          status: 'WARNING',
          detail:
            'PermitRootLogin prohibit-password — blocks password root logins but root may still log in with keys; set "no" unless key-based root access is explicitly required',
          evidence,
        }
      }
      if (value === 'yes') {
        return {
          status: 'FAIL',
          detail: 'PermitRootLogin yes — direct root SSH login is allowed; brute force against root becomes possible',
          evidence,
        }
      }
      return {
        status: 'WARNING',
        detail: 'PermitRootLogin not set — sshd default is prohibit-password; make the policy explicit in sshd_config',
        evidence,
      }
    },
    explanation: {
      en: 'The root account has unrestricted power over the system. Exposing it directly to SSH gives attackers a well-known username to brute-force or key-harvest; operating as unprivileged users with sudo is safer and auditable.',
      es: 'La cuenta root tiene poder ilimitado sobre el sistema. Exponerla por SSH ofrece a los atacantes un usuario conocido para fuerza bruta o robo de claves; operar como usuarios sin privilegios con sudo es más seguro y auditable.',
    },
    references: [REF_DEBIAN, REF_OPENSSH, REF_CIS, REF_MITRE],
    remediation: rem(
      'HIGH',
      {
        en: 'sshd accepts direct root logins (PermitRootLogin is "yes", or defaults to "prohibit-password" which still allows key-based root access).',
        es: 'sshd acepta inicios de sesión root directos (PermitRootLogin es "yes", o queda por defecto "prohibit-password" que aún permite acceso root con claves).',
      },
      {
        en: 'Default vendor configuration or an explicit permissive override; include files under /etc/ssh/sshd_config.d may re-enable it.',
        es: 'Configuración por defecto del fabricante o una anulación permisiva explícita; los includes en /etc/ssh/sshd_config.d pueden reactivarlo.',
      },
      {
        en: 'Direct root access enables brute-force and credential-stuffing attacks against the most powerful account (MITRE ATT&CK T1078/T1110).',
        es: 'El acceso root directo habilita fuerza bruta y credential stuffing contra la cuenta más poderosa (MITRE ATT&CK T1078/T1110).',
      },
      GENERIC_STATE,
      { en: 'PermitRootLogin no (or "prohibit-password" only if key-based root access is formally required).', es: 'PermitRootLogin no (o "prohibit-password" solo si el acceso root con claves está formalmente justificado).' },
      [
        {
          title: { en: 'Back up the SSH configuration', es: 'Respaldar la configuración de SSH' },
          command: 'sudo cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)',
          note: MANUAL,
        },
        {
          title: { en: 'Set the policy explicitly', es: 'Fijar la política explícitamente' },
          command: 'echo "PermitRootLogin no" | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf',
          note: MANUAL,
        },
        {
          title: { en: 'Validate syntax before reloading', es: 'Validar sintaxis antes de recargar' },
          command: 'sudo sshd -t',
          note: MANUAL,
        },
        {
          title: { en: 'Reload sshd (keep your session open until verified)', es: 'Recargar sshd (mantenga su sesión abierta hasta verificar)' },
          command: 'sudo systemctl reload ssh || sudo systemctl reload sshd',
          note: MANUAL,
        },
      ],
      ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/'],
      {
        en: 'Root will no longer be reachable over SSH; ensure a named sudo user with working keys exists first.',
        es: 'root ya no será alcanzable por SSH; asegure antes un usuario con sudo nombrado y claves funcionales.',
      },
      GENERIC_PREREQ,
      {
        en: 'Delete /etc/ssh/sshd_config.d/99-hardening.conf (or restore the backup) and run sshd -t before reloading.',
        es: 'Elimine /etc/ssh/sshd_config.d/99-hardening.conf (o restaure el respaldo) y ejecute sshd -t antes de recargar.',
      },
      {
        en: 'sudo sshd -T | grep -i permitrootlogin → must print "permitrootlogin no".',
        es: 'sudo sshd -T | grep -i permitrootlogin → debe mostrar "permitrootlogin no".',
      },
    ),
    limitations: {
      en: 'Merged sshd_config.d view approximates sshd first-occurrence semantics; Match blocks are not evaluated. If no sshd is installed the control is NOT_APPLICABLE.',
      es: 'La vista fusionada de sshd_config.d aproxima la semántica de primera ocurrencia de sshd; los bloques Match no se evalúan. Sin sshd instalado el control es NOT_APPLICABLE.',
    },
  },
  {
    id: 'VC-LNX-0102',
    version: '1.0.0',
    name: { en: 'SSH password authentication disabled', es: 'Autenticación por contraseña de SSH deshabilitada' },
    description: {
      en: 'PasswordAuthentication must be "no" so SSH access relies on public keys only, eliminating password guessing attacks.',
      es: 'PasswordAuthentication debe ser "no" para que el acceso SSH dependa solo de claves públicas, eliminando ataques de adivinación de contraseñas.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/ssh/sshd_config (+ sshd_config.d)',
    evaluate(bag): ControlEvaluation {
      if (!bag.sshdConfigPresent) {
        return { status: 'NOT_APPLICABLE', reason: NO_SSHD }
      }
      const value = bag.sshdConfigMerged['PasswordAuthentication']
      const evidence = [
        frag(
          'file-read',
          '/etc/ssh/sshd_config',
          { sshdConfigPresent: true, option: 'PasswordAuthentication', effectiveValue: value ?? null },
          value !== undefined ? 'MEDIUM' : 'HIGH',
        ),
      ]
      if (value === 'no') {
        return { status: 'PASS', detail: 'PasswordAuthentication no — SSH accepts public keys only', evidence }
      }
      if (value === 'yes') {
        return {
          status: 'FAIL',
          detail: 'PasswordAuthentication yes — SSH password guessing is possible on every exposed account',
          evidence,
        }
      }
      return {
        status: 'WARNING',
        detail: 'PasswordAuthentication not set — sshd default is "yes" in the main config; key-only policy should be made explicit',
        evidence,
      }
    },
    explanation: {
      en: 'Passwords can be guessed, reused or phrished; public keys are not. Disabling password auth on SSH removes the primary vector of automated intrusion attempts (MITRE ATT&CK T1110).',
      es: 'Las contraseñas se pueden adivinar, reutilizar o phishing; las claves públicas no. Deshabilitar la autenticación por contraseña en SSH elimina el vector principal de intrusiones automatizadas (MITRE ATT&CK T1110).',
    },
    references: [REF_OPENSSH, REF_DEBIAN, REF_CIS, REF_MITRE],
    remediation: rem(
      'HIGH',
      {
        en: 'sshd still accepts passwords (option "yes" or unset default), so exposed accounts can be brute-forced.',
        es: 'sshd aún acepta contraseñas (opción "yes" o el defecto sin fijar), por lo que las cuentas expuestas pueden ser atacadas por fuerza bruta.',
      },
      {
        en: 'Vendor default; password login is convenient during provisioning and rarely disabled afterwards.',
        es: 'Defecto del fabricante; el acceso por contraseña es cómodo al aprovisionar y rara vez se deshabilita después.',
      },
      {
        en: 'Automated password guessing against SSH is among the most common internet background noise; weak passwords get compromised in hours.',
        es: 'La fuerza bruta contra SSH es de los ruidos de internet más comunes; contraseñas débiles se comprometen en horas.',
      },
      GENERIC_STATE,
      { en: 'PasswordAuthentication no, with verified key-based access for every required user.', es: 'PasswordAuthentication no, con acceso por claves verificado para cada usuario requerido.' },
      [
        {
          title: { en: 'Verify key-based login works BEFORE disabling passwords', es: 'Verificar que el acceso por clave funciona ANTES de deshabilitar contraseñas' },
          command: 'ssh -i ~/.ssh/id_ed25519 usuario@host "echo ok"',
          note: MANUAL,
        },
        {
          title: { en: 'Set key-only policy', es: 'Fijar política solo-claves' },
          command: 'echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf',
          note: MANUAL,
        },
        {
          title: { en: 'Validate and reload', es: 'Validar y recargar' },
          command: 'sudo sshd -t && sudo systemctl reload ssh',
          note: MANUAL,
        },
      ],
      ['/etc/ssh/sshd_config', '/etc/ssh/sshd_config.d/'],
      {
        en: 'If no valid key is configured for a user, that user loses SSH access immediately.',
        es: 'Si un usuario no tiene clave válida configurada, pierde el acceso SSH de inmediato.',
      },
      {
        en: 'Confirmed key access for all required accounts; a second active session while validating.',
        es: 'Acceso por clave confirmado para todas las cuentas requeridas; una segunda sesión activa mientras valida.',
      },
      {
        en: 'Remove the override file (or restore the backup) and reload sshd.',
        es: 'Elimine el archivo de anulación (o restaure el respaldo) y recargue sshd.',
      },
      {
        en: 'sudo sshd -T | grep -i passwordauthentication → must print "passwordauthentication no"; a password login attempt must be refused.',
        es: 'sudo sshd -T | grep -i passwordauthentication → debe mostrar "passwordauthentication no"; un intento con contraseña debe ser rechazado.',
      },
    ),
    limitations: {
      en: 'Merged sshd_config.d view approximates sshd semantics; Match blocks (per-user overrides) are not evaluated.',
      es: 'La vista fusionada de sshd_config.d aproxima la semántica de sshd; los bloques Match (anulaciones por usuario) no se evalúan.',
    },
  },
  {
    id: 'VC-LNX-0103',
    version: '1.0.0',
    name: { en: 'No accounts with empty passwords', es: 'Sin cuentas con contraseña vacía' },
    description: {
      en: 'No account in /etc/shadow may have an empty password field; empty passwords allow unauthenticated local or remote login.',
      es: 'Ninguna cuenta en /etc/shadow puede tener el campo de contraseña vacío; una contraseña vacía permite inicio de sesión sin autenticación.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'CRITICAL',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/shadow',
    evaluate(bag): ControlEvaluation {
      if (!bag.shadowReadable) {
        return {
          status: 'NOT_ASSESSED',
          reason: SHADOW_NO_ROOT,
          evidence: [frag('file-read', '/etc/shadow', { shadowReadable: false }, 'LOW', 'root')],
        }
      }
      const statuses = (bag as LinuxEvidenceBagWithShadow).shadowStatuses
      if (!statuses) {
        return {
          status: 'NOT_ASSESSED',
          reason: 'shadow readable but per-account statuses unavailable (collection degraded)',
        }
      }
      const empties = statuses.filter((s) => s.status === 'EMPTY')
      const locked = statuses.filter((s) => s.status === 'locked').length
      const setCount = statuses.filter((s) => s.status === 'SET').length
      // Payload contains ONLY statuses — hash strings are never collected or stored.
      const evidence = [
        frag(
          'file-read',
          '/etc/shadow',
          { shadowReadable: true, statuses: statuses.slice(0, 200), note: 'per-account status only — hashes never stored' },
          'HIGH',
          'root',
        ),
      ]
      if (empties.length > 0) {
        return {
          status: 'FAIL',
          detail: `${empties.length} account(s) with EMPTY password: ${empties.map((s) => s.name).join(', ')} — these accounts can log in without any password`,
          evidence,
        }
      }
      return {
        status: 'PASS',
        detail: `no empty passwords — ${setCount} account(s) with hash set, ${locked} locked`,
        evidence,
      }
    },
    explanation: {
      en: 'An empty password field in /etc/shadow means the account authenticates with just a username. Attackers pivot to such accounts after any foothold; PAM may also treat them as password-less on consoles (MITRE ATT&CK T1078).',
      es: 'Un campo de contraseña vacío en /etc/shadow significa que la cuenta se autentica solo con el nombre de usuario. Los atacantes pivotean a esas cuentas tras obtener cualquier acceso; PAM también puede tratarlas como sin contraseña en consolas (MITRE ATT&CK T1078).',
    },
    references: [REF_DEBIAN, REF_CIS, REF_NIST, REF_MITRE],
    remediation: rem(
      'CRITICAL',
      {
        en: 'One or more accounts have an empty password in /etc/shadow.',
        es: 'Una o más cuentas tienen contraseña vacía en /etc/shadow.',
      },
      {
        en: 'Accounts created without passwords (automation mistakes, legacy service accounts, interrupted provisioning).',
        es: 'Cuentas creadas sin contraseña (errores de automatización, cuentas de servicio heredadas, aprovisionamiento interrumpido).',
      },
      {
        en: 'Unauthenticated access to those accounts; immediate privilege escalation path once any foothold exists.',
        es: 'Acceso sin autenticación a esas cuentas; vía inmediata de escalada de privilegios en cuanto exista cualquier acceso inicial.',
      },
      GENERIC_STATE,
      { en: 'Every account either has a strong password hash or is locked ("!" / "*").', es: 'Toda cuenta debe tener un hash de contraseña fuerte o estar bloqueada ("!" / "*").' },
      [
        {
          title: { en: 'List accounts with empty passwords (names only)', es: 'Listar cuentas con contraseña vacía (solo nombres)' },
          command: 'sudo awk -F: \'($2==""){print $1}\' /etc/shadow',
          note: MANUAL,
        },
        {
          title: { en: 'Set a strong password for required accounts', es: 'Asignar contraseña fuerte a las cuentas requeridas' },
          command: 'sudo passwd <usuario>',
          note: MANUAL,
        },
        {
          title: { en: 'Or lock unnecessary accounts', es: 'O bloquear cuentas innecesarias' },
          command: 'sudo passwd -l <usuario> && sudo usermod -s /usr/sbin/nologin <usuario>',
          note: MANUAL,
        },
      ],
      ['/etc/shadow'],
      {
        en: 'Locking an account stops its scheduled jobs/service logins; confirm nothing depends on it first.',
        es: 'Bloquear una cuenta detiene sus tareas programadas/accesos de servicio; confirme primero que nada depende de ella.',
      },
      GENERIC_PREREQ,
      {
        en: 'passwd -l is reversible with passwd -u; restoring the pre-change /etc/shadow backup also reverts changes.',
        es: 'passwd -l es reversible con passwd -u; restaurar el respaldo previo de /etc/shadow también revierte los cambios.',
      },
      {
        en: 'Re-run the scan with root, or verify: sudo awk -F: \'($2==""){print $1}\' /etc/shadow prints nothing.',
        es: 'Reejecute el escaneo con root, o verifique: sudo awk -F: \'($2==""){print $1}\' /etc/shadow no imprime nada.',
      },
    ),
    limitations: {
      en: 'Requires readable /etc/shadow (root). Without it the control is NOT_ASSESSED; statuses (locked/empty/set) are derived, hashes are never read into evidence.',
      es: 'Requiere /etc/shadow legible (root). Sin ello el control es NOT_ASSESSED; se derivan solo estados (bloqueada/vacía/definida), nunca se leen hashes a la evidencia.',
    },
  },
  {
    id: 'VC-LNX-0104',
    version: '1.0.0',
    name: { en: 'No extra UID 0 accounts', es: 'Sin cuentas adicionales con UID 0' },
    description: {
      en: 'Only "root" should own UID 0 in /etc/passwd; any other UID 0 account is an undeclared superuser.',
      es: 'Solo "root" debe tener UID 0 en /etc/passwd; cualquier otra cuenta con UID 0 es un superusuario no declarado.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/passwd',
    evaluate(bag): ControlEvaluation {
      if (!bag.passwd) {
        return { status: 'NOT_ASSESSED', reason: '/etc/passwd unreadable' }
      }
      const uid0 = bag.passwd.filter((u) => u.uid === 0).map((u) => u.name)
      const evidence = [
        frag('file-read', '/etc/passwd', { uid0Accounts: uid0, total: uid0.length, accountsListed: bag.passwd.length }, 'HIGH'),
      ]
      if (uid0.length === 1 && uid0[0] === 'root') {
        return { status: 'PASS', detail: 'only "root" has UID 0', evidence }
      }
      return {
        status: 'FAIL',
        detail: `CRITICAL: ${uid0.length} accounts with UID 0 (${uid0.join(', ')}) — every one of them has unrestricted superuser power; only "root" is expected`,
        evidence,
      }
    },
    explanation: {
      en: 'Any account with UID 0 bypasses all per-user restrictions. Hidden UID 0 users are a classic backdoor and evade administrator account reviews (MITRE ATT&CK T1136).',
      es: 'Cualquier cuenta con UID 0 evita todas las restricciones por usuario. Los usuarios UID 0 ocultos son una puerta trasera clásica y evaden las revisiones de cuentas de administrador (MITRE ATT&CK T1136).',
    },
    references: [REF_DEBIAN, REF_CIS, REF_MITRE, REF_NIST],
    remediation: rem(
      'HIGH',
      {
        en: 'Accounts other than "root" hold UID 0.',
        es: 'Cuentas distintas de "root" tienen UID 0.',
      },
      {
        en: 'Manual /etc/passwd edits, malicious backdoors, or legacy cloning of root.',
        es: 'Ediciones manuales de /etc/passwd, puertas traseras maliciosas o clonado heredado de root.',
      },
      {
        en: 'Undeclared superusers: no audit trail, no sudo boundary, ideal persistence mechanism.',
        es: 'Superusuarios no declarados: sin rastro de auditoría, sin frontera sudo, mecanismo ideal de persistencia.',
      },
      GENERIC_STATE,
      { en: 'Exactly one UID 0 account: "root". Administrative users must use sudo.', es: 'Exactamente una cuenta con UID 0: "root". Los administradores deben usar sudo.' },
      [
        {
          title: { en: 'Inspect UID 0 accounts', es: 'Inspeccionar cuentas con UID 0' },
          command: 'getent passwd | awk -F: \'$3==0 {print}\'',
          note: MANUAL,
        },
        {
          title: { en: 'Investigate origin (history, shell, home) of every extra UID 0 account', es: 'Investigar el origen (historial, shell, home) de cada cuenta UID 0 extra' },
          note: MANUAL,
        },
        {
          title: { en: 'Lock or remove the extra account after confirmation', es: 'Bloquear o eliminar la cuenta extra tras confirmación' },
          command: 'sudo usermod -L <usuario> && sudo usermod -s /usr/sbin/nologin <usuario>  # o: sudo userdel <usuario>',
          note: MANUAL,
        },
      ],
      ['/etc/passwd', '/etc/shadow'],
      {
        en: 'If the account is actually used by a service, locking it breaks that service; verify ownership first.',
        es: 'Si la cuenta es usada realmente por un servicio, bloquearla lo rompe; verifique antes su titularidad.',
      },
      {
        en: 'Confidence that the account is not required by any service or operator; incident-response suspicion should follow IR procedure.',
        es: 'Certeza de que ninguna servicio u operador requiere la cuenta; ante sospecha de incidente siga el procedimiento de respuesta.',
      },
      {
        en: 'Re-create the account entries exactly as found (back up /etc/passwd before editing).',
        es: 'Recrear las entradas exactamente como estaban (respalde /etc/passwd antes de editar).',
      },
      {
        en: 'getent passwd | awk -F: \'$3==0 {print}\' returns only root; re-run the scan shows PASS.',
        es: 'getent passwd | awk -F: \'$3==0 {print}\' devuelve solo root; reejecutar el escaneo muestra PASS.',
      },
    ),
    limitations: {
      en: '/etc/passwd does not prove group memberships or sudo rights; those are reviewed by other controls. NSS backends beyond files are not enumerated.',
      es: '/etc/passwd no prueba membresías de grupo ni derechos sudo; eso lo cubren otros controles. No se enumeran backends NSS distintos de archivos.',
    },
  },
  {
    id: 'VC-LNX-0105',
    version: '1.0.0',
    name: { en: 'Password aging policy', es: 'Política de expiración de contraseñas' },
    description: {
      en: 'PASS_MAX_DAYS in /etc/login.defs must be defined and <= 90 so passwords are rotated on a bounded cycle.',
      es: 'PASS_MAX_DAYS en /etc/login.defs debe estar definido y ser <= 90 para que las contraseñas roten en un ciclo acotado.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/login.defs',
    evaluate(bag): ControlEvaluation {
      if (bag.loginDefs === null) {
        return {
          status: 'NOT_ASSESSED',
          reason: `/etc/login.defs unreadable${bag.loginDefsError ? ` (${bag.loginDefsError})` : ''}`,
        }
      }
      const raw = bag.loginDefs['PASS_MAX_DAYS']
      const evidence = [
        frag('file-read', '/etc/login.defs', { PASS_MAX_DAYS: raw ?? null, PASS_MIN_DAYS: bag.loginDefs['PASS_MIN_DAYS'] ?? null }, 'HIGH'),
      ]
      if (raw === undefined) {
        return {
          status: 'WARNING',
          detail: 'PASS_MAX_DAYS not set in /etc/login.defs — new accounts get unlimited password lifetime',
          evidence,
        }
      }
      const n = parseInt(raw, 10)
      if (!Number.isFinite(n)) {
        return { status: 'WARNING', detail: `PASS_MAX_DAYS value "${raw}" is not numeric`, evidence }
      }
      if (n <= 90) {
        return { status: 'PASS', detail: `PASS_MAX_DAYS = ${n} (<= 90)`, evidence }
      }
      return {
        status: 'FAIL',
        detail: `PASS_MAX_DAYS = ${n} exceeds the 90-day recommendation — passwords live longer than the rotation window`,
        evidence,
      }
    },
    explanation: {
      en: 'A bounded password lifetime limits how long a stolen credential remains valid and forces periodic re-evaluation of secret quality (NIST SP 800-63B balances this against rotation fatigue).',
      es: 'Una vida útil acotada limita cuánto tiempo una credencial robada sigue válida y fuerza reevaluación periódica de la calidad del secreto (NIST SP 800-63B matiza la fatiga por rotación).',
    },
    references: [REF_DEBIAN, REF_NIST, REF_CIS],
    remediation: rem(
      'MEDIUM',
      {
        en: 'PASS_MAX_DAYS is unset or above 90 in /etc/login.defs.',
        es: 'PASS_MAX_DAYS no está definido o supera 90 en /etc/login.defs.',
      },
      {
        en: 'Vendor defaults do not include an explicit aging policy.',
        es: 'Los defectos del fabricante no incluyen una política de expiración explícita.',
      },
      {
        en: 'Long-lived credentials increase exposure window after leaks or personnel changes.',
        es: 'Credenciales de vida larga amplían la ventana de exposición tras filtraciones o cambios de personal.',
      },
      GENERIC_STATE,
      { en: 'PASS_MAX_DAYS <= 90, PASS_MIN_DAYS >= 1 (avoid trivial rotation), PASS_WARN_AGE >= 7.', es: 'PASS_MAX_DAYS <= 90, PASS_MIN_DAYS >= 1 (evitar rotación trivial), PASS_WARN_AGE >= 7.' },
      [
        {
          title: { en: 'Back up login.defs', es: 'Respaldar login.defs' },
          command: 'sudo cp -a /etc/login.defs /etc/login.defs.bak.$(date +%F)',
          note: MANUAL,
        },
        {
          title: { en: 'Set the aging policy', es: 'Fijar la política de expiración' },
          command: 'sudo sed -i \'s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS  90/\' /etc/login.defs && grep -E "^PASS_(MAX|MIN|WARN)" /etc/login.defs',
          note: MANUAL,
        },
        {
          title: { en: 'Apply to existing accounts where policy requires (example)', es: 'Aplicar a cuentas existentes cuando la política lo exija (ejemplo)' },
          command: 'sudo chage -M 90 <usuario>',
          note: MANUAL,
        },
      ],
      ['/etc/login.defs'],
      {
        en: 'Affects newly created accounts and changed passwords; aggressive rotation on operational/service accounts can break workflows — scope deliberately.',
        es: 'Afecta a cuentas nuevas y contraseñas cambiadas; una rotación agresiva sobre cuentas de servicio puede romper flujos — delimite deliberadamente.',
      },
      GENERIC_PREREQ,
      { en: 'Restore the backup copy of /etc/login.defs.', es: 'Restaure la copia de respaldo de /etc/login.defs.' },
      {
        en: 'grep -E "^PASS_MAX_DAYS" /etc/login.defs shows 90; chage -l <usuario> reflects the maximum.',
        es: 'grep -E "^PASS_MAX_DAYS" /etc/login.defs muestra 90; chage -l <usuario> refleja el máximo.',
      },
    ),
    limitations: {
      en: 'Per-account chage overrides in /etc/shadow are not enumerated; the control evaluates the default policy only.',
      es: 'Las anulaciones por cuenta (chage) en /etc/shadow no se enumeran; el control evalúa solo la política por defecto.',
    },
  },
  {
    id: 'VC-LNX-0106',
    version: '1.0.0',
    name: { en: 'No NOPASSWD in sudo', es: 'Sin NOPASSWD en sudo' },
    description: {
      en: 'sudoers must not grant commands without password re-authentication (NOPASSWD) except where formally justified per-command.',
      es: 'sudoers no debe conceder comandos sin re-autenticación por contraseña (NOPASSWD), salvo justificación formal por comando.',
    },
    category: 'IDENTITY_ACCESS',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/sudoers',
    evaluate(bag): ControlEvaluation {
      if (!bag.sudoersReadable) {
        return {
          status: 'NOT_ASSESSED',
          reason: SUDOERS_NO_ROOT,
          evidence: [frag('file-read', '/etc/sudoers', { sudoersReadable: false, sudoersFiles: bag.sudoersFiles }, 'LOW', 'root')],
        }
      }
      if (!bag.sudoersContent) {
        return { status: 'NOT_ASSESSED', reason: 'sudoers readable flag set but content unavailable' }
      }
      const hits = bag.sudoersContent
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0)
        .filter((l) => !l.startsWith('#'))
        .filter((l) => !l.includes('@includedir'))
        .filter((l) => /\bNOPASSWD\b/.test(l))
        .map((l) => l.slice(0, 120))
      const evidence = [
        frag(
          'file-read',
          '/etc/sudoers',
          { nopasswdLines: hits.slice(0, 10), totalNopasswdLines: hits.length, sudoersFiles: bag.sudoersFiles },
          'HIGH',
          'root',
        ),
      ]
      if (hits.length > 0) {
        return {
          status: 'FAIL',
          detail: `NOPASSWD found in /etc/sudoers: ${hits.slice(0, 10).join(' | ')}${hits.length > 10 ? ' | …' : ''} — these rules run privileged commands with no password check`,
          evidence,
        }
      }
      return { status: 'PASS', detail: 'no NOPASSWD grants in /etc/sudoers', evidence }
    },
    explanation: {
      en: 'NOPASSWD converts any compromise of the user account into silent root compromise — no second factor, no password prompt, nothing logged in auth.log about a failed check (MITRE ATT&CK T1548.003 sudo caching/abuse).',
      es: 'NOPASSWD convierte el compromiso de la cuenta de usuario en compromiso silencioso de root — sin segundo factor, sin prompt, sin registro de fallo en auth.log (MITRE ATT&CK T1548.003 abuso de sudo).',
    },
    references: [REF_DEBIAN, REF_CIS, REF_MITRE, REF_UBUNTU],
    remediation: rem(
      'HIGH',
      {
        en: '/etc/sudoers contains NOPASSWD grants.',
        es: '/etc/sudoers contiene concesiones NOPASSWD.',
      },
      {
        en: 'Convenience configuration during provisioning or tooling that demanded silent privileged execution.',
        es: 'Configuración por comodidad durante el aprovisionamiento o herramientas que exigían ejecución privilegiada silenciosa.',
      },
      {
        en: 'Phished or stolen user session = immediate root without any additional control.',
        es: 'Sesión de usuario phished o robada = root inmediato sin ningún control adicional.',
      },
      GENERIC_STATE,
      {
        en: 'sudo always re-authenticates; if automation needs silent privilege, scope it to exact commands with arguments and separate accounts.',
        es: 'sudo siempre re-autentica; si la automatización necesita privilegio silencioso, acótela a comandos y argumentos exactos con cuentas separadas.',
      },
      [
        {
          title: { en: 'Back up sudoers (never edit directly)', es: 'Respaldar sudoers (nunca editar directamente)' },
          command: 'sudo cp -a /etc/sudoers /etc/sudoers.bak.$(date +%F)',
          note: MANUAL,
        },
        {
          title: { en: 'Edit with visudo and remove NOPASSWD directives', es: 'Editar con visudo y eliminar directivas NOPASSWD' },
          command: 'sudo visudo',
          note: MANUAL,
        },
        {
          title: { en: 'Validate every sudoers file', es: 'Validar todos los archivos sudoers' },
          command: 'sudo visudo -cf /etc/sudoers && for f in /etc/sudoers.d/*; do sudo visudo -cf "$f"; done',
          note: MANUAL,
        },
      ],
      ['/etc/sudoers', '/etc/sudoers.d/'],
      {
        en: 'Automation relying on NOPASSWD (CI agents, monitoring) will start failing; migrate it to scoped rules or dedicated credentials first.',
        es: 'La automatización que depende de NOPASSWD (agentes CI, monitoreo) empezará a fallar; migre primero a reglas acotadas o credenciales dedicadas.',
      },
      GENERIC_PREREQ,
      { en: 'Restore /etc/sudoers.bak.<date> and re-validate with visudo -cf.', es: 'Restaure /etc/sudoers.bak.<fecha> y revalide con visudo -cf.' },
      { en: 'grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ returns only comments; re-run scan shows PASS.', es: 'grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ devuelve solo comentarios; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Requires root-readable /etc/sudoers; entries in /etc/sudoers.d are listed but their contents may be unreadable without root — the evaluation covers the main file.',
      es: 'Requiere /etc/sudoers legible por root; los archivos de /etc/sudoers.d se listan pero su contenido puede ser ilegible sin root — la evaluación cubre el archivo principal.',
    },
  },

  // ── OS_SECURITY / SYSTEM_CONFIG / PATCH_MANAGEMENT ────────────────────────
  {
    id: 'VC-LNX-0201',
    version: '1.0.0',
    name: { en: 'ASLR full', es: 'ASLR completo' },
    description: {
      en: 'kernel.randomize_va_space must be 2 (full address space layout randomization) to make memory-corruption exploits unreliable.',
      es: 'kernel.randomize_va_space debe ser 2 (aleatorización completa del espacio de direcciones) para hacer poco fiables los exploits de corrupción de memoria.',
    },
    category: 'OS_SECURITY',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/proc/sys/kernel/randomize_va_space',
    evaluate(bag): ControlEvaluation {
      const v = bag.sysctls.randomize_va_space
      const evidence = [frag('proc-read', '/proc/sys/kernel/randomize_va_space', { randomize_va_space: v }, 'HIGH')]
      if (v === null) {
        return {
          status: 'NOT_ASSESSED',
          reason: '/proc/sys/kernel/randomize_va_space unreadable (restricted /proc)',
        }
      }
      if (v === 2) return { status: 'PASS', detail: 'randomize_va_space = 2 (full ASLR)', evidence }
      if (v === 1) {
        return {
          status: 'WARNING',
          detail: 'randomize_va_space = 1 — conservative ASLR: stack/VDSO randomized but shared libraries/heap not fully',
          evidence,
        }
      }
      return { status: 'FAIL', detail: 'randomize_va_space = 0 — ASLR disabled', evidence }
    },
    explanation: {
      en: 'ASLR randomizes memory layout so pre-computed exploit addresses fail. Disabling it (or running partial) is a direct gift to memory-corruption exploitation chains.',
      es: 'ASLR aleatoriza la disposición de memoria para que las direcciones precalculadas de exploits fallen. Desactivarlo (o dejarlo parcial) regala directamente a las cadenas de explotación.',
    },
    references: [REF_DEBIAN, REF_NIST, REF_CIS, REF_MITRE],
    remediation: rem(
      'HIGH',
      { en: 'kernel.randomize_va_space is 0 or 1.', es: 'kernel.randomize_va_space es 0 o 1.' },
      { en: 'Explicit sysctl override, kernel cmdline parameter, or a debugging-tuned host.', es: 'Anulación sysctl explícita, parámetro del kernel en cmdline o un host afinado para depuración.' },
      { en: 'Memory-corruption exploits become dramatically more reliable (MITRE ATT&CK T1068 exploitation for privilege escalation).', es: 'Los exploits de corrupción de memoria se vuelven mucho más fiables (MITRE ATT&CK T1068 explotación para escalada de privilegios).' },
      GENERIC_STATE,
      { en: 'kernel.randomize_va_space = 2, persisted in /etc/sysctl.d/.', es: 'kernel.randomize_va_space = 2, persistido en /etc/sysctl.d/.' },
      [
        {
          title: { en: 'Enable full ASLR at runtime', es: 'Habilitar ASLR completo en runtime' },
          command: 'sudo sysctl -w kernel.randomize_va_space=2',
          note: MANUAL,
        },
        {
          title: { en: 'Persist across reboots', es: 'Persistir entre reinicios' },
          command: 'echo "kernel.randomize_va_space = 2" | sudo tee /etc/sysctl.d/99-aslr.conf && sudo sysctl --system',
          note: MANUAL,
        },
      ],
      ['/etc/sysctl.d/99-aslr.conf', '/proc/sys/kernel/randomize_va_space'],
      {
        en: 'Extremely rare legacy binaries relying on fixed addresses may fail; virtually all modern software is ASLR-safe.',
        es: 'Binarios legados muy raros que dependan de direcciones fijas podrían fallar; prácticamente todo el software moderno es seguro con ASLR.',
      },
      {
        en: 'Root on the host. In containers this sysctl belongs to the shared kernel — change it on the HOST, not inside the container.',
        es: 'Root en el host. En contenedores este sysctl pertenece al kernel compartido — cámbielo en el HOST, no dentro del contenedor.',
      },
      { en: 'Set the value back (sysctl -w kernel.randomize_va_space=1) or remove the .conf file and re-run sysctl --system.', es: 'Devuelva el valor (sysctl -w kernel.randomize_va_space=1) o elimine el .conf y reejecute sysctl --system.' },
      { en: 'cat /proc/sys/kernel/randomize_va_space → "2"; re-run scan shows PASS.', es: 'cat /proc/sys/kernel/randomize_va_space → "2"; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Containers share the host kernel: the observed value may reflect the HOST, and the engine cannot distinguish ownership from inside a container.',
      es: 'Los contenedores comparten el kernel del host: el valor observado puede reflejar el HOST y el motor no puede distinguir la propiedad desde dentro de un contenedor.',
    },
  },
  {
    id: 'VC-LNX-0202',
    version: '1.0.0',
    name: { en: 'Kernel pointer restriction', es: 'Restricción de punteros del kernel' },
    description: {
      en: 'kernel.kptr_restrict must be >= 1 so kernel pointers are not exposed to unprivileged readers via /proc and other interfaces.',
      es: 'kernel.kptr_restrict debe ser >= 1 para que los punteros del kernel no se expongan a lectores sin privilegios vía /proc y otras interfaces.',
    },
    category: 'OS_SECURITY',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/proc/sys/kernel/kptr_restrict',
    evaluate(bag): ControlEvaluation {
      const v = bag.sysctls.kptr_restrict
      const evidence = [frag('proc-read', '/proc/sys/kernel/kptr_restrict', { kptr_restrict: v }, 'HIGH')]
      if (v === null) {
        return { status: 'NOT_ASSESSED', reason: '/proc/sys/kernel/kptr_restrict unreadable (restricted /proc)' }
      }
      if (v >= 1) {
        return {
          status: 'PASS',
          detail: `kptr_restrict = ${v}${v >= 2 ? ' (strictest: hidden even for privileged users without CAP_SYSLOG)' : ''}`,
          evidence,
        }
      }
      return { status: 'FAIL', detail: 'kptr_restrict = 0 — kernel pointer addresses visible to unprivileged users, easing KASLR defeat', evidence }
    },
    explanation: {
      en: 'Leaked kernel pointers help attackers defeat KASLR and craft kernel exploits; kptr_restrict=1/2 hides %pK output from unauthorized readers.',
      es: 'Los punteros del kernel filtrados ayudan a derrotar KASLR y a construir exploits de kernel; kptr_restrict=1/2 oculta la salida %pK a lectores no autorizados.',
    },
    references: [REF_DEBIAN, REF_NIST, REF_CIS],
    remediation: rem(
      'HIGH',
      { en: 'kernel.kptr_restrict = 0.', es: 'kernel.kptr_restrict = 0.' },
      { en: 'Default on several distributions for compatibility with debugging tools.', es: 'Defecto en varias distribuciones por compatibilidad con herramientas de depuración.' },
      { en: 'Information leak that weakens KASLR and accelerates kernel exploitation.', es: 'Fuga de información que debilita KASLR y acelera la explotación del kernel.' },
      GENERIC_STATE,
      { en: 'kernel.kptr_restrict = 1 (or 2 for the strictest mode), persisted in /etc/sysctl.d/.', es: 'kernel.kptr_restrict = 1 (o 2 para el modo más estricto), persistido en /etc/sysctl.d/.' },
      [
        {
          title: { en: 'Persist pointer restriction', es: 'Persistir la restricción de punteros' },
          command: 'echo "kernel.kptr_restrict = 1" | sudo tee /etc/sysctl.d/99-kptr.conf && sudo sysctl --system',
          note: MANUAL,
        },
      ],
      ['/etc/sysctl.d/99-kptr.conf', '/proc/sys/kernel/kptr_restrict'],
      { en: 'Some low-level diagnostics (perf, /proc/modules formatting) show zeroed pointers for unprivileged users — expected behavior.', es: 'Algunos diagnósticos de bajo nivel (perf, formato de /proc/modules) muestran punteros a cero para usuarios sin privilegios — comportamiento esperado.' },
      { en: 'Root on the host (shared kernel in containers).', es: 'Root en el host (kernel compartido en contenedores).' },
      { en: 'Remove the .conf file and re-run sysctl --system.', es: 'Elimine el .conf y reejecute sysctl --system.' },
      { en: 'cat /proc/sys/kernel/kptr_restrict → "1" or "2".', es: 'cat /proc/sys/kernel/kptr_restrict → "1" o "2".' },
    ),
    limitations: {
      en: 'Containers share the host kernel; the value may reflect the host configuration.',
      es: 'Los contenedores comparten el kernel del host; el valor puede reflejar la configuración del host.',
    },
  },
  {
    id: 'VC-LNX-0203',
    version: '1.0.0',
    name: { en: 'Core dumps restricted', es: 'Volcados de memoria (core dumps) restringidos' },
    description: {
      en: 'fs.suid_dumpable must be 0 so privileged processes never write core dumps containing secrets to disk.',
      es: 'fs.suid_dumpable debe ser 0 para que los procesos privilegiados nunca escriban core dumps con secretos al disco.',
    },
    category: 'SYSTEM_CONFIG',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/proc/sys/fs/suid_dumpable',
    evaluate(bag): ControlEvaluation {
      const v = bag.sysctls.suid_dumpable
      const evidence = [frag('proc-read', '/proc/sys/fs/suid_dumpable', { suid_dumpable: v }, 'HIGH')]
      if (v === null) {
        return { status: 'NOT_ASSESSED', reason: '/proc/sys/fs/suid_dumpable unreadable (restricted /proc)' }
      }
      if (v === 0) return { status: 'PASS', detail: 'suid_dumpable = 0 — setuid binaries never dump core', evidence }
      return {
        status: 'FAIL',
        detail: `suid_dumpable = ${v} — privileged process memory (keys, tokens) may be written to world-readable core files`,
        evidence,
      }
    },
    explanation: {
      en: 'Core dumps capture process memory: crypto keys, tokens, passwords. For setuid/privileged processes that memory is high-value loot for local attackers (MITRE ATT&CK T1003 credential dumping).',
      es: 'Los core dumps capturan memoria de proceso: claves, tokens, contraseñas. Para procesos setuid/privilegiados esa memoria es botín de alto valor para atacantes locales (MITRE ATT&CK T1003 credential dumping).',
    },
    references: [REF_DEBIAN, REF_CIS, REF_MITRE],
    remediation: rem(
      'MEDIUM',
      { en: 'fs.suid_dumpable is not 0.', es: 'fs.suid_dumpable no es 0.' },
      { en: 'Debugging-oriented defaults or an application that requested dumps for setuid tools.', es: 'Defectos orientados a depuración o una aplicación que pidió dumps para herramientas setuid.' },
      { en: 'Sensitive material from privileged processes can land in files readable by others.', es: 'Material sensible de procesos privilegiados puede acabar en archivos legibles por otros.' },
      GENERIC_STATE,
      { en: 'fs.suid_dumpable = 0, persisted in /etc/sysctl.d/; core dumps disabled via limits too.', es: 'fs.suid_dumpable = 0, persistido en /etc/sysctl.d/; también deshabilitar core dumps vía limits.' },
      [
        {
          title: { en: 'Persist the restriction', es: 'Persistir la restricción' },
          command: 'echo "fs.suid_dumpable = 0" | sudo tee /etc/sysctl.d/99-coredump.conf && sudo sysctl --system',
          note: MANUAL,
        },
        {
          title: { en: 'Optionally disable dumps per-login (PAM limits)', es: 'Opcionalmente deshabilitar dumps por inicio de sesión (límites PAM)' },
          command: 'echo "* hard core 0" | sudo tee /etc/security/limits.d/99-coredump.conf',
          note: MANUAL,
        },
      ],
      ['/etc/sysctl.d/99-coredump.conf', '/proc/sys/fs/suid_dumpable'],
      { en: 'Developers lose automatic core files for crashing setuid tools; route debugging through systemd-coredump with restricted perms instead.', es: 'Los desarrolladores pierden los core automáticos de herramientas setuid; canalice la depuración por systemd-coredump con permisos restringidos.' },
      { en: 'Root on the host (shared kernel in containers).', es: 'Root en el host (kernel compartido en contenedores).' },
      { en: 'Remove the .conf file(s) and re-run sysctl --system.', es: 'Elimine los .conf y reejecute sysctl --system.' },
      { en: 'cat /proc/sys/fs/suid_dumpable → "0".', es: 'cat /proc/sys/fs/suid_dumpable → "0".' },
    ),
    limitations: {
      en: 'Containers share the host kernel; value may reflect the host. systemd-coredump behavior is governed by additional units not inspected here.',
      es: 'Los contenedores comparten el kernel del host; el valor puede reflejar el host. systemd-coredump se rige por unidades adicionales no inspeccionadas aquí.',
    },
  },
  {
    id: 'VC-LNX-0204',
    version: '1.0.0',
    name: { en: 'Sensitive file permissions', es: 'Permisos de archivos sensibles' },
    description: {
      en: '/etc/shadow must be at most 640 root-owned; /etc/passwd, /etc/group and /etc/login.defs must be at most 644 — stricter is always acceptable.',
      es: '/etc/shadow debe estar como máximo 640 con dueño root; /etc/passwd, /etc/group y /etc/login.defs como máximo 644 — más estricto siempre es aceptable.',
    },
    category: 'SYSTEM_CONFIG',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: 'stat(): /etc/passwd /etc/shadow /etc/group /etc/login.defs',
    evaluate(bag): ControlEvaluation {
      if (bag.filePerms.length === 0) {
        return { status: 'NOT_ASSESSED', reason: 'stat() failed for every sensitive file' }
      }
      const notes: string[] = []
      let errors = 0
      let bad = 0
      const modes: { path: string; mode: string | null; error?: string }[] = []
      for (const entry of bag.filePerms) {
        if (entry.mode === '' || entry.error) {
          errors += 1
          modes.push({ path: entry.path, mode: null, error: entry.error })
          notes.push(`${entry.path}: stat error (${entry.error ?? 'unknown'})`)
          continue
        }
        const isShadow = entry.path === '/etc/shadow'
        const ok = modeWithin(entry.mode, isShadow ? 0o640 : 0o644)
        modes.push({ path: entry.path, mode: entry.mode })
        if (!ok) {
          bad += 1
          notes.push(
            isShadow
              ? `${entry.path} ${entry.mode} (expected 640/600/000 or stricter)`
              : `${entry.path} ${entry.mode} (expected 644 or stricter)`,
          )
        }
      }
      const evidence = [
        frag('file-read', '/etc/shadow', { fileModes: modes, expectation: 'shadow<=640, others<=644' }, 'HIGH'),
      ]
      if (errors === bag.filePerms.length) {
        return { status: 'NOT_ASSESSED', reason: 'stat() failed for every sensitive file', evidence }
      }
      if (bad > 0) {
        return {
          status: 'FAIL',
          detail: `${bad} sensitive file(s) with excessive permissions: ${notes.join('; ')}`,
          evidence,
        }
      }
      return {
        status: 'PASS',
        detail: `all sensitive files within expected modes${errors > 0 ? ` (${errors} stat error(s) noted: ${notes.join('; ')})` : ''}`,
        evidence,
      }
    },
    explanation: {
      en: 'World-readable /etc/shadow exposes password hashes for offline cracking; writable /etc/passwd or /etc/login.defs lets any local user inject accounts or weaken policy.',
      es: 'Un /etc/shadow legible por todos expone hashes para crackeo offline; un /etc/passwd o /etc/login.defs escribibles permiten a cualquier usuario local inyectar cuentas o debilitar la política.',
    },
    references: [REF_DEBIAN, REF_CIS, REF_NIST],
    remediation: rem(
      'HIGH',
      { en: 'One or more sensitive files have more permissive modes than expected.', es: 'Uno o más archivos sensibles tienen permisos más permisivos de lo esperado.' },
      { en: 'Manual chmod, packaging mistakes, or provisioning scripts loosening permissions.', es: 'chmod manuales, errores de empaquetado o scripts de aprovisionamiento que aflojan permisos.' },
      { en: 'Hash disclosure (offline cracking) or local privilege escalation via writable identity configuration.', es: 'Divulgación de hashes (crackeo offline) o escalada local vía configuración de identidad escribible.' },
      GENERIC_STATE,
      { en: 'shadow 640 (root:shadow); passwd/group/login.defs 644; never world-writable.', es: 'shadow 640 (root:shadow); passwd/group/login.defs 644; nunca escribibles por todos.' },
      [
        {
          title: { en: 'Check current modes and ownership', es: 'Verificar modos y propiedad actuales' },
          command: 'stat -c "%a %U %G %n" /etc/passwd /etc/shadow /etc/group /etc/login.defs',
          note: MANUAL,
        },
        {
          title: { en: 'Tighten shadow', es: 'Endurecer shadow' },
          command: 'sudo chown root:shadow /etc/shadow && sudo chmod 640 /etc/shadow',
          note: MANUAL,
        },
        {
          title: { en: 'Normalize the rest', es: 'Normalizar el resto' },
          command: 'sudo chmod 644 /etc/passwd /etc/group /etc/login.defs',
          note: MANUAL,
        },
      ],
      ['/etc/shadow', '/etc/passwd', '/etc/group', '/etc/login.defs'],
      { en: 'Over-tightening can break tools that legitimately read these files (e.g. removing group-read from shadow breaks some daemons); apply the documented modes.', es: 'Endurecer de más puede romper herramientas que leen estos archivos legítimamente (p. ej. quitar lectura de grupo a shadow rompe algunos demonios); aplique los modos documentados.' },
      GENERIC_PREREQ,
      { en: 'Restore previous modes with chmod/chown as recorded in the pre-change stat output.', es: 'Restaure los modos previos con chmod/chown según el stat previo al cambio.' },
      { en: 'stat -c "%a %n" over the four files shows the expected modes; re-run scan shows PASS.', es: 'stat -c "%a %n" sobre los cuatro archivos muestra los modos esperados; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'stat follows symlinks (mode of the target is shown); ownership names are resolved separately and not part of this evaluation beyond modes.',
      es: 'stat sigue enlaces simbólicos (se muestra el modo del destino); la propiedad por nombre no forma parte de esta evaluación más allá de los modos.',
    },
  },
  {
    id: 'VC-LNX-0205',
    version: '1.0.0',
    name: { en: 'Unattended upgrades enabled', es: 'Actualizaciones desatendidas habilitadas' },
    description: {
      en: 'unattended-upgrades must be installed and enabled (APT::Periodic::Unattended-Upgrade "1") so security patches are applied automatically.',
      es: 'unattended-upgrades debe estar instalado y habilitado (APT::Periodic::Unattended-Upgrade "1") para que los parches de seguridad se apliquen automáticamente.',
    },
    category: 'PATCH_MANAGEMENT',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/apt/apt.conf.d/20auto-upgrades',
    evaluate(bag): ControlEvaluation {
      const evidence = [
        frag(
          'file-read',
          '/etc/apt/apt.conf.d/20auto-upgrades',
          { unattendedUpgradesEnabled: bag.unattendedUpgradesEnabled, unattendedInstalled: bag.unattendedInstalled },
          'HIGH',
        ),
      ]
      if (bag.unattendedUpgradesEnabled === true && bag.unattendedInstalled) {
        return { status: 'PASS', detail: 'unattended-upgrades enabled and binary present', evidence }
      }
      if (bag.unattendedUpgradesEnabled === true && !bag.unattendedInstalled) {
        return {
          status: 'WARNING',
          detail: 'flag enabled in APT config but the unattended-upgrade binary was not detected — install the package to make it effective',
          evidence,
        }
      }
      return {
        status: 'FAIL',
        detail: 'unattended upgrades not enabled — /etc/apt/apt.conf.d/20auto-upgrades (and 10periodic) missing or without APT::Periodic::Unattended-Upgrade "1"',
        evidence,
      }
    },
    explanation: {
      en: 'Most breaches exploit vulnerabilities with existing patches. Automatic security updates close that window without depending on operator memory.',
      es: 'La mayoría de las brechas explotan vulnerabilidades con parche existente. Las actualizaciones automáticas cierran esa ventana sin depender de la memoria del operador.',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_CIS, REF_NIST],
    remediation: rem(
      'MEDIUM',
      { en: 'unattended-upgrades is missing or disabled.', es: 'unattended-upgrades falta o está deshabilitado.' },
      { en: 'Package not installed at provisioning, or dpkg-reconfigure answered "No".', es: 'Paquete no instalado al aprovisionar, o dpkg-reconfigure respondió "No".' },
      { en: 'Known-vulnerable packages remain installed indefinitely; patch level depends entirely on manual discipline.', es: 'Los paquetes vulnerables conocidos permanecen indefinidamente; el nivel de parches depende solo de disciplina manual.' },
      GENERIC_STATE,
      { en: 'unattended-upgrades installed, periodic timers active, security origins enabled.', es: 'unattended-upgrades instalado, temporizadores periódicos activos, orígenes de seguridad habilitados.' },
      [
        {
          title: { en: 'Install the package', es: 'Instalar el paquete' },
          command: 'sudo apt update && sudo apt install unattended-upgrades',
          note: MANUAL,
        },
        {
          title: { en: 'Enable automatic security upgrades', es: 'Habilitar actualizaciones automáticas de seguridad' },
          command: 'sudo dpkg-reconfigure -plow unattended-upgrades',
          note: MANUAL,
        },
        {
          title: { en: 'Confirm effective configuration', es: 'Confirmar la configuración efectiva' },
          command: 'apt-config dump APT::Periodic::Unattended-Upgrade && systemctl status unattended-upgrades --no-pager',
          note: MANUAL,
        },
      ],
      ['/etc/apt/apt.conf.d/20auto-upgrades', '/etc/apt/apt.conf.d/50unattended-upgrades'],
      {
        en: 'Automatic upgrades restart services and may reboot (if configured); review /etc/apt/apt.conf.d/50unattended-upgrades (Blacklist, Automatic-Reboot) before enabling on production.',
        es: 'Las actualizaciones automáticas reinician servicios y pueden reiniciar el equipo (si se configura); revise 50unattended-upgrades (Blacklist, Automatic-Reboot) antes de habilitarlo en producción.',
      },
      { en: 'APT repositories reachable; maintenance window agreed for service restarts.', es: 'Repositorios APT alcanzables; ventana de mantenimiento acordada para reinicios de servicios.' },
      {
        en: 'sudo apt remove unattended-upgrades (config files remain; purge removes them too).',
        es: 'sudo apt remove unattended-upgrades (los archivos de configuración permanecen; purge los elimina también).',
      },
      { en: 'apt-config dump APT::Periodic::Unattended-Upgrade → "1"; re-run scan shows PASS.', es: 'apt-config dump APT::Periodic::Unattended-Upgrade → "1"; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Config-file based: proves intent, not successful runs. Timer execution results live in journald and are not inspected.',
      es: 'Basado en archivos de configuración: prueba intención, no ejecuciones exitosas. Los resultados de los timers están en journald y no se inspeccionan.',
    },
  },
  {
    id: 'VC-LNX-0206',
    version: '1.0.0',
    name: { en: 'Pending updates reviewed', es: 'Actualizaciones pendientes revisadas' },
    description: {
      en: 'Pending package upgrades must be known and reviewed: apt-get -s upgrade is simulated (never applied) and security-classified pending packages are counted.',
      es: 'Las actualizaciones pendientes deben conocerse y revisarse: se simula apt-get -s upgrade (nunca se aplica) y se cuentan los paquetes de seguridad pendientes.',
    },
    category: 'PATCH_MANAGEMENT',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: 'apt-get -s upgrade + /var/lib/apt/lists',
    evaluate(bag): ControlEvaluation {
      if (bag.aptCacheFresh !== true) {
        return {
          status: 'NOT_ASSESSED',
          reason: 'APT cache empty/stale or unreadable — run apt update (never done by the engine)',
        }
      }
      if (bag.pendingUpdates === null) {
        return {
          status: 'NOT_ASSESSED',
          reason: `upgrade simulation failed (${bag.pendingError ?? 'unknown error'})`,
        }
      }
      const evidence = [
        frag(
          'execFile:apt-get',
          'apt-get -s upgrade (simulation — no changes applied)',
          { aptCacheFresh: true, pendingUpdates: bag.pendingUpdates, pendingSecurityUpdates: bag.pendingSecurityUpdates },
          'MEDIUM',
        ),
      ]
      if (bag.pendingUpdates === 0) {
        return { status: 'PASS', detail: 'no packages pending upgrade (per simulated apt-get upgrade)', evidence }
      }
      return {
        status: 'WARNING',
        detail: `${bag.pendingUpdates} packages pending upgrade (${bag.pendingSecurityUpdates ?? 0} security-classified) — review and schedule the upgrade`,
        evidence,
      }
    },
    explanation: {
      en: 'Pending security updates are unpatched, actively-exploited-window vulnerabilities. Knowing the count and reviewing it turns patching from guesswork into a managed process.',
      es: 'Las actualizaciones de seguridad pendientes son vulnerabilidades con ventana de explotación activa. Conocerlas y revisarlas convierte el parchado en un proceso gestionado.',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_NIST],
    remediation: rem(
      'HIGH',
      { en: 'Packages with available upgrades are pending on the host.', es: 'Hay paquetes con actualizaciones disponibles pendientes en el host.' },
      { en: 'Patches are published continuously; hosts drift behind between maintenance runs.', es: 'Los parches se publican continuamente; los hosts se rezagan entre mantenimientos.' },
      { en: 'Public exploits target known CVEs; the longer the drift, the larger the exploitable surface.', es: 'Los exploits públicos apuntan a CVEs conocidos; a mayor rezago, mayor superficie explotable.' },
      GENERIC_STATE,
      { en: 'Zero pending security upgrades, or pending items reviewed and scheduled in a change window.', es: 'Cero actualizaciones de seguridad pendientes, o pendientes revisadas y programadas en una ventana de cambios.' },
      [
        {
          title: { en: 'Refresh the package index (operator action)', es: 'Refrescar el índice de paquetes (acción del operador)' },
          command: 'sudo apt update',
          note: MANUAL,
        },
        {
          title: { en: 'Review what would change (simulation)', es: 'Revisar qué cambiaría (simulación)' },
          command: 'apt-get -s upgrade | less   # y: apt list --upgradable',
          note: MANUAL,
        },
        {
          title: { en: 'Apply upgrades inside the agreed maintenance window', es: 'Aplicar actualizaciones dentro de la ventana acordada' },
          command: 'sudo apt upgrade',
          note: MANUAL,
        },
      ],
      ['/var/lib/apt/lists', '/etc/apt/sources.list'],
      { en: 'Upgrades may restart services or require a reboot; check release notes for critical packages (libc, openssl, kernel).', es: 'Las actualizaciones pueden reiniciar servicios o requerir reinicio; revise notas de paquetes críticos (libc, openssl, kernel).' },
      { en: 'APT cache fresh (apt update) and a change window for service-affecting upgrades.', es: 'Caché APT fresca (apt update) y ventana de cambios para actualizaciones que afectan servicios.' },
      { en: 'Not applicable — applying updates is the intended change; roll back via package downgrades only with a documented reason.', es: 'No aplica — aplicar actualizaciones es el cambio previsto; revertir por downgrade solo con motivo documentado.' },
      { en: 'apt list --upgradable shows the remaining set; re-run scan and compare pendingUpdates.', es: 'apt list --upgradable muestra el conjunto restante; reejecute el escaneo y compare pendingUpdates.' },
    ),
    limitations: {
      en: 'The engine NEVER runs apt update (read-only policy): with an empty/stale cache the control is honestly NOT_ASSESSED. The simulation depends on the cache age at scan time.',
      es: 'El motor NUNCA ejecuta apt update (política de solo lectura): con caché vacía/vieja el control es NOT_ASSESSED honestamente. La simulación depende de la antigüedad de la caché al escanear.',
    },
  },
  {
    id: 'VC-LNX-0207',
    version: '1.0.0',
    name: { en: 'Supported OS release', es: 'Versión de SO soportada' },
    description: {
      en: 'The running distribution/version must be inside its vendor support window (Debian stable/oldstable, Ubuntu LTS).',
      es: 'La distribución/versión en ejecución debe estar dentro de la ventana de soporte del fabricante (Debian stable/oldstable, Ubuntu LTS).',
    },
    category: 'PATCH_MANAGEMENT',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/os-release',
    evaluate(bag): ControlEvaluation {
      const rel = bag.osRelease
      const evidence = [
        frag('file-read', '/etc/os-release', rel ? { id: rel.id, versionId: rel.versionId, prettyName: rel.prettyName, idLike: rel.idLike } : null, 'HIGH'),
      ]
      if (!rel || (rel.id !== 'debian' && rel.id !== 'ubuntu')) {
        return {
          status: 'NOT_APPLICABLE',
          reason: rel
            ? `distribution not in support matrix (id=${rel.id})`
            : 'distribution not in support matrix (os-release unreadable)',
          evidence,
        }
      }
      if (rel.id === 'debian') {
        const major = parseInt(rel.versionId, 10)
        if (!Number.isFinite(major)) {
          return {
            status: 'WARNING',
            detail: `Debian versionId "${rel.versionId}" not recognized (testing/sid?) — verify the support window manually`,
            evidence,
          }
        }
        if (major >= 13) {
          return { status: 'PASS', detail: `${rel.prettyName} — stable release, full security support`, evidence }
        }
        if (major === 12) {
          return { status: 'PASS', detail: `${rel.prettyName} — oldstable, still within security/LTS support`, evidence }
        }
        return {
          status: 'WARNING',
          detail: `Debian ${major} is at or past the end of LTS support — plan the upgrade to a supported release`,
          evidence,
        }
      }
      // ubuntu
      if (rel.versionId === '24.04' || rel.versionId === '22.04') {
        return { status: 'PASS', detail: `${rel.prettyName} — supported LTS (standard support window)`, evidence }
      }
      if (rel.versionId === '20.04') {
        return {
          status: 'WARNING',
          detail: 'Ubuntu 20.04 — standard support ended; only ESM covers it, verify the subscription or upgrade to 22.04/24.04',
          evidence,
        }
      }
      return {
        status: 'WARNING',
        detail: `Ubuntu "${rel.versionId}" — verify support window (interim releases expire after 9 months)`,
        evidence,
      }
    },
    explanation: {
      en: 'Unsupported releases stop receiving security patches entirely: every later CVE stays exploitable forever. Running a supported release is the precondition of all patch management.',
      es: 'Las versiones sin soporte dejan de recibir parches: cada CVE posterior queda explotable para siempre. Usar una versión soportada es la precondición de toda la gestión de parches.',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_NIST],
    remediation: rem(
      'MEDIUM',
      { en: 'The OS release is outside (or near the edge of) the vendor support window.', es: 'La versión del SO está fuera (o al borde) de la ventana de soporte del fabricante.' },
      { en: 'Long-lived hosts never migrated; release cadence outpaced by operational inertia.', es: 'Hosts de larga vida nunca migrados; la cadencia de versiones superada por la inercia operativa.' },
      { en: 'No security patches for new CVEs; compliance frameworks fail unsupported OSes outright.', es: 'Sin parches de seguridad para nuevos CVEs; los marcos de cumplimiento reprueban SO sin soporte.' },
      GENERIC_STATE,
      { en: 'A release inside the vendor window: Debian 13/12 or Ubuntu 24.04/22.04 LTS.', es: 'Una versión dentro de la ventana: Debian 13/12 o Ubuntu 24.04/22.04 LTS.' },
      [
        {
          title: { en: 'Confirm the exact release', es: 'Confirmar la versión exacta' },
          command: 'cat /etc/os-release',
          note: MANUAL,
        },
        {
          title: { en: 'Back up data and configuration before release upgrade', es: 'Respaldar datos y configuración antes de la actualización de versión' },
          note: MANUAL,
        },
        {
          title: { en: 'Upgrade following the official release-upgrade path (example Ubuntu LTS)', es: 'Actualizar siguiendo la vía oficial de actualización (ejemplo Ubuntu LTS)' },
          command: 'sudo apt update && sudo apt full-upgrade && sudo do-release-upgrade',
          note: MANUAL,
        },
      ],
      ['/etc/os-release', '/etc/apt/sources.list'],
      {
        en: 'Release upgrades are major changes: service configs, kernels and third-party repositories may need adaptation; test on staging first.',
        es: 'Las actualizaciones de versión son cambios mayores: configs de servicios, kernels y repositorios de terceros pueden requerir adaptación; pruebe antes en staging.',
      },
      { en: 'Full backup/restore point, staging validation, vendor upgrade documentation read.', es: 'Backup/restauración completa, validación en staging, documentación oficial de actualización leída.' },
      { en: 'Vendor-specific: restore from backup (snapshot/VM image) taken before the release upgrade.', es: 'Según fabricante: restaurar desde backup (snapshot/imagen VM) previo a la actualización.' },
      { en: 'cat /etc/os-release shows the target release; vendor lifecycle page confirms active support.', es: 'cat /etc/os-release muestra la versión objetivo; la página de ciclo de vida confirma soporte activo.' },
    ),
    limitations: {
      en: 'Support matrix hardcoded for Debian (13/12 pass) and Ubuntu (22.04/24.04 pass, 20.04 warn); other distributions and non-release ids report NOT_APPLICABLE rather than guessing.',
      es: 'Matriz fija para Debian (13/12 pasan) y Ubuntu (22.04/24.04 pasan, 20.04 advierte); otras distribuciones o ids sin versión reportan NOT_APPLICABLE en lugar de adivinar.',
    },
  },

  // ── NETWORK_SECURITY / FIREWALL ───────────────────────────────────────────
  {
    id: 'VC-LNX-0301',
    version: '1.0.0',
    name: { en: 'Listening ports exposure reviewed', es: 'Exposición de puertos en escucha revisada' },
    description: {
      en: 'Every socket bound to wildcard addresses (0.0.0.0/::/*) must be reviewed and justified; unneeded listeners widen the remote attack surface.',
      es: 'Todo socket enlazado a direcciones wildcard (0.0.0.0/::/*) debe revisarse y justificarse; los listeners innecesarios amplían la superficie de ataque remota.',
    },
    category: 'NETWORK_SECURITY',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: 'ss -tulnH',
    evaluate(bag): ControlEvaluation {
      if (!bag.listeners) {
        return {
          status: 'NOT_ASSESSED',
          reason: `listening sockets unavailable (${bag.listenersError ?? 'ss failed'})`,
        }
      }
      const external = bag.listeners.filter(
        (l) => l.address === '0.0.0.0' || l.address === '::' || l.address === '*',
      )
      const fmt = (l: { proto: string; address: string; port: number }) => `${l.proto} ${l.address}:${l.port}`
      const evidence = [
        frag('execFile:ss', 'ss -tulnH', { listeners: bag.listeners.slice(0, 200), total: bag.listeners.length }, 'HIGH'),
      ]
      if (external.length === 0) {
        return {
          status: 'PASS',
          detail: `no wildcard-bound listeners (${bag.listeners.length} socket(s) reviewed)`,
          evidence,
        }
      }
      return {
        status: 'WARNING',
        detail: `${external.length} socket(s) bound to all interfaces: ${external
          .slice(0, 12)
          .map(fmt)
          .join('; ')}${external.length > 12 ? ' …' : ''} — verify each is intended and firewall-restricted`,
        evidence,
      }
    },
    explanation: {
      en: 'A listening port is an open door from any network the host reaches. Wildcard bindings often come from services meant to be local-only; each unreviewed listener is an unassessed exploit path (MITRE ATT&CK T1046 discovery / initial access surface).',
      es: 'Un puerto en escucha es una puerta abierta desde cualquier red que alcance el host. Los enlaces wildcard suelen venir de servicios pensados para uso local; cada listener sin revisar es una vía de explotación no evaluada (MITRE ATT&CK T1046).',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_CIS, REF_MITRE],
    remediation: rem(
      'MEDIUM',
      { en: 'Sockets bound to all interfaces were found; some may be unintended.', es: 'Se encontraron sockets enlazados a todas las interfaces; algunos pueden no ser intencionados.' },
      { en: 'Service defaults bind to wildcard unless a listen address is configured.', es: 'Por defecto los servicios se enlazan a wildcard salvo que se configure la dirección de escucha.' },
      { en: 'Remote exploitation surface for every flaw in the exposed service; perimeter firewall alone is not defense in depth.', es: 'Superficie de explotación remota por cada falla del servicio expuesto; el firewall perimetral no es defensa en profundidad.' },
      GENERIC_STATE,
      { en: 'Only justified services on wildcards; everything else on 127.0.0.1 or disabled.', es: 'Solo servicios justificados en wildcard; el resto en 127.0.0.1 o deshabilitado.' },
      [
        {
          title: { en: 'Review listeners with owning processes', es: 'Revisar listeners con sus procesos' },
          command: 'sudo ss -tulnp',
          note: MANUAL,
        },
        {
          title: { en: 'Disable services that must not run', es: 'Deshabilitar servicios que no deben correr' },
          command: 'sudo systemctl disable --now <servicio>',
          note: MANUAL,
        },
        {
          title: { en: 'Bind internal-only services to localhost (example)', es: 'Enlazar servicios internos a localhost (ejemplo)' },
          command: '# en la config del servicio: listen 127.0.0.1:<puerto>',
          note: MANUAL,
        },
      ],
      ['/etc/'],
      { en: 'Changing listen addresses breaks clients that reach the service over the network; coordinate before applying.', es: 'Cambiar direcciones de escucha rompe clientes que acceden por red; coordine antes de aplicar.' },
      { en: 'Root for ss -tulnp process attribution.', es: 'Root para la atribución de procesos con ss -tulnp.' },
      { en: 'Re-enable/reconfigure the service exactly as before.', es: 'Rehabilitar/reconfigurar el servicio como estaba.' },
      { en: 'ss -tulnH shows only the intended sockets; re-run scan and compare the external list.', es: 'ss -tulnH muestra solo los sockets previstos; reejecute el escaneo y compare la lista externa.' },
    ),
    limitations: {
      en: 'Snapshot of the moment; short-lived sockets between scans are invisible. Owner process names require root (not collected here).',
      es: 'Fotografía del momento; sockets efímeros entre escaneos son invisibles. Los nombres de proceso dueño requieren root (no se recogen aquí).',
    },
  },
  {
    id: 'VC-LNX-0302',
    version: '1.0.0',
    name: { en: 'IPv4 forwarding', es: 'Reenvío IPv4' },
    description: {
      en: 'net.ipv4.ip_forward should be 0 on hosts that are not routers/gateways; forwarding turns a host into a traffic relay.',
      es: 'net.ipv4.ip_forward debe ser 0 en hosts que no son routers/gateways; el reenvío convierte al host en repetidor de tráfico.',
    },
    category: 'NETWORK_SECURITY',
    severity: 'LOW',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/proc/sys/net/ipv4/ip_forward',
    evaluate(bag): ControlEvaluation {
      const evidence = [frag('proc-read', '/proc/sys/net/ipv4/ip_forward', { ip_forward: bag.ipForward }, 'HIGH')]
      if (bag.ipForward === null) {
        return { status: 'NOT_ASSESSED', reason: 'ip_forward unreadable (/proc restricted)' }
      }
      if (bag.ipForward === 0) {
        return { status: 'PASS', detail: 'ip_forward = 0 — the host does not relay packets between interfaces', evidence }
      }
      return {
        status: 'WARNING',
        detail: 'ip_forward = 1 — enabled — expected only on routers/gateways/NAT containers; on ordinary hosts it enables unintended traffic relay',
        evidence,
      }
    },
    explanation: {
      en: 'With forwarding on, the host silently routes packets between its interfaces — attackers can use it to pivot across segments, and misconfigured routing can bypass segmentation designs.',
      es: 'Con reenvío activo, el host enruta paquetes entre sus interfaces silenciosamente — los atacantes pueden pivotear entre segmentos y un enrutado erróneo puede saltarse la segmentación.',
    },
    references: [REF_DEBIAN, REF_CIS, REF_NIST],
    remediation: rem(
      'LOW',
      { en: 'IPv4 forwarding is enabled on a host without a documented router role.', es: 'El reenvío IPv4 está habilitado en un host sin rol de router documentado.' },
      { en: 'Docker/NAT setups enable it globally; leftover from a gateway experiment.', es: 'Montajes Docker/NAT lo habilitan globalmente; residual de un experimento de gateway.' },
      { en: 'Unintentional relay/pivot capability across network segments.', es: 'Capacidad no intencionada de repetir/pivotar entre segmentos de red.' },
      GENERIC_STATE,
      { en: 'ip_forward = 0 unless the host is a documented router/gateway/NAT container.', es: 'ip_forward = 0 salvo que el host sea router/gateway/contenedor NAT documentado.' },
      [
        {
          title: { en: 'Disable forwarding at runtime', es: 'Deshabilitar el reenvío en runtime' },
          command: 'sudo sysctl -w net.ipv4.ip_forward=0',
          note: MANUAL,
        },
        {
          title: { en: 'Persist the setting', es: 'Persistir el ajuste' },
          command: 'echo "net.ipv4.ip_forward = 0" | sudo tee /etc/sysctl.d/99-no-forward.conf && sudo sysctl --system',
          note: MANUAL,
        },
      ],
      ['/etc/sysctl.d/99-no-forward.conf', '/proc/sys/net/ipv4/ip_forward'],
      { en: 'Disabling forwarding on a real router/NAT breaks connectivity for everything behind it — confirm the role first.', es: 'Desactivar el reenvío en un router/NAT real rompe la conectividad de lo que hay detrás — confirme el rol primero.' },
      { en: 'Root on the host (shared kernel in containers).', es: 'Root en el host (kernel compartido en contenedores).' },
      { en: 'Remove the .conf file and re-run sysctl --system (or sysctl -w net.ipv4.ip_forward=1).', es: 'Elimine el .conf y reejecute sysctl --system (o sysctl -w net.ipv4.ip_forward=1).' },
      { en: 'cat /proc/sys/net/ipv4/ip_forward → "0"; re-run scan shows PASS.', es: 'cat /proc/sys/net/ipv4/ip_forward → "0"; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Value reflects the shared kernel in containers; Docker-style runtimes legitimately enable it for NAT.',
      es: 'El valor refleja el kernel compartido en contenedores; los runtimes tipo Docker lo habilitan legítimamente para NAT.',
    },
  },
  {
    id: 'VC-LNX-0303',
    version: '1.0.0',
    name: { en: 'Host firewall present and active', es: 'Firewall del host presente y activo' },
    description: {
      en: 'A host firewall (ufw active, or nftables config) must exist and be active to bound inbound traffic independently of the perimeter.',
      es: 'Debe existir y estar activo un firewall del host (ufw activo o config nftables) para acotar el tráfico entrante independientemente del perímetro.',
    },
    category: 'FIREWALL',
    severity: 'HIGH',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/ufw/ufw.conf + /etc/nftables.conf (binarios vía stat)',
    evaluate(bag): ControlEvaluation {
      const fw = bag.firewall
      const evidence = [
        frag('file-read', '/etc/ufw/ufw.conf', { firewall: fw }, fw.ufwEnabled === true ? 'HIGH' : 'MEDIUM'),
      ]
      // Runtime probes are the strongest evidence (real kernel state); config
      // files only infer intent. Order: ufw runtime → nft runtime → config.
      if (fw.ufwRuntime === true) {
        return { status: 'PASS', detail: 'ufw status reports "active" (runtime probe)', evidence }
      }
      if (fw.ufwRuntime === false) {
        return { status: 'FAIL', detail: 'ufw status reports inactive (runtime probe) — host firewall not enforcing', evidence }
      }
      if (fw.nftRulesetLoaded === true) {
        return { status: 'PASS', detail: 'nftables ruleset loaded in the kernel (runtime probe)', evidence }
      }
      if (fw.ufwInstalled && fw.ufwEnabled === true) {
        return { status: 'PASS', detail: 'ufw installed and ENABLED=yes in /etc/ufw/ufw.conf (runtime probe unavailable — verify "ufw status")', evidence }
      }
      if (fw.ufwInstalled && fw.ufwEnabled === false) {
        return { status: 'FAIL', detail: 'ufw installed but ENABLED=no — host firewall inactive', evidence }
      }
      if (fw.nftablesInstalled && fw.nftablesConfExists) {
        return {
          status: 'WARNING',
          detail: 'nftables config present; enforcement state cannot be verified without root — confirm "nft list ruleset" applies the intended policy',
          evidence,
        }
      }
      if (fw.tool) {
        return {
          status: 'WARNING',
          detail: `firewall tooling present (${fw.tool}) but its active/enforcement state could not be verified without root`,
          evidence,
        }
      }
      return { status: 'FAIL', detail: 'no ufw/nftables/iptables binary or config detected', evidence }
    },
    explanation: {
      en: 'Defense in depth: the host firewall bounds exposure even when perimeter controls fail or change. Without it, every listening service is reachable from everywhere the network allows.',
      es: 'Defensa en profundidad: el firewall del host acota la exposición aunque los controles perimetrales fallen o cambien. Sin él, todo servicio en escucha es alcanzable desde donde la red permita.',
    },
    references: [REF_UBUNTU, REF_DEBIAN, REF_CIS, REF_NIST],
    remediation: rem(
      'HIGH',
      { en: 'No active host firewall detected (or ufw disabled).', es: 'Sin firewall de host activo detectado (o ufw deshabilitado).' },
      { en: 'Firewall not configured at provisioning; ufw present but disabled.', es: 'Firewall no configurado al aprovisionar; ufw presente pero deshabilitado.' },
      { en: 'All listening services fully exposed to the network segment; lateral movement becomes trivial after any foothold.', es: 'Todos los servicios en escucha totalmente expuestos al segmento; el movimiento lateral se vuelve trivial tras cualquier acceso inicial.' },
      GENERIC_STATE,
      { en: 'ufw active with default-deny inbound and explicit allows; or an enforced nftables/iptables baseline.', es: 'ufw activo con entrada por defecto denegada y permisos explícitos; o una base nftables/iptables aplicada.' },
      [
        {
          title: { en: 'Install ufw and set the default policy', es: 'Instalar ufw y fijar la política por defecto' },
          command: 'sudo apt update && sudo apt install ufw && sudo ufw default deny incoming && sudo ufw default allow outgoing',
          note: MANUAL,
        },
        {
          title: { en: 'Allow SSH BEFORE enabling (avoid lockout)', es: 'Permitir SSH ANTES de habilitar (evitar bloqueo)' },
          command: 'sudo ufw allow OpenSSH',
          note: MANUAL,
        },
        {
          title: { en: 'Enable the firewall', es: 'Habilitar el firewall' },
          command: 'sudo ufw enable && sudo ufw status verbose',
          note: MANUAL,
        },
        {
          title: { en: 'Alternative: nftables baseline', es: 'Alternativa: base con nftables' },
          command: 'sudo apt install nftables && sudo systemctl enable --now nftables',
          note: MANUAL,
        },
      ],
      ['/etc/ufw/ufw.conf', '/etc/nftables.conf', '/etc/default/ufw'],
      { en: 'Enabling a firewall can cut remote access instantly (SSH sessions included); always pre-allow management ports and keep a console fallback.', es: 'Habilitar un firewall puede cortar el acceso remoto al instante (incluidas sesiones SSH); pre-permita siempre los puertos de gestión y tenga consola de respaldo.' },
      { en: 'Console/out-of-band access as a lockout fallback; knowledge of required inbound ports.', es: 'Acceso por consola/fuera de banda como respaldo ante bloqueo; conocimiento de los puertos entrantes requeridos.' },
      { en: 'sudo ufw disable (or systemctl disable --now nftables) restores the previous state.', es: 'sudo ufw disable (o systemctl disable --now nftables) restaura el estado previo.' },
      { en: 'sudo ufw status verbose → "Status: active"; re-run scan shows PASS.', es: 'sudo ufw status verbose → "Status: active"; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Container hosts may intentionally rely on external perimeter controls — declared as limitation, not as exemption. ufw.conf reflects configuration; runtime ruleset is not dumped (would need root).',
      es: 'Los hosts contenedor pueden apoyarse deliberadamente en controles perimetrales externos — se declara como limitación, no como exención. ufw.conf refleja configuración; el ruleset en runtime no se vuelca (requeriría root).',
    },
  },

  // ── SERVICES_PROCESSES / ENDPOINT_PROTECTION / ENCRYPTION ─────────────────
  {
    id: 'VC-LNX-0401',
    version: '1.0.0',
    name: { en: 'Running services reviewed', es: 'Servicios en ejecución revisados' },
    description: {
      en: 'The set of running systemd services must be inventoried and reviewed: every extra service is persistent code with a potential network or privilege surface.',
      es: 'El conjunto de servicios systemd en ejecución debe inventariarse y revisarse: cada servicio extra es código persistente con posible superficie de red o privilegios.',
    },
    category: 'SERVICES_PROCESSES',
    severity: 'LOW',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: 'systemctl is-system-running / list-units',
    evaluate(bag): ControlEvaluation {
      if (bag.systemdRunning === null) {
        return {
          status: 'NOT_ASSESSED',
          reason: `systemd state unknown (collection error${bag.systemdError ? `: ${bag.systemdError}` : ''})`,
        }
      }
      if (bag.systemdRunning === false) {
        return {
          status: 'NOT_ASSESSED',
          reason: `systemd not operational in this environment (${bag.systemdError ?? 'offline'}) — service inventory unavailable`,
        }
      }
      const services = bag.runningServices
      if (!services) {
        return { status: 'NOT_ASSESSED', reason: 'systemd running but service inventory unavailable' }
      }
      const evidence = [
        frag(
          'execFile:systemctl',
          'systemctl list-units --type=service --state=running',
          { systemdRunning: true, runningServices: services.slice(0, 100), total: services.length },
          'HIGH',
        ),
      ]
      return {
        status: 'PASS',
        detail: `${services.length} running services — inventory informational (no universal dangerous-service list applied); review against the host's intended role`,
        evidence,
      }
    },
    explanation: {
      en: 'Minimizing running services minimizes update burden, exploit surface and persistence spots. An inventory is the first step of that reduction; "unknown service running" is a common audit finding.',
      es: 'Minimizar servicios en ejecución reduce carga de actualización, superficie de explotación y puntos de persistencia. El inventario es el primer paso de esa reducción; "servicio desconocido corriendo" es un hallazgo típico de auditoría.',
    },
    references: [REF_DEBIAN, REF_CIS, REF_NIST],
    remediation: rem(
      'LOW',
      { en: 'Running services have not been reviewed against the intended role of the host.', es: 'Los servicios en ejecución no se han revisado contra el rol previsto del host.' },
      { en: 'Accumulated tooling over time; images with broad default service sets.', es: 'Herramientas acumuladas con el tiempo; imágenes con conjuntos de servicios amplios por defecto.' },
      { en: 'Each unnecessary service adds patch load, restart risk and potential remote or privilege surface.', es: 'Cada servicio innecesario añade carga de parches, riesgo de reinicio y potencial superficie remota o de privilegios.' },
      GENERIC_STATE,
      { en: 'A minimal, documented service set matching the host role.', es: 'Un conjunto de servicios mínimo y documentado acorde al rol del host.' },
      [
        {
          title: { en: 'List running services with descriptions', es: 'Listar servicios en ejecución con descripciones' },
          command: 'systemctl list-units --type=service --state=running --no-pager',
          note: MANUAL,
        },
        {
          title: { en: 'Inspect any unknown unit before acting', es: 'Inspeccionar cualquier unidad desconocida antes de actuar' },
          command: 'systemctl cat <unidad>.service',
          note: MANUAL,
        },
        {
          title: { en: 'Disable confirmed-unnecessary services', es: 'Deshabilitar servicios confirmados como innecesarios' },
          command: 'sudo systemctl disable --now <unidad>.service',
          note: MANUAL,
        },
      ],
      ['/etc/systemd/system/', '/usr/lib/systemd/system/'],
      { en: 'Disabling a service in use breaks its function (databases, agents, schedulers); verify dependencies first.', es: 'Deshabilitar un servicio en uso rompe su función (bases de datos, agentes, schedulers); verifique dependencias primero.' },
      GENERIC_PREREQ,
      { en: 'sudo systemctl enable --now <unidad>.service re-enables a disabled unit.', es: 'sudo systemctl enable --now <unidad>.service rehabilita una unidad deshabilitada.' },
      { en: 'systemctl list-units --type=service --state=running shows the reduced, intended set.', es: 'systemctl list-units --type=service --state=running muestra el conjunto reducido previsto.' },
    ),
    limitations: {
      en: 'Only systemd units when PID1 is systemd; containers with other inits report NOT_ASSESSED honestly. No universal "dangerous service" list is applied — judgement stays with the operator.',
      es: 'Solo unidades systemd cuando PID1 es systemd; contenedores con otros init reportan NOT_ASSESSED honestamente. No se aplica una lista universal de "servicios peligrosos" — el criterio queda en el operador.',
    },
  },
  {
    id: 'VC-LNX-0501',
    version: '1.0.0',
    name: { en: 'Malware scanner present', es: 'Antimalware presente' },
    description: {
      en: 'A malware scanner (ClamAV clamscan/clamd) must be installed so on-demand or on-access scanning is possible on this host.',
      es: 'Debe haber un antimalware instalado (ClamAV clamscan/clamd) para permitir escaneo bajo demanda o al acceso en este host.',
    },
    category: 'ENDPOINT_PROTECTION',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: 'stat(): /usr/bin/clamscan /usr/sbin/clamd',
    evaluate(bag): ControlEvaluation {
      const evidence = [
        frag('execFile:stat', 'stat /usr/bin/clamscan | /usr/sbin/clamd', { clamavInstalled: bag.clamavInstalled, clamavDaemonRunning: bag.clamavDaemonRunning, gccInstalled: bag.gccInstalled }, 'HIGH'),
      ]
      if (bag.clamavInstalled) {
        return {
          status: 'PASS',
          detail:
            bag.clamavDaemonRunning === true
              ? 'clamav detected (clamscan/clamd binary present) and clamav-daemon is running — on-access scanning active'
              : bag.clamavDaemonRunning === false
                ? 'clamav detected (clamscan/clamd binary present); clamav-daemon NOT running — on-demand scans only, consider enabling clamav-daemon'
                : 'clamav detected (clamscan/clamd binary present); daemon state unknown (systemd offline or unavailable)',
          evidence,
        }
      }
      return {
        status: 'FAIL',
        detail: 'clamav not detected (dpkg/stat) — no malware scanning tooling found',
        evidence,
      }
    },
    explanation: {
      en: 'Linux malware (cryptominers, ransomware, webshells) is a real and growing category; a scanner adds a detection layer for payloads that arrive via uploads, packages or compromised services.',
      es: 'El malware en Linux (criptomineros, ransomware, webshells) es una categoría real y creciente; un escáner añade una capa de detección para cargas que llegan por uploads, paquetes o servicios comprometidos.',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_CIS, REF_NIST],
    remediation: rem(
      'MEDIUM',
      { en: 'No malware scanner detected on the host.', es: 'Sin antimalware detectado en el host.' },
      { en: 'Endpoint protection often skipped on Linux servers.', es: 'La protección de endpoint suele omitirse en servidores Linux.' },
      { en: 'Malicious payloads can persist and run undetected; cleaning after the fact is far costlier than scanning.', es: 'Cargas maliciosas pueden persistir y ejecutarse sin detección; limpiar después cuesta mucho más que escanear.' },
      GENERIC_STATE,
      { en: 'ClamAV installed with fresh signatures; scheduled/on-access scans for user data and upload paths.', es: 'ClamAV instalado con firmas al día; escaneos programados/al acceso para datos de usuario y rutas de upload.' },
      [
        {
          title: { en: 'Install ClamAV', es: 'Instalar ClamAV' },
          command: 'sudo apt update && sudo apt install clamav clamav-daemon',
          note: MANUAL,
        },
        {
          title: { en: 'Update signatures and run a first scan', es: 'Actualizar firmas y ejecutar un primer escaneo' },
          command: 'sudo freshclam && sudo clamscan -r -i /var/www /home',
          note: MANUAL,
        },
        {
          title: { en: 'Enable the daemon (on-access/background) if policy requires', es: 'Habilitar el demonio (al acceso/segundo plano) si la política lo exige' },
          command: 'sudo systemctl enable --now clamav-daemon',
          note: MANUAL,
        },
      ],
      ['/usr/bin/clamscan', '/usr/sbin/clamd'],
      {
        en: 'On-access scanning costs I/O and CPU; scope paths deliberately. Heuristic scanning can produce false positives — define an isolation workflow.',
        es: 'El escaneo al acceso cuesta I/O y CPU; delimite rutas. El escaneo heurístico puede dar falsos positivos — defina un flujo de cuarentena.',
      },
      { en: 'APT repositories reachable; disk space for signatures; agreed scan scope.', es: 'Repositorios APT alcanzables; espacio en disco para firmas; alcance de escaneo acordado.' },
      { en: 'sudo apt remove clamav clamav-daemon.', es: 'sudo apt remove clamav clamav-daemon.' },
      { en: 'clamscan --version works and freshclam reports up-to-date signatures; re-run scan shows PASS.', es: 'clamscan --version funciona y freshclam reporta firmas al día; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Binary-presence based: other EDR products are NOT detected, so a FAIL means "ClamAV absent", not "no protection exists". Installation does not prove active scanning.',
      es: 'Basado en presencia de binarios: otros productos EDR NO se detectan, así que FAIL significa "ClamAV ausente", no "no existe protección". La instalación no prueba escaneo activo.',
    },
  },
  {
    id: 'VC-LNX-0502',
    version: '1.0.0',
    name: { en: 'Mandatory access control active', es: 'Control de acceso mandatorio activo' },
    description: {
      en: 'AppArmor must be listed as an active Linux Security Module in /sys/kernel/security/lsm, confining processes beyond classic Unix permissions.',
      es: 'AppArmor debe aparecer como módulo de seguridad LSM activo en /sys/kernel/security/lsm, confinando procesos más allá de los permisos Unix clásicos.',
    },
    category: 'OS_SECURITY',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/sys/kernel/security/lsm',
    evaluate(bag): ControlEvaluation {
      const evidence = [
        frag('proc-read', '/sys/kernel/security/lsm', { apparmorLsmActive: bag.apparmorLsmActive, apparmorProfilesDirExists: bag.apparmorProfilesDirExists }, 'HIGH'),
      ]
      if (bag.apparmorLsmActive === null) {
        return { status: 'NOT_ASSESSED', reason: 'LSM list unreadable (/sys/kernel/security/lsm)' }
      }
      if (bag.apparmorLsmActive) {
        return {
          status: 'PASS',
          detail: `apparmor active in kernel LSM list${bag.apparmorProfilesDirExists ? '; profiles present in /etc/apparmor.d' : ''}`,
          evidence,
        }
      }
      return {
        status: 'FAIL',
        detail: 'apparmor not listed in /sys/kernel/security/lsm — no AppArmor confinement on this kernel',
        evidence,
      }
    },
    explanation: {
      en: 'Mandatory access control confines a compromised service to its profile: file paths, capabilities and network actions beyond the profile are denied, shrinking the blast radius of any exploit.',
      es: 'El control mandatorio confina un servicio comprometido a su perfil: rutas, capacidades y acciones de red fuera del perfil se deniegan, reduciendo el radio de daño de cualquier exploit.',
    },
    references: [REF_DEBIAN, REF_UBUNTU, REF_NIST, REF_CIS],
    remediation: rem(
      'MEDIUM',
      { en: 'AppArmor is not active in the kernel LSM list.', es: 'AppArmor no está activo en la lista LSM del kernel.' },
      { en: 'Kernel booted with AppArmor disabled, another LSM selected, or an AppArmor-less kernel.', es: 'Kernel arrancado con AppArmor deshabilitado, otro LSM seleccionado o un kernel sin AppArmor.' },
      { en: 'Compromised services run with full Unix privileges of their user — no confinement layer exists.', es: 'Los servicios comprometidos corren con todos los privilegios Unix de su usuario — sin capa de confinamiento.' },
      GENERIC_STATE,
      { en: 'AppArmor in the LSM list and enforcing profiles for network-facing services.', es: 'AppArmor en la lista LSM y perfiles en modo enforcing para servicios expuestos a red.' },
      [
        {
          title: { en: 'Install AppArmor tooling', es: 'Instalar las herramientas AppArmor' },
          command: 'sudo apt update && sudo apt install apparmor apparmor-utils',
          note: MANUAL,
        },
        {
          title: { en: 'Ensure AppArmor is enabled at boot (GRUB cmdline, when needed)', es: 'Asegurar AppArmor habilitado en el arranque (cmdline de GRUB, si hace falta)' },
          command: 'grep -E "apparmor=1|security=apparmor" /etc/default/grub || echo "apparmor=1 security=apparmor" | sudo tee -a /etc/default/grub && sudo update-grub',
          note: MANUAL,
        },
        {
          title: { en: 'Reboot into AppArmor and verify', es: 'Reiniciar con AppArmor y verificar' },
          command: 'sudo reboot  # luego: cat /sys/kernel/security/lsm && sudo aa-status',
          note: MANUAL,
        },
      ],
      ['/etc/default/grub', '/etc/apparmor.d/'],
      { en: 'Switching LSMs requires a reboot; wrong cmdline parameters can prevent boot — follow vendor documentation.', es: 'Cambiar de LSM exige reinicio; parámetros de cmdline erróneos pueden impedir arrancar — siga la documentación del fabricante.' },
      { en: 'Root, reboot window, vendor kernel with AppArmor support.', es: 'Root, ventana de reinicio, kernel del fabricante con soporte AppArmor.' },
      { en: 'Remove the added GRUB parameters, update-grub and reboot.', es: 'Elimine los parámetros GRUB añadidos, update-grub y reinicie.' },
      { en: 'cat /sys/kernel/security/lsm contains "apparmor"; aa-status shows loaded profiles; re-run scan shows PASS.', es: 'cat /sys/kernel/security/lsm contiene "apparmor"; aa-status muestra perfiles cargados; reejecutar el escaneo muestra PASS.' },
    ),
    limitations: {
      en: 'Container shares the host kernel (LSM belongs to the host). SELinux-only hosts will report FAIL here by design — this adapter targets the AppArmor ecosystem.',
      es: 'El contenedor comparte el kernel del host (el LSM es del host). Hosts solo-SELinux reportarán FAIL por diseño — este adaptador apunta al ecosistema AppArmor.',
    },
  },
  {
    id: 'VC-LNX-0601',
    version: '1.0.0',
    name: { en: 'Disk encryption', es: 'Cifrado de disco' },
    description: {
      en: 'Data-at-rest protection must be present: /etc/crypttab volumes (LUKS) or, when absent, an explicit assessment that the platform relies on external layers.',
      es: 'Debe existir protección de datos en reposo: volúmenes en /etc/crypttab (LUKS) o, si no, una evaluación explícita de que la plataforma depende de capas externas.',
    },
    category: 'ENCRYPTION',
    severity: 'MEDIUM',
    platforms: ['linux'],
    distros: ['debian', 'ubuntu'],
    implemented: true,
    evidenceSource: '/etc/crypttab + cryptsetup + lsblk TYPE=crypt (runtime)',
    evaluate(bag): ControlEvaluation {
      const evidence = [
        frag('file-read', '/etc/crypttab', { crypttabExists: bag.crypttabExists, cryptsetupInstalled: bag.cryptsetupInstalled, luksVolumes: bag.luksVolumes }, 'HIGH'),
      ]
      // Runtime evidence first: lsblk TYPE=crypt proves volumes are mapped NOW.
      if (bag.luksVolumes && bag.luksVolumes.length > 0) {
        return {
          status: 'PASS',
          detail: `LUKS volumes mapped at runtime (lsblk): ${bag.luksVolumes.slice(0, 6).join(', ')}${bag.luksVolumes.length > 6 ? ' …' : ''}`,
          evidence,
        }
      }
      if (bag.crypttabExists) {
        return { status: 'PASS', detail: '/etc/crypttab present — encrypted volumes configured at boot (not visible as mapped in this session)', evidence }
      }
      if (bag.cryptsetupInstalled) {
        return {
          status: 'WARNING',
          detail: 'cryptsetup installed but no encrypted volumes configured in /etc/crypttab — tooling exists without data-at-rest protection',
          evidence,
        }
      }
      return {
        status: 'NOT_APPLICABLE',
        reason:
          'no disk-encryption tooling or /etc/crypttab present (typical for containers/VMs) — if this is physical hardware, assess LUKS manually',
        evidence,
      }
    },
    explanation: {
      en: 'Disk encryption protects against physical/media theft and improper disposal of disks; without it, anyone with the drive (or a hypervisor snapshot) reads every file.',
      es: 'El cifrado de disco protege contra robo físico del medio y eliminación incorrecta de discos; sin él, quien tenga la unidad (o un snapshot del hipervisor) lee todos los archivos.',
    },
    references: [REF_DEBIAN, REF_NIST, REF_CIS],
    remediation: rem(
      'MEDIUM',
      { en: 'No LUKS/crypttab data-at-rest encryption detected.', es: 'Sin cifrado en reposo LUKS/crypttab detectado.' },
      { en: 'OS installed without the encrypted-LVM/encrypted-root option; containers/VMs inheriting host layers.', es: 'SO instalado sin la opción root/LVM cifrado; contenedores/VMs que heredan capas del host.' },
      { en: 'Physical theft, decommissioned disks and hypervisor snapshots expose plaintext data.', es: 'Robo físico, discos dados de baja y snapshots del hipervisor exponen los datos en claro.' },
      GENERIC_STATE,
      { en: 'LUKS-protected volumes for sensitive data (ideally the root volume), registered in /etc/crypttab.', es: 'Volúmenes protegidos con LUKS para datos sensibles (idealmente el volumen raíz), registrados en /etc/crypttab.' },
      [
        {
          title: { en: 'Install cryptsetup', es: 'Instalar cryptsetup' },
          command: 'sudo apt update && sudo apt install cryptsetup',
          note: MANUAL,
        },
        {
          title: { en: 'Encrypt a DEDICATED data volume (DESTRUCTIVE to that volume — never the bare root of a live system)', es: 'Cifrar un volumen de datos DEDICADO (DESTRUCTIVO para ese volumen — nunca el root en caliente sin procedimiento)' },
          command: 'sudo cryptsetup luksFormat /dev/sdX1 && sudo cryptsetup open /dev/sdX1 datos && sudo mkfs.ext4 /dev/mapper/datos',
          note: MANUAL,
        },
        {
          title: { en: 'Register it in /etc/crypttab and /etc/fstab, then update initramfs', es: 'Registrarlo en /etc/crypttab y /etc/fstab, luego actualizar initramfs' },
          command: 'echo "datos UUID=<uuid> none luks" | sudo tee -a /etc/crypttab && sudo update-initramfs -u',
          note: MANUAL,
        },
      ],
      ['/etc/crypttab', '/etc/fstab'],
      {
        en: 'luksFormat DESTROYS data on the target volume; forgetting the passphrase means permanent loss. For root encryption use the installer or a documented migration procedure.',
        es: 'luksFormat DESTRUYE los datos del volumen; olvidar la frase significa pérdida permanente. Para cifrar root use el instalador o un procedimiento documentado.',
      },
      {
        en: 'Verified backups, a dedicated volume, offline recovery key stored safely, console access for the passphrase prompt at boot.',
        es: 'Backups verificados, volumen dedicado, frase de recuperación guardada con seguridad, acceso a consola para la frase al arrancar.',
      },
      {
        en: 'Restore the volume from backup (encryption is not reversible in place); remove crypttab/fstab entries to unmount at boot.',
        es: 'Restaure el volumen desde backup (el cifrado no se revierte en sitio); elimine las entradas crypttab/fstab para no montarlo al arrancar.',
      },
      { en: 'lsblk -f shows the LUKS type and crypttab maps it; reboot prompts for the passphrase and mounts cleanly.', es: 'lsblk -f muestra tipo LUKS y crypttab lo mapea; el reinicio pide la frase y monta correctamente.' },
    ),
    limitations: {
      en: 'Evidence is config-presence based: the engine cannot verify that mounted filesystems are actually the encrypted mappings. Containers/VMs typically inherit the HOST layer — assess at the right level.',
      es: 'La evidencia es por presencia de configuración: el motor no puede verificar que los sistemas montados sean realmente los mapeos cifrados. Contenedores/VMs heredan la capa del HOST — evalúe en el nivel correcto.',
    },
  },
]
