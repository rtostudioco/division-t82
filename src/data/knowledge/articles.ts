// DIVISION T82 — Knowledge Center articles (Task 2-b)
// Spanish technical body content; bilingual title/summary. Defensive framing only.
// Schema: KnowledgeArticleData (src/lib/engine/types.ts)
import type { KnowledgeArticleData } from '../../lib/engine/types'

export const KNOWLEDGE_ARTICLES: KnowledgeArticleData[] = [
  // ─────────────────────────────────────────────────────────────────────────────
  // 1. ssh-root-login
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'ssh-root-login',
    title: {
      en: 'Direct SSH login as root',
      es: 'Inicio de sesión SSH directo como root',
    },
    summary: {
      en: 'Why direct SSH access to the root account should be disabled, how the PermitRootLogin directive controls it, and how to verify the effective setting on a Debian or Ubuntu host.',
      es: 'Por qué el acceso SSH directo a la cuenta root debe estar deshabilitado, cómo la directiva PermitRootLogin lo controla y cómo verificar el valor efectivo en un host Debian o Ubuntu.',
    },
    level: 'INTERMEDIATE',
    category: 'OS_SECURITY',
    platforms: ['linux'],
    technicalDescription: {
      en: 'The OpenSSH server exposes the PermitRootLogin directive in sshd_config, which accepts the values yes, prohibit-password, forced-commands-only and no. When set to yes, the most privileged account on the system becomes reachable over the network, so every dictionary-based credential attack against the service targets an account with unrestricted power. Modern Debian and Ubuntu releases default to prohibit-password, which still exposes the root account to public-key authentication but blocks password attempts. The defensible baseline for most environments is no, combined with individual named accounts and sudo for privileged operations.',
      es: 'El servidor OpenSSH expone la directiva PermitRootLogin en sshd_config, que acepta los valores yes, prohibit-password, forced-commands-only y no. Cuando se establece en yes, la cuenta con más privilegios del sistema queda accesible por red, de modo que cada ataque de credenciales contra el servicio apunta directamente a una cuenta sin restricciones. Las versiones recientes de Debian y Ubuntu usan por defecto prohibit-password, que bloquea los intentos con contraseña pero todavía expone root a la autenticación por clave pública. La línea base defendible en la mayoría de entornos es no, combinada con cuentas individuales con nombre y el uso de sudo para operaciones privilegiadas.',
    },
    rootCause: {
      en: 'The setting usually stays open because of provisioning convenience: automated installers, cloud images and legacy runbooks frequently enable direct root SSH to simplify initial configuration. Because administrators can still log in through their own accounts and escalate with sudo, disabling the directive rarely breaks legitimate workflows; it remains open mostly by inertia.',
      es: 'El ajuste suele permanecer abierto por conveniencia en el aprovisionamiento: los instaladores automatizados, las imágenes de nube y los runbooks heredados frecuentemente habilitan el SSH directo de root para simplificar la configuración inicial. Como los administradores pueden seguir entrando con sus propias cuentas y escalar con sudo, deshabilitar la directiva rara vez rompe flujos de trabajo legítimos; permanece abierta sobre todo por inercia.',
    },
    howItHappens: {
      en: 'A server is deployed from a template or base image that ships PermitRootLogin yes, or an operator enables it to run a one-time migration script and never reverts the change. From that moment the SSH daemon accepts authentication attempts for root from any network that can reach port 22. Automated scanners and credential-guessing tools discover the service within hours and start probing the account continuously, generating noise in the authentication logs that can mask other activity.',
      es: 'Un servidor se despliega desde una plantilla o imagen base que incluye PermitRootLogin yes, o un operador lo habilita para ejecutar un script de migración puntual y nunca revierte el cambio. A partir de ese momento el demonio SSH acepta intentos de autenticación de root desde cualquier red que alcance el puerto 22. Los escáneres automatizados y las herramientas de prueba de credenciales descubren el servicio en cuestión de horas y comienzan a sondear la cuenta de forma continua, generando ruido en los registros de autenticación que puede ocultar otra actividad.',
    },
    threatContext: {
      en: 'MITRE ATT&CK associates direct compromise of privileged local accounts with technique T1078.003 (Local Accounts), used both for initial access and for persistence. A root account reachable over SSH concentrates two problems: it is the highest-value credential in the system and it is shared, so attribution of actions to a specific person disappears. Restricting interactive root access keeps privilege usage attributable, allows sudo policy to apply, and reduces the exposure surface of the service to named accounts only.',
      es: 'MITRE ATT&CK asocia el compromiso directo de cuentas locales privilegiadas con la técnica T1078.003 (Local Accounts), empleada tanto para acceso inicial como para persistencia. Una cuenta root accesible por SSH concentra dos problemas: es la credencial de mayor valor del sistema y es compartida, por lo que desaparece la atribución de las acciones a una persona concreta. Restringir el acceso interactivo de root mantiene el uso de privilegios atribuible, permite aplicar la política de sudo y reduce la superficie de exposición del servicio a cuentas con nombre.',
    },
    mitre: [{ id: 'T1078.003', name: 'Local Accounts' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Relevant signals include PermitRootLogin yes or prohibit-password in the effective sshd configuration, authentication log entries showing repeated Failed password or Accepted publickey messages for root, and sessions recorded as root@pts/N that no scheduled maintenance window explains. A rising volume of authentication failures for root in /var/log/auth.log is a reliable sign that the account is being probed.',
      es: 'Las señales relevantes incluyen PermitRootLogin yes o prohibit-password en la configuración efectiva de sshd, entradas de registro de autenticación con mensajes repetidos de Failed password o Accepted publickey para root, y sesiones registradas como root@pts/N que ninguna ventana de mantenimiento planificado explica. Un volumen creciente de fallos de autenticación de root en /var/log/auth.log es una indicación fiable de que la cuenta está siendo sondeada.',
    },
    detection: {
      en: 'Determine the effective value with sshd -T (requires administrative privileges), which merges sshd_config with the include files under sshd_config.d. Compare it with the distribution default and with the CIS benchmark expectation for the platform. Complement the configuration review with log analysis: count authentication failures per account over time to distinguish background noise from targeted probing of root.',
      es: 'Determina el valor efectivo con sshd -T (requiere privilegios administrativos), que combina sshd_config con los archivos incluidos bajo sshd_config.d. Compáralo con el valor por defecto de la distribución y con la expectativa de la referencia CIS para la plataforma. Complementa la revisión de configuración con análisis de registros: cuenta los fallos de autenticación por cuenta a lo largo del tiempo para distinguir el ruido de fondo de un sondeo dirigido contra root.',
    },
    prevention: {
      en: 'Set PermitRootLogin no in a dedicated drop-in file such as /etc/ssh/sshd_config.d/50-hardening.conf so package upgrades do not overwrite the decision, and reload the sshd service afterwards. Ensure every administrator has a personal account with membership in the sudo group, and keep working key-based authentication before closing password paths. Document the exception procedure for console-only root use in recovery scenarios.',
      es: 'Establece PermitRootLogin no en un archivo dedicado como /etc/ssh/sshd_config.d/50-hardening.conf para que las actualizaciones de paquetes no sobrescriban la decisión, y recarga el servicio sshd a continuación. Asegúrate de que cada administrador disponga de una cuenta personal con pertenencia al grupo sudo y de que la autenticación por clave funcione antes de cerrar las vías con contraseña. Documenta el procedimiento de excepción para el uso de root solo por consola en escenarios de recuperación.',
    },
    mitigation: {
      en: 'If direct root SSH was found enabled, disable the directive and reload the service, then review the authentication logs for the exposure period to identify successful sessions that were not part of change management. Rotate any keys authorized for root in /root/.ssh/authorized_keys and consider rebuilding the host if evidence of interactive misuse appears. Confirm that at least one named account retains administrative access before applying the change to avoid locking out the team.',
      es: 'Si se encontró el SSH directo de root habilitado, deshabilita la directiva y recarga el servicio; después revisa los registros de autenticación del periodo de exposición para identificar sesiones exitosas ajenas a la gestión de cambios. Rota las claves autorizadas para root en /root/.ssh/authorized_keys y valora reconstruir el host si aparece evidencia de uso interactivo indebido. Confirma que al menos una cuenta con nombre conserva acceso administrativo antes de aplicar el cambio, para evitar bloquear al equipo.',
    },
    verification: {
      en: 'After the change, sshd -T must report permitrootlogin no, and a connection attempt to root from a test host must be rejected before any credential prompt. Confirm that named accounts still authenticate correctly and that sudo works for the expected operations. Schedule periodic re-checks because configuration management drift and package upgrades can reintroduce include files with different directives.',
      es: 'Tras el cambio, sshd -T debe informar permitrootlogin no, y un intento de conexión a root desde un host de prueba debe ser rechazado antes de cualquier solicitud de credenciales. Confirma que las cuentas con nombre siguen autenticando correctamente y que sudo funciona para las operaciones esperadas. Programa comprobaciones periódicas, porque la deriva de la gestión de configuración y las actualizaciones de paquetes pueden reintroducir archivos include con directivas distintas.',
    },
    secureConfigExample: {
      label: 'Fragmento sshd_config — inicio de sesión directo de root deshabilitado',
      language: 'ini',
      code: `# /etc/ssh/sshd_config.d/50-hardening.conf
# Deshabilita el acceso interactivo directo del superusuario por SSH.
# Los administradores operan con cuentas con nombre y sudo.
PermitRootLogin no
MaxAuthTries 4
LoginGraceTime 30

# Aplicar y verificar (no recorta sesiones activas):
#   sshd -t && systemctl reload ssh   (Debian)
#   sshd -t && systemctl reload sshd  (Ubuntu)
#   sshd -T | grep -i permitrootlogin`,
    },
    defensiveCodeExample: {
      label: 'Script de verificación (solo lectura) del valor efectivo de PermitRootLogin',
      language: 'bash',
      code: `#!/usr/bin/env bash
# Verificación defensiva de configuración: SOLO LECTURA.
# No modifica archivos, no reinicia servicios ni intenta autenticaciones.
value=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')
case "$value" in
  no)
    echo "OK: el inicio de sesión directo de root está deshabilitado"
    ;;
  "")
    echo "INDETERMINADO: sshd -T requiere privilegios administrativos"
    ;;
  *)
    echo "REVISAR: PermitRootLogin = $value en /etc/ssh/sshd_config o sshd_config.d/"
    ;;
esac`,
    },
    references: [
      { label: 'OpenSSH Documentation', url: 'https://www.openssh.com/manual.html' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'MITRE ATT&CK — Local Accounts (T1078.003)', url: 'https://attack.mitre.org/techniques/T1078/003/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0101'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 2. ssh-password-authentication
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'ssh-password-authentication',
    title: {
      en: 'SSH password authentication and key-based access',
      es: 'Autenticación por contraseña en SSH y acceso basado en claves',
    },
    summary: {
      en: 'Disabling password authentication in OpenSSH removes the most abused credential path on a Linux server and replaces it with public-key authentication. This article explains the directives involved, the operational prerequisites, and how to verify the effective configuration.',
      es: 'Deshabilitar la autenticación por contraseña en OpenSSH elimina la vía de credenciales más abusada en un servidor Linux y la sustituye por la autenticación de clave pública. Este artículo explica las directivas implicadas, los requisitos operativos y cómo verificar la configuración efectiva.',
    },
    level: 'INTERMEDIATE',
    category: 'IDENTITY_ACCESS',
    platforms: ['linux'],
    technicalDescription: {
      en: 'OpenSSH supports several authentication methods, controlled by directives such as PasswordAuthentication, KbdInteractiveAuthentication, PubkeyAuthentication and AuthenticationMethods. Password authentication converts the SSH endpoint into an online oracle where any client can test arbitrary credential guesses indefinitely, at network speed and without leaving traces beyond log entries. Public-key authentication instead verifies possession of a private key that never crosses the wire, making remote guessing infeasible in practice. Setting AuthenticationMethods publickey restricts the session establishment exclusively to that method.',
      es: 'OpenSSH admite varios métodos de autenticación, controlados por directivas como PasswordAuthentication, KbdInteractiveAuthentication, PubkeyAuthentication y AuthenticationMethods. La autenticación por contraseña convierte el punto final SSH en un oráculo en línea donde cualquier cliente puede probar suposiciones de credenciales de forma indefinida, a velocidad de red y sin dejar rastro más allá de los registros. La autenticación de clave pública, en cambio, verifica la posesión de una clave privada que nunca viaja por la red, haciendo inviable en la práctica la adivinación remota. Establecer AuthenticationMethods publickey restringe el establecimiento de sesión exclusivamente a ese método.',
    },
    rootCause: {
      en: 'Password authentication remains enabled because it is the simplest path for interactive use: it requires no key distribution, works from any client, and matches the workflow of shared service accounts. The cost of distributing and protecting keys is paid once per administrator, while the risk of an online password oracle is paid continuously by the service.',
      es: 'La autenticación por contraseña sigue habilitada porque es la vía más sencilla para el uso interactivo: no requiere distribución de claves, funciona desde cualquier cliente y coincide con el flujo de cuentas de servicio compartidas. El coste de distribuir y proteger claves se paga una vez por administrador, mientras que el riesgo de un oráculo de contraseñas en línea lo paga el servicio de forma continua.',
    },
    howItHappens: {
      en: 'Automated credential-guessing campaigns enumerate internet-reachable SSH services and try common username and password combinations for weeks, often from distributed sources that keep the attempt rate below obvious thresholds. Any weak or reused password eventually falls, and the gained account provides a stable foothold. Even strong passwords extend the attack surface to every credential leak: a password reused elsewhere and disclosed in a third-party breach becomes directly usable against the server.',
      es: 'Las campañas automatizadas de prueba de credenciales enumeran los servicios SSH alcanzables por internet y prueban combinaciones habituales de usuario y contraseña durante semanas, a menudo desde fuentes distribuidas que mantienen la tasa de intentos por debajo de umbrales evidentes. Cualquier contraseña débil o reutilizada acaba cayendo, y la cuenta obtenida proporciona un punto de apoyo estable. Incluso las contraseñas fuertes amplían la superficie de ataque a cada filtración de credenciales: una contraseña reutilizada en otro sitio y divulgada en una brecha de terceros se vuelve directamente utilizable contra el servidor.',
    },
    threatContext: {
      en: 'MITRE ATT&CK classifies systematic password guessing against services under T1110 (Brute Force), one of the most frequently observed initial access techniques. Beyond credential guessing, a widely reachable sshd is an exploitable surface by itself: CVE-2024-6387 (regreSSHion), a race condition in the OpenSSH signal handler, demonstrated that a pre-authentication vulnerability in the daemon can lead to unauthenticated remote code execution, which is why key-only exposure, network restriction and timely patching are evaluated together in this control family.',
      es: 'MITRE ATT&CK clasifica la adivinación sistemática de contraseñas contra servicios bajo T1110 (Brute Force), una de las técnicas de acceso inicial más observadas. Más allá de la adivinación de credenciales, un sshd ampliamente alcanzable es por sí mismo una superficie explotable: CVE-2024-6387 (regreSSHion), una condición de carrera en el gestor de señales de OpenSSH, demostró que una vulnerabilidad de preautenticación en el demonio puede conducir a ejecución remota de código sin autenticación; por eso la exposición solo por clave, la restricción de red y el parcheado puntual se evalúan conjuntamente en esta familia de controles.',
    },
    mitre: [{ id: 'T1110', name: 'Brute Force' }],
    cve: ['CVE-2024-6387'],
    cwe: [],
    indicators: {
      en: 'Watch for high volumes of Invalid user or Failed password lines in /var/log/auth.log, authentication attempts spread across many usernames from a small set of source addresses, and sessions established immediately after a burst of failures. The presence of PasswordAuthentication yes in the effective configuration is itself a risk indicator that the password oracle is open.',
      es: 'Vigila grandes volúmenes de líneas Invalid user o Failed password en /var/log/auth.log, intentos de autenticación repartidos entre muchos nombres de usuario desde un conjunto pequeño de direcciones de origen, y sesiones establecidas justo tras una ráfaga de fallos. La presencia de PasswordAuthentication yes en la configuración efectiva es en sí misma un indicador de riesgo de que el oráculo de contraseñas está abierto.',
    },
    detection: {
      en: 'Verify the effective configuration with sshd -T and confirm that passwordauthentication reports no and authenticationmethods reports publickey. Tools such as ssh-audit audit the negotiated algorithms and authentication posture of the service from a client perspective, which is useful to detect drift between intended policy and effective daemon behaviour. Correlate auth.log volumes per source address to quantify ongoing guessing activity.',
      es: 'Verifica la configuración efectiva con sshd -T y confirma que passwordauthentication informa no y authenticationmethods informa publickey. Herramientas como ssh-audit auditan los algoritmos negociados y la postura de autenticación del servicio desde la perspectiva del cliente, lo que resulta útil para detectar deriva entre la política prevista y el comportamiento efectivo del demonio. Correlaciona los volúmenes de auth.log por dirección de origen para cuantificar la actividad de adivinación en curso.',
    },
    prevention: {
      en: 'Deploy keys for every administrator first, test them from a second session, and only then disable password paths with PasswordAuthentication no, KbdInteractiveAuthentication no and AuthenticationMethods publickey in a drop-in configuration file. Restrict authorized_keys per account, prefer ed25519 keys, protect private keys with passphrases, and keep the SSH service reachable only from management networks where a firewall allows it.',
      es: 'Despliega primero las claves de cada administrador, pruébalas desde una segunda sesión y solo entonces deshabilita las vías con contraseña mediante PasswordAuthentication no, KbdInteractiveAuthentication no y AuthenticationMethods publickey en un archivo de configuración drop-in. Restringe authorized_keys por cuenta, prefiere claves ed25519, protege las claves privadas con frase de paso y mantén el servicio SSH alcanzable solo desde redes de gestión donde un cortafuegos lo permita.',
    },
    mitigation: {
      en: 'If an SSH account was compromised through password guessing, disable password authentication immediately, remove unknown entries from authorized_keys files, and terminate suspicious sessions. Review process history and file changes attributable to the compromised account, rotate any credentials it could read, and tighten firewall rules so the service is only reachable from expected sources during the investigation.',
      es: 'Si una cuenta SSH fue comprometida mediante adivinación de contraseñas, deshabilita de inmediato la autenticación por contraseña, elimina entradas desconocidas de los archivos authorized_keys y cierra las sesiones sospechosas. Revisa el historial de procesos y los cambios de archivos atribuibles a la cuenta comprometida, rota las credenciales que pudiera leer y restringe las reglas del cortafuegos para que el servicio solo sea alcanzable desde fuentes esperadas durante la investigación.',
    },
    verification: {
      en: 'Confirm with sshd -T that the effective values match the policy, and validate behaviourally: a connection attempt that only offers password authentication must be refused without reaching a password prompt. Re-run the verification after every OpenSSH package upgrade, and include the check in scheduled configuration audits so a rollback or an include file cannot silently reopen the password path.',
      es: 'Confirma con sshd -T que los valores efectivos coinciden con la política y valida el comportamiento: un intento de conexión que solo ofrezca autenticación por contraseña debe ser rechazado sin llegar a la solicitud de contraseña. Repite la verificación tras cada actualización del paquete OpenSSH e incluye la comprobación en auditorías programadas de configuración, para que una reversión o un archivo include no reabra la vía de contraseñas en silencio.',
    },
    secureConfigExample: {
      label: 'Fragmento sshd_config — autenticación exclusiva por clave pública',
      language: 'ini',
      code: `# /etc/ssh/sshd_config.d/50-auth.conf
# Deshabilita el oráculo de contraseñas en línea y exige clave pública.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey

# Aplicar y verificar:
#   sshd -t && systemctl reload ssh
#   sshd -T | grep -Ei 'passwordauthentication|authenticationmethods'`,
    },
    defensiveCodeExample: {
      label: 'Script de verificación (solo lectura) del método de autenticación efectivo',
      language: 'bash',
      code: `#!/usr/bin/env bash
# Verificación defensiva de configuración: SOLO LECTURA.
# Consulta el demonio sin modificar archivos ni abrir sesiones.
if ! command -v sshd >/dev/null 2>&1; then
  echo "NOTA: sshd no está instalado en este sistema"
  exit 0
fi
pass_auth=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')
auth_meth=$(sshd -T 2>/dev/null | awk '/^authenticationmethods/{$1=""; sub(/^ /,""); print}')
case "$pass_auth" in
  no)
    echo "OK: PasswordAuthentication no"
    echo "Métodos requeridos: $auth_meth"
    ;;
  "")
    echo "INDETERMINADO: ejecuta este script con privilegios suficientes (sshd -T)"
    ;;
  *)
    echo "REVISAR: PasswordAuthentication = $pass_auth; la adivinación de contraseñas en línea sigue posible"
    ;;
esac`,
    },
    references: [
      { label: 'OpenSSH Documentation', url: 'https://www.openssh.com/manual.html' },
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'MITRE ATT&CK — Brute Force (T1110)', url: 'https://attack.mitre.org/techniques/T1110/' },
      { label: 'NIST NVD — CVE-2024-6387', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387' },
    ],
    relatedControls: ['VC-LNX-0102'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 3. host-firewall-linux
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'host-firewall-linux',
    title: {
      en: 'Host firewall on Linux: default-deny incoming',
      es: 'Cortafuegos de host en Linux: denegación por defecto del tráfico entrante',
    },
    summary: {
      en: 'A host firewall with a default-deny incoming policy turns every new listening service into an explicit, reviewed decision. This article covers ufw and nftables concepts on Debian and Ubuntu and why disabling or bypassing the firewall is itself an attacker objective.',
      es: 'Un cortafuegos de host con política de entrada por defecto denegada convierte cada nuevo servicio en escucha en una decisión explícita y revisada. Este artículo cubre los conceptos de ufw y nftables en Debian y Ubuntu, y por qué deshabilitar o sortear el cortafuegos es en sí mismo un objetivo del atacante.',
    },
    level: 'BEGINNER',
    category: 'FIREWALL',
    platforms: ['linux'],
    technicalDescription: {
      en: 'The Linux kernel classifies packets through netfilter hooks that ruleset tools such as nftables program; ufw is a user-friendly front end that generates those rules. A default-deny incoming policy drops any connection that no explicit rule allows, while outbound traffic is typically allowed. This inversion of defaults means the set of reachable services equals the set of documented and reviewed exceptions, so an accidentally installed dev server, database or management interface does not become silently reachable. Stateful rules (ct state established,related accept) preserve established connections, and loopback traffic must always be accepted for local processes to communicate.',
      es: 'El núcleo Linux clasifica los paquetes mediante ganchos netfilter que herramientas de reglas como nftables programan; ufw es una interfaz amigable que genera esas reglas. Una política de entrada por defecto denegada descarta cualquier conexión que ninguna regla explícita permita, mientras que el tráfico saliente normalmente se permite. Esta inversión de los valores por defecto implica que el conjunto de servicios alcanzables equivale al conjunto de excepciones documentadas y revisadas, de modo que un servidor de desarrollo, una base de datos o una interfaz de gestión instalados por accidente no quedan alcanzables en silencio. Las reglas con estado (ct state established,related accept) conservan las conexiones establecidas, y el tráfico de loopback debe aceptarse siempre para que los procesos locales se comuniquen.',
    },
    rootCause: {
      en: 'Hosts frequently lack a host firewall because the environment is assumed to be protected by a perimeter device, or because early setup steps disabled the firewall to rule it out as a source of problems and it was never re-enabled. Container and lab hosts are often treated as trusted networks, which is exactly the assumption that lateral movement exploits.',
      es: 'Los hosts frecuentemente carecen de cortafuegos de host porque se asume que el entorno está protegido por un dispositivo perimetral, o porque los primeros pasos de instalación lo deshabilitaron para descartarlo como origen de problemas y nunca se reactivó. Los hosts de contenedores y laboratorios suelen tratarse como redes de confianza, que es justo la suposición que el movimiento lateral explota.',
    },
    howItHappens: {
      en: 'An attacker who gains a foothold on a single internal host finds that every other service on the network segment is directly reachable, because no host-level filtering exists. Service discovery inside the segment then proceeds unimpeded: databases, caches and administrative endpoints can be contacted from the compromised host. Conversely, when defenses are present, impairing them is a standard step: MITRE ATT&CK documents under T1562.001 how defenders\' tools and configurations, including host firewalls, are disabled or modified to remove friction.',
      es: 'Un atacante que obtiene un punto de apoyo en un único host interno comprueba que todos los demás servicios del segmento de red son directamente alcanzables, porque no existe filtrado a nivel de host. El descubrimiento de servicios dentro del segmento avanza entonces sin obstáculos: bases de datos, cachés y puntos finales administrativos pueden contactarse desde el host comprometido. A la inversa, cuando las defensas están presentes, degradarlas es un paso estándar: MITRE ATT&CK documenta bajo T1562.001 cómo las herramientas y configuraciones de los defensores, incluidos los cortafuegos de host, se deshabilitan o modifican para eliminar fricción.',
    },
    threatContext: {
      en: 'In defense-in-depth terms, the host firewall is the control that contains the blast radius of a single compromised workload. Perimeter filtering cannot distinguish traffic destined to a compromised host from legitimate traffic, while host-level default-deny stops unexpected service-to-service connections inside the segment. Keeping the ruleset minimal, documented and under change control also makes firewall tampering detectable by comparing the effective ruleset against the reviewed baseline.',
      es: 'En términos de defensa en profundidad, el cortafuegos de host es el control que contiene el radio de impacto de una única carga de trabajo comprometida. El filtrado perimetral no puede distinguir el tráfico destinado a un host comprometido del tráfico legítimo, mientras que la denegación por defecto a nivel de host detiene las conexiones inesperadas entre servicios dentro del segmento. Mantener el conjunto de reglas mínimo, documentado y bajo gestión de cambios también hace la manipulación del cortafuegos detectable, comparando el conjunto efectivo contra la línea base revisada.',
    },
    mitre: [{ id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Signals include an inactive or absent firewall (ufw status reporting inactive, no nftables ruleset loaded), iptables/nftables rules flushed at boot without a persistence mechanism, and log entries showing ufw BLOCK messages for ports that no rule should allow. An abrupt change in the ruleset outside change windows suggests manual tampering.',
      es: 'Las señales incluyen un cortafuegos inactivo o ausente (ufw status informando inactive, sin conjunto de reglas nftables cargado), reglas de iptables/nftables vaciadas en el arranque sin mecanismo de persistencia, y mensajes de registro ufw BLOCK en puertos que ninguna regla debería permitir. Un cambio abrupto en el conjunto de reglas fuera de las ventanas de cambio sugiere manipulación manual.',
    },
    detection: {
      en: 'Query the effective state rather than assuming it: ufw status verbose for ufw, nft list ruleset for nftables, and check that the corresponding systemd unit is enabled so the policy survives reboots. Compare the listening ports inventory (ss -tulnH) against the allowed set; any listener without a matching allow rule is only protected by the default-deny policy, and any allow rule without a listener is dead configuration worth removing.',
      es: 'Consulta el estado efectivo en lugar de asumirlo: ufw status verbose para ufw, nft list ruleset para nftables, y comprueba que la unidad systemd correspondiente esté habilitada para que la política sobreviva a los reinicios. Compara el inventario de puertos en escucha (ss -tulnH) con el conjunto permitido; todo servicio en escucha sin regla de permiso asociada queda protegido solo por la denegación por defecto, y toda regla de permiso sin servicio asociado es configuración muerta que conviene eliminar.',
    },
    prevention: {
      en: 'Define the default-deny incoming policy first, add explicit rules only for management and published services, and enable the firewall before exposing the host to any network. Use ufw limit for SSH to add rate limiting against credential guessing, persist nftables rules through the distribution mechanism, and review the ruleset whenever a new service is installed. Test the policy from a second session to avoid losing remote administration.',
      es: 'Define primero la política de entrada por defecto denegada, añade reglas explícitas solo para la administración y los servicios publicados, y habilita el cortafuegos antes de exponer el host a cualquier red. Usa ufw limit para SSH y añade limitación de tasa contra la adivinación de credenciales, persiste las reglas nftables mediante el mecanismo de la distribución y revisa el conjunto de reglas cada vez que se instale un nuevo servicio. Prueba la política desde una segunda sesión para no perder la administración remota.',
    },
    mitigation: {
      en: 'If the firewall was found disabled, re-apply the documented baseline ruleset, then review connection logs for the unprotected period to identify which internal services were contacted. If tampering is suspected, compare the current ruleset against configuration management history and treat unexplained changes as security events. Re-enable the policy incrementally, starting with management access, to keep the recovery path available.',
      es: 'Si se encontró el cortafuegos deshabilitado, vuelve a aplicar el conjunto de reglas de línea base documentado y después revisa los registros de conexiones del periodo desprotegido para identificar qué servicios internos fueron contactados. Si se sospecha manipulación, compara el conjunto de reglas actual con el historial de gestión de configuración y trata los cambios inexplicados como eventos de seguridad. Reactiva la política de forma incremental, empezando por el acceso de administración, para mantener disponible la vía de recuperación.',
    },
    verification: {
      en: 'Verify from outside the host: allowed ports accept connections and everything else is refused or dropped. Confirm that the policy is active after a reboot, that loopback and established connections still work, and that the configuration files are under change control. Re-run the listener inventory periodically so the allowed set and the listening reality never diverge silently.',
      es: 'Verifica desde fuera del host: los puertos permitidos aceptan conexiones y todo lo demás es rechazado o descartado. Confirma que la política sigue activa tras un reinicio, que el loopback y las conexiones establecidas siguen funcionando, y que los archivos de configuración están bajo gestión de cambios. Repite el inventario de servicios en escucha periódicamente para que el conjunto permitido y la realidad de escucha nunca diverjan en silencio.',
    },
    secureConfigExample: {
      label: 'Comandos ufw — política por defecto denegada con administración conservada',
      language: 'bash',
      code: `# Política por defecto: denegar el tráfico entrante, permitir el saliente.
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Excepciones explícitas y revisadas (mantén el acceso de administración).
sudo ufw allow 22/tcp comment 'SSH administration'
sudo ufw limit 22/tcp comment 'SSH with rate limiting'

# Activar y comprobar el estado efectivo.
sudo ufw enable
sudo ufw status verbose`,
    },
    labScenario: {
      title: {
        en: 'Guided exercise: default-deny host firewall in an isolated VM',
        es: 'Ejercicio guiado: cortafuegos de host por defecto denegado en una VM aislada',
      },
      steps: [
        'Prepara una máquina virtual propia y aislada (por ejemplo, Debian o Ubuntu en modo red interna) y toma una instantánea antes de tocar la configuración.',
        'Instala ufw con el gestor de paquetes de la distribución y observa el estado inicial con ufw status verbose; identifica qué puertos quedarian alcanzables sin política.',
        'Establece la política por defecto denegada para el tráfico entrante y permite explícitamente solo el puerto de administración SSH, usando ufw allow y ufw limit.',
        'Activa el cortafuegos y verifica desde el equipo anfitrión que la administración SSH funciona y que un puerto de prueba sin regla (por ejemplo, un servidor HTTP efímero) queda bloqueado.',
        'Revisa los registros de bloqueo del cortafuegos para confirmar que los intentos contra el puerto no autorizado se registran, y que el servicio en escucha sigue existiendo por dentro (ss -tulnH).',
        'Restaura la instantánea de la VM para dejar el entorno de prácticas limpio.',
      ],
      safetyNote: {
        en: 'Perform this exercise only on a local virtual machine isolated from production networks. Never apply default-deny policies to a remote server in a single session without a confirmed second session or console access, and do not test firewall rules against hosts you do not own.',
        es: 'Realiza este ejercicio únicamente en una máquina virtual local aislada de las redes de producción. Nunca apliques políticas de denegación por defecto a un servidor remoto en una sola sesión sin una segunda sesión confirmada o acceso por consola, y no pruebes reglas de cortafuegos contra hosts que no te pertenezcan.',
      },
    },
    references: [
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001)', url: 'https://attack.mitre.org/techniques/T1562/001/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0303'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 4. unattended-upgrades
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'unattended-upgrades',
    title: {
      en: 'Automated security updates with unattended-upgrades',
      es: 'Actualizaciones de seguridad automatizadas con unattended-upgrades',
    },
    summary: {
      en: 'Missing patching is consistently among the highest-impact risks on any system inventory. This article explains how unattended-upgrades automates the security channel on Debian and Ubuntu, which configuration makes it reliable, and how to verify that it is actually working.',
      es: 'La falta de parcheado figura de forma consistente entre los riesgos de mayor impacto en cualquier inventario de sistemas. Este artículo explica cómo unattended-upgrades automatiza el canal de seguridad en Debian y Ubuntu, qué configuración lo hace fiable y cómo verificar que realmente funciona.',
    },
    level: 'BEGINNER',
    category: 'PATCH_MANAGEMENT',
    platforms: ['linux'],
    technicalDescription: {
      en: 'The unattended-upgrades package runs a scheduled systemd timer that downloads and installs updates from the configured origins, by default the -security pocket of the distribution. Its behaviour is driven by APT configuration fragments: APT::Periodic::Update-Package-Lists refreshes the package index daily, APT::Periodic::Unattended-Upgrade enables the installation run, and the 50unattended-upgrades file lists the allowed origins and options such as removing unused dependencies or scheduling automatic reboots. Logs land in /var/log/unattended-upgrades, and mail or notifications can be configured for failures, so the process is observable rather than magical.',
      es: 'El paquete unattended-upgrades ejecuta un temporizador systemd programado que descarga e instala actualizaciones de los orígenes configurados, por defecto el bolsillo -security de la distribución. Su comportamiento lo dirigen fragmentos de configuración de APT: APT::Periodic::Update-Package-Lists refresca el índice de paquetes a diario, APT::Periodic::Unattended-Upgrade habilita la ejecución de instalación, y el archivo 50unattended-upgrades enumera los orígenes permitidos y opciones como eliminar dependencias no usadas o programar reinicios automáticos. Los registros quedan en /var/log/unattended-upgrades, y es posible configurar correo o notificaciones de fallos, de modo que el proceso es observable y no mágico.',
    },
    rootCause: {
      en: 'Patching gaps almost never stem from a technical limitation: apt and unattended-upgrades exist precisely for this. The causes are operational — hosts that nobody owns, fear that an update will break a legacy application, frozen base images, and the absence of a periodic review that connects pending security updates with actual exposure. Without automation, patch state decays from the day the host is deployed.',
      es: 'Las carencias de parcheado casi nunca provienen de una limitación técnica: apt y unattended-upgrades existen precisamente para eso. Las causas son operativas: hosts sin responsable claro, el temor a que una actualización rompa una aplicación heredada, imágenes base congeladas y la ausencia de una revisión periódica que conecte las actualizaciones de seguridad pendientes con la exposición real. Sin automatización, el estado de parcheado se degrada desde el día en que se despliega el host.',
    },
    howItHappens: {
      en: 'An attacker does not need novel techniques when a known, exploitable vulnerability persists on a public-facing service: MITRE ATT&CK tracks this pattern as T1190 (Exploit Public-Facing Application), and the CISA Known Exploited Vulnerabilities catalog documents how quickly public proof-of-concept code follows the publication of security patches. Internet-wide scanning continuously fingerprints software versions, so the window between patch publication and automated exploitation is often measured in days. A host that installs security updates the same day they are released compresses that window to nearly zero for known vulnerabilities.',
      es: 'Un atacante no necesita técnicas novedosas cuando una vulnerabilidad conocida y explotable persiste en un servicio expuesto a internet: MITRE ATT&CK registra este patrón como T1190 (Exploit Public-Facing Application), y el catálogo de Vulnerabilidades Conocidamente Explotadas de CISA documenta la rapidez con que el código de prueba público sigue a la publicación de parches. El escaneo continuo de internet perfila versiones de software, de modo que la ventana entre la publicación del parche y la explotación automatizada suele medirse en días. Un host que instala las actualizaciones de seguridad el mismo día de su publicación reduce esa ventana casi a cero para las vulnerabilidades conocidas.',
    },
    threatContext: {
      en: 'Patch management is the control that converts public vulnerability information into closed exposure. Every vulnerability management framework — CIS benchmarks, NIST guidance and CISA advisories — treats timely patching as a foundational requirement, precisely because exploitation of known flaws is cheaper and more reliable for attackers than developing new techniques. Automating the security channel does not eliminate the need for vulnerability review, but it removes the dependency on someone remembering to patch each host.',
      es: 'La gestión de parches es el control que convierte la información pública de vulnerabilidades en exposición cerrada. Todos los marcos de gestión de vulnerabilidades — referencias CIS, guías NIST y avisos de CISA — tratan el parcheado puntual como requisito foundational, precisamente porque explotar fallos conocidos es más barato y fiable para los atacantes que desarrollar técnicas nuevas. Automatizar el canal de seguridad no elimina la necesidad de revisión de vulnerabilidades, pero elimina la dependencia de que alguien recuerde parchear cada host.',
    },
    mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Signals include unattended-upgrades not installed or its systemd timer disabled, 20auto-upgrades missing the Unattended-Upgrade directive or set to 0, an outdated APT package index (apt-get -s upgrade showing long-standing pending security updates), and empty /var/log/unattended-upgrades despite months of uptime. Hosts reporting pendingSecurityUpdates greater than zero across consecutive scans deserve immediate attention.',
      es: 'Las señales incluyen unattended-upgrades sin instalar o con su temporizador systemd deshabilitado, 20auto-upgrades sin la directiva Unattended-Upgrade o con valor 0, un índice de paquetes APT desactualizado (apt-get -s upgrade mostrando actualizaciones de seguridad pendientes de larga duración) y /var/log/unattended-upgrades vacío a pesar de meses de actividad. Los hosts que reportan pendingSecurityUpdates mayor que cero en escaneos consecutivos merecen atención inmediata.',
    },
    detection: {
      en: 'Check the four observable facts: the package is installed (dpkg-query -W unattended-upgrades), the timer is enabled (systemctl status apt-daily-upgrade.timer), the policy fragment enables it (APT::Periodic::Unattended-Upgrade 1 in /etc/apt/apt.conf.d/20auto-upgrades), and the log shows recent completed runs. Estimate exposure separately with a simulated upgrade (apt-get -s upgrade) and classify pending packages that originate from the security origin, which is exactly how the scan engine computes pendingSecurityUpdates.',
      es: 'Comprueba los cuatro hechos observables: el paquete está instalado (dpkg-query -W unattended-upgrades), el temporizador está habilitado (systemctl status apt-daily-upgrade.timer), el fragmento de política lo habilita (APT::Periodic::Unattended-Upgrade 1 en /etc/apt/apt.conf.d/20auto-upgrades) y el registro muestra ejecuciones recientes completadas. Estima la exposición por separado con una actualización simulada (apt-get -s upgrade) y clasifica los paquetes pendientes que provienen del origen de seguridad, que es exactamente cómo el motor de escaneo calcula pendingSecurityUpdates.',
    },
    prevention: {
      en: 'Install unattended-upgrades, write the 20auto-upgrades fragment with both periodic directives enabled, and review 50unattended-upgrades to confirm the -security origin is active for your distribution. Decide reboot policy explicitly: either enable Unattended-Upgrade::Automatic-Reboot with a time window, or track hosts that need manual reboots for kernel updates. Keep the package index fresh (Update-Package-Lists 1) so the daily run evaluates real availability, not stale metadata.',
      es: 'Instala unattended-upgrades, escribe el fragmento 20auto-upgrades con ambas directivas periódicas habilitadas y revisa 50unattended-upgrades para confirmar que el origen -security está activo en tu distribución. Decide explícitamente la política de reinicios: o habilita Unattended-Upgrade::Automatic-Reboot con una ventana horaria, o registra los hosts que necesitan reinicios manuales para actualizaciones del kernel. Mantén el índice de paquetes fresco (Update-Package-Lists 1) para que la ejecución diaria evalúe la disponibilidad real, no metadatos obsoletos.',
    },
    mitigation: {
      en: 'For a host with accumulated pending security updates, first update the package index, then install the security origin updates and restart the affected services so running processes actually pick up the patched libraries. Verify with the simulated upgrade that the security list is empty, review unattended-upgrades logs for failures that explain the backlog, and add the host to the automated channel so the gap does not reopen. Where an update cannot be applied, document the risk acceptance and apply compensating controls such as network restriction.',
      es: 'Para un host con actualizaciones de seguridad pendientes acumuladas, primero refresca el índice de paquetes, después instala las actualizaciones del origen de seguridad y reinicia los servicios afectados para que los procesos en ejecución incorporen realmente las bibliotecas parcheadas. Verifica con la actualización simulada que la lista de seguridad queda vacía, revisa los registros de unattended-upgrades en busca de fallos que expliquen la acumulación y añade el host al canal automatizado para que la carencia no se repita. Cuando una actualización no pueda aplicarse, documenta la aceptación del riesgo y aplica controles compensatorios como la restricción de red.',
    },
    verification: {
      en: 'A configured system shows: both directives at 1 in 20auto-upgrades, the apt-daily-upgrade.timer active, recent entries in /var/log/unattended-upgrades listing the installed security packages, and a simulated upgrade that returns no pending security packages. Re-verify after major version upgrades of the distribution, because release upgrades can reset APT configuration fragments or disable the timer.',
      es: 'Un sistema configurado muestra: ambas directivas a 1 en 20auto-upgrades, el temporizador apt-daily-upgrade.timer activo, entradas recientes en /var/log/unattended-upgrades con los paquetes de seguridad instalados, y una actualización simulada que no devuelve paquetes de seguridad pendientes. Verifica de nuevo tras actualizaciones de versión mayor de la distribución, porque las actualizaciones de versión pueden reiniciar los fragmentos de configuración de APT o deshabilitar el temporizador.',
    },
    secureConfigExample: {
      label: 'Configuración APT — actualizaciones de seguridad automáticas diarias',
      language: 'ini',
      code: `# /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";

# /etc/apt/apt.conf.d/50unattended-upgrades (fragmento recomendado)
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// Decide explícitamente la política de reinicio para actualizaciones del kernel:
Unattended-Upgrade::Automatic-Reboot "false";`,
    },
    defensiveCodeExample: {
      label: 'Script de verificación (solo lectura) del canal de actualizaciones automáticas',
      language: 'bash',
      code: `#!/usr/bin/env bash
# Verificación defensiva de configuración: SOLO LECTURA.
# No instala, descarga ni actualiza paquetes; solo consulta estado.
echo "--- servicio y temporizador ---"
systemctl is-enabled unattended-upgrades.service 2>/dev/null || echo "REVISAR: servicio unattended-upgrades no habilitado"
systemctl is-active apt-daily-upgrade.timer 2>/dev/null || echo "REVISAR: apt-daily-upgrade.timer inactivo"
echo "--- política APT (20auto-upgrades) ---"
grep -hE '^\\s*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo "REVISAR: fragmento 20auto-upgrades ausente o incompleto"
echo "--- paquete instalado ---"
dpkg-query -W unattended-upgrades 2>/dev/null || echo "REVISAR: paquete unattended-upgrades no instalado"`,
    },
    references: [
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'MITRE ATT&CK — Exploit Public-Facing Application (T1190)', url: 'https://attack.mitre.org/techniques/T1190/' },
      { label: 'CISA Known Exploited Vulnerabilities Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
    ],
    relatedControls: ['VC-LNX-0205', 'VC-LNX-0206'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 5. linux-memory-hardening
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'linux-memory-hardening',
    title: {
      en: 'Kernel memory hardening: ASLR, kptr_restrict and core dumps',
      es: 'Endurecimiento de memoria del kernel: ASLR, kptr_restrict y volcados de memoria',
    },
    summary: {
      en: 'Kernel sysctls such as kernel.randomize_va_space, kernel.kptr_restrict and fs.suid_dumpable raise the cost of memory-corruption exploitation by hiding addresses, pointers and crash contents from unprivileged users. This article explains what each knob does and how to deploy them as a coherent sysctl profile.',
      es: 'Los sysctls del kernel como kernel.randomize_va_space, kernel.kptr_restrict y fs.suid_dumpable elevan el coste de explotar corrupción de memoria al ocultar direcciones, punteros y contenidos de fallos a usuarios sin privilegios. Este artículo explica qué hace cada ajuste y cómo desplegarlos como un perfil sysctl coherente.',
    },
    level: 'ADVANCED',
    category: 'OS_SECURITY',
    platforms: ['linux'],
    technicalDescription: {
      en: 'kernel.randomize_va_space controls Address Space Layout Randomization: 2 enables randomized offsets for the stack, heap, shared libraries and mmap regions on every process, so a memory-corruption payload cannot rely on fixed addresses. kernel.kptr_restrict hides kernel pointer values exposed through /proc and other interfaces (value 2 hides them even from the root-owned reading context where supported), removing a rich source of information for building kernel exploits. fs.suid_dumpable=0 prevents setuid binaries from producing core dumps, so crash artifacts containing privileged memory cannot be left readable in the working directory. kernel.dmesg_restrict complements the set by limiting the kernel ring buffer to privileged readers, cutting another information disclosure channel.',
      es: 'kernel.randomize_va_space controla la aleatorización del diseño del espacio de direcciones (ASLR): el valor 2 habilita desplazamientos aleatorios para la pila, el montículo, las bibliotecas compartidas y las regiones mmap en cada proceso, de modo que un payload de corrupción de memoria no puede apoyarse en direcciones fijas. kernel.kptr_restrict oculta los valores de punteros del kernel expuestos por /proc y otras interfaces (el valor 2 los oculta incluso al contexto de lectura privilegiado donde está soportado), eliminando una rica fuente de información para construir exploits de kernel. fs.suid_dumpable=0 impide que los binarios setuid generen volcados de memoria, de modo que artefactos de fallo con contenido privilegiado no queden legibles en el directorio de trabajo. kernel.dmesg_restrict complementa el conjunto al limitar el búfer de anillo del kernel a lectores privilegiados, recortando otro canal de divulgación de información.',
    },
    rootCause: {
      en: 'These protections trade convenience for security: easier debugging, easier performance analysis and readable kernel pointers are genuinely useful during development, so development-friendly defaults persist into production images. Hardening profiles are also frequently documented but rarely applied wholesale, and each kernel or distribution upgrade can silently reset a sysctl that was only configured at runtime instead of through a persisted sysctl.d file.',
      es: 'Estas protecciones cambian conveniencia por seguridad: una depuración más sencilla, un análisis de rendimiento más fácil y punteros del kernel legibles son realmente útiles durante el desarrollo, por lo que los valores por defecto amigables con el desarrollo persisten en las imágenes de producción. Los perfiles de endurecimiento además se documentan con frecuencia pero rara vez se aplican por completo, y cada actualización del kernel o de la distribución puede reiniciar en silencio un sysctl configurado solo en tiempo de ejecución en lugar de mediante un archivo persistente en sysctl.d.',
    },
    howItHappens: {
      en: 'Memory-corruption exploitation follows an information-gathering phase: with ASLR disabled, an attacker reproduces fixed addresses locally; with kptr_restrict=0, reading /proc/kallsyms or similar interfaces leaks symbol and pointer values that defeat KASLR; with suid_dumpable enabled, a deliberately crashed setuid helper can leave a core file that contains privileged memory fragments. MITRE ATT&CK tracks the exploitation of these conditions for privilege escalation under T1068, and the underlying software defects are typically classified as memory-safety issues such as CWE-119 (improper restriction of operations within the bounds of a memory buffer).',
      es: 'La explotación por corrupción de memoria sigue una fase de recolección de información: con ASLR deshabilitado, un atacante reproduce direcciones fijas localmente; con kptr_restrict=0, la lectura de /proc/kallsyms u otras interfaces similares filtra valores de símbolos y punteros que anulan el KASLR; con suid_dumpable habilitado, un binario setuid hecho fallar deliberadamente puede dejar un archivo core con fragmentos de memoria privilegiada. MITRE ATT&CK registra la explotación de estas condiciones para escalada de privilegios bajo T1068, y los defectos de software subyacentes se clasifican típicamente como problemas de seguridad de memoria como CWE-119 (restricción inadecuada de operaciones dentro de los límites de un búfer de memoria).',
    },
    threatContext: {
      en: 'These sysctls do not fix software defects; they raise the reliability and information cost of exploiting them. Kernel privilege escalation chains routinely combine a memory-safety bug with leaked pointers or predictable addresses, so each removed information channel lowers the practical feasibility of an exploit even when the vulnerable code remains present. On long-lived servers where every kernel patch cannot be applied instantly, this friction is meaningful defense-in-depth and is required by hardened baselines such as the CIS benchmarks.',
      es: 'Estos sysctls no corrigen defectos de software; elevan el coste de información y fiabilidad de explotarlos. Las cadenas de escalada de privilegios del kernel combinan rutinariamente un error de seguridad de memoria con punteros filtrados o direcciones predecibles, de modo que cada canal de información eliminado reduce la viabilidad práctica de un exploit incluso cuando el código vulnerable sigue presente. En servidores de larga vida donde no todos los parches de kernel pueden aplicarse al instante, esta fricción constituye una defensa en profundidad significativa y es exigida por líneas base endurecidas como las referencias CIS.',
    },
    mitre: [{ id: 'T1068', name: 'Exploitation for Privilege Escalation' }],
    cve: [],
    cwe: ['CWE-119'],
    indicators: {
      en: 'Direct indicators are sysctl values: kernel.randomize_va_space below 2, kernel.kptr_restrict below 1, fs.suid_dumpable above 0 and kernel.dmesg_restrict equal to 0, all readable by unprivileged users under /proc/sys. Indirect indicators include core dump patterns (kernel.core_pattern) writing to world-readable locations and debugging packages that relax these values during troubleshooting and are never reverted.',
      es: 'Los indicadores directos son los valores de sysctl: kernel.randomize_va_space por debajo de 2, kernel.kptr_restrict por debajo de 1, fs.suid_dumpable por encima de 0 y kernel.dmesg_restrict igual a 0, todos legibles por usuarios sin privilegios bajo /proc/sys. Los indicadores indirectos incluyen patrones de volcado (kernel.core_pattern) que escriben en ubicaciones legibles por todos y paquetes de depuración que relajan estos valores durante el diagnóstico y nunca se revierten.',
    },
    detection: {
      en: 'Read the effective values directly from /proc/sys (sysctl kernel.randomize_va_space, for example) and compare them against the hardened baseline; because every unprivileged user can read them, the check needs no special privileges. Verify that a persisted file in /etc/sysctl.d exists so the values survive reboots, and confirm that the applied profile matches what configuration management declares. Review boot parameters as well, since noexec/rollback options and LSM settings live outside sysctl.',
      es: 'Lee los valores efectivos directamente de /proc/sys (sysctl kernel.randomize_va_space, por ejemplo) y compáralos con la línea base endurecida; como cualquier usuario sin privilegios puede leerlos, la comprobación no requiere privilegios especiales. Verifica que exista un archivo persistente en /etc/sysctl.d para que los valores sobrevivan a los reinicios, y confirma que el perfil aplicado coincide con lo que declara la gestión de configuración. Revisa también los parámetros de arranque, ya que opciones como noexec y los ajustes LSM viven fuera de sysctl.',
    },
    prevention: {
      en: 'Deploy the values as a single persisted profile file in /etc/sysctl.d, apply it with sysctl --system, and encode the expected values in configuration management so drift is detectable. Coordinate with development teams: core dumps for debugging can be enabled per-process and per-session instead of globally, and kernel pointer visibility can be relaxed temporarily during controlled diagnostics and restored afterwards. Re-verify after kernel upgrades, which may introduce new related knobs.',
      es: 'Despliega los valores como un único archivo de perfil persistente en /etc/sysctl.d, aplícalo con sysctl --system y codifica los valores esperados en la gestión de configuración para que la deriva sea detectable. Coordínate con los equipos de desarrollo: los volcados de memoria para depuración pueden habilitarse por proceso y por sesión en lugar de globalmente, y la visibilidad de los punteros del kernel puede relajarse temporalmente durante diagnósticos controlados y restaurarse después. Verifica de nuevo tras las actualizaciones del kernel, que pueden introducir nuevos ajustes relacionados.',
    },
    mitigation: {
      en: 'If a hardened value was found relaxed, restore it through the persisted profile and immediately apply it to the running kernel. Then assess the exposure window: whether core dumps were actually created in writable paths, whether pointer interfaces were readable by service accounts, and whether unprivileged users could capture kernel logs. Remove any leftover core files from user-writable directories and treat evidence of exploitation attempts in kernel logs as a privilege escalation investigation.',
      es: 'Si se encontró un valor endurecido relajado, restáuralo mediante el perfil persistente y aplícalo de inmediato al kernel en ejecución. Después evalúa la ventana de exposición: si se crearon realmente volcados en rutas escribibles, si las interfaces de punteros eran legibles por cuentas de servicio y si usuarios sin privilegios pudieron capturar registros del kernel. Elimina cualquier archivo core remanente en directorios escribibles por usuarios y trata la evidencia de intentos de explotación en los registros del kernel como una investigación de escalada de privilegios.',
    },
    verification: {
      en: 'Verification is read-only and unprivileged: confirm randomize_va_space=2, kptr_restrict at the hardened level, suid_dumpable=0 and dmesg_restrict=1 both in the running kernel and in the sysctl.d profile. Attempt an unprivileged read of a kernel pointer interface to confirm the restriction is effective, and confirm that a core dump of a non-setuid test process still respects your intended core_pattern policy.',
      es: 'La verificación es de solo lectura y sin privilegios: confirma randomize_va_space=2, kptr_restrict en el nivel endurecido, suid_dumpable=0 y dmesg_restrict=1 tanto en el kernel en ejecución como en el perfil sysctl.d. Intenta una lectura sin privilegios de una interfaz de punteros del kernel para confirmar que la restricción es efectiva, y confirma que un volcado de un proceso de prueba no setuid respeta la política de core_pattern prevista.',
    },
    secureConfigExample: {
      label: 'Perfil sysctl.d — endurecimiento de memoria del kernel',
      language: 'ini',
      code: `# /etc/sysctl.d/90-memory-hardening.conf
# ASLR completo: pila, montículo, bibliotecas y mmap aleatorizados por proceso.
kernel.randomize_va_space = 2
# Oculta los punteros del kernel expuestos por /proc a lectores sin privilegios.
kernel.kptr_restrict = 2
# Restringe el búfer de anillo del kernel (dmesg) a lectores privilegiados.
kernel.dmesg_restrict = 1
# Sin volcados de memoria de binarios setuid (fragmentos de memoria privilegiada).
fs.suid_dumpable = 0

# Aplicar y verificar:
#   sysctl --system
#   sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable`,
    },
    references: [
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
      { label: 'MITRE ATT&CK — Exploitation for Privilege Escalation (T1068)', url: 'https://attack.mitre.org/techniques/T1068/' },
      { label: 'NIST NVD', url: 'https://nvd.nist.gov/' },
    ],
    relatedControls: ['VC-LNX-0201', 'VC-LNX-0202', 'VC-LNX-0203'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 6. password-policy-linux
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'password-policy-linux',
    title: {
      en: 'Password and account policy on Linux: shadow, aging, UID 0 and sudo',
      es: 'Política de contraseñas y cuentas en Linux: shadow, vigencia, UID 0 y sudo',
    },
    summary: {
      en: 'Four local account controls — robust password hashing, password aging, a single UID 0 account, and no NOPASSWD sudo grants — form the identity baseline of a Linux host. This article explains each one and how they are verified with read-only evidence.',
      es: 'Cuatro controles locales de cuenta — hashing robusto de contraseñas, vigencia de contraseñas, una única cuenta con UID 0 y sin concesiones sudo NOPASSWD — forman la línea base de identidad de un host Linux. Este artículo explica cada uno y cómo se verifican con evidencia de solo lectura.',
    },
    level: 'INTERMEDIATE',
    category: 'IDENTITY_ACCESS',
    platforms: ['linux'],
    technicalDescription: {
      en: 'Password hashes live in /etc/shadow, whose readability is restricted to privileged processes; the hashing algorithm is selected through PAM and login.defs (ENCRYPT_METHOD), with yescrypt or SHA-512/crypt preferred over legacy MD5. Aging is governed by login.defs defaults (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE) and per-account by chage. The UID 0 check enforces that exactly one account holds the superuser identity, since any additional UID 0 account bypasses audit trails built around root. Finally, NOPASSWD entries in sudoers allow privilege escalation without re-authentication, which extends any compromised non-privileged session directly to full control.',
      es: 'Los hashes de contraseñas residen en /etc/shadow, cuya lectura está restringida a procesos privilegiados; el algoritmo de hashing se selecciona mediante PAM y login.defs (ENCRYPT_METHOD), prefiriendo yescrypt o SHA-512/crypt sobre el MD5 heredado. La vigencia se rige por los valores por defecto de login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE) y por cuenta mediante chage. La comprobación de UID 0 exige que exactamente una cuenta posea la identidad de superusuario, ya que cualquier cuenta adicional con UID 0 elude las pistas de auditoría construidas en torno a root. Por último, las entradas NOPASSWD en sudoers permiten escalar privilegios sin reautenticación, lo que extiende cualquier sesión no privilegiada comprometida directamente al control total.',
    },
    rootCause: {
      en: 'Weak identity settings accumulate for pragmatic reasons: aging is disabled to stop recurring password change complaints, a second UID 0 account is created as a service workaround, and NOPASSWD is added to make a script work in automation. Each decision is individually small, but together they remove the re-authentication barriers and attribution that the rest of the identity design depends on.',
      es: 'Los ajustes débiles de identidad se acumulan por razones pragmáticas: la vigencia se deshabilita para evitar quejas recurrentes sobre el cambio de contraseñas, se crea una segunda cuenta con UID 0 como solución para un servicio, y se añade NOPASSWD para que un script funcione en automatización. Cada decisión es pequeña por separado, pero en conjunto eliminan las barreras de reautenticación y la atribución de las que depende el resto del diseño de identidad.',
    },
    howItHappens: {
      en: 'When identity controls decay, a single credential compromise becomes a persistent full compromise: MITRE ATT&CK describes under T1078 (Valid Accounts) how attackers prefer legitimate credentials precisely because they evade suspicion. Weak or legacy-hashed passwords are recovered offline once the hash database leaks; stale passwords outlive the employees who knew them; duplicate UID 0 accounts hide administrative activity from reviews that only look at root; and a NOPASSWD grant converts any code execution as the granted user into instant superuser. CWE-521 (weak password requirements) captures the software-level dimension of these decisions.',
      es: 'Cuando los controles de identidad decaen, un único compromiso de credenciales se convierte en un compromiso total persistente: MITRE ATT&CK describe bajo T1078 (Valid Accounts) cómo los atacantes prefieren credenciales legítimas precisamente porque no despiertan sospechas. Las contraseñas débiles o con hashing heredado se recuperan sin conexión en cuanto la base de hashes se filtra; las contraseñas caducadas sobreviven a los empleados que las conocían; las cuentas duplicadas con UID 0 ocultan la actividad administrativa a las revisiones que solo miran root; y una concesión NOPASSWD convierte cualquier ejecución de código como el usuario concedido en superusuario instantáneo. CWE-521 (requisitos de contraseñas débiles) recoge la dimensión a nivel de software de estas decisiones.',
    },
    threatContext: {
      en: 'Local account policy is the substrate every other control trusts: SSH restrictions, sudo rules and audit trails all assume that accounts are unique, attributed and protected by credentials with a defined lifetime. NIST password guidance (SP 800-63B family) and the OWASP Authentication Cheat Sheet converge on the same principles for local systems: strength through length and modern hashing, aging used to bound exposure rather than to rotate arbitrarily, and privileged operations re-authenticated. Where a central directory exists, these controls shift to the directory, but standalone hosts and service accounts still need the local baseline.',
      es: 'La política local de cuentas es el sustrato en el que confía cualquier otro control: las restricciones SSH, las reglas de sudo y las pistas de auditoría asumen cuentas únicas, atribuibles y protegidas por credenciales con vigencia definida. La guía de contraseñas de NIST (familia SP 800-63B) y la hoja de autenticación de OWASP convergen en los mismos principios para sistemas locales: fortaleza mediante longitud y hashing moderno, vigencia usada para acotar la exposición en lugar de rotar arbitrariamente, y operaciones privilegiadas con reautenticación. Cuando existe un directorio central, estos controles se trasladan al directorio, pero los hosts aislados y las cuentas de servicio siguen necesitando la línea base local.',
    },
    mitre: [{ id: 'T1078', name: 'Valid Accounts' }],
    cve: [],
    cwe: ['CWE-521'],
    indicators: {
      en: 'Observable indicators include more than one account with UID 0 in /etc/passwd, ENCRYPT_METHOD set to a legacy algorithm in login.defs, PASS_MAX_DAYS absent or extremely large, per-account aging values (chage -l) expired or unlimited for privileged users, and NOPASSWD lines in /etc/sudoers or /etc/sudoers.d. Readability of /etc/shadow itself is also evidence: a world-readable shadow database is a critical finding by its own.',
      es: 'Los indicadores observables incluyen más de una cuenta con UID 0 en /etc/passwd, ENCRYPT_METHOD fijado a un algoritmo heredado en login.defs, PASS_MAX_DAYS ausente o excesivamente grande, valores de vigencia por cuenta (chage -l) caducados o ilimitados para usuarios privilegiados, y líneas NOPASSWD en /etc/sudoers o /etc/sudoers.d. La legibilidad de /etc/shadow es también evidencia: una base de hashes legible por todos es un hallazgo crítico por sí misma.',
    },
    detection: {
      en: 'All four checks are read-only: parse /etc/passwd for UID 0 duplicates, read login.defs for the aging defaults and hash method, query per-account expiry with chage, and grep the sudoers fragments for NOPASSWD (visudo -c validates syntax safely). Note that /etc/shadow and sudoers are root-readable only, so the engine reports NOT_ASSESSED with a reason when the scan runs without sufficient privileges, instead of guessing.',
      es: 'Las cuatro comprobaciones son de solo lectura: analiza /etc/passwd en busca de duplicados con UID 0, lee login.defs para los valores de vigencia y el método de hash, consulta la caducidad por cuenta con chage, y busca NOPASSWD en los fragmentos de sudoers (visudo -c valida la sintaxis de forma segura). Ten en cuenta que /etc/shadow y sudoers solo son legibles por root, así que el motor reporta NOT_ASSESSED con un motivo cuando el escaneo corre sin privilegios suficientes, en lugar de adivinar.',
    },
    prevention: {
      en: 'Set the aging baseline in login.defs, apply modern hashing (ENCRYPT_METHOD YESCRYPT on current Debian and Ubuntu), and enforce per-account expiry for privileged users with chage. Keep exactly one UID 0 account (root) and create service identities as normal unprivileged users. Restrict NOPASSWD to narrowly scoped commands where automation genuinely requires it, prefer timestamp-based sudo for humans, and document every exception with an owner and a review date.',
      es: 'Fija la línea base de vigencia en login.defs, aplica hashing moderno (ENCRYPT_METHOD YESCRYPT en Debian y Ubuntu actuales) y exige caducidad por cuenta para los usuarios privilegiados con chage. Mantén exactamente una cuenta con UID 0 (root) y crea las identidades de servicio como usuarios normales sin privilegios. Restringe NOPASSWD a comandos acotados donde la automatización lo exija de verdad, prefiere sudo con marca de tiempo para personas y documenta cada excepción con un responsable y una fecha de revisión.',
    },
    mitigation: {
      en: 'When a weak identity setting is found, correct it with care: removing a second UID 0 account or a NOPASSWD grant can break automation, so inventory what depends on it first, migrate it to scoped grants, and then remove the broad grant. Force password renewal for affected accounts, rotate credentials that may have been exposed, and review authentication history for sessions that used the weak configuration. Validate sudoers syntax with visudo before reloading changes.',
      es: 'Cuando se encuentra un ajuste de identidad débil, corrígelo con cuidado: eliminar una segunda cuenta con UID 0 o una concesión NOPASSWD puede romper la automatización, así que inventaría primero qué depende de ella, migra a concesiones acotadas y después elimina la concesión amplia. Fuerza la renovación de contraseñas de las cuentas afectadas, rota las credenciales que puedan haberse expuesto y revisa el historial de autenticación en busca de sesiones que usaran la configuración débil. Valida la sintaxis de sudoers con visudo antes de recargar los cambios.',
    },
    verification: {
      en: 'Re-verify all four dimensions with read-only commands: a single UID 0 line in passwd, modern ENCRYPT_METHOD and bounded PASS_MAX_DAYS in login.defs, sane chage values for privileged accounts, and no unjustified NOPASSWD entries. Repeat after automation changes and user lifecycle operations (joiners, leavers), which are the most common source of identity drift.',
      es: 'Verifica de nuevo las cuatro dimensiones con comandos de solo lectura: una única línea con UID 0 en passwd, ENCRYPT_METHOD moderno y PASS_MAX_DAYS acotado en login.defs, valores de chage razonables para las cuentas privilegiadas y ninguna entrada NOPASSWD injustificada. Repite tras cambios de automatización y operaciones del ciclo de vida de usuarios (altas y bajas), que son la fuente más habitual de deriva de identidad.',
    },
    secureConfigExample: {
      label: 'login.defs — vigencia y método de hashing de contraseñas',
      language: 'ini',
      code: `# /etc/login.defs — política de vigencia y hashing (aplica a cuentas nuevas)
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    14
PASS_WARN_AGE   14
ENCRYPT_METHOD  YESCRYPT

# Ajustes por cuenta existente (lectura con chage):
#   chage -l usuario
#   chage -M 90 -m 7 -W 14 usuario`,
    },
    defensiveCodeExample: {
      label: 'Script de auditoría (solo lectura) de identidad local',
      language: 'bash',
      code: `#!/usr/bin/env bash
# Auditoría defensiva de identidad: SOLO LECTURA.
# No modifica cuentas, contraseñas ni políticas.
echo "--- cuentas con UID 0 (debe aparecer solo root) ---"
awk -F: '($3 == 0) { print "UID0:", $1 }' /etc/passwd
echo "--- política de vigencia (login.defs) ---"
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD)' /etc/login.defs 2>/dev/null || echo "REVISAR: login.defs sin política definida"
echo "--- concesiones NOPASSWD (sudo) ---"
if [ -r /etc/sudoers ]; then
  grep -nE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || echo "OK: sin NOPASSWD visibles"
else
  echo "NOTA: /etc/sudoers no legible sin privilegios (evidencia parcial)"
fi`,
    },
    references: [
      { label: 'OWASP Cheat Sheet Series — Authentication', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'MITRE ATT&CK — Valid Accounts (T1078)', url: 'https://attack.mitre.org/techniques/T1078/' },
      { label: 'NIST Cybersecurity', url: 'https://www.nist.gov/cybersecurity' },
    ],
    relatedControls: ['VC-LNX-0103', 'VC-LNX-0104', 'VC-LNX-0105', 'VC-LNX-0106'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 7. listening-ports-attack-surface
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'listening-ports-attack-surface',
    title: {
      en: 'Listening ports and attack surface: reading ss -tulnH',
      es: 'Puertos en escucha y superficie de ataque: leer ss -tulnH',
    },
    summary: {
      en: 'Every listening socket is attack surface; every socket bound to all interfaces instead of loopback multiplies it. This article teaches how to read ss -tulnH, interpret 0.0.0.0 versus 127.0.0.1 bindings, and shrink the reachable service set to what is actually needed.',
      es: 'Todo socket en escucha es superficie de ataque; todo socket enlazado a todas las interfaces en lugar de a loopback la multiplica. Este artículo enseña a leer ss -tulnH, interpretar los enlaces 0.0.0.0 frente a 127.0.0.1 y reducir el conjunto de servicios alcanzables a lo realmente necesario.',
    },
    level: 'BEGINNER',
    category: 'NETWORK_SECURITY',
    platforms: ['linux'],
    technicalDescription: {
      en: 'The command ss -tulnH lists TCP and UDP sockets in a listening state without resolving names (-n), and -H removes the header line. Each row shows the protocol, state, queue counters, and the local address and port; the local address part is the security-relevant field. A binding of 0.0.0.0 (IPv4) or :: (IPv6) means the service accepts connections on every interface, so anything that can route to the host can reach it; a binding of 127.0.0.1 or ::1 restricts the service to connections originating on the same host. UDP entries have no connection state, which is why they appear with UNCONN and deserve equal attention.',
      es: 'El comando ss -tulnH enumera los sockets TCP y UDP en estado de escucha sin resolver nombres (-n), y -H elimina la línea de cabecera. Cada fila muestra el protocolo, el estado, los contadores de cola y la dirección y puerto locales; la parte de la dirección local es el campo relevante para la seguridad. Un enlace a 0.0.0.0 (IPv4) o :: (IPv6) significa que el servicio acepta conexiones en todas las interfaces, de modo que cualquier cosa que pueda enrutar hasta el host puede alcanzarlo; un enlace a 127.0.0.1 o ::1 restringe el servicio a conexiones originadas en el mismo host. Las entradas UDP no tienen estado de conexión, por lo que aparecen como UNCONN y merecen igual atención.',
    },
    rootCause: {
      en: 'Unnecessary exposure usually originates in defaults: daemons bind to all interfaces unless configured otherwise, package installations start services immediately, and container or lab setups accumulate components that outlive their original purpose. Because a listening service causes no symptoms, the only way to notice the growth is an explicit inventory — which most hosts never receive.',
      es: 'La exposición innecesaria suele originarse en los valores por defecto: los demonios se enlazan a todas las interfaces salvo configuración contraria, la instalación de paquetes arranca servicios de inmediato, y los entornos de contenedores o laboratorios acumulan componentes que sobreviven a su propósito original. Como un servicio en escucha no produce síntomas, la única forma de notar el crecimiento es un inventario explícito, que la mayoría de los hosts nunca recibe.',
    },
    howItHappens: {
      en: 'Network service discovery is a standard reconnaissance step: MITRE ATT&CK documents it as T1046, and it ranges from a single scan of the target host to systematic sweeps across a network segment. Any listening service — even one considered harmless, such as an unauthenticated cache or an administrative interface bound to all interfaces — becomes a candidate for exploitation of its known vulnerabilities or misconfigurations. The practical defense is arithmetic: fewer reachable services means fewer candidate entry points, and loopback-only bindings remove services from the network equation entirely.',
      es: 'El descubrimiento de servicios de red es un paso estándar de reconocimiento: MITRE ATT&CK lo documenta como T1046, y abarca desde un único escaneo del host objetivo hasta barridos sistemáticos por un segmento de red. Cualquier servicio en escucha — incluso uno considerado inocuo, como una caché sin autenticación o una interfaz administrativa enlazada a todas las interfaces — se convierte en candidato para la explotación de sus vulnerabilidades o configuraciones erróneas conocidas. La defensa práctica es aritmética: menos servicios alcanzables significa menos puntos de entrada candidatos, y los enlaces solo a loopback eliminan servicios de la ecuación de red por completo.',
    },
    threatContext: {
      en: 'Attack surface reduction is the cheapest vulnerability control available: a service that is not reachable cannot be exploited remotely, patched or not. The listening-ports inventory also provides the baseline for other controls — the host firewall exception list and the patch priority list both derive from which services are actually listening and where. Hosts whose inventory has not been reviewed in months routinely surprise their owners with services that no longer have a documented owner.',
      es: 'La reducción de la superficie de ataque es el control de vulnerabilidades más barato disponible: un servicio que no es alcanzable no puede ser explotado remotamente, parcheado o no. El inventario de puertos en escucha sirve además de línea base para otros controles: la lista de excepciones del cortafuegos de host y la lista de prioridades de parcheado derivan ambas de qué servicios escuchan realmente y dónde. Los hosts cuyo inventario no se revisa durante meses sorprenden rutinariamente a sus responsables con servicios que ya no tienen un propietario documentado.',
    },
    mitre: [{ id: 'T1046', name: 'Network Service Discovery' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Signals include listeners bound to 0.0.0.0 or :: for services that only local processes should use, undocumented ports in the inventory, UDP listeners without an identified owner, and services whose process name no longer corresponds to any documented application. A growing delta between two successive ss snapshots indicates configuration drift worth investigating.',
      es: 'Las señales incluyen servicios enlazados a 0.0.0.0 o :: que solo deberían usar procesos locales, puertos no documentados en el inventario, servicios UDP sin responsable identificado, y servicios cuyo nombre de proceso ya no corresponde a ninguna aplicación documentada. Un delta creciente entre dos instantáneas sucesivas de ss indica deriva de configuración que conviene investigar.',
    },
    detection: {
      en: 'Build the inventory with ss -tulnH and enrich it with process attribution using ss -tulnp (which requires privileges to see other users\' processes). Classify each row: local-only (127.0.0.1, ::1), internal, or externally reachable, and cross-check with the firewall exception list. Repeat the inventory on a schedule and diff against the previous baseline; the diff is usually more informative than the absolute list.',
      es: 'Construye el inventario con ss -tulnH y enriquécelo con atribución de proceso mediante ss -tulnp (que requiere privilegios para ver procesos de otros usuarios). Clasifica cada fila: solo local (127.0.0.1, ::1), interno o alcanzable externamente, y contrástalo con la lista de excepciones del cortafuegos. Repite el inventario de forma programada y compara con la línea base anterior; la diferencia suele aportar más información que la lista absoluta.',
    },
    prevention: {
      en: 'Configure every service to bind to loopback unless it must be reached over the network, disable or uninstall services that have no owner, and align the host firewall exception list with the reviewed inventory. Where a service must listen externally, keep it behind the default-deny firewall policy with an explicit allow rule, and document which application and which owner justify it. Treat each new package installation as a potential new listener and re-run the inventory afterwards.',
      es: 'Configura cada servicio para enlazarse a loopback salvo que deba alcanzarse por red, deshabilita o desinstala los servicios sin responsable, y alinea la lista de excepciones del cortafuegos de host con el inventario revisado. Cuando un servicio deba escuchar externamente, manténlo tras la política de denegación por defecto del cortafuegos con una regla de permiso explícita, y documenta qué aplicación y qué responsable lo justifican. Trata cada instalación de paquete como un posible nuevo servicio en escucha y vuelve a ejecutar el inventario después.',
    },
    mitigation: {
      en: 'For an unexpected listener, first identify the owning process and package, then decide between reconfiguring it to loopback, disabling its systemd unit, or uninstalling it. Re-check the firewall rules so the service is not simultaneously removed from the listener list and left allowed by an obsolete rule. Document the closure in the inventory baseline so the next diff reflects intentional change.',
      es: 'Para un servicio en escucha inesperado, identifica primero el proceso y paquete responsable, y después decide entre reconfigurarlo a loopback, deshabilitar su unidad systemd o desinstalarlo. Revisa también las reglas del cortafuegos para que el servicio no quede simultáneamente fuera de la lista de escucha y permitido por una regla obsoleta. Documenta el cierre en la línea base del inventario para que la siguiente comparación refleje un cambio intencionado.',
    },
    verification: {
      en: 'Verify that the listener inventory matches the documented baseline, that no new 0.0.0.0 or :: binding appears without a matching justification, and that loopback-restricted services still function for their local consumers. The check is fully read-only, so it can run unprivileged in scheduled audits; process attribution (ss -p) is the only part that benefits from privileges.',
      es: 'Verifica que el inventario de servicios en escucha coincide con la línea base documentada, que no aparecen nuevos enlaces a 0.0.0.0 o :: sin justificación asociada, y que los servicios restringidos a loopback siguen funcionando para sus consumidores locales. La comprobación es completamente de solo lectura, por lo que puede ejecutarse sin privilegios en auditorías programadas; la atribución de proceso (ss -p) es la única parte que se beneficia de privilegios.',
    },
    secureConfigExample: {
      label: 'nftables — política defensiva de entrada mínima',
      language: 'ini',
      code: `# /etc/nftables.conf — complementa la reducción de superficie:
# solo el tráfico revisado alcanza los servicios en escucha.
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif "lo" accept
    tcp dport 22 ct state new limit rate 15/minute accept comment "administracion SSH"
  }
}`,
    },
    defensiveCodeExample: {
      label: 'Script de verificación (solo lectura) de enlaces fuera de loopback',
      language: 'bash',
      code: `#!/usr/bin/env bash
# Verificación defensiva: SOLO LECTURA.
# Lista los sockets TCP/UDP en escucha enlazados fuera de loopback.
# (ss -tulnH no requiere privilegios; no modifica nada del sistema.)
ss -tulnH | awk '$5 !~ /^(127\\.0\\.0\\.1|\\[::1\\]|127\\.0\\.0\\.53)/ { print $1, $5 }' | sort -u
echo "--- nota: cada línea es superficie alcanzable por red; documéntala o restríngela ---"`,
    },
    labScenario: {
      title: {
        en: 'Guided exercise: listening-port inventory in a VM',
        es: 'Ejercicio guiado: inventario de puertos en escucha en una VM',
      },
      steps: [
        'Prepara una máquina virtual aislada con un servicio de demostración (por ejemplo, un servidor web simple instalado desde la distribución) y toma una instantánea previa.',
        'Ejecuta ss -tulnH y registra el inventario inicial: protocolo, puerto y dirección local de cada socket en escucha.',
        'Identifica el proceso responsable de cada socket con ss -tulnp (con privilegios dentro de la VM) y anótalo junto a cada línea del inventario.',
        'Reconfigura el servicio de demostración para que se enlace exclusivamente a 127.0.0.1, reinícialo y repite ss -tulnH para verificar que la dirección local cambió de 0.0.0.0 a 127.0.0.1.',
        'Comprueba desde el equipo anfitrión que el servicio ya no es alcanzable por red, mientras que desde dentro de la VM sigue respondiendo en localhost.',
        'Desinstala o deshabilita el servicio de demostración, ejecuta el inventario una última vez y restaura la instantánea para dejar la VM limpia.',
      ],
      safetyNote: {
        en: 'Perform the exercise only on your own isolated VM. Passive observation commands (ss) are read-only; do not port-scan machines you do not own, and do not leave demo services listening when the exercise ends.',
        es: 'Realiza el ejercicio únicamente en tu propia VM aislada. Los comandos de observación pasiva (ss) son de solo lectura; no escanees puertos de máquinas que no te pertenezcan y no dejes servicios de demostración en escucha al terminar el ejercicio.',
      },
    },
    references: [
      { label: 'MITRE ATT&CK — Network Service Discovery (T1046)', url: 'https://attack.mitre.org/techniques/T1046/' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0301'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 8. apparmor-mandatory-access-control
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'apparmor-mandatory-access-control',
    title: {
      en: 'AppArmor: mandatory access control on Linux',
      es: 'AppArmor: control de acceso obligatorio en Linux',
    },
    summary: {
      en: 'AppArmor complements traditional file permissions with per-application mandatory access control profiles. This article explains the LSM mechanism, the enforce and complain modes, how to read aa-status, and why degrading it is a recognized attacker objective.',
      es: 'AppArmor complementa los permisos tradicionales de archivos con perfiles de control de acceso obligatorio por aplicación. Este artículo explica el mecanismo LSM, los modos enforce y complain, cómo leer aa-status, y por qué degradarlo es un objetivo reconocido del atacante.',
    },
    level: 'ADVANCED',
    category: 'OS_SECURITY',
    platforms: ['linux'],
    technicalDescription: {
      en: 'AppArmor is a Linux Security Module that mediates access to files, capabilities and network operations per program, through profiles loaded into the kernel. Unlike discretionary permissions (DAC), which the file owner controls, mandatory access control (MAC) decisions are enforced by policy that the process cannot relax, regardless of the account running it. Profiles operate in enforce mode, where violations are blocked and logged, or complain mode, where violations are only logged, which is the standard way to build a profile from observed behaviour. Debian and Ubuntu ship AppArmor enabled by default with profiles for common system binaries; aa-status summarizes how many profiles are loaded and how many processes run confined.',
      es: 'AppArmor es un módulo de seguridad de Linux (LSM) que media el acceso a archivos, capacidades y operaciones de red por programa, mediante perfiles cargados en el kernel. A diferencia de los permisos discrecionales (DAC), que controla el propietario del archivo, las decisiones de control de acceso obligatorio (MAC) las aplica una política que el proceso no puede relajar, con independencia de la cuenta que lo ejecute. Los perfiles operan en modo enforce, donde las violaciones se bloquean y registran, o en modo complain, donde solo se registran, que es la forma estándar de construir un perfil a partir del comportamiento observado. Debian y Ubuntu traen AppArmor habilitado por defecto con perfiles para binarios de sistema habituales; aa-status resume cuántos perfiles están cargados y cuántos procesos ejecutan confinados.',
    },
    rootCause: {
      en: 'AppArmor is frequently left as installed but underused: profiles remain in complain mode after initial testing, custom services run unconfined because nobody profiles them, and occasional application failures lead operators to unload the offending profile instead of correcting its rules. Because DAC permissions already appear to work, the additional layer is perceived as optional rather than as the barrier that contains the next exploit.',
      es: 'AppArmor con frecuencia queda instalado pero infrautilizado: los perfiles permanecen en modo complain tras las pruebas iniciales, los servicios personalizados ejecutan sin confinar porque nadie crea sus perfiles, y fallos puntuales de aplicaciones llevan a los operadores a descargar el perfil problemático en lugar de corregir sus reglas. Como los permisos DAC ya parecen funcionar, la capa adicional se percibe como opcional y no como la barrera que contiene el siguiente exploit.',
    },
    howItHappens: {
      en: 'When an application is exploited, its execution environment defines what the attacker inherits: a confined process with a tight profile limits file access, capability use and network reach to the profiled scope, containing the intrusion inside one service. Disabling or modifying those defenses is therefore a documented attacker objective — MITRE ATT&CK records it under T1562.001 (Impair Defenses: Disable or Modify Tools) — which is why the security state of AppArmor is itself a monitored property and not a one-time setup.',
      es: 'Cuando una aplicación es explotada, su entorno de ejecución define qué hereda el atacante: un proceso confinado con un perfil ajustado limita el acceso a archivos, el uso de capacidades y el alcance de red al ámbito perfilado, conteniendo la intrusión dentro de un servicio. Deshabilitar o modificar esas defensas es por tanto un objetivo de atacante documentado — MITRE ATT&CK lo registra bajo T1562.001 (Impair Defenses: Disable or Modify Tools) — razón por la cual el estado de seguridad de AppArmor es en sí mismo una propiedad monitorizada y no una configuración de una sola vez.',
    },
    threatContext: {
      en: 'In the defense-in-depth stack, AppArmor is the layer that assumes a component will eventually be compromised and limits what that compromise can touch. It materially changes exploit outcomes: remote code execution in a profiled daemon, for example, cannot read arbitrary paths or use capabilities the profile does not grant. Hardened baselines such as the CIS benchmarks require the framework to be enabled, intact and enforced for exposed services, and treat profile removal as a configuration finding.',
      es: 'En la pila de defensa en profundidad, AppArmor es la capa que asume que algún componente acabará siendo comprometido y limita qué puede tocar ese compromiso. Cambia materialmente el resultado de un exploit: la ejecución remota de código en un demonio perfilado, por ejemplo, no puede leer rutas arbitrarias ni usar capacidades que el perfil no concede. Las líneas base endurecidas como las referencias CIS exigen que el marco esté habilitado, íntegro y en modo obligatorio para los servicios expuestos, y tratan la eliminación de perfiles como un hallazgo de configuración.',
    },
    mitre: [{ id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Signals include the apparmor LSM not active in the kernel configuration, profiles unloaded that the distribution ships by default, custom or exposed services reported as unconfined by aa-status, profiles left in complain mode long after their tuning period, and kernel log lines reporting DENIED operations that reveal rules too tight or someone testing the boundaries. Boot parameters removing security=apparmor are a direct impairment indicator.',
      es: 'Las señales incluyen el LSM apparmor no activo en la configuración del kernel, perfiles descargados que la distribución trae por defecto, servicios personalizados o expuestos reportados como sin confinar por aa-status, perfiles abandonados en modo complain mucho después de su periodo de ajuste, y líneas del registro del kernel con operaciones DENIED que revelan reglas demasiado ajustadas o alguien probando los límites. Parámetros de arranque que eliminan security=apparmor son un indicador directo de degradación.',
    },
    detection: {
      en: 'Check the framework state with aa-status, which reports loaded profiles, their modes and the confined process list without modifying anything. Verify kernel boot parameters retain apparmor=1 security=apparmor, confirm the profiles directory (/etc/apparmor.d) matches what the distribution and configuration management define, and review audit logs for DENIED entries correlated with services that recently changed behaviour.',
      es: 'Comprueba el estado del marco con aa-status, que informa de los perfiles cargados, sus modos y la lista de procesos confinados sin modificar nada. Verifica que los parámetros de arranque del kernel conservan apparmor=1 security=apparmor, confirma que el directorio de perfiles (/etc/apparmor.d) coincide con lo que definen la distribución y la gestión de configuración, y revisa los registros de auditoría en busca de entradas DENIED correlacionadas con servicios que cambiaron recientemente de comportamiento.',
    },
    prevention: {
      en: 'Keep the distribution-maintained profiles loaded and in enforce mode, profile custom services during development using complain mode and a bounded tuning window, and enforce them before production exposure. Guard the profiles under configuration management so unloading or editing them requires a reviewed change, and include AppArmor state in service acceptance checklists. Avoid removing profiles as a troubleshooting shortcut; adjust rules based on logged denials instead.',
      es: 'Mantén los perfiles mantenidos por la distribución cargados y en modo enforce, perfila los servicios personalizados durante el desarrollo usando el modo complain con una ventana de ajuste acotada, y aplícalos en modo obligatorio antes de la exposición en producción. Protege los perfiles bajo gestión de configuración para que descargarlos o editarlos exija un cambio revisado, e incluye el estado de AppArmor en las listas de aceptación de servicios. Evita eliminar perfiles como atajo de diagnóstico; ajusta las reglas a partir de las denegaciones registradas.',
    },
    mitigation: {
      en: 'If AppArmor was found impaired — inactive LSM, missing profiles or services switched to complain — restore the framework first (boot parameters, systemd services) and then reload the expected profile set. Review logs for the impairment period to determine what ran unconfined, tighten any profile that recorded unexpected DENIED activity, and re-run aa-status to confirm the restored baseline. Treat unexplained profile edits as a security event, not a configuration fix.',
      es: 'Si se encontró AppArmor degradado — LSM inactivo, perfiles ausentes o servicios pasados a complain — restaura primero el marco (parámetros de arranque, servicios systemd) y después recarga el conjunto de perfiles esperado. Revisa los registros del periodo de degradación para determinar qué se ejecutó sin confinar, ajusta cualquier perfil que registrara actividad DENIED inesperada y vuelve a ejecutar aa-status para confirmar la línea base restaurada. Trata las ediciones de perfiles inexplicadas como un evento de seguridad, no como un arreglo de configuración.',
    },
    verification: {
      en: 'Verification is read-only: aa-status must report the LSM enabled, a nonzero set of loaded profiles in enforce mode, and your exposed services listed among confined processes. Confirm the persisted state too — the apparmor systemd units enabled and the profile files present — so the state survives reboots. Repeat after kernel upgrades, which can change the active LSM set.',
      es: 'La verificación es de solo lectura: aa-status debe informar del LSM habilitado, un conjunto no vacío de perfiles cargados en modo enforce y tus servicios expuestos entre los procesos confinados. Confirma también el estado persistido — las unidades systemd de apparmor habilitadas y los archivos de perfil presentes — para que el estado sobreviva a los reinicios. Repite tras las actualizaciones del kernel, que pueden cambiar el conjunto de LSM activos.',
    },
    references: [
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'MITRE ATT&CK — Impair Defenses: Disable or Modify Tools (T1562.001)', url: 'https://attack.mitre.org/techniques/T1562/001/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0502'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 9. luks-disk-encryption
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'luks-disk-encryption',
    title: {
      en: 'LUKS disk encryption: protecting data at rest',
      es: 'Cifrado de disco con LUKS: protección de datos en reposo',
    },
    summary: {
      en: 'LUKS encrypts block devices so that data at rest is unreadable without the passphrase, protecting disks and laptops against offline access. This article explains the LUKS model, the crypttab mechanism, its operational requirements and its honest limitations.',
      es: 'LUKS cifra dispositivos de bloque de modo que los datos en reposo sean ilegibles sin la frase de paso, protegiendo discos y portátiles frente al acceso sin conexión. Este artículo explica el modelo LUKS, el mecanismo de crypttab, sus requisitos operativos y sus limitaciones honestas.',
    },
    level: 'INTERMEDIATE',
    category: 'ENCRYPTION',
    platforms: ['linux'],
    technicalDescription: {
      en: 'LUKS (Linux Unified Key Setup) manages full-disk encryption on top of the kernel device-mapper (dm-crypt): the volume stores encrypted key slots protected by a passphrase or keyfile, and the kernel presents the decrypted device once a slot is unlocked at boot or on demand. Volumes are declared in /etc/crypttab, which pairs the mapper name with the backing device and options such as luks or discard, and the resulting /dev/mapper/<name> is mounted through /etc/fstab. cryptsetup is the administrative tool: luksDump inspects headers read-only, luksAddKey manages slots, and luksHeaderBackup saves the critical header that would otherwise be unrecoverable if damaged.',
      es: 'LUKS (Linux Unified Key Setup) gestiona el cifrado de disco completo sobre el device-mapper del kernel (dm-crypt): el volumen almacena ranuras de claves cifradas protegidas por una frase de paso o un archivo de clave, y el kernel presenta el dispositivo descifrado una vez que una ranura se desbloquea en el arranque o bajo demanda. Los volúmenes se declaran en /etc/crypttab, que empareja el nombre del mapper con el dispositivo soporte y opciones como luks o discard, y el /dev/mapper/<nombre> resultante se monta mediante /etc/fstab. cryptsetup es la herramienta administrativa: luksDump inspecciona cabeceras en modo lectura, luksAddKey gestiona las ranuras y luksHeaderBackup guarda la cabecera crítica, que de otro modo sería irrecuperable si se daña.',
    },
    rootCause: {
      en: 'Encryption at rest is often deferred because it requires reinstallation or careful migration of existing volumes, complicates unattended boots (someone or something must supply the secret), and its benefit is invisible until a device is lost or decommissioned. Hosts that never leave a datacenter are the ones most often left unencrypted, even though decommissioning, repairs and disposal are exactly the moments when disks change hands.',
      es: 'El cifrado en reposo suele aplazarse porque exige reinstalación o una migración cuidadosa de los volúmenes existentes, complica los arranques desatendidos (alguien o algo debe suministrar el secreto) y su beneficio es invisible hasta que se pierde o se da de baja un dispositivo. Los hosts que nunca salen del centro de datos son los que más a menudo quedan sin cifrar, aunque la baja, las reparaciones y el desguace son justo los momentos en que los discos cambian de manos.',
    },
    howItHappens: {
      en: 'Without encryption at rest, physical possession of the storage equals possession of the data: a lost laptop, a stolen drive, a decommissioned server sold without sanitization, or a maintenance technician servicing a disk all expose filesystems directly. Snapshots, backups and swap devices inherit the same exposure, which is why swap is typically encrypted together with the data volumes. MITRE ATT&CK does not require a technique number for this scenario: the data is simply readable, and CWE-311 (missing encryption of sensitive data) classifies the underlying weakness of leaving it in cleartext.',
      es: 'Sin cifrado en reposo, la posesión física del almacenamiento equivale a la posesión de los datos: un portátil perdido, un disco robado, un servidor de baja vendido sin higienización o un técnico que lleva un disco a reparación exponen los sistemas de archivos directamente. Las instantáneas, las copias de seguridad y los dispositivos de intercambio (swap) heredan la misma exposición, razón por la que el swap suele cifrarse junto con los volúmenes de datos. MITRE ATT&CK no requiere un número de técnica para este escenario: los datos simplemente son legibles, y CWE-311 (ausencia de cifrado de datos sensibles) clasifica la debilidad subyacente de dejarlos en claro.',
    },
    threatContext: {
      en: 'LUKS addresses the offline threat model: an attacker with the device but without the passphrase cannot read the volume, even with full filesystem access after boot is irrelevant here — the protection targets the unpowered or removed disk. It does not defend the running system, where the unlocked volume is visible to root and to any process with its privileges; that runtime boundary belongs to access controls, mandatory access control and logging. NIST encryption guidance and the CIS benchmarks place encryption at rest among the baseline data protection controls for laptops and portable media first, and server volumes wherever physical access is not fully controlled.',
      es: 'LUKS responde al modelo de amenaza sin conexión: un atacante con el dispositivo pero sin la frase de paso no puede leer el volumen, incluso con acceso completo al sistema de archivos tras el arranque — aquí irrelevante — la protección apunta al disco apagado o extraído. No defiende al sistema en ejecución, donde el volumen desbloqueado es visible para root y para cualquier proceso con sus privilegios; ese límite en ejecución corresponde a los controles de acceso, al control de acceso obligatorio y al registro. La guía de cifrado de NIST y las referencias CIS sitúan el cifrado en reposo entre los controles básicos de protección de datos, primero para portátiles y medios portátiles, y para volúmenes de servidor dondequiera que el acceso físico no esté totalmente controlado.',
    },
    mitre: [],
    cve: [],
    cwe: ['CWE-311'],
    indicators: {
      en: 'Observable indicators include block devices without a LUKS signature (cryptsetup isLuks returns false for data volumes), an absent or empty /etc/crypttab, no dm-crypt mapper entries in lsblk, and unencrypted swap devices. For portables and removable media, the absence of any encrypted volume is itself the finding.',
      es: 'Los indicadores observables incluyen dispositivos de bloque sin firma LUKS (cryptsetup isLuks devuelve falso para los volúmenes de datos), un /etc/crypttab ausente o vacío, sin entradas de mapper dm-crypt en lsblk, y dispositivos de intercambio sin cifrar. Para portátiles y medios extraíbles, la ausencia de cualquier volumen cifrado es en sí misma el hallazgo.',
    },
    detection: {
      en: 'The inventory is read-only: list devices with lsblk --fs, test for LUKS signatures with cryptsetup isLuks per data device, and read /etc/crypttab plus /etc/fstab to understand what would be unlocked at boot. Identify swap devices (cat /proc/swaps) and verify whether they are mapped through encryption. The scan engine records crypttabExists and cryptsetupInstalled as evidence for this control family.',
      es: 'El inventario es de solo lectura: lista los dispositivos con lsblk --fs, comprueba las firmas LUKS con cryptsetup isLuks en cada dispositivo de datos, y lee /etc/crypttab junto con /etc/fstab para entender qué se desbloquearía en el arranque. Identifica los dispositivos de intercambio (cat /proc/swaps) y verifica si están mapeados a través del cifrado. El motor de escaneo registra crypttabExists y cryptsetupInstalled como evidencia para esta familia de controles.',
    },
    prevention: {
      en: 'Encrypt data volumes at provisioning time — the cost is trivial on new installations and high on migrations — enable encrypted swap, and protect boot integrity with the appropriate mechanism for your platform. Back up LUKS headers to secure storage after every slot change, store passphrases under the same protection level as the data, and document the unlock procedure for recovery scenarios. For unattended hosts, evaluate keyfile handling and network-bound disk encryption according to your threat model.',
      es: 'Cifra los volúmenes de datos en el aprovisionamiento — el coste es trivial en instalaciones nuevas y alto en migraciones — habilita un swap cifrado y protege la integridad de arranque con el mecanismo apropiado para tu plataforma. Haz copia de seguridad de las cabeceras LUKS en almacenamiento seguro tras cada cambio de ranuras, almacena las frases de paso con el mismo nivel de protección que los datos y documenta el procedimiento de desbloqueo para escenarios de recuperación. Para hosts desatendidos, evalúa la gestión de keyfiles y el cifrado de disco ligado a red según tu modelo de amenaza.',
    },
    mitigation: {
      en: 'If an unencrypted volume holding sensitive data is discovered, plan the migration to a LUKS volume with a maintenance window and verified backups, treating the transition as a data operation rather than a configuration tweak. For devices already lost or decommissioned unencrypted, treat the data as exposed: rotate credentials stored on them and confirm the exposure scope. Keep header backups current, because a corrupted header without backup renders the volume permanently unreadable — the mitigation must not create a worse loss than the threat it addresses.',
      es: 'Si se descubre un volumen sin cifrar que contiene datos sensibles, planifica la migración a un volumen LUKS con una ventana de mantenimiento y copias de seguridad verificadas, tratando la transición como una operación de datos y no como un ajuste de configuración. Para dispositivos ya perdidos o dados de baja sin cifrar, trata los datos como expuestos: rota las credenciales almacenadas en ellos y confirma el alcance de la exposición. Mantén las copias de cabecera al día, porque una cabecera dañada sin copia vuelve el volumen ilegible de forma permanente — la mitigación no debe crear una pérdida peor que la amenaza que resuelve.',
    },
    verification: {
      en: 'Verify with read-only commands: cryptsetup isLuks on each data device, cryptsetup luksDump on encrypted volumes to confirm version and slot configuration, crypttab and fstab coherence, and an encrypted swap entry in /proc/swaps. Confirm the header backup files exist where your procedure defines them, and that the unlock path was tested from an actual reboot, not only from the running system.',
      es: 'Verifica con comandos de solo lectura: cryptsetup isLuks en cada dispositivo de datos, cryptsetup luksDump en los volúmenes cifrados para confirmar la versión y la configuración de ranuras, la coherencia de crypttab y fstab, y una entrada de intercambio cifrado en /proc/swaps. Confirma que los archivos de copia de cabecera existen donde tu procedimiento los define, y que la vía de desbloqueo se probó desde un reinicio real, no solo desde el sistema en ejecución.',
    },
    secureConfigExample: {
      label: 'crypttab y fstab — volumen LUKS desbloqueado en el arranque',
      language: 'ini',
      code: `# /etc/crypttab — volumen cifrado desbloqueado al arranque con frase de paso
data  UUID=<uuid-del-volumen-luks>  none  luks,discard

# /etc/fstab — montaje del dispositivo descifrado resultante
# /dev/mapper/data  /data  ext4  defaults  0  2

# Inspección de solo lectura (sin desbloquear nada):
#   cryptsetup isLuks /dev/<dispositivo> && echo "LUKS presente"
#   cryptsetup luksDump /dev/<dispositivo>
#   lsblk --fs`,
    },
    references: [
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'NIST Cybersecurity', url: 'https://www.nist.gov/cybersecurity' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0601'],
    reviewedAt: '2026-11-13',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // 10. endpoint-protection-linux
  // ─────────────────────────────────────────────────────────────────────────────
  {
    slug: 'endpoint-protection-linux',
    title: {
      en: 'Endpoint protection on Linux: ClamAV and defense in depth',
      es: 'Protección de punto final en Linux: ClamAV y defensa en profundidad',
    },
    summary: {
      en: 'Linux systems are not exempt from malware, and on-demand scanning with ClamAV adds a detection layer that complements hardening and patching. This article explains what antivirus can and cannot do on Linux and where it fits in a defense-in-depth design.',
      es: 'Los sistemas Linux no están exentos de malware, y el análisis bajo demanda con ClamAV añade una capa de detección que complementa el endurecimiento y el parcheado. Este artículo explica qué puede y qué no puede hacer un antivirus en Linux y dónde encaja en un diseño de defensa en profundidad.',
    },
    level: 'BEGINNER',
    category: 'ENDPOINT_PROTECTION',
    platforms: ['linux'],
    technicalDescription: {
      en: 'ClamAV is the reference open-source antivirus engine on Linux: it combines signature databases with heuristic analysis and is updated through freshclam. On servers it typically runs as on-demand scans (clamscan over directories or clamdscan against a running daemon) rather than as a resident interceptor, which keeps the performance profile predictable. Its strongest role on Linux hosts is detecting cross-platform threats — Windows malware relayed through a Linux server, web shells uploaded to application directories, and droppers for cryptominers or botnet agents — where the Linux host acts as storage or transit rather than final payload host.',
      es: 'ClamAV es el motor antivirus de referencia de código abierto en Linux: combina bases de firmas con análisis heurístico y se actualiza mediante freshclam. En servidores funciona típicamente como análisis bajo demanda (clamscan sobre directorios o clamdscan contra un demonio en ejecución) en lugar de como interceptor residente, lo que mantiene un perfil de rendimiento predecible. Su papel más fuerte en hosts Linux es detectar amenazas multiplataforma — malware de Windows retransmitido por un servidor Linux, web shells subidos a directorios de aplicaciones y droppers de mineros de criptomonedas o agentes de botnet — casos en los que el host Linux actúa como almacén o tránsito en lugar de host final del payload.',
    },
    rootCause: {
      en: 'The absence of endpoint protection on Linux is often justified by the statement that Linux malware does not exist, which conflates lower prevalence with zero risk. Budget and attention then go entirely to hardening, and detection capability is left out of the design. The result is a host that resists automated compromise but would never notice a manual intrusion, a malicious upload, or a file serving as a malware relay for other platforms.',
      es: 'La ausencia de protección de punto final en Linux suele justificarse con la afirmación de que el malware para Linux no existe, lo que confunde menor prevalencia con riesgo nulo. El presupuesto y la atención van entonces íntegramente al endurecimiento, y la capacidad de detección queda fuera del diseño. El resultado es un host que resiste el compromiso automatizado pero que nunca notaría una intrusión manual, una subida maliciosa o un archivo que actúa como repetidor de malware para otras plataformas.',
    },
    howItHappens: {
      en: 'Client-side exploitation — the class MITRE ATT&CK records as T1203 (Exploitation for Client Execution) — remains relevant on servers through files that will be opened or processed later: documents uploaded for conversion, attachments relayed through mail services, or archives staged in download directories. A signature-based scanner is not a complete defense against these flows, but it converts an unnoticed malware deposit into a logged detection event with a file path, which is exactly the artifact an incident response process needs to start.',
      es: 'La explotación del lado del cliente — la clase que MITRE ATT&CK registra como T1203 (Exploitation for Client Execution) — sigue siendo relevante en servidores a través de archivos que se abrirán o procesarán después: documentos subidos para conversión, adjuntos retransmitidos por servicios de correo o archivos comprimidos depositados en directorios de descarga. Un analizador basado en firmas no es una defensa completa contra estos flujos, pero convierte un depósito de malware inadvertido en un evento de detección registrado con una ruta de archivo, que es justo el artefacto que un proceso de respuesta a incidentes necesita para comenzar.',
    },
    threatContext: {
      en: 'Endpoint protection is the detection layer of defense in depth, not the primary prevention: hardening, patching, least privilege and mandatory access control reduce the probability of compromise, while antivirus and logging reduce the time a compromise stays unnoticed. Signature coverage lags new threats by definition, and heuristic detection produces false positives, so the value of the layer depends on operationally sane handling — updated definitions, scheduled scans of the right directories, and a triage path for detections. NIST incident handling guidance and the CIS benchmarks treat malware detection as a baseline capability regardless of operating system.',
      es: 'La protección de punto final es la capa de detección de la defensa en profundidad, no la prevención primaria: el endurecimiento, el parcheado, el menor privilegio y el control de acceso obligatorio reducen la probabilidad de compromiso, mientras que el antivirus y el registro reducen el tiempo que un compromiso pasa inadvertido. La cobertura de firmas va por detrás de las nuevas amenazas por definición, y la detección heurística produce falsos positivos, de modo que el valor de la capa depende de una operación sensata — definiciones actualizadas, análisis programados de los directorios adecuados y una vía de triaje para las detecciones. La guía de gestión de incidentes de NIST y las referencias CIS tratan la detección de malware como una capacidad básica con independencia del sistema operativo.',
    },
    mitre: [{ id: 'T1203', name: 'Exploitation for Client Execution' }],
    cve: [],
    cwe: [],
    indicators: {
      en: 'Observable indicators include ClamAV not installed on hosts that handle untrusted files, a stale signature database (freshclam logs showing failed or long-absent updates), no scan activity recorded in logs, and quarantine directories that nobody reviews. At the system level, unexplained CPU or network consumption consistent with cryptomining, and new executables in world-writable paths, are signs that warrant a targeted scan.',
      es: 'Los indicadores observables incluyen ClamAV sin instalar en hosts que manejan archivos no confiables, una base de firmas obsoleta (registros de freshclam con actualizaciones fallidas o muy antiguas), ausencia de actividad de análisis registrada, y directorios de cuarentena que nadie revisa. A nivel de sistema, un consumo de CPU o de red inexplicado coherente con criptominado, y ejecutables nuevos en rutas escribibles por todos, son señales que justifican un análisis dirigido.',
    },
    detection: {
      en: 'Confirm installation with dpkg-query, the daemon state with systemctl status clamav-freshclam, and the database age with the freshclam logs or the daily.cld timestamp. Scheduled scans should cover the directories where untrusted files land — upload areas, mail spools, temporary directories — and their output should be shipped to wherever detections are triaged. Treat the scanner itself as part of the attack surface: keep it updated and monitor its daemon for abnormal behaviour.',
      es: 'Confirma la instalación con dpkg-query, el estado del demonio con systemctl status clamav-freshclam, y la antigüedad de la base con los registros de freshclam o la marca de tiempo de daily.cld. Los análisis programados deben cubrir los directorios donde aterrizan los archivos no confiables — áreas de subida, colas de correo, directorios temporales — y su salida debe enviarse a donde se traten las detecciones. Trata el propio analizador como parte de la superficie de ataque: manténlo actualizado y monitoriza su demonio por comportamientos anómalos.',
    },
    prevention: {
      en: 'Install ClamAV from the distribution repositories, enable freshclam so signatures update automatically, and schedule on-demand scans of the relevant directories instead of pretending a single full-filesystem sweep is a strategy. Define in advance what happens on a detection: quarantine, alert, and review — otherwise findings pile up without consequence. Keep the layer proportional: on a hardened server it complements the existing controls and fills the detection gap, on a workstation it is one of several mandatory layers.',
      es: 'Instala ClamAV desde los repositorios de la distribución, habilita freshclam para que las firmas se actualicen automáticamente y programa análisis bajo demanda de los directorios relevantes en lugar de pretender que un único barrido completo del sistema sea una estrategia. Define de antemano qué ocurre ante una detección: cuarentena, alerta y revisión — de lo contrario los hallazgos se acumulan sin consecuencia. Mantén la capa proporcional: en un servidor endurecido complementa los controles existentes y cubre el vacío de detección; en una estación de trabajo es una de varias capas obligatorias.',
    },
    mitigation: {
      en: 'On a positive detection, quarantine the file first to stop further handling, record its hashes and path, and investigate how it arrived before deleting it — the arrival path is usually a more valuable finding than the file itself. Update definitions and rescan the host and adjacent storage to bound the deposit, and review the service that accepted the file so the intake path is hardened. Document the incident handling so the triage path works the next time without improvisation.',
      es: 'Ante una detección positiva, pon primero el archivo en cuarentena para evitar más manipulación, registra sus hashes y su ruta, e investiga cómo llegó antes de borrarlo — la vía de llegada suele ser un hallazgo más valioso que el propio archivo. Actualiza las definiciones y reanaliza el host y el almacenamiento adyacente para acotar el depósito, y revisa el servicio que aceptó el archivo para endurecer la vía de entrada. Documenta la gestión del incidente para que la vía de triaje funcione la próxima vez sin improvisación.',
    },
    verification: {
      en: 'Verify read-only that the package is installed, freshclam runs on schedule, the signature database is current (days old, not months), and recent scan logs exist with meaningful coverage. Confirm that detections would actually reach a human: a scanner that writes to a log nobody reads provides no detection value. Re-verify after distribution upgrades, which can disable auxiliary units.',
      es: 'Verifica de forma pasiva que el paquete está instalado, que freshclam se ejecuta según lo programado, que la base de firmas está al día (con una antigüedad de días, no de meses) y que existen registros recientes de análisis con cobertura significativa. Confirma que las detecciones llegarían realmente a una persona: un analizador que escribe en un registro que nadie lee no aporta valor de detección. Verifica de nuevo tras las actualizaciones de la distribución, que pueden deshabilitar unidades auxiliares.',
    },
    references: [
      { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/' },
      { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/' },
      { label: 'MITRE ATT&CK — Exploitation for Client Execution (T1203)', url: 'https://attack.mitre.org/techniques/T1203/' },
      { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks' },
    ],
    relatedControls: ['VC-LNX-0501'],
    reviewedAt: '2026-11-13',
  },
]
