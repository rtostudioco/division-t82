# PLATFORM COMPATIBILITY MATRIX — DIVISION T82

## Por plataforma

| Plataforma | Estado | Colectores | Controles | Notas |
|---|---|---|---|---|
| Debian 13 (sandbox) | ✅ AUDITABLE (real) | read-only /proc,/etc,ss,dpkg,apt | 20 VC-LNX | sin root → `NOT_ASSESSED` donde aplica |
| Ubuntu LTS | ✅ Soportado por el mismo adaptador | idéntico | 20 VC-LNX | ufw presente típicamente → más controles puntuados |
| Debian estable | ✅ Soportado | idéntico | 20 VC-LNX | |
| Windows 10/11 | 🔶 DISEÑADO | WMI/CIM/PowerShell/registro (lectura) | 6 VC-WIN | requiere build Tauri/host Windows |
| macOS | 🔶 DISEÑADO | APIs Apple (FileVault, Gatekeeper, SIP, pf) | 6 VC-MAC | requiere build Tauri/host macOS |

## Controles Linux (VC-LNX) y privilegios

| ID | Control | Fuente | Requiere root? |
|---|---|---|---|
| VC-LNX-0101 | SSH: PermitRootLogin | /etc/ssh/sshd_config(.d) | No (lectura si existe) |
| VC-LNX-0102 | SSH: PasswordAuthentication | /etc/ssh/sshd_config(.d) | No |
| VC-LNX-0103 | Cuentas sin contraseña | /etc/shadow | **Sí** → NOT_ASSESSED si no root |
| VC-LNX-0104 | Cuentas UID 0 adicionales | /etc/passwd | No |
| VC-LNX-0105 | Política de aging (login.defs) | /etc/login.defs | No |
| VC-LNX-0106 | sudo NOPASSWD | /etc/sudoers(.d) | **Sí** → NOT_ASSESSED |
| VC-LNX-0201 | ASLR (randomize_va_space=2) | /proc/sys/kernel | No |
| VC-LNX-0202 | kptr_restrict ≥1 | /proc/sys/kernel | No |
| VC-LNX-0203 | suid_dumpable=0 | /proc/sys/fs | No |
| VC-LNX-0204 | Permisos de archivos sensibles | stat() | No |
| VC-LNX-0205 | unattended-upgrades habilitado | /etc/apt/apt.conf.d/* | No |
| VC-LNX-0206 | Actualizaciones pendientes | apt-get -s upgrade + frescura de lists | No |
| VC-LNX-0207 | OS soportada (Debian/Ubuntu) | /etc/os-release | No |
| VC-LNX-0301 | Listeners en 0.0.0.0/:: | ss -tulnH | No |
| VC-LNX-0302 | IPv4 forwarding (no-router) | /proc/sys/net/ipv4/ip_forward | No |
| VC-LNX-0303 | Firewall host presente/activo | ufw/nft/iptables + configs | No (estado binario/config) |
| VC-LNX-0401 | Servicios activos (systemd) | systemctl (si disponible) | No (→ NOT_ASSESSED si offline) |
| VC-LNX-0501 | Antimalware presente (clamav) | dpkg-query + binarios | No |
| VC-LNX-0502 | LSM/AppArmor activo | /sys/kernel/security/lsm, /sys/module/apparmor | No |
| VC-LNX-0601 | Cifrado de disco (LUKS) | /etc/crypttab, cryptsetup | No |

## Controles diseñados (no ejecutables en este entorno)

VC-WIN-0101 UAC · VC-WIN-0102 Defender real-time · VC-WIN-0103 Firewall profiles · VC-WIN-0104 BitLocker · VC-WIN-0105 Secure Boot/TPM · VC-WIN-0106 Updates activos
VC-MAC-0101 FileVault · VC-MAC-0102 Gatekeeper · VC-MAC-0103 SIP · VC-MAC-0104 Firewall · VC-MAC-0105 Updates · VC-MAC-0106 Administradores

## Limitaciones transversales declaradas

- Contenedor comparte kernel → sysctls/LSM pueden reflejar el host.
- `systemctl offline` → servicios `NOT_ASSESSED` (razón visible en UI).
- Caché APT vacía/antigua → control de parches `NOT_ASSESSED` (evita PASS falsos).
