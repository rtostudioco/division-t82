// DIVISION T82 — official documentary sources (master prompt §8.9)
export interface OfficialSource {
  label: string
  url: string
  kind: 'official' | 'standard' | 'vendor'
}

export const OFFICIAL_SOURCES: OfficialSource[] = [
  { label: 'MITRE ATT&CK', url: 'https://attack.mitre.org/', kind: 'standard' },
  { label: 'NIST Cybersecurity', url: 'https://www.nist.gov/cybersecurity', kind: 'standard' },
  { label: 'CISA', url: 'https://www.cisa.gov/', kind: 'official' },
  { label: 'Microsoft Learn — Windows Security', url: 'https://learn.microsoft.com/en-us/windows/security/', kind: 'vendor' },
  { label: 'Ubuntu Server Security', url: 'https://ubuntu.com/server/docs/how-to/security/', kind: 'vendor' },
  { label: 'Securing Debian Manual', url: 'https://www.debian.org/doc/manuals/securing-debian-manual/', kind: 'vendor' },
  { label: 'Apple Platform Security', url: 'https://support.apple.com/guide/security/welcome/web', kind: 'vendor' },
  { label: 'Apple Security Documentation', url: 'https://developer.apple.com/documentation/security', kind: 'vendor' },
  { label: 'OWASP Cheat Sheet Series', url: 'https://cheatsheetseries.owasp.org/', kind: 'standard' },
  { label: 'OpenSSH Documentation', url: 'https://www.openssh.com/manual.html', kind: 'official' },
  { label: 'CIS Benchmarks', url: 'https://www.cisecurity.org/cis-benchmarks', kind: 'standard' },
  { label: 'NIST NVD', url: 'https://nvd.nist.gov/', kind: 'official' },
  { label: 'CISA KEV', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', kind: 'official' },
]
