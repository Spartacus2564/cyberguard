// ═══════════════════════════════════════════════════════════════════════════════
// NMAP OUTPUT PARSER — Converts raw nmap output to NormalizedFindings
// ═══════════════════════════════════════════════════════════════════════════════

import { ToolOutput, NormalizedFinding } from '../types';
import { Severity } from '../../types';

const PORT_SERVICE_MAP: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  80: 'http', 88: 'kerberos', 110: 'pop3', 135: 'msrpc',
  139: 'netbios', 143: 'imap', 389: 'ldap', 443: 'https',
  445: 'smb', 464: 'kpasswd', 587: 'submission', 636: 'ldaps',
  993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql',
  3389: 'rdp', 5432: 'postgresql', 5985: 'winrm', 5986: 'winrm-ssl',
  6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
  9200: 'elasticsearch', 27017: 'mongodb',
};

const HIGH_RISK_SERVICES = new Set(['telnet', 'ftp', 'vnc', 'ms-wbt-server', 'rlogin']);
const MEDIUM_RISK_SERVICES = new Set(['telnet', 'netbios', 'msrpc']);

export default function parseNmap(output: ToolOutput): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const lines = output.stdout.split('\n');

  let currentPort = '';
  let currentService = '';
  let currentVersion = '';

  for (const line of lines) {
    // Port line: "80/tcp open http Apache/2.4.41"
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
    if (portMatch) {
      const [, port, protocol, service, version] = portMatch;
      currentPort = port;
      currentService = service;
      currentVersion = version.trim();

      // Generate finding for high-risk services
      const serviceLower = service.toLowerCase();
      if (HIGH_RISK_SERVICES.has(serviceLower)) {
        findings.push({
          title: `High-Risk Service Exposed: ${service} (port ${port}/${protocol})`,
          description: `${service} service is exposed on port ${port}/${protocol}${version ? ` running ${version}` : ''}. High-risk services can provide unauthorized remote access.`,
          severity: Severity.HIGH,
          category: 'Service Exposure',
          affectedAsset: `${output.target}:${port}`,
          evidence: line.trim(),
          impact: `Exposed ${service} service may allow unauthorized remote access or data exfiltration`,
          remediation: `Restrict ${service} access to authorized networks; disable if not needed`,
          references: [],
          toolName: 'nmap',
          toolOutput: line.trim(),
          validationStatus: 'DISCOVERED',
          confidence: 0.9,
        });
      }

      // Generate finding for medium-risk services
      if (MEDIUM_RISK_SERVICES.has(serviceLower) && !HIGH_RISK_SERVICES.has(serviceLower)) {
        findings.push({
          title: `Medium-Risk Service Exposed: ${service} (port ${port}/${protocol})`,
          description: `${service} service is exposed on port ${port}/${protocol}${version ? ` running ${version}` : ''}.`,
          severity: Severity.MEDIUM,
          category: 'Service Exposure',
          affectedAsset: `${output.target}:${port}`,
          evidence: line.trim(),
          impact: `Exposed ${service} service increases attack surface`,
          remediation: `Review if ${service} needs to be externally accessible; restrict with firewall`,
          references: [],
          toolName: 'nmap',
          toolOutput: line.trim(),
          validationStatus: 'DISCOVERED',
          confidence: 0.8,
        });
      }

      continue;
    }

    // NSE vulnerability output
    if (line.includes('VULNERABLE') || line.includes('CVE-')) {
      const cveMatch = line.match(/(CVE-\d{4}-\d+)/);
      const severity = line.includes('CRITICAL') || line.includes('HIGH')
        ? Severity.HIGH
        : line.includes('MEDIUM')
          ? Severity.MEDIUM
          : Severity.MEDIUM;

      findings.push({
        title: `Nmap Vulnerability Detection${cveMatch ? `: ${cveMatch[1]}` : ''} on port ${currentPort}`,
        description: line.trim(),
        severity,
        category: 'Vulnerability Detection',
        affectedAsset: `${output.target}:${currentPort}`,
        evidence: line.trim(),
        impact: 'Nmap NSE scripts detected a potential vulnerability',
        remediation: 'Investigate and patch the affected service',
        references: cveMatch ? [`https://nvd.nist.gov/vuln/detail/${cveMatch[1]}`] : [],
        toolName: 'nmap',
        toolOutput: line.trim(),
        validationStatus: 'DISCOVERED',
        confidence: 0.7,
      });
    }

    // SSL/TLS issues
    if (line.includes('SSL') && (line.includes('weak') || line.includes('vulnerable') || line.includes('grade'))) {
      findings.push({
        title: `SSL/TLS Configuration Issue on port ${currentPort}`,
        description: line.trim(),
        severity: Severity.MEDIUM,
        category: 'Cryptographic Issues',
        affectedAsset: `${output.target}:${currentPort}`,
        evidence: line.trim(),
        impact: 'Weak SSL/TLS configurations can allow man-in-the-middle attacks',
        remediation: 'Upgrade to TLS 1.3; disable weak cipher suites',
        references: ['https://ssl-config.mozilla.org/'],
        toolName: 'nmap',
        toolOutput: line.trim(),
        validationStatus: 'DISCOVERED',
        confidence: 0.8,
      });
    }

    // SMB signing not required
    if (line.includes('Message signing enabled but not required')) {
      findings.push({
        title: `SMB Signing Not Required on port ${currentPort}`,
        description: 'SMB message signing is enabled but not required, allowing relay attacks.',
        severity: Severity.HIGH,
        category: 'Service Exposure',
        affectedAsset: `${output.target}:${currentPort}`,
        evidence: line.trim(),
        impact: 'SMB relay attacks can intercept and modify SMB traffic',
        remediation: 'Require SMB signing via Group Policy',
        references: ['https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always'],
        toolName: 'nmap',
        toolOutput: line.trim(),
        validationStatus: 'DISCOVERED',
        confidence: 0.9,
      });
    }

    // OS detection
    const osMatch = line.match(/OS details?:\s*(.+)/i);
    if (osMatch) {
      findings.push({
        title: `Operating System Detected: ${osMatch[1].trim()}`,
        description: `Nmap OS fingerprinting identified: ${osMatch[1].trim()}`,
        severity: Severity.INFO,
        category: 'Information Disclosure',
        affectedAsset: output.target,
        evidence: line.trim(),
        impact: 'OS information helps attackers select platform-specific exploits',
        remediation: 'Use a CDN or reverse proxy to hide origin server details',
        references: [],
        toolName: 'nmap',
        toolOutput: line.trim(),
        validationStatus: 'DISCOVERED',
        confidence: 0.7,
      });
    }
  }

  return findings;
}
