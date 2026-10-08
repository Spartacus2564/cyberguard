import { exec } from 'child_process';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logExploit, logVuln, logInfo, logDone, logWarn } from '../scanLogger';
import { CVE_DATABASE } from '../cve/database';
import { getAI } from '../../services/ai.service';

const execAsync = promisify(exec);

function stripBinaryChars(str: string): string {
  // Remove non-printable characters except newlines and tabs
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
}

// Look up CVE in local database for proper description
function lookupCve(cveId: string): { title: string; description: string; cvss: number; severity: Severity; remediation: string; references: string[] } | null {
  const entry = CVE_DATABASE.find(e => e.id === cveId);
  if (entry) {
    return {
      title: `${cveId}: ${entry.title}`,
      description: entry.description,
      cvss: entry.cvss,
      severity: entry.severity as Severity,
      remediation: entry.remediation,
      references: entry.references,
    };
  }
  return null;
}

// Parse nmap vuln line into structured info
function parseNmapVulnLine(line: string): { cveId: string | null; service: string; rawInfo: string } {
  const cveMatch = line.match(/(CVE-\d{4}-\d+)/);
  // Nmap format: "State: VULNERABLE (Evidence: ...)" or "| CVE-2023-51385 6.5 https://..."
  const parts = line.split('|').map(p => p.trim()).filter(Boolean);
  const rawInfo = parts.length > 1 ? parts.slice(1).join(' | ') : line.trim();
  // Try to extract service name from context
  let service = 'unknown';
  const lower = line.toLowerCase();
  if (lower.includes('ssh') || lower.includes('openssh')) service = 'OpenSSH';
  else if (lower.includes('apache') || lower.includes('httpd')) service = 'Apache';
  else if (lower.includes('nginx')) service = 'Nginx';
  else if (lower.includes('iis')) service = 'IIS';
  else if (lower.includes('smb') || lower.includes('samba')) service = 'SMB';
  else if (lower.includes('ssl') || lower.includes('tls')) service = 'SSL/TLS';
  else if (lower.includes('ftp')) service = 'FTP';
  else if (lower.includes('smtp')) service = 'SMTP';
  else if (lower.includes('mysql')) service = 'MySQL';
  else if (lower.includes('postgres')) service = 'PostgreSQL';
  else if (lower.includes('redis')) service = 'Redis';
  else if (lower.includes('php')) service = 'PHP';
  else if (lower.includes('wordpress')) service = 'WordPress';
  else if (lower.includes('tomcat')) service = 'Tomcat';
  return { cveId: cveMatch?.[1] || null, service, rawInfo };
}

// ─── Tool Availability Check ──────────────────────────────────────────────────
async function checkTool(name: string): Promise<boolean> {
  try {
    await execAsync(`which ${name}`, { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function getAvailableTools(): Promise<Set<string>> {
  const toolNames = ['nmap', 'nikto', 'whatweb', 'nuclei', 'dirb'];
  const results = await Promise.all(toolNames.map(async (t) => ({ name: t, available: await checkTool(t) })));
  const available = new Set<string>();
  for (const r of results) {
    if (r.available) available.add(r.name);
  }
  return available;
}

// ─── Tool Runners ─────────────────────────────────────────────────────────────

async function runNmap(domain: string, findings: Finding[], errors: string[]): Promise<string> {
  const allOutput: string[] = [];
  try {
    // ── PHASE 1: Service Discovery — fast SYN scan on top 1000 ports ──
    logInfo('kaliTools', `[nmap] Phase 1: Service discovery on ${domain}`);
    const start1 = Date.now();
    const { stdout: discoveryOutput } = await execAsync(
      `nmap -sT -sV -T4 --top-ports 1000 --open -oN - ${domain}`,
      { timeout: 180000, maxBuffer: 10 * 1024 * 1024 }
    );
    const dur1 = Date.now() - start1;
    logDone('kaliTools', `nmap discovery completed in ${(dur1 / 1000).toFixed(1)}s`, dur1);
    allOutput.push(discoveryOutput);

    // Parse discovered open ports for phase 2
    const openPorts: string[] = [];
    const portLines = discoveryOutput.split('\n');
    for (const line of portLines) {
      const portMatch = line.match(/^(\d+\/\w+)\s+open\s+(\S+)\s*(.*)/);
      if (portMatch) {
        const [, port, service, version] = portMatch;
        openPorts.push(port);

        // Flag risky services
        const riskyServices = ['ftp', 'telnet', 'rlogin', 'rsh', 'vnc', 'X11', 'ms-wbt-server'];
        if (riskyServices.some(r => service.toLowerCase().includes(r))) {
          findings.push(generateFinding(
            `Exposed Risky Service: ${service}`,
            `Port ${port} is running ${service} ${version}, which is a high-risk service often associated with weak authentication or unencrypted communication.`,
            Severity.HIGH,
            'Service Exposure',
            domain,
            `Port: ${port}, Service: ${service}, Version: ${version}`,
            'Risky services can provide direct remote access or leak sensitive data',
            'Disable unnecessary services; use SSH tunneling instead of Telnet/VNC; restrict access with firewall rules',
            ['https://www.cisa.gov/news-events/cybersecurity-advisories']
          ));
          logVuln('kaliTools', `Exposed Risky Service: ${service}`, 'HIGH', `port=${port}`);
        }
      }
    }

    if (openPorts.length > 0) {
      findings.push(generateFinding(
        'Open Ports Detected',
        `Nmap found ${openPorts.length} open port(s): ${openPorts.slice(0, 15).join(', ')}${openPorts.length > 15 ? '...' : ''}`,
        openPorts.length > 10 ? Severity.MEDIUM : Severity.INFO,
        'Service Exposure',
        domain,
        `Open ports: ${openPorts.join('; ')}`,
        'Each open port increases the attack surface',
        'Close unnecessary ports; use firewall rules to restrict access',
        []
      ));
    }

    // ── PHASE 2: Vulnerability Scanning — run vuln scripts on discovered ports ──
    if (openPorts.length > 0) {
      logInfo('kaliTools', `[nmap] Phase 2: Vulnerability scanning on ${openPorts.length} open ports`);
      const start2 = Date.now();
      const portList = openPorts.map(p => p.split('/')[0]).join(',');
      const { stdout: vulnOutput } = await execAsync(
        `nmap -sV --script=vuln,ssl-enum-ciphers,ssl-heartbleed,ssh-vuln-cve2023-38408,ssh-vuln-cve2023-51385,ssh-vuln-cve2023-48795,ssh2-enum-algos -T4 -p ${portList} --open -oN - ${domain}`,
        { timeout: 300000, maxBuffer: 10 * 1024 * 1024 }
      );
      const dur2 = Date.now() - start2;
      logDone('kaliTools', `nmap vuln scan completed in ${(dur2 / 1000).toFixed(1)}s`, dur2);
      allOutput.push(vulnOutput);

      // Parse vulnerability findings
      const cleanedOutput = stripBinaryChars(vulnOutput);
      const vulnLines = cleanedOutput.split('\n');
      for (const line of vulnLines) {
        if (line.includes('VULNERABLE') || line.includes('CVE-')) {
          const { cveId, service, rawInfo } = parseNmapVulnLine(line);
          const existingCve = findings.find(f => cveId && f.evidence?.includes(cveId));
          if (existingCve) continue;

          // Look up CVE in local database for proper description
          const cveInfo = cveId ? lookupCve(cveId) : null;

          if (cveInfo) {
            // Use local database description
            findings.push(generateFinding(
              cveInfo.title,
              `${cveInfo.description}\n\nService: ${service}\nDetected by: Nmap vulnerability scripts`,
              cveInfo.severity,
              'Vulnerability Detection',
              domain,
              `CVE: ${cveId}\nService: ${service}\nRaw: ${rawInfo}\nCVSS: ${cveInfo.cvss}`,
              `Known vulnerability in ${service} — CVSS ${cveInfo.cvss}`,
              cveInfo.remediation,
              cveInfo.references
            ));
          } else {
            // No local data — use nmap info and let enrichment fetch from NVD
            const title = cveId
              ? `${cveId}: Vulnerability detected in ${service}`
              : `Vulnerability detected in ${service}`;
            findings.push(generateFinding(
              title,
              `Nmap vulnerability scripts detected a potential vulnerability in ${service}.\n\nCVE: ${cveId || 'Unknown'}\nDetails: ${rawInfo}\n\nThis vulnerability will be enriched with NVD data for full details.`,
              Severity.HIGH,
              'Vulnerability Detection',
              domain,
              `CVE: ${cveId || 'Unknown'}\nService: ${service}\nRaw nmap output: ${rawInfo}`,
              `Potential vulnerability in ${service} — requires investigation`,
              'Investigate and patch the affected service',
              cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`, 'https://vulners.com/cve/' + cveId] : []
            ));
          }
          logVuln('kaliTools', `Nmap vuln: ${cveId || 'Unknown'} on ${service}`, 'HIGH');
        }
        // SSL/TLS issues
        if (line.includes('SSL') && (line.includes('weak') || line.includes('vulnerable') || line.includes('grade'))) {
          findings.push(generateFinding(
            'SSL/TLS Configuration Issue',
            stripBinaryChars(line).trim(),
            Severity.MEDIUM,
            'TLS/HTTP',
            domain,
            stripBinaryChars(line).trim(),
            'Weak SSL/TLS configurations can allow man-in-the-middle attacks',
            'Upgrade to TLS 1.3; disable weak cipher suites',
            ['https://ssl-config.mozilla.org/']
          ));
        }
      }
    }

    // ── PHASE 3: Service-Specific Enumeration ──
    logInfo('kaliTools', `[nmap] Phase 3: Service enumeration`);
    const start3 = Date.now();

    // SMB enumeration
    const smbPorts = openPorts.filter(p => p.startsWith('445/') || p.startsWith('139/'));
    if (smbPorts.length > 0) {
      logInfo('kaliTools', `[nmap] Running SMB enumeration`);
      try {
        const { stdout: smbOutput } = await execAsync(
          `nmap --script=smb-enum-shares,smb-enum-users,smb-protocols,smb-security-mode,smb2-security-mode -p 445,139 -T4 ${domain}`,
          { timeout: 120000, maxBuffer: 5 * 1024 * 1024 }
        );
        allOutput.push(smbOutput);
        // Check for SMBv1
        if (smbOutput.includes('SMBv1')) {
          findings.push(generateFinding(
            'SMBv1 Protocol Enabled',
            'The target supports SMBv1, which is vulnerable to EternalBlue (MS17-010) and other attacks.',
            Severity.HIGH,
            'Service Exposure',
            domain,
            'SMBv1 detected on port 445',
            'SMBv1 is deprecated and vulnerable to ransomware attacks',
            'Disable SMBv1; use SMB2/3 only',
            ['https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-used-by-default']
          ));
        }
      } catch {}
    }

    // HTTP enumeration + vulnerability detection
    const httpPorts = openPorts.filter(p => p.startsWith('80/') || p.startsWith('443/') || p.startsWith('8080/') || p.startsWith('8443/'));
    if (httpPorts.length > 0) {
      logInfo('kaliTools', `[nmap] Running HTTP enumeration + vulnerability scripts`);
      try {
        const portList = httpPorts.map(p => p.split('/')[0]).join(',');
        const { stdout: httpOutput } = await execAsync(
          `nmap --script=http-enum,http-headers,http-methods,http-title,http-server-header,http-robots.txt,http-shellshock,http-vuln-cve2011-3368,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-5638,http-vuln-cve2017-5689,http-vuln-cve2018-0006,http-vuln-cve2019-0232,http-csrf,http-sql-injection,http-xssed,http-open-redirect,http-header-injection,http-splitting -p ${portList} -T4 ${domain}`,
          { timeout: 180000, maxBuffer: 10 * 1024 * 1024 }
        );
        allOutput.push(httpOutput);
        // Parse HTTP vulnerability findings
        const cleanedHttpOutput = stripBinaryChars(httpOutput);
        const httpLines = cleanedHttpOutput.split('\n');
        for (const line of httpLines) {
          if (line.includes('VULNERABLE') || line.includes('CVE-')) {
            const { cveId, service, rawInfo } = parseNmapVulnLine(line);
            const existingCve = findings.find(f => cveId && f.evidence?.includes(cveId));
            if (existingCve) continue;

            const cveInfo = cveId ? lookupCve(cveId) : null;
            const httpService = service === 'unknown' ? 'HTTP' : service;

            if (cveInfo) {
              findings.push(generateFinding(
                cveInfo.title,
                `${cveInfo.description}\n\nService: ${httpService}\nDetected by: Nmap HTTP scripts`,
                cveInfo.severity,
                'Web Application Vulnerability',
                domain,
                `CVE: ${cveId}\nService: ${httpService}\nRaw: ${rawInfo}\nCVSS: ${cveInfo.cvss}`,
                `Known vulnerability in ${httpService} — CVSS ${cveInfo.cvss}`,
                cveInfo.remediation,
                cveInfo.references
              ));
            } else {
              const title = line.split('|')[1]?.trim() || line.trim().substring(0, 80);
              findings.push(generateFinding(
                `HTTP Vulnerability: ${title}${cveId ? ` (${cveId})` : ''}`,
                `Nmap HTTP scripts detected a potential vulnerability in ${httpService}.\n\nCVE: ${cveId || 'Unknown'}\nDetails: ${rawInfo}\n\nThis vulnerability will be enriched with NVD data for full details.`,
                Severity.HIGH,
                'Web Application Vulnerability',
                domain,
                `CVE: ${cveId || 'Unknown'}\nService: ${httpService}\nRaw nmap output: ${rawInfo}`,
                `Potential vulnerability in ${httpService} — requires investigation`,
                'Investigate and patch the affected endpoint',
                cveId ? [`https://nvd.nist.gov/vuln/detail/${cveId}`] : []
              ));
            }
            logVuln('kaliTools', `HTTP vuln: ${cveId || 'Unknown'} on ${httpService}`, 'HIGH');
          }
          if (line.includes('http-shellshock') && line.includes('VULNERABLE')) {
            findings.push(generateFinding(
              'Shellshock (CVE-2014-6271) Detected',
              'The target is vulnerable to Shellshock via HTTP headers. This allows remote code execution through crafted User-Agent or other HTTP headers.',
              Severity.CRITICAL,
              'Web Application Vulnerability',
              domain,
              stripBinaryChars(line).trim(),
              'Shellshock enables unauthenticated remote code execution',
              'Patch Bash immediately; update all systems using Bash',
              ['https://nvd.nist.gov/vuln/detail/CVE-2014-6271']
            ));
          }
          if (line.includes('http-csrf') && !line.includes('NOT')) {
            findings.push(generateFinding(
              'CSRF Vulnerability Detected',
              stripBinaryChars(line).trim(),
              Severity.MEDIUM,
              'Web Application Vulnerability',
              domain,
              stripBinaryChars(line).trim(),
              'Cross-Site Request Forgery allows attackers to perform actions as authenticated users',
              'Implement CSRF tokens; use SameSite cookies; verify Origin headers',
              ['https://owasp.org/www-community/attacks/csrf']
            ));
          }
        }
      } catch {}
    }

    // SSL/TLS vulnerability detection
    const sslPorts = openPorts.filter(p => p.startsWith('443/') || p.startsWith('8443/'));
    if (sslPorts.length > 0) {
      logInfo('kaliTools', `[nmap] Running SSL/TLS vulnerability scripts`);
      try {
        const portList = sslPorts.map(p => p.split('/')[0]).join(',');
        const { stdout: sslOutput } = await execAsync(
          `nmap --script=ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params,ssl-enum-ciphers,ssl-known-key,ssl-cert,ssl-dh-groups,ssl-dsa-known-key,ssl-rc4 -p ${portList} -T4 ${domain}`,
          { timeout: 120000, maxBuffer: 5 * 1024 * 1024 }
        );
        allOutput.push(sslOutput);
        // Parse SSL/TLS findings
        const cleanedSslOutput = stripBinaryChars(sslOutput);
        const sslLines = cleanedSslOutput.split('\n');
        for (const line of sslLines) {
          if (line.includes('VULNERABLE') || line.includes('CVE-')) {
            const cveMatch = line.match(/(CVE-\d{4}-\d+)/);
            const existingCve = findings.find(f => cveMatch && f.evidence?.includes(cveMatch[1]));
            if (existingCve) continue;
            const title = line.split('|')[1]?.trim() || line.trim().substring(0, 80);
            findings.push(generateFinding(
              `SSL/TLS Vulnerability: ${title}${cveMatch ? ` (${cveMatch[1]})` : ''}`,
              stripBinaryChars(line).trim(),
              cveMatch?.[1] === 'CVE-2014-0160' ? Severity.CRITICAL : Severity.HIGH,
              'Cryptographic Issues',
              domain,
              stripBinaryChars(line).trim(),
              'SSL/TLS vulnerabilities can allow man-in-the-middle attacks and data interception',
              'Update TLS configuration; disable vulnerable protocols and ciphers',
              cveMatch ? [`https://nvd.nist.gov/vuln/detail/${cveMatch[1]}`] : ['https://ssl-config.mozilla.org/']
            ));
            logVuln('kaliTools', `SSL/TLS: ${title.substring(0, 60)}`, 'HIGH');
          }
          if (line.includes('ssl-heartbleed') && line.includes('VULNERABLE')) {
            findings.push(generateFinding(
              'Heartbleed (CVE-2014-0160) Detected',
              'The target is vulnerable to Heartbleed, allowing attackers to read sensitive data from server memory including private keys and session tokens.',
              Severity.CRITICAL,
              'Cryptographic Issues',
              domain,
              stripBinaryChars(line).trim(),
              'Heartbleed can leak private keys, session tokens, and user credentials',
              'Patch OpenSSL immediately; revoke and regenerate all SSL certificates',
              ['https://nvd.nist.gov/vuln/detail/CVE-2014-0160', 'https://heartbleed.com/']
            ));
          }
          if (line.includes('ssl-rc4') && line.includes('VULNERABLE')) {
            findings.push(generateFinding(
              'RC4 Cipher Suite Detected',
              'The server supports RC4 ciphers which are cryptographically broken and can be exploited to recover plaintext.',
              Severity.HIGH,
              'Cryptographic Issues',
              domain,
              stripBinaryChars(line).trim(),
              'RC4 biases allow plaintext recovery within hours',
              'Disable RC4 ciphers; use AES-GCM or ChaCha20-Poly1305',
              ['https://datatracker.ietf.org/doc/html/rfc7465']
            ));
          }
        }
      } catch {}
    }

    // SSH enumeration + CVE detection
    const sshPorts = openPorts.filter(p => p.startsWith('22/'));
    if (sshPorts.length > 0) {
      logInfo('kaliTools', `[nmap] Running SSH enumeration + CVE detection`);
      try {
        const { stdout: sshOutput } = await execAsync(
          `nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-vuln-cve2023-38408,ssh-vuln-cve2023-51385,ssh-vuln-cve2023-48795 -p 22 -T4 -sV ${domain}`,
          { timeout: 120000, maxBuffer: 5 * 1024 * 1024 }
        );
        allOutput.push(sshOutput);

        // Parse SSH version from banner
        const versionMatch = sshOutput.match(/OpenSSH[_ ](\d+)\.(\d+)(?:p(\d+))?/i)
          || sshOutput.match(/SSH[_-][\d.]+-OpenSSH[_ ](\d+)\.(\d+)(?:p(\d+))?/i);
        let majorVer = 0, minorVer = 0, patchLevel = 0;
        if (versionMatch) {
          majorVer = parseInt(versionMatch[1]) || 0;
          minorVer = parseInt(versionMatch[2]) || 0;
          patchLevel = parseInt(versionMatch[3]) || 0;
        }
        const versionStr = majorVer > 0 ? `${majorVer}.${minorVer}p${patchLevel}` : 'unknown';

        // Check for weak algorithms
        if (sshOutput.includes('diffie-hellman-group1-sha1') || sshOutput.includes('ssh-dss')) {
          findings.push(generateFinding(
            'SSH Weak Key Exchange Algorithms',
            `The SSH server supports weak key exchange algorithms (diffie-hellman-group1-sha1, ssh-dss). These algorithms are deprecated and vulnerable to downgrade attacks.\n\nOpenSSH Version: ${versionStr}\nDetected by: ssh2-enum-algos`,
            Severity.MEDIUM,
            'Cryptographic Issues',
            domain,
            sshOutput.substring(0, 1000),
            'Weak algorithms can be cracked by modern hardware; downgrade attacks possible',
            'Disable weak algorithms; use curve255119-sha256 or diffie-hellman-group16-sha512',
            []
          ));
        }

        // Check for Terrapin (CVE-2023-48795) - affects OpenSSH < 9.6p1
        if (majorVer > 0 && (majorVer < 9 || (majorVer === 9 && minorVer < 6) || (majorVer === 9 && minorVer === 6 && patchLevel < 1))) {
          const terrapinEvidence = sshOutput.includes('chacha20-poly1305') || sshOutput.includes('sntrup761x25519-sha512');
          findings.push(generateFinding(
            'CVE-2023-48795: Terrapin Attack on SSH Binary Packet Protocol',
            `OpenSSH ${versionStr} is vulnerable to the Terrapin attack (CVE-2023-48795, CVSS 5.9 MEDIUM). This attack targets the SSH Binary Packet Protocol by prefix truncation, allowing an active MITM attacker to weaken the channel security. The attack requires a vulnerable key exchange algorithm (chacha20-poly1305@openssh.com or sntrup761x25519-sha512@openssh.com) to be present.\n\nAffected: OpenSSH < 9.6p1\nDetected: OpenSSH ${versionStr}`,
            Severity.MEDIUM,
            'Vulnerability Detection',
            domain,
            `CVE: CVE-2023-48795\nService: OpenSSH ${versionStr}\nDetected by: ssh-vuln-cve2023-48795 + version comparison`,
            'Terrapin prefix truncation attack weakens SSH channel security',
            'Upgrade to OpenSSH 9.6p1 or later; disable chacha20-poly1305 and sntrup761x25519-sha512 if upgrade is not possible',
            ['https://nvd.nist.gov/vuln/detail/CVE-2023-48795', 'https://terrapinattack.com/', 'https://github.com/openssh/openssh-portable/commits/V_9_6']
          ));
        }

        // Check for SSH Agent Forwarding RCE (CVE-2023-38408) - affects OpenSSH < 9.3p2
        if (majorVer > 0 && (majorVer < 9 || (majorVer === 9 && minorVer < 3) || (majorVer === 9 && minorVer === 3 && patchLevel < 2))) {
          findings.push(generateFinding(
            'CVE-2023-38408: OpenSSH Agent Forwarding Remote Code Execution',
            `OpenSSH ${versionStr} is vulnerable to remote code execution via agent forwarding (CVE-2023-38408, CVSS 9.8 CRITICAL). A malicious SSH server can exploit the PKCS#11 provider in ssh-agent to achieve code execution when agent forwarding is enabled.\n\nAffected: OpenSSH < 9.3p2\nDetected: OpenSSH ${versionStr}\nAgent forwarding is commonly enabled by default.`,
            Severity.CRITICAL,
            'Vulnerability Detection',
            domain,
            `CVE: CVE-2023-38408\nService: OpenSSH ${versionStr}\nCVSS: 9.8 CRITICAL\nDetected by: ssh-vuln-cve2023-38408 + version comparison`,
            'Remote code execution through malicious SSH server exploiting ssh-agent',
            'Upgrade to OpenSSH 9.3p2 or later; disable agent forwarding if not needed',
            ['https://nvd.nist.gov/vuln/detail/CVE-2023-38408', 'https://www.openssh.com/security.html']
          ));
        }

        // Check for AuthorizedKeysCommand privilege escalation (CVE-2021-41617) - affects < 8.5p1
        if (majorVer > 0 && (majorVer < 8 || (majorVer === 8 && minorVer < 5) || (majorVer === 8 && minorVer === 5 && patchLevel < 1))) {
          findings.push(generateFinding(
            'CVE-2021-41617: OpenSSH AuthorizedKeysCommand Privilege Escalation',
            `OpenSSH ${versionStr} is vulnerable to privilege escalation via AuthorizedKeysCommand (CVE-2021-41617, CVSS 7.0 HIGH). A local attacker can use AuthorizedKeysCommand to bypass security restrictions.\n\nAffected: OpenSSH < 8.5p1\nDetected: OpenSSH ${versionStr}`,
            Severity.HIGH,
            'Vulnerability Detection',
            domain,
            `CVE: CVE-2021-41617\nService: OpenSSH ${versionStr}\nCVSS: 7.0 HIGH\nDetected by: version comparison`,
            'Privilege escalation through AuthorizedKeysCommand bypass',
            'Upgrade to OpenSSH 8.5p1 or later',
            ['https://nvd.nist.gov/vuln/detail/CVE-2021-41617', 'https://www.openssh.com/security.html']
          ));
        }

        // Check for Command Injection via ProxyCommand (CVE-2023-51385) - affects < 9.3p2
        if (majorVer > 0 && (majorVer < 9 || (majorVer === 9 && minorVer < 3) || (majorVer === 9 && minorVer === 3 && patchLevel < 2))) {
          findings.push(generateFinding(
            'CVE-2023-51385: OpenSSH ProxyCommand/ProxyJump Command Injection',
            `OpenSSH ${versionStr} is vulnerable to OS command injection via ProxyCommand or ProxyJump (CVE-2023-51385, CVSS 6.5 HIGH). An attacker can inject commands through crafted ProxyCommand or ProxyJump options.\n\nAffected: OpenSSH < 9.3p2\nDetected: OpenSSH ${versionStr}`,
            Severity.HIGH,
            'Vulnerability Detection',
            domain,
            `CVE: CVE-2023-51385\nService: OpenSSH ${versionStr}\nCVSS: 6.5 HIGH\nDetected by: version comparison`,
            'OS command injection through crafted ProxyCommand/ProxyJump options',
            'Upgrade to OpenSSH 9.3p2 or later',
            ['https://nvd.nist.gov/vuln/detail/CVE-2023-51385', 'https://www.openssh.com/security.html']
          ));
        }

        // If version was detected, log it even if no CVE found
        if (majorVer > 0) {
          logInfo('kaliTools', `[ssh] Detected OpenSSH ${versionStr}`);
        }
      } catch (e) {
        logWarn('kaliTools', `SSH scan failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    const dur3 = Date.now() - start3;
    logDone('kaliTools', `nmap service enumeration completed in ${(dur3 / 1000).toFixed(1)}s`, dur3);

    return allOutput.join('\n\n');
  } catch (e) {
    const msg = `nmap failed: ${e instanceof Error ? e.message : String(e)}`;
    errors.push(msg);
    logWarn('kaliTools', msg);
    return allOutput.join('\n');
  }
}

async function runNikto(domain: string, findings: Finding[], errors: string[]): Promise<string> {
  try {
    logInfo('kaliTools', `Running nikto scan on ${domain}`);
    const start = Date.now();
    const { stdout } = await execAsync(
      `nikto -h http://${domain} -Tuning 1234567890abc -timeout 5 -maxtime 90s -output - -nointeractive`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 }
    );
    const duration = Date.now() - start;
    logDone('kaliTools', `nikto scan completed in ${(duration / 1000).toFixed(1)}s`, duration);

    const cleanedNiktoOutput = stripBinaryChars(stdout);
    const lines = cleanedNiktoOutput.split('\n');
    for (const line of lines) {
      // Nikto findings start with "+ " and contain vulnerability info
      if (line.startsWith('+ ') && !line.startsWith('+ No CGI') && !line.startsWith('+ Server:')) {
        const osvdbMatch = line.match(/OSVDB-(\d+)/);
        const cveMatch = line.match(/(CVE-\d{4}-\d+)/);
        const existingCve = findings.find(f => cveMatch && f.evidence?.includes(cveMatch[1]));
        if (existingCve) continue;
        const lower = line.toLowerCase();

        // Determine severity based on finding type
        let severity = Severity.MEDIUM;
        let category = 'Web Server Misconfiguration';
        if (lower.includes('xss') || lower.includes('cross-site') || lower.includes('script')) {
          category = 'Cross-Site Scripting';
          severity = Severity.HIGH;
        } else if (lower.includes('injection') || lower.includes('sql') || lower.includes('command')) {
          category = 'Injection';
          severity = Severity.HIGH;
        } else if (lower.includes('directory listing') || lower.includes('traversal') || lower.includes('path')) {
          category = 'Path Traversal';
          severity = Severity.HIGH;
        } else if (lower.includes('default') || lower.includes('admin') || lower.includes('login')) {
          category = 'Authentication';
          severity = Severity.HIGH;
        } else if (lower.includes('file disclosure') || lower.includes('backup') || lower.includes('config')) {
          category = 'Information Disclosure';
          severity = Severity.HIGH;
        } else if (lower.includes('header') || lower.includes('cookie')) {
          category = 'Security Headers';
        }

        const finding = generateFinding(
          `Nikto: ${line.substring(2, 80).trim()}`,
          stripBinaryChars(line.substring(2)).trim(),
          severity,
          category,
          domain,
          stripBinaryChars(line.substring(2)).trim(),
          'Nikto identified a potential web server vulnerability or misconfiguration',
          'Review and remediate the identified issue',
          cveMatch ? [`https://nvd.nist.gov/vuln/detail/${cveMatch[1]}`] :
          osvdbMatch ? [`https://osvdb.org/show/osvdb/${osvdbMatch[1]}`] : []
        );
        findings.push(finding);
        logVuln('kaliTools', `Nikto: ${line.substring(2, 60).trim()}`, severity);
      }
      // Parse specific vulnerability patterns
      if (line.includes('XSS') || line.includes('Cross-Site Scripting')) {
        // Already handled above
      }
    }

    return stdout;
  } catch (e) {
    const msg = `nikto failed: ${e instanceof Error ? e.message : String(e)}`;
    errors.push(msg);
    logWarn('kaliTools', msg);
    return '';
  }
}

async function runWhatweb(domain: string, findings: Finding[], errors: string[]): Promise<string> {
  try {
    logInfo('kaliTools', `Running whatweb fingerprinting on ${domain}`);
    const start = Date.now();
    const { stdout } = await execAsync(
      `whatweb -a 3 --color=never ${domain}`,
      { timeout: 60000, maxBuffer: 5 * 1024 * 1024 }
    );
    const duration = Date.now() - start;
    logDone('kaliTools', `whatweb fingerprinting completed in ${(duration / 1000).toFixed(1)}s`, duration);

    // Parse whatweb output for technology detection and misconfigurations
    if (stdout.includes('X-Powered-By')) {
      findings.push(generateFinding(
        'Server Technology Disclosure (whatweb)',
        `whatweb detected technology disclosure headers that reveal server stack information.`,
        Severity.LOW,
        'Information Disclosure',
        domain,
        stdout.substring(0, 500),
        'Technology disclosure helps attackers select targeted exploits',
        'Remove or obscure X-Powered-By and Server headers',
        []
      ));
    }
    // Check for known vulnerable technologies
    const vulnTechs = [
      { pattern: /WordPress\s+[\d.]+/i, name: 'WordPress', check: (v: string) => { const m = v.match(/[\d.]+/); return m ? parseFloat(m[0]) < 6.4 : false; }, cve: 'CVE-2023-35001' },
      { pattern: /Apache\/[\d.]+/i, name: 'Apache', check: (v: string) => { const m = v.match(/[\d.]+/); return m ? parseFloat(m[0].split('.')[0]) <= 2 && parseFloat(m[0].split('.')[1] || '0') < 47 : false; }, cve: '' },
      { pattern: /nginx\/[\d.]+/i, name: 'nginx', check: (v: string) => { const m = v.match(/[\d.]+/); return m ? parseFloat(m[0]) < 1.25 : false; }, cve: '' },
      { pattern: /PHP\/[\d.]+/i, name: 'PHP', check: (v: string) => { const m = v.match(/[\d.]+/); return m ? parseFloat(m[0]) < 8.1 : false; }, cve: '' },
      { pattern: /IIS\/[\d.]+/i, name: 'IIS', check: (v: string) => { const m = v.match(/[\d.]+/); return m ? parseFloat(m[0]) < 10 : false; }, cve: '' },
      { pattern: /OpenSSH\/[\d.]+/i, name: 'OpenSSH', check: (v: string) => {
        const m = v.match(/(\d+)\.(\d+)(?:p(\d+))?/);
        if (!m) return false;
        const [, maj, min, p] = m.map(Number);
        return maj < 8 || (maj === 8 && min < 5) || (maj === 8 && min === 5 && (p || 0) < 1);
      }, cve: 'CVE-2021-41617' },
    ];
    for (const vt of vulnTechs) {
      const match = stdout.match(vt.pattern);
      if (match && vt.check(match[0])) {
        findings.push(generateFinding(
          `Potentially Outdated ${vt.name} Version`,
          `whatweb detected ${match[0]} which may contain known vulnerabilities. Running outdated server software increases attack surface.`,
          Severity.MEDIUM,
          'Information Disclosure',
          domain,
          `Technology: ${match[0]}`,
          `Outdated ${vt.name} versions may contain known CVEs`,
          `Update ${vt.name} to the latest stable version`,
          vt.cve ? [`https://nvd.nist.gov/vuln/detail/${vt.cve}`] : []
        ));
      }
    }

    return stdout;
  } catch (e) {
    const msg = `whatweb failed: ${e instanceof Error ? e.message : String(e)}`;
    errors.push(msg);
    logWarn('kaliTools', msg);
    return '';
  }
}

async function runNuclei(domain: string, findings: Finding[], errors: string[]): Promise<string> {
  try {
    // Check if nuclei templates exist
    try {
      const { stdout: templateCheck } = await execAsync(
        `ls /home/cyberguard/nuclei-templates/http/ 2>/dev/null | head -1`,
        { timeout: 5000 }
      );
      if (!templateCheck.trim()) {
        logWarn('kaliTools', 'Nuclei templates not found, attempting update');
        await execAsync(`nuclei -update-templates -silent`, { timeout: 60000 });
      }
    } catch {
      logWarn('kaliTools', 'Nuclei templates not available, skipping nuclei scan');
      return '';
    }

    logInfo('kaliTools', `Running nuclei vulnerability scanner on ${domain}`);
    const start = Date.now();
    // Try HTTPS first, fall back to HTTP if HTTPS fails
    const urls = [`https://${domain}`, `http://${domain}`];
    let stdout = '';
    let lastError: string | null = null;

    for (const url of urls) {
      try {
        const result = await execAsync(
          `nuclei -u ${url} -severity critical,high,medium -silent -timeout 8 -retries 2 -rl 30 -c 5 -duc -t /home/cyberguard/nuclei-templates -stats -limit 50`,
          { timeout: 300000, maxBuffer: 10 * 1024 * 1024 }
        );
        stdout = result.stdout;
        break;
      } catch (e) {
        lastError = e instanceof Error ? e.message : String(e);
        if (url === urls[urls.length - 1]) {
          throw e;
        }
      }
    }

    const duration = Date.now() - start;
    logDone('kaliTools', `nuclei scan completed in ${(duration / 1000).toFixed(1)}s`, duration);

    const lines = stdout.split('\n').filter(l => l.trim());
    const seenTemplates = new Set<string>();

    for (const line of lines) {
      // Nuclei output: [template-id] [type] [severity] url [extra]
      const match = line.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)/);
      if (match) {
        const [, templateId, type, severity, targetUrl, extra] = match;

        // Deduplicate findings per template+target
        const key = `${templateId}:${targetUrl}`;
        if (seenTemplates.has(key)) continue;
        seenTemplates.add(key);

        const sevMap: Record<string, Severity> = {
          critical: Severity.CRITICAL, high: Severity.HIGH, medium: Severity.MEDIUM,
          low: Severity.LOW, info: Severity.INFO,
        };
        const sev = sevMap[severity.toLowerCase()] || Severity.MEDIUM;

        findings.push(generateFinding(
          `Nuclei: ${templateId} (${type})`,
          `Nuclei template ${templateId} (${type}) detected at ${targetUrl}. ${extra}`.trim(),
          sev,
          'Automated Vulnerability Detection',
          domain,
          `Template: ${templateId}, Type: ${type}, Target: ${targetUrl}, Detail: ${extra}`,
          `Nuclei template ${templateId} indicates a confirmed vulnerability`,
          `Investigate and remediate the ${type} vulnerability`,
          [`https://github.com/projectdiscovery/nuclei-templates/blob/main/http/${type}/${templateId}.yaml`]
        ));
        logVuln('kaliTools', `Nuclei: ${templateId} (${type})`, severity.toUpperCase(), `target=${targetUrl}`);
      }
    }

    return stdout;
  } catch (e) {
    const msg = `nuclei failed: ${e instanceof Error ? e.message : String(e)}`;
    errors.push(msg);
    logWarn('kaliTools', msg);
    return '';
  }
}

async function runDirb(domain: string, findings: Finding[], errors: string[]): Promise<string> {
  try {
    logInfo('kaliTools', `Running directory brute-force on ${domain}`);
    const start = Date.now();

    // Try multiple wordlists and protocols
    const wordlists = [
      '/usr/share/wordlists/dirb/common.txt',
      '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
      '/usr/share/seclists/Discovery/Web-Content/common.txt',
    ];

    // Find an available wordlist
    let wordlist = wordlists[0];
    for (const wl of wordlists) {
      try {
        await execAsync(`test -f ${wl}`, { timeout: 5000 });
        wordlist = wl;
        break;
      } catch {}
    }

    // Try HTTPS first, fall back to HTTP
    const urls = [`https://${domain}`, `http://${domain}`];
    let stdout = '';
    for (const url of urls) {
      try {
        const result = await execAsync(
          `dirb ${url} ${wordlist} -r -z 100 -S -t 10 -o /tmp/dirb_out.txt`,
          { timeout: 120000, maxBuffer: 10 * 1024 * 1024 }
        );
        stdout = result.stdout;
        break;
      } catch {
        // Try next URL
      }
    }

    const duration = Date.now() - start;
    logDone('kaliTools', `directory brute-force completed in ${(duration / 1000).toFixed(1)}s`, duration);

    // Parse found paths
    const foundPaths: string[] = [];
    const lines = stdout.split('\n');
    for (const line of lines) {
      const match = line.match(/\+ (https?:\/\/\S+)/);
      if (match) foundPaths.push(match[1]);
    }

    // Flag sensitive paths
    const sensitivePatterns = [
      '/admin', '/backup', '/config', '/database', '/.env', '/.git',
      '/phpmyadmin', '/wp-admin', '/server-status', '/server-info',
      '/.htaccess', '/.htpasswd', '/wp-config.php.bak', '/web.config',
      '/robots.txt', '/sitemap.xml', '/.DS_Store', '/crossdomain.xml',
      '/elmah.axd', '/trace.axd', '/handler.ashx', '/debug',
    ];
    const sensitiveHits = foundPaths.filter(p => sensitivePatterns.some(s => p.toLowerCase().includes(s)));
    if (sensitiveHits.length > 0) {
      findings.push(generateFinding(
        'Sensitive Directories Exposed',
        `Directory brute-force found ${sensitiveHits.length} sensitive paths: ${sensitiveHits.join(', ')}`,
        Severity.HIGH,
        'Directory Enumeration',
        domain,
        `Sensitive paths found: ${sensitiveHits.join('; ')}`,
        'Exposed sensitive directories can leak configuration, credentials, and source code',
        'Restrict access to sensitive directories; remove from production',
        []
      ));
      logVuln('kaliTools', `Sensitive directories: ${sensitiveHits.join(', ')}`, 'HIGH');
    }

    // Also flag any interesting paths (not just sensitive)
    if (foundPaths.length > 0 && sensitiveHits.length === 0) {
      findings.push(generateFinding(
        'Directory Enumeration Results',
        `Directory brute-force found ${foundPaths.length} paths: ${foundPaths.slice(0, 10).join(', ')}${foundPaths.length > 10 ? '...' : ''}`,
        Severity.INFO,
        'Directory Enumeration',
        domain,
        `Found paths: ${foundPaths.join('; ')}`,
        'Discovered paths may reveal application structure',
        'Review discovered paths for sensitive information',
        []
      ));
    }

    return stdout;
  } catch (e) {
    const msg = `dirb failed: ${e instanceof Error ? e.message : String(e)}`;
    errors.push(msg);
    logWarn('kaliTools', msg);
    return '';
  }
}

// ─── MODULE ENTRY POINT ───────────────────────────────────────────────────────
export async function runKaliToolsScan(domain: string, profile?: { reconSummary?: string; wafDetected?: boolean; hasLoginForm?: boolean; hasAPI?: boolean }): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const toolOutputs: Record<string, string> = {};

  logInfo('kaliTools', `Checking available security tools on ${domain}`);

  // Check which tools are available
  const tools = await getAvailableTools();
  const toolList = [...tools];
  logInfo('kaliTools', `Available tools: ${toolList.length > 0 ? toolList.join(', ') : 'none'}`);

  if (tools.size === 0) {
    logWarn('kaliTools', 'No Kali tools found in PATH — install nmap, nikto, nuclei');
    return {
      module: 'kaliTools',
      findings: [],
      duration: Date.now() - startTime,
      errors: ['No security tools installed in container'],
    };
  }

  // Determine which tools to run based on profile
  const runThese: string[] = [];
  if (tools.has('nmap')) runThese.push('nmap');
  if (tools.has('whatweb')) runThese.push('whatweb');
  if (tools.has('nikto')) runThese.push('nikto');
  if (tools.has('nuclei')) runThese.push('nuclei');
  if (tools.has('dirb')) runThese.push('dirb');

  logInfo('kaliTools', `Running ${runThese.length} tools: ${runThese.join(', ')}`);

  // Run tools sequentially (they each consume significant resources)
  for (const tool of runThese) {
    switch (tool) {
      case 'nmap':
        toolOutputs.nmap = await runNmap(domain, findings, errors);
        break;
      case 'nikto':
        toolOutputs.nikto = await runNikto(domain, findings, errors);
        break;
      case 'whatweb':
        toolOutputs.whatweb = await runWhatweb(domain, findings, errors);
        break;
      case 'nuclei':
        toolOutputs.nuclei = await runNuclei(domain, findings, errors);
        break;
      case 'dirb':
        toolOutputs.dirb = await runDirb(domain, findings, errors);
        break;
    }
  }

  const duration = Date.now() - startTime;

  // AI-enhanced kaliTools result interpretation
  try {
    const ai = getAI();
    const kaliFindings = findings.filter(f =>
      f.category === 'Kali Tools' ||
      f.category === 'Network' ||
      f.evidence?.includes('nmap') ||
      f.evidence?.includes('nikto') ||
      f.evidence?.includes('nuclei')
    );
    if (kaliFindings.length > 0) {
      // Use AI to interpret tool results and correlate findings
      const toolResults = kaliFindings.slice(0, 10).map(f => `${f.title}: ${f.description.substring(0, 100)}`).join('\n');
      const aiResult = await ai.reasonAboutVulnerabilities(['Network', 'Web Server', 'Services'], kaliFindings);
      if (aiResult.versionSpecificRisks.length > 0) {
        for (const risk of aiResult.versionSpecificRisks) {
          findings.push(generateFinding(
            `AI-Interpreted Tool Result: ${risk}`,
            `AI analyzed kaliTools output and identified version-specific risk: ${risk}. This may indicate exploitable vulnerabilities in specific service versions.`,
            Severity.HIGH,
            'AI Tool Interpretation',
            domain,
            'Review the specific service version and apply vendor patches. Verify with targeted exploitation.',
            'Version-specific vulnerabilities often have public exploits available',
            'Update affected services to patched versions. Implement virtual patching if update not possible.',
            [],
          ));
        }
      }
      if (aiResult.novelAttackVectors.length > 0) {
        for (const vector of aiResult.novelAttackVectors) {
          findings.push(generateFinding(
            `AI-Detected Attack from Tool Results: ${vector}`,
            `AI identified novel attack vector from tool output: ${vector}. This may not be directly flagged by the scanners.`,
            Severity.MEDIUM,
            'AI Tool Interpretation',
            domain,
            'Investigate the attack vector and add custom validation tests',
            'Tool output analysis can reveal attack paths that individual findings miss',
            'Add targeted tests for this attack vector in future scans',
            [],
          ));
        }
      }
    }
  } catch {}

  logDone('kaliTools', `Kali tools completed — ${findings.length} finding(s) from ${toolList.length} tool(s)`, duration, findings.length);

  return {
    module: 'kaliTools',
    findings,
    duration,
    errors,
  };
}
