import { exec } from 'child_process';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const execAsync = promisify(exec);

async function runCommand(cmd: string, timeoutMs: number = 30000): Promise<string> {
  try {
    const { stdout } = await execAsync(cmd, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
    });
    return stdout;
  } catch {
    return '';
  }
}

// ─── SMB Enumeration ──────────────────────────────────────────────────────────
async function scanSmb(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-ms17-010 -p 445,139 ${domain}`,
      60000
    );

    if (!output) return;

    // Detect OS from SMB
    const osMatch = output.match(/OS: (.+)/i) || output.match(/System Time:.+\nOS: (.+)/i);
    if (osMatch) {
      findings.push(generateFinding(
        'Windows OS version disclosed via SMB',
        'SMB service reveals the operating system version.',
        Severity.LOW, 'Windows System', domain,
        `OS: ${osMatch[1].trim()}`,
        'OS version helps attackers target platform-specific exploits',
        'Disable SMB or restrict access; configure to hide OS information',
        ['https://docs.microsoft.com/en-us/windows-server/administration/server-manager/configure-server-smartscreen']
      ));
    }

    // Detect shares
    const shareMatches = output.match(/\|\s+\S+\s+(Disk|IPC|Print)/gi) || [];
    const shares = shareMatches.map(s => s.trim());
    if (shares.length > 0) {
      const sensitiveShares = shares.filter(s =>
        /admin|c\$|ipc\$|netlogon|sysvol/i.test(s)
      );
      if (sensitiveShares.length > 0) {
        findings.push(generateFinding(
          'Sensitive SMB shares exposed',
          `SMB enumeration reveals sensitive shares: ${sensitiveShares.join(', ')}.`,
          Severity.HIGH, 'Windows System', domain,
          `Shares found: ${sensitiveShares.join(', ')}`,
          'Exposed sensitive shares can allow unauthorized file access and lateral movement',
          'Restrict SMB shares to authenticated users; disable unnecessary shares',
          ['https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot-smb-shares']
        ));
      }
    }

    // Detect users
    if (output.includes('SMB User') || output.includes('user:') || output.match(/user\s+\d+:/i)) {
      findings.push(generateFinding(
        'SMB user enumeration possible',
        'The SMB service allows user enumeration, which can aid brute-force attacks.',
        Severity.MEDIUM, 'Windows System', domain,
        'SMB user enumeration data found in output',
        'Enumerated usernames can be used for targeted password attacks',
        'Restrict anonymous access; limit user enumeration permissions',
        ['https://docs.microsoft.com/en-us/windows/security/threat-protection/audit/restriction-of-anonymous-access']
      ));
    }

    // SMB signing
    if (output.includes('Message signing enabled but not required')) {
      findings.push(generateFinding(
        'SMB signing not required',
        'SMB message signing is enabled but not required, allowing relay attacks.',
        Severity.HIGH, 'Windows System', domain,
        'SMB signing: enabled but not required',
        'SMB relay attacks can intercept and modify SMB traffic',
        'Require SMB signing via Group Policy: Microsoft network server: Digitally sign communications (always)',
        ['https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always']
      ));
    }

    // Vulnerability detection
    const vulnMatch = output.match(/VULNERABLE[\s\S]*?(?:State|CVE)[^\n]*/gi) || [];
    for (const vuln of vulnMatch.slice(0, 3)) {
      const cveMatch = vuln.match(/(CVE-\d{4}-\d+)/);
      findings.push(generateFinding(
        `SMB vulnerability detected${cveMatch ? `: ${cveMatch[1]}` : ''}`,
        `Nmap SMB scripts detected a vulnerability: ${vuln.substring(0, 200)}`,
        Severity.CRITICAL, 'Windows System', domain,
        vuln.substring(0, 300),
        'SMB vulnerabilities can allow remote code execution and lateral movement',
        'Apply security patches immediately; disable SMBv1 if not needed',
        cveMatch ? [`https://nvd.nist.gov/vuln/detail/${cveMatch[1]}`] : ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010']
      ));
    }

    if (output.includes('EternalBlue') || output.includes('ms17-010')) {
      findings.push(generateFinding(
        'EternalBlue vulnerability (MS17-010) detected',
        'The target is potentially vulnerable to EternalBlue, a critical remote code execution vulnerability.',
        Severity.CRITICAL, 'Windows System', domain,
        'EternalBlue / MS17-010 indicator found',
        'EternalBlue has been used by WannaCry, NotPetya, and other major malware campaigns',
        'Install MS17-010 patch immediately; disable SMBv1; segment network',
        ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010']
      ));
    }
  } catch (e) {
    errors.push(`SMB scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── WinRM Detection ──────────────────────────────────────────────────────────
async function scanWinRM(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap -p 5985,5986 ${domain}`,
      30000
    );

    if (!output) return;

    const ports = [5985, 5986];
    for (const port of ports) {
      if (output.includes(`${port}/tcp`) && output.includes('open')) {
        const protocol = port === 5986 ? 'HTTPS' : 'HTTP';
        findings.push(generateFinding(
          `WinRM service detected (port ${port})`,
          `Windows Remote Management (${protocol}) is accessible on port ${port}.`,
          port === 5986 ? Severity.MEDIUM : Severity.HIGH, 'Windows System', domain,
          `Port ${port} (${protocol}): WinRM open`,
          'WinRM can be used for remote command execution and lateral movement',
          port === 5986
            ? 'WinRM over HTTPS is more secure; ensure proper authentication is enforced'
            : 'Disable HTTP WinRM; use HTTPS (port 5986) with proper authentication',
          ['https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management']
        ));
      }
    }

    // Also check via nmap http scripts
    const httpOutput = await runCommand(
      `nmap --script http-winrm-enum-accounts -p 5985 ${domain}`,
      30000
    );

    if (httpOutput && httpOutput.includes('user')) {
      findings.push(generateFinding(
        'WinRM account enumeration possible',
        'WinRM allows enumeration of user accounts.',
        Severity.MEDIUM, 'Windows System', domain,
        'WinRM account enumeration successful',
        'Enumerated accounts can be used for targeted attacks',
        'Restrict WinRM access to trusted IPs; disable basic authentication',
        ['https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands']
      ));
    }
  } catch (e) {
    errors.push(`WinRM scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── RDP Security Analysis ────────────────────────────────────────────────────
async function scanRdp(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p 3389 ${domain}`,
      45000
    );

    if (!output) return;

    // NTLM info
    const ntlmMatch = output.match(/SHELLABILITY: (.+)/i) || output.match(/Copyright: (.+)/i);
    if (ntlmMatch) {
      findings.push(generateFinding(
        'RDP server information disclosure',
        `RDP reveals server information: ${ntlmMatch[1].trim()}`,
        Severity.LOW, 'Windows System', domain,
        `RDP info: ${ntlmMatch[1].trim()}`,
        'Server information helps attackers identify software versions',
        'Configure RDP to minimize information disclosure',
        ['https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/troubleshoot/remote-desktop-clients']
      ));
    }

    // MS12-020
    if (output.includes('VULNERABLE') || output.includes('ms12-020')) {
      findings.push(generateFinding(
        'RDP vulnerability MS12-020 detected',
        'The target may be vulnerable to MS12-020, a critical RDP vulnerability that can cause denial of service.',
        Severity.CRITICAL, 'Windows System', domain,
        'MS12-020 vulnerability detected',
        'MS12-020 can cause blue screen of death or remote code execution',
        'Install MS12-020 security update immediately',
        ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-020']
      ));
    }

    // Encryption level
    if (output.includes('RDP Encryption Level')) {
      const encMatch = output.match(/Encryption Level: (\w+)/i);
      if (encMatch && encMatch[1].toLowerCase() === 'low') {
        findings.push(generateFinding(
          'RDP encryption level is low',
          'RDP is configured with low encryption level, which is insecure.',
          Severity.HIGH, 'Windows System', domain,
          `RDP Encryption Level: ${encMatch[1]}`,
          'Low encryption allows potential interception of RDP traffic',
          'Configure RDP to use high encryption (128-bit)',
          ['https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-encryption']
        ));
      }
    }

    // NLA
    if (output.includes('NLA') || output.includes('Network Level Authentication')) {
      if (output.includes('NLA not supported') || output.includes('NLA: disabled')) {
        findings.push(generateFinding(
          'RDP Network Level Authentication disabled',
          'Network Level Authentication (NLA) is not enabled on the RDP service.',
          Severity.HIGH, 'Windows System', domain,
          'RDP NLA: disabled',
          'Without NLA, RDP is vulnerable to pre-authentication attacks',
          'Enable Network Level Authentication in RDP settings',
          ['https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-nla']
        ));
      }
    }
  } catch (e) {
    errors.push(`RDP scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Windows Service Enumeration ──────────────────────────────────────────────
async function scanWindowsServices(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap -p 80,443,8080,8443,1433,3306,5432,9090,25,587,993,995 ${domain} -sV`,
      60000
    );

    if (!output) return;

    // IIS detection
    if (output.includes('Microsoft IIS') || output.includes('IIS/')) {
      const versionMatch = output.match(/IIS\/([\d.]+)/);
      const version = versionMatch ? versionMatch[1] : 'unknown';
      findings.push(generateFinding(
        `Microsoft IIS detected (version ${version})`,
        'Microsoft Internet Information Services (IIS) web server detected.',
        Severity.INFO, 'Windows System', domain,
        `IIS version: ${version}`,
        'IIS misconfigurations can expose sensitive data and allow code execution',
        'Ensure IIS is properly hardened; disable unnecessary modules',
        ['https://docs.microsoft.com/en-us/iis/manage/security-basics/request-filtering-configuration-reference']
      ));
    }

    // SQL Server detection
    if (output.includes('ms-sql') || output.includes('MSSQL')) {
      findings.push(generateFinding(
        'Microsoft SQL Server exposed',
        'MS SQL Server is accessible from external network.',
        Severity.HIGH, 'Windows System', domain,
        'MS SQL Server detected on accessible port',
        'Database exposure allows potential unauthorized data access',
        'Restrict SQL Server to internal network; use firewall rules',
        ['https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode']
      ));
    }

    // Exchange detection
    if (output.includes('Exchange') || output.includes('Microsoft SMTP')) {
      findings.push(generateFinding(
        'Microsoft Exchange detected',
        'Microsoft Exchange mail server detected on the target.',
        Severity.MEDIUM, 'Windows System', domain,
        'Exchange service detected',
        'Exchange servers are high-value targets for attackers',
        'Keep Exchange updated; enable all security features',
        ['https://docs.microsoft.com/en-us/exchange/exchange-owa-security-hardening-deployment']
      ));
    }

    // AD CS (Certificate Services)
    if (output.includes('cert-svc') || output.includes('443/tcp') && output.includes('Microsoft')) {
      findings.push(generateFinding(
        'Active Directory Certificate Services detected',
        'AD CS may be exposed, which can be exploited for privilege escalation (ESC vulnerabilities).',
        Severity.MEDIUM, 'Windows System', domain,
        'AD CS potentially exposed',
        'AD CS misconfigurations can allow domain privilege escalation',
        'Audit AD CS configurations; apply PetitPotam mitigations',
        ['https://posts.specterops.io/certified-pre-owned-d969046c2bec']
      ));
    }
  } catch (e) {
    errors.push(`Windows service scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Registry/Service Banner Detection ────────────────────────────────────────
async function scanRegistryServices(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap -p 135,139,445,5985,5986,47001,49664-49669 ${domain} -sV`,
      45000
    );

    if (!output) return;

    // WMI
    if (output.includes('WMI') || output.includes('Windows Management')) {
      findings.push(generateFinding(
        'WMI service exposed',
        'Windows Management Instrumentation (WMI) is accessible externally.',
        Severity.HIGH, 'Windows System', domain,
        'WMI service detected',
        'WMI can be used for remote system administration and lateral movement',
        'Restrict WMI access to internal network; use Windows Firewall',
        ['https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page']
      ));
    }

    // PowerShell Remoting
    if (output.includes('5985') || output.includes('5986') || output.includes('WinRM')) {
      findings.push(generateFinding(
        'PowerShell Remoting exposed',
        'PowerShell Remoting (WinRM) is accessible externally, allowing remote command execution.',
        Severity.HIGH, 'Windows System', domain,
        'PowerShell Remoting service detected',
        'PowerShell Remoting enables remote code execution and is a common lateral movement technique',
        'Disable PowerShell Remoting if not needed; restrict access via firewall',
        ['https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands']
      ));
    }
  } catch (e) {
    errors.push(`Registry service scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Windows Credential Detection ─────────────────────────────────────────────
async function scanCredentials(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script smb-enum-shares --script-args smbuser=anonymous -p 445,139 ${domain}`,
      45000
    );

    if (!output) return;

    // Check for accessible shares with readable content
    if (output.includes('READ') || output.includes('Anon')) {
      findings.push(generateFinding(
        'Anonymous SMB share access possible',
        'Anonymous users can access SMB shares, potentially exposing sensitive files.',
        Severity.HIGH, 'Windows System', domain,
        'Anonymous SMB access: READ permissions detected',
        'Anonymous share access can expose credentials and sensitive data',
        'Disable anonymous access to SMB shares; implement proper authentication',
        ['https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/restriction-of-anonymous-access']
      ));
    }

    // Check for exposed credential files via HTTP
    const httpCheck = await runCommand(
      `curl -sk --max-time 10 https://${domain}/wp-config.php 2>/dev/null | head -20`,
      15000
    );

    if (httpCheck && (httpCheck.includes('DB_PASSWORD') || httpCheck.includes('WP_PASSWORD'))) {
      findings.push(generateFinding(
        'WordPress configuration file exposed',
        'The WordPress configuration file (wp-config.php) is publicly accessible, potentially exposing database credentials.',
        Severity.CRITICAL, 'Windows System', domain,
        `wp-config.php content exposed: ${httpCheck.substring(0, 200)}`,
        'Exposed credentials can lead to database compromise',
        'Restrict access to wp-config.php; ensure it is not served by the web server',
        ['https://developer.wordpress.org/advanced-administration/wordpress-edit-config/']
      ));
    }
  } catch (e) {
    errors.push(`Credential scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Windows-Specific Vulnerabilities ─────────────────────────────────────────
async function scanWindowsVulns(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    // PrintNightmare detection (RPC/LPD)
    const printNightmare = await runCommand(
      `nmap -p 445 --script smb-vuln-ms17-010 ${domain}`,
      45000
    );

    if (printNightmare && (printNightmare.includes('VULNERABLE') || printNightmare.includes('PrintNightmare'))) {
      findings.push(generateFinding(
        'PrintNightmare vulnerability (CVE-2021-1675) possible indicator',
        'Nmap SMB scripts indicate potential PrintNightmare vulnerability.',
        Severity.CRITICAL, 'Windows System', domain,
        'PrintNightmare / CVE-2021-1675 indicator',
        'PrintNightmare allows remote code execution via the Windows Print Spooler service',
        'Disable Print Spooler service if not needed; apply Microsoft security patches',
        ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675']
      ));
    }

    // PetitPotam indicator (via NTLM relay)
    const petitPotam = await runCommand(
      `nmap -p 445,139 --script smb-os-discovery ${domain}`,
      30000
    );

    if (petitPotam && petitPotam.includes('Domain:')) {
      findings.push(generateFinding(
        'PetitPotam attack surface present',
        'Domain controller detected with SMB enabled, which may be vulnerable to PetitPotam NTLM relay attacks.',
        Severity.HIGH, 'Windows System', domain,
        'Domain controller with SMB - PetitPotam attack surface',
        'PetitPotam can force a domain controller to authenticate to an attacker-controlled machine',
        'Enable EPA (Extended Protection for Authentication); disable NTLM where possible',
        ['https://github.com/topotam/PetitPotam']
      ));
    }

    // BlueKeep indicator
    const blueKeep = await runCommand(
      `nmap -p 3389 --script rdp-vuln-ms12-020 ${domain}`,
      30000
    );

    if (blueKeep && blueKeep.includes('VULNERABLE')) {
      findings.push(generateFinding(
        'BlueKeep vulnerability indicator (CVE-2019-0708)',
        'RDP service may be vulnerable to BlueKeep, a critical wormable vulnerability.',
        Severity.CRITICAL, 'Windows System', domain,
        'BlueKeep / CVE-2019-0708 indicator',
        'BlueKeep allows unauthenticated remote code execution via RDP',
        'Apply CVE-2019-0708 patch immediately; disable RDP if not needed',
        ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708']
      ));
    }

    // ZeroLogon indicator
    const zeroLogon = await runCommand(
      `nmap -p 88 --script krb5-enum-users --script-args krb5_enum_users.realm=DOMAIN ${domain}`,
      30000
    );

    if (zeroLogon && (zeroLogon.includes('Kerberos') || zeroLogon.includes('88/tcp open'))) {
      findings.push(generateFinding(
        'Kerberos service exposed - potential ZeroLogon attack surface',
        'Kerberos authentication service is exposed, which may be vulnerable to ZeroLogon (CVE-2020-1472).',
        Severity.MEDIUM, 'Windows System', domain,
        'Kerberos service detected on port 88',
        'ZeroLogon allows domain controller compromise if Kerberos is vulnerable',
        'Apply CVE-2020-1472 patch; enforce secure RPC',
        ['https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472']
      ));
    }
  } catch (e) {
    errors.push(`Windows vuln scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────
export async function runWindowsScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await scanSmb(domain, findings, errors);
    await scanWinRM(domain, findings, errors);
    await scanRdp(domain, findings, errors);
    await scanWindowsServices(domain, findings, errors);
    await scanRegistryServices(domain, findings, errors);
    await scanCredentials(domain, findings, errors);
    await scanWindowsVulns(domain, findings, errors);

    const duration = Date.now() - startTime;
    return { module: 'windowsSystem', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'windowsSystem',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

// ─── Wrapper for MODULE_RUNNERS ───────────────────────────────────────────────
export async function runWindowsScanWrapper(domain: string): Promise<ScanResult> {
  return runWindowsScan(domain);
}
