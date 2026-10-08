import { exec } from 'child_process';
import { promisify } from 'util';
import * as dns from 'dns';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logInfo, logVuln, logDone, logWarn, logExploit } from '../scanLogger';

const execAsync = promisify(exec);
const resolveSrv = promisify(dns.resolveSrv);
const resolveTxt = promisify(dns.resolveTxt);
const resolve = promisify(dns.resolve);

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function runCmd(cmd: string, timeoutMs = 30000): Promise<{ stdout: string; stderr: string; ok: boolean }> {
  try {
    const { stdout, stderr } = await execAsync(cmd, {
      timeout: timeoutMs,
      maxBuffer: 5 * 1024 * 1024,
    });
    return { stdout, stderr, ok: true };
  } catch (e: any) {
    return { stdout: e?.stdout || '', stderr: e?.stderr || e?.message || String(e), ok: false };
  }
}

// ─── SRV Record Enumeration ──────────────────────────────────────────────────

async function enumerateSRVRecords(domain: string, findings: Finding[], errors: string[]): Promise<string[]> {
  const servicePrefixes = [
    { prefix: '_ldap._tcp', name: 'LDAP', category: 'Active Directory' },
    { prefix: '_kerberos._tcp', name: 'Kerberos', category: 'Kerberos' },
    { prefix: '_gc._tcp', name: 'Global Catalog', category: 'Active Directory' },
    { prefix: '_kpasswd._tcp', name: 'Kerberos Password', category: 'Kerberos' },
    { prefix: '_ldap._tcp.dc._msdcs', name: 'Domain Controller', category: 'Active Directory' },
  ];

  const discoveredHosts: string[] = [];

  for (const svc of servicePrefixes) {
    try {
      const records = await resolveSrv(`${svc.prefix}.${domain}`);
      if (records.length > 0) {
        const hosts = records.map(r => `${r.name}:${r.port}`);
        discoveredHosts.push(...records.map(r => r.name));

        findings.push(generateFinding(
          `${svc.name} SRV records discovered`,
          `DNS SRV records for ${svc.prefix}.${domain} reveal ${records.length} service endpoint(s).`,
          svc.name === 'Domain Controller' ? Severity.HIGH : Severity.INFO,
          svc.category,
          domain,
          `Records: ${hosts.join(', ')}`,
          'SRV records expose internal service topology including domain controllers',
          'Restrict DNS responses; consider split-horizon DNS for internal records',
          ['https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/configure-ldap-query-to-quer-domains']
        ));
        logVuln('activeDirectory', `${svc.name} SRV records found`, svc.name === 'Domain Controller' ? 'HIGH' : 'INFO');
      }
    } catch {
      // SRV record not found - expected if not AD
    }
  }

  return [...new Set(discoveredHosts)];
}

// ─── DNS Zone Transfer Attempt ───────────────────────────────────────────────

async function attemptZoneTransfer(domain: string, findings: Finding[], errors: string[]): Promise<string[]> {
  const subdomains: string[] = [];

  // First discover nameservers
  const { stdout: nsOutput } = await runCmd(`dig +short NS ${domain}`, 15000);
  const nameservers = nsOutput.split('\n').map(l => l.trim()).filter(l => l.length > 0);

  if (nameservers.length === 0) {
    errors.push('No nameservers found for zone transfer attempt');
    return subdomains;
  }

  for (const ns of nameservers) {
    try {
      const { stdout, ok } = await runCmd(`dig @${ns} ${domain} AXFR +timeout=10`, 30000);

      if (ok && stdout && !stdout.includes('Transfer failed') && !stdout.includes('NOTAUTH') && !stdout.includes('REFUSED')) {
        // Parse zone transfer output for DNS records
        const lines = stdout.split('\n');
        const records: string[] = [];
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 5 && parts[3] === 'IN') {
            records.push(line.trim());
          }
        }

        if (records.length > 0) {
          // Extract subdomains from zone data
          for (const line of lines) {
            const match = line.match(/^(\S+\.${domain.replace('.', '\\.')})/i);
            if (match && !match[1].startsWith(domain)) {
              subdomains.push(match[1]);
            }
          }

          findings.push(generateFinding(
            'DNS zone transfer successful',
            `Nameserver ${ns} permitted an AXFR zone transfer for ${domain}. This exposes the entire DNS zone.`,
            Severity.CRITICAL,
            'DNS Zone Transfer',
            domain,
            `Nameserver: ${ns}\nRecords found: ${records.length}\nSample: ${records.slice(0, 5).join('; ')}`,
            'Full DNS zone exposure reveals internal hosts, services, and network topology',
            'Disable zone transfers to unauthorized hosts; restrict to known secondary DNS servers',
            ['https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/']
          ));
          logVuln('activeDirectory', 'DNS zone transfer successful', 'CRITICAL', `ns=${ns} records=${records.length}`);
          logExploit('activeDirectory', 'AXFR Zone Transfer', domain, `ns=${ns}`);
        }
      }
    } catch (e) {
      errors.push(`Zone transfer attempt against ${ns} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return [...new Set(subdomains)];
}

// ─── SPN / Kerberoastable Account Detection ──────────────────────────────────

async function detectSPNs(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Attempt LDAP SPN enumeration via nmap if available
  const { stdout: nmapOut, ok } = await runCmd(
    `nmap -p 389,636 --script ldap-search --script-args "ldap.search.attrib=servicePrincipalName,ldap.search.base=DC=${domain.split('.').join(',DC=')}" -oN - ${domain}`,
    45000
  );

  if (ok && nmapOut.includes('servicePrincipalName')) {
    const spnEntries = nmapOut.match(/servicePrincipalName: (.+)/g) || [];
    if (spnEntries.length > 0) {
      findings.push(generateFinding(
        'Kerberoastable service accounts detected',
        `LDAP enumeration discovered ${spnEntries.length} service principal name(s). Accounts with SPNs are vulnerable to Kerberoasting attacks.`,
        Severity.HIGH,
        'Kerberos Security',
        domain,
        `SPN entries found:\n${spnEntries.slice(0, 10).join('\n')}`,
        'Kerberoasting allows offline cracking of service account passwords from TGS responses',
        'Use gMSA accounts instead of static service accounts; enforce strong passwords; enable AES-only encryption',
        ['https://attacktechniques.com/techniques/kerberoasting/']
      ));
      logVuln('activeDirectory', 'Kerberoastable accounts detected', 'HIGH', `spn_count=${spnEntries.length}`);
    }
  }

  // Attempt AS-REP roast detection via nmap
  const { stdout: asrepOut, ok: asrepOk } = await runCmd(
    `nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=${domain},userdb=/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -oN - ${domain}`,
    60000
  );

  if (asrepOk && asrepOut.includes('PREAUTH')) {
    findings.push(generateFinding(
      'AS-REP roastable accounts detected',
      `Kerberos enumeration found accounts that do not require pre-authentication. These accounts are vulnerable to AS-REP Roasting.`,
      Severity.CRITICAL,
      'Kerberos Security',
      domain,
      'Accounts without pre-authentication detected via Kerberos enumeration',
      'AS-REP Roasting allows offline password cracking for accounts without Kerberos pre-authentication',
      'Enable Kerberos pre-authentication for all accounts',
      ['https://attacktechniques.com/techniques/kerberoasting/']
    ));
    logVuln('activeDirectory', 'AS-REP roastable accounts', 'CRITICAL');
  }
}

// ─── Kerberos Port and Encryption Analysis ───────────────────────────────────

async function analyzeKerberos(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Check if Kerberos (port 88) is accessible
  const { stdout: portOut } = await runCmd(`nmap -p 88 -sV -oN - ${domain}`, 30000);

  if (portOut.includes('88/tcp') && portOut.includes('open')) {
    // Detect weak encryption types via nmap
    const { stdout: encOut } = await runCmd(
      `nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=${domain} -oN - ${domain}`,
      45000
    );

    if (encOut.includes('rc4') || encOut.includes('des') || encOut.toLowerCase().includes('weak')) {
      findings.push(generateFinding(
        'Weak Kerberos encryption types detected',
        'Kerberos service supports weak encryption algorithms (RC4, DES). These are vulnerable to offline brute-force attacks.',
        Severity.HIGH,
        'Kerberos Security',
        domain,
        `Kerberos port 88 detected. Weak encryption types identified.`,
        'Weak Kerberos encryption allows attackers to crack captured authentication traffic',
        'Disable RC4 and DES encryption; enforce AES-256 for all Kerberos communication',
        ['https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys']
      ));
      logVuln('activeDirectory', 'Weak Kerberos encryption', 'HIGH');
    }

    findings.push(generateFinding(
      'Kerberos service exposed',
      'Kerberos authentication service (port 88) is accessible from external network.',
      Severity.MEDIUM,
      'Kerberos Security',
      domain,
      'Port 88 (Kerberos) is open and reachable',
      'Exposed Kerberos service may be targeted for Kerberoasting, AS-REP Roasting, or Kerberoasting',
      'Restrict Kerberos access to internal network segments only',
      ['https://attacktechniques.com/techniques/kerberoasting/']
    ));
  }

  // Check for unconstrained delegation via LDAP
  const { stdout: ldapOut } = await runCmd(
    `nmap -p 389,636 --script ldap-search --script-args "ldap.search.filter=(userAccountControl:1.2.840.113556.1.4.803:=524288)" -oN - ${domain}`,
    45000
  );

  if (ldapOut.includes('524288') || ldapOut.includes('TRUSTED_FOR_DELEGATION')) {
    findings.push(generateFinding(
      'Unconstrained delegation detected',
      'One or more accounts are configured with unconstrained Kerberos delegation, which can lead to credential theft.',
      Severity.CRITICAL,
      'Kerberos Security',
      domain,
      'Accounts with unconstrained delegation flag detected via LDAP',
      'Unconstrained delegation stores TGTs for all users on the delegating host, enabling lateral movement',
      'Use constrained delegation or resource-based constrained delegation instead',
      ['https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview']
    ));
    logVuln('activeDirectory', 'Unconstrained delegation', 'CRITICAL');
  }
}

// ─── Trust Relationship Detection ────────────────────────────────────────────

async function detectTrusts(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Check for trust-related DNS records
  const trustPatterns = ['_msdcs', '_sites', '_tcp', '_udp'];

  for (const pattern of trustPatterns) {
    try {
      const records = await resolveTxt(`${pattern}.${domain}`);
      if (records.length > 0) {
        findings.push(generateFinding(
          'Active Directory DNS structure discovered',
          `DNS zone ${pattern}.${domain} contains ${records.length} TXT record(s), indicating Active Directory DNS infrastructure.`,
          Severity.MEDIUM,
          'Active Directory',
          domain,
          `Zone: ${pattern}.${domain}, Records: ${records.length}`,
          'AD DNS records reveal domain topology and infrastructure details',
          'Restrict DNS zone visibility; use split-horizon DNS',
          ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--terms-and-acronyms']
        ));
        break;
      }
    } catch {
      // Zone not found
    }
  }

  // Attempt to detect forest trusts via LDAP search
  const { stdout: trustOut } = await runCmd(
    `nmap -p 389 --script ldap-search --script-args "ldap.search.base=CN=System,CN=trust,DC=${domain.split('.').join(',DC=')}" -oN - ${domain}`,
    30000
  );

  if (trustOut.includes('trustedDomain') || trustOut.includes('TRUST') || trustOut.includes('trustDirection')) {
    findings.push(generateFinding(
      'Domain trust relationship detected',
      'LDAP enumeration found evidence of domain trust relationships. Trusts may provide cross-domain attack paths.',
      Severity.MEDIUM,
      'Active Directory',
      domain,
      'Trust objects found in AD configuration',
      'Domain trusts can be exploited for lateral movement between forests/domains',
      'Review and audit all trust relationships; remove unnecessary trusts',
      ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/domain-trust']
    ));
    logVuln('activeDirectory', 'Domain trust detected', 'MEDIUM');
  }

  // Detect Site topology via _sites SRV records
  try {
    const siteRecords = await resolveSrv(`_sites._tcp.${domain}`);
    if (siteRecords.length > 0) {
      const sites = [...new Set(siteRecords.map(r => {
        const parts = r.name.split('.');
        return parts[0];
      }))];

      findings.push(generateFinding(
        'AD Site topology exposed',
        `SRV records reveal ${sites.length} Active Directory site(s): ${sites.join(', ')}`,
        Severity.LOW,
        'Active Directory',
        domain,
        `Sites discovered: ${sites.join(', ')}`,
        'Site topology reveals internal network structure',
        'Consider restricting SRV record visibility',
        []
      ));
    }
  } catch {
    // Sites not found
  }
}

// ─── GPO / SYSVOL Enumeration ────────────────────────────────────────────────

async function enumerateGPO(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Check for SYSVOL exposure via SMB
  const { stdout: smbOut } = await runCmd(
    `nmap -p 445 --script smb-enum-shares,smb-os-discovery -oN - ${domain}`,
    30000
  );

  if (smbOut.includes('SYSVOL') || smbOut.includes('netlogon')) {
    findings.push(generateFinding(
      'SYSVOL share accessible',
      'The SYSVOL share is accessible, which may contain Group Policy Objects and scripts with sensitive data.',
      Severity.HIGH,
      'Group Policy',
      domain,
      'SYSVOL and/or NETLOGON shares found via SMB enumeration',
      'SYSVOL contains GPO files, login scripts, and potentially hardcoded credentials',
      'Restrict SYSVOL access; audit GPO files for embedded credentials',
      ['https://attacktechniques.com/techniques/credential-access/']
    ));
    logVuln('activeDirectory', 'SYSVOL share accessible', 'HIGH');
  }

  // Detect GPO-related DNS records
  try {
    const gpoRecords = await resolveTxt(`_ldap._tcp.${domain}`);
    if (gpoRecords.length > 0) {
      findings.push(generateFinding(
        'LDAP service records expose GPO infrastructure',
        'LDAP SRV records indicate Group Policy infrastructure is present and discoverable.',
        Severity.LOW,
        'Group Policy',
        domain,
        `LDAP records found: ${gpoRecords.length}`,
        'GPO infrastructure visibility aids in policy-based attacks',
        'Restrict DNS record visibility for internal services',
        []
      ));
    }
  } catch {
    // Not found
  }
}

// ─── DNS Domain Information ──────────────────────────────────────────────────

async function enumerateDomainInfo(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // SOA record for domain info
  try {
    const { stdout: soaOut } = await runCmd(`dig +short SOA ${domain}`, 15000);
    if (soaOut) {
      const parts = soaOut.split(/\s+/);
      if (parts.length >= 2) {
        findings.push(generateFinding(
          'Domain SOA record information',
          `SOA record reveals primary nameserver and admin contact information.`,
          Severity.INFO,
          'DNS Security',
          domain,
          `SOA: ${soaOut.trim()}`,
          'SOA records may disclose internal server names and admin contact details',
          'Review SOA record for information leakage',
          []
        ));
      }
    }
  } catch {
    // Not found
  }

  // Check for DNS recursion
  try {
    const { stdout: recOut } = await runCmd(`dig +short +recurse google.com @${domain}`, 15000);
    if (recOut && recOut.includes('.') && !recOut.includes('timed out')) {
      findings.push(generateFinding(
        'DNS recursion enabled',
        `DNS server at ${domain} allows recursive queries, which can be abused for DNS amplification attacks.`,
        Severity.MEDIUM,
        'DNS Security',
        domain,
        `Recursive query to google.com returned: ${recOut.substring(0, 200)}`,
        'Open DNS recursion enables amplification DDoS attacks and information gathering',
        'Restrict recursive queries to authorized clients only',
        ['https://www.acunetix.com/blog/articles/dns-enumeration/']
      ));
      logVuln('activeDirectory', 'DNS recursion enabled', 'MEDIUM');
    }
  } catch {
    // Recursion not available or failed
  }
}

// ─── Impacket LDAP Enumeration ──────────────────────────────────────────────

async function impacketLdapEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Use impacket-ldapsearch for anonymous LDAP enumeration
  const { stdout: ldapOut, ok } = await runCmd(
    `impacket-ldapsearch - "${domain}" -unsafe -dc-ip ${domain} 2>&1 | head -200`,
    45000
  );

  if (ok && ldapOut) {
    // Check for sensitive data in LDAP output
    const sensitivePatterns = [
      { pattern: /userPassword/i, name: 'userPassword attribute', sev: Severity.CRITICAL },
      { pattern: /unicodePwd/i, name: 'unicodePwd attribute', sev: Severity.CRITICAL },
      { pattern: /lmHash/i, name: 'LM hash', sev: Severity.CRITICAL },
      { pattern: /ntHash/i, name: 'NT hash', sev: Severity.CRITICAL },
      { pattern: /supplementalCredentials/i, name: 'supplementalCredentials', sev: Severity.HIGH },
      { pattern: /servicePrincipalName/i, name: 'SPN entries', sev: Severity.MEDIUM },
    ];

    for (const { pattern, name, sev } of sensitivePatterns) {
      if (pattern.test(ldapOut)) {
        findings.push(generateFinding(
          `Impacket LDAP: ${name} exposed`,
          `Anonymous LDAP enumeration via impacket discovered ${name} in directory data.`,
          sev,
          'LDAP Security',
          domain,
          `Pattern "${name}" found in LDAP response (first 200 lines)`,
          `Exposed ${name} enables offline credential attacks`,
          'Disable anonymous LDAP access; require signing and channel binding',
          ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/ldap-signing-and-channel-binding']
        ));
        logVuln('activeDirectory', `Impacket LDAP: ${name}`, sev === Severity.CRITICAL ? 'CRITICAL' : 'HIGH');
      }
    }

    // Check for AdminSDHolder exposure
    if (ldapOut.includes('AdminSDHolder')) {
      findings.push(generateFinding(
        'AdminSDHolder container exposed',
        'The AdminSDHolder container is visible via anonymous LDAP, indicating weak ACL configurations.',
        Severity.HIGH,
        'LDAP Security',
        domain,
        'AdminSDHolder found in LDAP enumeration output',
        'AdminSDHolder exposure indicates potential AD ACL misconfiguration',
        'Review and harden ACLs on AdminSDHolder and protected objects',
        ['https://adsecurity.org/?p=4308']
      ));
    }
  }
}

// ─── Impacket SMB Enumeration ───────────────────────────────────────────────

async function impacketSmbEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Use impacket-smbclient for anonymous/null session SMB enumeration
  const { stdout: smbOut, ok } = await runCmd(
    `impacket-smbclient -list "${domain}" 2>&1 | head -100`,
    30000
  );

  if (ok && smbOut) {
    // Detect shares
    const shareLines = smbOut.split('\n').filter(l => l.includes('Disk') || l.includes('IPC') || l.includes('Print'));
    if (shareLines.length > 0) {
      const shares = shareLines.map(l => l.trim()).join('\n');

      findings.push(generateFinding(
        'SMB shares accessible via anonymous session',
        `Impacket SMB client discovered ${shareLines.length} share(s) via null/anonymous session.`,
        Severity.HIGH,
        'SMB Security',
        domain,
        `Shares:\n${shares}`,
        'Anonymous SMB access exposes file shares and potentially sensitive data',
        'Disable anonymous access; require authentication for all shares',
        ['https://attacktechniques.com/techniques/remote-services/']
      ));
      logVuln('activeDirectory', 'SMB anonymous shares', 'HIGH', `shares=${shareLines.length}`);

      // Check for sensitive share names
      const sensitiveShares = ['backup', 'confidential', 'hr', 'finance', 'admin', 'passwords', 'secrets'];
      for (const share of shareLines) {
        const shareLower = share.toLowerCase();
        for (const sensitive of sensitiveShares) {
          if (shareLower.includes(sensitive)) {
            findings.push(generateFinding(
              `Sensitive SMB share detected: ${sensitive}`,
              `Share "${share.trim()}" appears to contain sensitive data based on its naming convention.`,
              Severity.CRITICAL,
              'SMB Security',
              domain,
              `Share: ${share.trim()}`,
              'Shares with sensitive naming conventions may contain confidential data',
              'Restrict access to sensitive shares; audit file contents',
              []
            ));
            logExploit('activeDirectory', 'Sensitive SMB share', share.trim());
          }
        }
      }
    }

    // Detect null session
    if (smbOut.includes('SMBSessionSetupAndX') || smbOut.includes('Anonymous') || smbOut.includes('null')) {
      findings.push(generateFinding(
        'SMB null session established',
        'Impacket successfully established an anonymous/null SMB session, indicating weak access controls.',
        Severity.CRITICAL,
        'SMB Security',
        domain,
        'Null session established via impacket-smbclient',
        'Null sessions allow attackers to enumerate shares, users, and policies without credentials',
        'Restrict anonymous access; disable null sessions in group policy',
        ['https://attacktechniques.com/techniques/remote-services/']
      ));
      logExploit('activeDirectory', 'SMB null session', domain);
    }
  }

  // Check for SMB signing
  const { stdout: signingOut } = await runCmd(
    `nmap -p 445 --script smb-security-mode -oN - ${domain}`,
    30000
  );

  if (signingOut.includes('signing_disabled') || signingOut.includes('Message signing enabled but not required')) {
    findings.push(generateFinding(
      'SMB signing not required',
      'SMB signing is enabled but not required, allowing potential relay attacks.',
      Severity.HIGH,
      'SMB Security',
      domain,
      'SMB signing status: enabled but not required',
      'SMB signing bypass enables NTLM relay attacks',
      'Require SMB signing via group policy (Domain Controller: RequireSecuritySignature = 1)',
      ['https://attacktechniques.com/techniques/credential-access/']
    ));
  }
}

// ─── Impacket User Enumeration ──────────────────────────────────────────────

async function impacketUserEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Use impacket-enumUsers to enumerate domain users
  const { stdout: userOut, ok } = await runCmd(
    `impacket-enumUsers -dc-ip ${domain} "${domain}" 2>&1 | head -100`,
    45000
  );

  if (ok && userOut) {
    // Count users
    const userLines = userOut.split('\n').filter(l => l.includes('Enabled') || l.includes('RID'));
    if (userLines.length > 0) {
      findings.push(generateFinding(
        'Domain user enumeration successful',
        `Impacket enumerated ${userLines.length} user account(s) from the domain.`,
        Severity.MEDIUM,
        'User Enumeration',
        domain,
        `Users found: ${userLines.length}\nSample: ${userLines.slice(0, 5).join(', ')}`,
        'User enumeration enables targeted brute-force and social engineering attacks',
        'Restrict anonymous user enumeration; implement account lockout policies',
        ['https://attacktechniques.com/techniques/brute-force/']
      ));
      logVuln('activeDirectory', 'User enumeration', 'MEDIUM', `users=${userLines.length}`);
    }

    // Check for admin accounts
    const adminUsers = userOut.match(/admin\w*/gi) || [];
    if (adminUsers.length > 0) {
      findings.push(generateFinding(
        'Administrative accounts discovered',
        `User enumeration identified potential administrative accounts: ${[...new Set(adminUsers)].join(', ')}`,
        Severity.MEDIUM,
        'User Enumeration',
        domain,
        `Admin accounts: ${[...new Set(adminUsers)].join(', ')}`,
        'Knowledge of admin accounts enables targeted attacks',
        'Rename default admin accounts; implement tiered administration',
        []
      ));
    }
  }
}

// ─── Impacket Kerberos Pre-Auth Check ──────────────────────────────────────

async function impacketKerberosCheck(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Use impacket-GetNPUsers for AS-REP roastable accounts (no pre-auth required)
  const { stdout: npOut, ok } = await runCmd(
    `impacket-GetNPUsers "${domain}/" -dc-ip ${domain} -usersfile /dev/null -outputfile /tmp/asrep_hash.txt -format hashcat 2>&1`,
    60000
  );

  if (ok && (npOut.includes('$krb5asrep') || npOut.includes('AS-REP'))) {
    findings.push(generateFinding(
      'AS-REP roastable accounts found via impacket',
      'Impacket GetNPUsers successfully identified accounts without Kerberos pre-authentication.',
      Severity.CRITICAL,
      'Kerberos Security',
      domain,
      `Output: ${npOut.substring(0, 300)}`,
      'AS-REP roastable accounts allow offline password cracking without any credentials',
      'Enable Kerberos pre-authentication for all accounts',
      ['https://attacktechniques.com/techniques/kerberoasting/']
    ));
    logExploit('activeDirectory', 'AS-REP roastable accounts', 'CRITICAL');
  }
}

// ─── Impacket SMB Vulnerability Check ──────────────────────────────────────

async function impacketSmbVulnCheck(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // Check for EternalBlue via nmap script
  const { stdout: ms17Out } = await runCmd(
    `nmap -p 445 --script smb-vuln-ms17-010 -oN - ${domain}`,
    45000
  );

  if (ms17Out.includes('VULNERABLE') || ms17Out.includes('MS17-010')) {
    findings.push(generateFinding(
      'EternalBlue (MS17-010) vulnerability detected',
      'Target is vulnerable to EternalBlue, a critical remote code execution vulnerability.',
      Severity.CRITICAL,
      'Windows Vulnerability',
      domain,
      'Nmap script smb-vuln-ms17-010 confirmed vulnerability',
      'EternalBlue enables remote code execution without authentication (WannaCry, NotPetya)',
      'Apply MS17-010 patch immediately; disable SMBv1',
      ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010']
    ));
    logExploit('activeDirectory', 'EternalBlue (MS17-010)', 'CRITICAL');
  }

  // Check for EternalRomance
  const { stdout: msOut } = await runCmd(
    `nmap -p 445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -oN - ${domain}`,
    45000
  );

  if (msOut.includes('MS08-067')) {
    findings.push(generateFinding(
      'MS08-067 vulnerability detected',
      'Target is vulnerable to MS08-067, a critical Windows Server Service remote code execution vulnerability.',
      Severity.CRITICAL,
      'Windows Vulnerability',
      domain,
      'Nmap confirmed MS08-067 vulnerability',
      'MS08-067 enables remote code execution via crafted RPC requests',
      'Apply MS08-067 security update immediately',
      ['https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067']
    ));
    logExploit('activeDirectory', 'MS08-067', 'CRITICAL');
  }
}

// ─── BloodyAD Enumeration ───────────────────────────────────────────────────

async function bloodyADEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // bloodyAD - Advanced AD enumeration and manipulation
  const { stdout: bloOut, ok } = await runCmd(
    `bloodyAD -d "${domain}" --host "${domain}" get object --filter "(objectClass=user)" --attr sAMAccountName,servicePrincipalName,userAccountControl,memberOf 2>&1 | head -200`,
    60000
  );

  if (ok && bloOut) {
    // Detect Kerberoastable accounts via bloodyAD
    const spnMatches = bloOut.match(/servicePrincipalName: .+/g) || [];
    if (spnMatches.length > 0) {
      findings.push(generateFinding(
        'BloodyAD: Kerberoastable accounts via SPN enumeration',
        `BloodyAD enumerated ${spnMatches.length} account(s) with Service Principal Names set.`,
        Severity.HIGH,
        'Active Directory',
        domain,
        `SPN accounts:\n${spnMatches.slice(0, 10).join('\n')}`,
        'SPN accounts are vulnerable to Kerberoasting - offline password cracking from TGS tickets',
        'Use gMSA accounts; enforce AES-256 encryption; rotate service account passwords',
        ['https://attacktechniques.com/techniques/kerberoasting/']
      ));
      logVuln('activeDirectory', 'BloodyAD: Kerberoastable accounts', 'HIGH', `count=${spnMatches.length}`);
    }

    // Detect accounts with DONT_EXPIRE_PASSWD flag
    const uacMatches = bloOut.match(/userAccountControl: .+/g) || [];
    const dontExpire = uacMatches.filter(l => l.includes('DONT_EXPIRE_PASSWD'));
    if (dontExpire.length > 0) {
      findings.push(generateFinding(
        'BloodyAD: Accounts with non-expiring passwords',
        `BloodyAD found ${dontExpire.length} account(s) with DONT_EXPIRE_PASSWD flag set.`,
        Severity.MEDIUM,
        'Active Directory',
        domain,
        `${dontExpire.length} accounts with non-expiring passwords`,
        'Non-expiring passwords increase risk of credential compromise',
        'Remove DONT_EXPIRE_PASSWD flag; enforce regular password rotation',
        []
      ));
    }

    // Detect sensitive group memberships
    const groupMemberships = bloOut.match(/memberOf: .+/g) || [];
    const sensitiveGroups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators'];
    for (const membership of groupMemberships) {
      for (const group of sensitiveGroups) {
        if (membership.includes(group)) {
          findings.push(generateFinding(
            `BloodyAD: Member of sensitive group - ${group}`,
            `BloodyAD enumeration revealed membership in the highly privileged "${group}" group.`,
            Severity.HIGH,
            'Active Directory',
            domain,
            `Group membership: ${membership}`,
            `Membership in ${group} grants excessive privileges`,
            'Review and minimize group memberships; implement tiered administration',
            ['https://attacktechniques.com/techniques/privileged-account/']
          ));
        }
      }
    }
  }

  // bloodyAD - GPO enumeration
  const { stdout: gpoOut } = await runCmd(
    `bloodyAD -d "${domain}" --host "${domain}" get object --filter "(objectClass=groupPolicyContainer)" --attr displayName,cn,gPCFileSysPath 2>&1 | head -100`,
    45000
  );

  if (gpoOut && (gpoOut.includes('gPCFileSysPath') || gpoOut.includes('displayName'))) {
    findings.push(generateFinding(
      'BloodyAD: GPO enumeration successful',
      'BloodyAD successfully enumerated Group Policy Objects, revealing policy configurations.',
      Severity.MEDIUM,
      'Active Directory',
      domain,
      `GPO data:\n${gpoOut.substring(0, 500)}`,
      'GPO enumeration reveals security policies and potential misconfigurations',
      'Audit GPO configurations for security weaknesses',
      ['https://attacktechniques.com/techniques/persistence/']
    ));
  }

  // bloodyAD - ACL enumeration for privilege escalation paths
  const { stdout: aclOut } = await runCmd(
    `bloodyAD -d "${domain}" --host "${domain}" get object --filter "(objectClass=*)" --attr nTSecurityDescriptor 2>&1 | head -100`,
    60000
  );

  if (aclOut && aclOut.includes('nTSecurityDescriptor')) {
    findings.push(generateFinding(
      'BloodyAD: ACL/ACE enumeration possible',
      'BloodyAD can read security descriptors, potentially revealing privilege escalation paths.',
      Severity.MEDIUM,
      'Active Directory',
      domain,
      'Security descriptors readable via anonymous access',
      'Readable ACLs may expose write permissions enabling privilege escalation',
      'Restrict anonymous LDAP access; enable LAPS; audit ACL configurations',
      ['https://attacktechniques.com/techniques/domain-policy/']
    ));
  }
}

// ─── Ldeep Enumeration ─────────────────────────────────────────────────────

async function ldeepEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // ldeep - LDAP enumeration tool for AD
  const { stdout: ldOut, ok } = await runCmd(
    `ldeep ldap -u anonymous -d "${domain}" -s ldap://${domain} users 2>&1 | head -100`,
    45000
  );

  if (ok && ldOut && ldOut.split('\n').filter(l => l.trim().length > 0).length > 2) {
    const userCount = ldOut.split('\n').filter(l => l.trim().length > 0).length;
    findings.push(generateFinding(
      'Ldeep: Anonymous LDAP user enumeration',
      `Ldeep successfully enumerated ${userCount} user(s) via anonymous LDAP bind.`,
      Severity.MEDIUM,
      'LDAP Security',
      domain,
      `Users found: ${userCount}\nSample: ${ldOut.split('\n').slice(0, 5).join(', ')}`,
      'Anonymous LDAP enumeration enables targeted attacks against discovered accounts',
      'Disable anonymous LDAP access; require LDAP signing',
      ['https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/ldap-signing-and-channel-binding']
    ));
  }

  // ldeep - Group enumeration
  const { stdout: grpOut } = await runCmd(
    `ldeep ldap -u anonymous -d "${domain}" -s ldap://${domain} groups 2>&1 | head -100`,
    45000
  );

  if (grpOut && grpOut.split('\n').filter(l => l.trim().length > 0).length > 0) {
    const groupCount = grpOut.split('\n').filter(l => l.trim().length > 0).length;
    findings.push(generateFinding(
      'Ldeep: Anonymous LDAP group enumeration',
      `Ldeep enumerated ${groupCount} group(s) revealing domain group structure.`,
      Severity.LOW,
      'LDAP Security',
      domain,
      `Groups found: ${groupCount}`,
      'Group enumeration reveals organizational structure and privileged groups',
      'Restrict anonymous LDAP access',
      []
    ));
  }

  // ldeep - Computer enumeration
  const { stdout: compOut } = await runCmd(
    `ldeep ldap -u anonymous -d "${domain}" -s ldap://${domain} computers 2>&1 | head -100`,
    45000
  );

  if (compOut && compOut.split('\n').filter(l => l.trim().length > 0).length > 0) {
    const compCount = compOut.split('\n').filter(l => l.trim().length > 0).length;
    findings.push(generateFinding(
      'Ldeep: Anonymous LDAP computer enumeration',
      `Ldeep enumerated ${compCount} computer(s) from Active Directory.`,
      Severity.LOW,
      'LDAP Security',
      domain,
      `Computers found: ${compCount}\nSample: ${compOut.split('\n').slice(0, 5).join(', ')}`,
      'Computer enumeration reveals network hosts and potential attack targets',
      'Restrict anonymous LDAP access',
      []
    ));
  }
}

// ─── Kerbrute Brute Force ──────────────────────────────────────────────────

async function kerbruteEnum(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // kerbrute - Kerberos pre-auth brute force and user enumeration
  // First check if kerbrute is available
  const { stdout: kbCheck } = await runCmd('which kerbrute 2>&1', 5000);
  if (!kbCheck.includes('/')) {
    errors.push('kerbrute not found, skipping brute force enumeration');
    return;
  }

  // User enumeration via valid Kerberos responses
  const { stdout: kbOut, ok } = await runCmd(
    `kerbrute userenum --dc "${domain}" -d "${domain}" /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt 2>&1 | tail -30`,
    120000
  );

  if (ok && kbOut) {
    const validUsers = (kbOut.match(/\[\+\]/g) || []).length;
    if (validUsers > 0) {
      findings.push(generateFinding(
        `Kerbrute: ${validUsers} valid user(s) enumerated`,
        `Kerbrute successfully enumerated ${validUsers} valid user account(s) via Kerberos pre-authentication.`,
        Severity.MEDIUM,
        'Kerberos Security',
        domain,
        `Valid users found: ${validUsers}\nOutput:\n${kbOut.substring(kbOut.length - 500)}`,
        'Valid user enumeration enables targeted brute-force attacks and AS-REP/Kerberoasting',
        'Implement account lockout policies; monitor for unusual authentication patterns',
        ['https://attacktechniques.com/techniques/brute-force/']
      ));
      logVuln('activeDirectory', 'Kerbrute: Valid users', 'MEDIUM', `users=${validUsers}`);
    }

    // Check for lockout detection
    if (kbOut.includes('Account lockout') || kbOut.includes('LOCKED')) {
      findings.push(generateFinding(
        'Kerbrute: Account lockout policy detected',
        'Kerbrute detected account lockout during brute force attempts, indicating lockout policy is active.',
        Severity.INFO,
        'Kerberos Security',
        domain,
        'Lockout policy detected during brute force enumeration',
        'Lockout policies provide protection against brute force attacks',
        'Verify lockout threshold is appropriate (recommended: 5-10 attempts)',
        []
      ));
    }
  }
}

// ─── BloodHound CE Collection ──────────────────────────────────────────────

async function bloodhoundCollect(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  // bloodhound-ce-collector - Collects AD data for BloodHound analysis
  const { stdout: bhOut, ok } = await runCmd(
    `bloodhound-ce-collector -d "${domain}" -c All --zip 2>&1 | tail -30`,
    120000
  );

  if (ok && bhOut) {
    // Check for successful collection
    if (bhOut.includes('BloodHound') || bhOut.includes('collection') || bhOut.includes('json')) {
      findings.push(generateFinding(
        'BloodHound CE: AD data collection completed',
        'BloodHound CE successfully collected Active Directory data for attack path analysis.',
        Severity.MEDIUM,
        'Active Directory',
        domain,
        `Collection output:\n${bhOut.substring(bhOut.length - 500)}`,
        'BloodHound data reveals attack paths, privilege escalation chains, and lateral movement opportunities',
        'Use BloodHound to identify and remediate attack paths; implement tiered administration',
        ['https://attacktechniques.com/techniques/domain-policy/']
      ));
      logVuln('activeDirectory', 'BloodHound collection', 'MEDIUM');

      // Analyze BloodHound output for critical paths
      if (bhOut.includes(' shortest paths to Domain Admin') || bhOut.includes('Shortest Paths')) {
        findings.push(generateFinding(
          'BloodHound: Attack paths to Domain Admin detected',
          'BloodHound analysis found attack paths that can lead to Domain Admin compromise.',
          Severity.CRITICAL,
          'Active Directory',
          domain,
          'BloodHound identified attack paths to Domain Admin',
          'Attack paths to DA enable full domain compromise',
          'Remediate identified attack paths; implement tiered administration; deploy LAPS',
          ['https://attacktechniques.com/techniques/privilege-escalation/']
        ));
        logExploit('activeDirectory', 'BloodHound: DA attack paths', 'CRITICAL');
      }

      if (bhOut.includes('Kerberoastable Users') || bhOut.includes('kerberoast')) {
        findings.push(generateFinding(
          'BloodHound: Kerberoastable users identified',
          'BloodHound found users with SPNs set, vulnerable to Kerberoasting.',
          Severity.HIGH,
          'Active Directory',
          domain,
          'BloodHound Kerberoastable Users query returned results',
          'Kerberoasting enables offline password cracking of service accounts',
          'Use gMSA accounts; enforce strong service account passwords; enable AES-only',
          ['https://attacktechniques.com/techniques/kerberoasting/']
        ));
      }

      if (bhOut.includes('AS-REP Roastable') || bhOut.includes('asrep')) {
        findings.push(generateFinding(
          'BloodHound: AS-REP roastable accounts identified',
          'BloodHound found accounts without Kerberos pre-authentication enabled.',
          Severity.CRITICAL,
          'Active Directory',
          domain,
          'BloodHound AS-REP Roastable query returned results',
          'AS-REP Roasting enables offline password cracking without any credentials',
          'Enable Kerberos pre-authentication for all accounts',
          ['https://attacktechniques.com/techniques/kerberoasting/']
        ));
      }

      if (bhOut.includes('DCSync') || bhOut.includes('dcsync')) {
        findings.push(generateFinding(
          'BloodHound: DCSync attack path detected',
          'BloodHound identified accounts with DCSync privileges (Replicating Directory Changes).',
          Severity.CRITICAL,
          'Active Directory',
          domain,
          'BloodHound found DCSync-capable accounts',
          'DCSync allows extraction of all domain credentials including krbtgt',
          'Audit and restrict DS-Replication-Get-Changes privileges; monitor for replication',
          ['https://attacktechniques.com/techniques/credential-access/']
        ));
        logExploit('activeDirectory', 'BloodHound: DCSync path', 'CRITICAL');
      }
    }
  }

  // Also check for BloodHound JSON output files
  const { stdout: lsOut } = await runCmd('ls /tmp/*.json 2>/dev/null | head -10', 5000);
  if (lsOut && lsOut.includes('.json')) {
    findings.push(generateFinding(
      'BloodHound: JSON data files available',
      'BloodHound collected AD data in JSON format for detailed analysis.',
      Severity.INFO,
      'Active Directory',
      domain,
      `JSON files: ${lsOut.trim()}`,
      'BloodHound JSON data enables in-depth attack path analysis',
      'Load data into BloodHound GUI for visualization and remediation planning',
      []
    ));
  }
}

// ─── Main Scan Function ──────────────────────────────────────────────────────

export async function runADScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  logInfo('activeDirectory', `Starting Active Directory enumeration for ${domain}`);

  try {
    // Phase 1: DNS-based enumeration
    logInfo('activeDirectory', 'Phase 1: DNS SRV record enumeration');
    const adHosts = await enumerateSRVRecords(domain, findings, errors);

    // Phase 2: Zone transfer attempt
    logInfo('activeDirectory', 'Phase 2: DNS zone transfer attempt');
    const subdomains = await attemptZoneTransfer(domain, findings, errors);
    if (subdomains.length > 0) {
      findings.push(generateFinding(
        'DNS zone transfer revealed subdomains',
        `Zone transfer disclosed ${subdomains.length} subdomain(s): ${subdomains.slice(0, 10).join(', ')}${subdomains.length > 10 ? '...' : ''}`,
        Severity.CRITICAL,
        'DNS Zone Transfer',
        domain,
        `Subdomains: ${subdomains.slice(0, 20).join(', ')}`,
        'Full subdomain enumeration exposes internal hosts and services',
        'Disable unauthorized zone transfers',
        []
      ));
    }

    // Phase 3: SPN / Kerberoasting detection
    logInfo('activeDirectory', 'Phase 3: SPN and Kerberoasting detection');
    await detectSPNs(domain, findings, errors);

    // Phase 4: Kerberos analysis
    logInfo('activeDirectory', 'Phase 4: Kerberos service analysis');
    await analyzeKerberos(domain, findings, errors);

    // Phase 5: Trust relationship detection
    logInfo('activeDirectory', 'Phase 5: Trust relationship detection');
    await detectTrusts(domain, findings, errors);

    // Phase 6: GPO / SYSVOL enumeration
    logInfo('activeDirectory', 'Phase 6: GPO and SYSVOL enumeration');
    await enumerateGPO(domain, findings, errors);

    // Phase 7: Domain info
    logInfo('activeDirectory', 'Phase 7: Domain information gathering');
    await enumerateDomainInfo(domain, findings, errors);

    // Phase 8: Impacket LDAP enumeration
    logInfo('activeDirectory', 'Phase 8: Impacket LDAP enumeration');
    await impacketLdapEnum(domain, findings, errors);

    // Phase 9: Impacket SMB enumeration
    logInfo('activeDirectory', 'Phase 9: Impacket SMB enumeration');
    await impacketSmbEnum(domain, findings, errors);

    // Phase 10: Impacket user enumeration
    logInfo('activeDirectory', 'Phase 10: Impacket user enumeration');
    await impacketUserEnum(domain, findings, errors);

    // Phase 11: Impacket Kerberos pre-auth check
    logInfo('activeDirectory', 'Phase 11: Impacket Kerberos pre-auth check');
    await impacketKerberosCheck(domain, findings, errors);

    // Phase 12: BloodyAD enumeration
    logInfo('activeDirectory', 'Phase 12: BloodyAD enumeration');
    await bloodyADEnum(domain, findings, errors);

    // Phase 13: Ldeep LDAP enumeration
    logInfo('activeDirectory', 'Phase 13: Ldeep LDAP enumeration');
    await ldeepEnum(domain, findings, errors);

    // Phase 14: Kerbrute user enumeration
    logInfo('activeDirectory', 'Phase 14: Kerbrute user enumeration');
    await kerbruteEnum(domain, findings, errors);

    // Phase 15: BloodHound CE collection
    logInfo('activeDirectory', 'Phase 15: BloodHound CE data collection');
    await bloodhoundCollect(domain, findings, errors);

    // Phase 16: SMB vulnerability checks
    logInfo('activeDirectory', 'Phase 16: SMB vulnerability checks');
    await impacketSmbVulnCheck(domain, findings, errors);

    const duration = Date.now() - startTime;
    logDone('activeDirectory', `AD enumeration completed — ${findings.length} finding(s)`, duration, findings.length);

    return { module: 'activeDirectory', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    const msg = error instanceof Error ? error.message : String(error);
    logWarn('activeDirectory', `AD scan failed: ${msg}`);
    return {
      module: 'activeDirectory',
      findings,
      duration,
      errors: [...errors, msg],
    };
  }
}

export async function runADEnum(domain: string): Promise<ScanResult> {
  return runADScan(domain);
}
