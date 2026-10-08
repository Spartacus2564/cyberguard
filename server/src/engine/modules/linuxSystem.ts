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

// ─── SSH Security Analysis ────────────────────────────────────────────────────
async function scanSsh(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 ${domain}`,
      45000
    );

    if (!output) return;

    // Detect weak algorithms
    const weakAlgos = [
      'diffie-hellman-group1-sha1',
      'diffie-hellman-group14-sha1',
      'ssh-dss',
      'arcfour',
      'arcfour128',
      'arcfour256',
      '3des-cbc',
      'blowfish-cbc',
      'cast128-cbc',
      'hmac-md5',
      'hmac-sha1-96',
    ];

    const foundAlgos = weakAlgos.filter(a => output.toLowerCase().includes(a));
    if (foundAlgos.length > 0) {
      findings.push(generateFinding(
        'SSH weak algorithms supported',
        `SSH server supports weak algorithms: ${foundAlgos.join(', ')}. These algorithms are considered cryptographically insecure.`,
        Severity.HIGH, 'Linux System', domain,
        `Weak algorithms: ${foundAlgos.join(', ')}`,
        'Weak algorithms can be exploited for man-in-the-middle attacks and data decryption',
        'Disable weak algorithms in SSH server configuration',
        ['https://infosec.mozilla.org/guidelines/openssh']
      ));
    }

    // Detect auth methods
    if (output.includes('password') && !output.includes('publickey')) {
      findings.push(generateFinding(
        'SSH password authentication enabled without publickey',
        'SSH server allows password authentication without requiring public key authentication.',
        Severity.MEDIUM, 'Linux System', domain,
        'SSH auth: password (publickey not enforced)',
        'Password authentication is vulnerable to brute-force attacks',
        'Enforce public key authentication; disable password authentication',
        ['https://www.ssh.com/ssh/public-key-authentication']
      ));
    }

    if (output.includes('keyboard-interactive')) {
      findings.push(generateFinding(
        'SSH keyboard-interactive authentication enabled',
        'Keyboard-interactive authentication is enabled, which may allow brute-force attacks.',
        Severity.MEDIUM, 'Linux System', domain,
        'SSH auth: keyboard-interactive',
        'Keyboard-interactive auth can be exploited for brute-force attacks',
        'Disable keyboard-interactive authentication; use public key only',
        ['https://www.ssh.com/ssh/tutorials/ssh-keygen']
      ));
    }

    // Host key type
    const hostKeyMatch = output.match(/ssh-(\w+)\s+(\d+)/);
    if (hostKeyMatch) {
      const keyType = hostKeyMatch[1];
      const keySize = parseInt(hostKeyMatch[2]);
      if (keyType === 'rsa' && keySize < 2048) {
        findings.push(generateFinding(
          'SSH RSA host key too short',
          `SSH RSA host key is only ${keySize} bits. Minimum recommended is 2048 bits.`,
          Severity.HIGH, 'Linux System', domain,
          `SSH host key: ${hostKeyMatch[0]}`,
          'Short RSA keys can be factored, compromising host identity verification',
          'Generate a new host key with at least 2048-bit RSA or use Ed25519',
          ['https://infosec.mozilla.org/guidelines/openssh']
        ));
      }
      if (keyType === 'dsa') {
        findings.push(generateFinding(
          'SSH DSA host key used',
          'SSH server uses DSA host key, which is deprecated and insecure.',
          Severity.HIGH, 'Linux System', domain,
          `SSH host key: ${hostKeyMatch[0]}`,
          'DSA keys are deprecated due to weaknesses in the algorithm',
          'Replace DSA key with RSA (2048+) or Ed25519',
          ['https://infosec.mozilla.org/guidelines/openssh']
        ));
      }
    }
  } catch (e) {
    errors.push(`SSH scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── FTP Security Analysis ────────────────────────────────────────────────────
async function scanFtp(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p 21 ${domain}`,
      45000
    );

    if (!output) return;

    // Anonymous FTP
    if (output.includes('Anonymous FTP login allowed') || output.includes('Anon')) {
      findings.push(generateFinding(
        'Anonymous FTP access enabled',
        'The FTP server allows anonymous login, which can expose sensitive files.',
        Severity.HIGH, 'Linux System', domain,
        'FTP anonymous access: allowed',
        'Anonymous FTP can expose sensitive data and is a compliance violation',
        'Disable anonymous FTP access; require authentication',
        ['https://www.rfc-editor.org/rfc/rfc2577']
      ));
    }

    // FTP bounce
    if (output.includes('FTP bounce') || output.includes('PORT')) {
      findings.push(generateFinding(
        'FTP bounce attack possible',
        'The FTP server may be vulnerable to bounce attacks, allowing port scanning through the FTP server.',
        Severity.MEDIUM, 'Linux System', domain,
        'FTP bounce: possible',
        'FTP bounce attacks can be used for port scanning and bypassing firewalls',
        'Disable PORT command or restrict FTP bounce functionality',
        ['https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/ftp-bounce-attack/']
      ));
    }

    // Backdoor detection
    if (output.includes('VULNERABLE') || output.includes('backdoor')) {
      findings.push(generateFinding(
        'FTP backdoor vulnerability detected',
        'The FTP server appears to have a known backdoor vulnerability.',
        Severity.CRITICAL, 'Linux System', domain,
        'FTP backdoor: VULNERABLE',
        'FTP backdoors allow unauthenticated remote code execution',
        'Immediately update or replace the vulnerable FTP server',
        ['https://www.cvedetails.com/cve/CVE-2011-2523/']
      ));
    }

    // Version detection
    if (output.includes('vsftpd')) {
      findings.push(generateFinding(
        'vsftpd detected',
        'The vsftpd FTP server is running. Ensure it is up to date.',
        Severity.INFO, 'Linux System', domain,
        'FTP server: vsftpd',
        'vsftpd versions before 2.3.4 contained a backdoor',
        'Ensure vsftpd is updated to the latest version',
        ['https://security.appspot.com/vsftpd.html']
      ));
    }
  } catch (e) {
    errors.push(`FTP scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Web Server Security ──────────────────────────────────────────────────────
async function scanWebServer(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script http-enum,http-headers,http-methods,http-title,http-server-header -p 80,443,8080,8443 ${domain}`,
      60000
    );

    if (!output) return;

    // Directory enumeration
    const dirMatches = output.match(/\|\s+\/\S+/g) || [];
    const sensitiveDirs = dirMatches.filter(d =>
      /admin|backup|config|database|\.git|\.env|phpmyadmin|wp-admin|server-status|cgi-bin/i.test(d)
    );

    if (sensitiveDirs.length > 0) {
      findings.push(generateFinding(
        'Sensitive web directories discovered',
        `HTTP enumeration found sensitive directories: ${sensitiveDirs.join(', ')}.`,
        Severity.HIGH, 'Linux System', domain,
        `Directories: ${sensitiveDirs.join(', ')}`,
        'Exposed sensitive directories can leak configuration, credentials, and source code',
        'Restrict access to sensitive directories; remove from production',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/']
      ));
    }

    // Security headers
    if (output.includes('X-Frame-Options') && output.includes('SAMEORIGIN')) {
      // Good - X-Frame-Options is set
    } else if (!output.includes('X-Frame-Options')) {
      findings.push(generateFinding(
        'Missing X-Frame-Options header',
        'The web server does not set the X-Frame-Options header, allowing clickjacking attacks.',
        Severity.MEDIUM, 'Linux System', domain,
        'X-Frame-Options: not set',
        'Without X-Frame-Options, the site is vulnerable to clickjacking',
        'Add X-Frame-Options: DENY or SAMEORIGIN header',
        ['https://owasp.org/www-project-secure-headers/']
      ));
    }

    // HTTP methods
    if (output.includes('PUT') || output.includes('DELETE') || output.includes('TRACE')) {
      findings.push(generateFinding(
        'Dangerous HTTP methods enabled',
        'The web server supports dangerous HTTP methods (PUT/DELETE/TRACE).',
        Severity.MEDIUM, 'Linux System', domain,
        'HTTP methods: PUT/DELETE/TRACE detected',
        'Dangerous HTTP methods can allow file upload, deletion, and cross-site tracing',
        'Disable unnecessary HTTP methods; restrict to GET, POST, HEAD only',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
      ));
    }

    if (output.includes('TRACE') && output.includes('TRACE method')) {
      findings.push(generateFinding(
        'HTTP TRACE method enabled',
        'The TRACE method is enabled, which can be exploited for cross-site tracing (XST) attacks.',
        Severity.HIGH, 'Linux System', domain,
        'HTTP TRACE: enabled',
        'TRACE method enables cross-site tracing attacks against cookies',
        'Disable TRACE method on the web server',
        ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1567']
      ));
    }
  } catch (e) {
    errors.push(`Web server scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Database Exposure ────────────────────────────────────────────────────────
async function scanDatabases(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap -p 3306,5432,6379,27017,9200 ${domain} -sV`,
      60000
    );

    if (!output) return;

    // MySQL
    if (output.includes('3306/tcp') && output.includes('open')) {
      const versionMatch = output.match(/3306\/tcp.*?MySQL ([\d.]+)/i);
      findings.push(generateFinding(
        `MySQL service exposed${versionMatch ? ` (version ${versionMatch[1]})` : ''}`,
        'MySQL database is accessible from the network.',
        Severity.HIGH, 'Linux System', domain,
        `MySQL exposed: ${versionMatch ? versionMatch[1] : 'version unknown'}`,
        'Exposed MySQL can be exploited for unauthorized data access and privilege escalation',
        'Restrict MySQL to localhost; use firewall rules to limit access',
        ['https://dev.mysql.com/doc/refman/8.0/en/security-against-attack.html']
      ));
    }

    // PostgreSQL
    if (output.includes('5432/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'PostgreSQL service exposed',
        'PostgreSQL database is accessible from the network.',
        Severity.HIGH, 'Linux System', domain,
        'PostgreSQL exposed on port 5432',
        'Exposed PostgreSQL can be exploited for unauthorized data access',
        'Restrict PostgreSQL to localhost; configure pg_hba.conf for network access',
        ['https://www.postgresql.org/docs/current/auth-pg-hba-conf.html']
      ));
    }

    // Redis
    if (output.includes('6379/tcp') && output.includes('open')) {
      const noAuth = !output.includes('AUTH') && !output.includes('NOAUTH');
      if (noAuth) {
        findings.push(generateFinding(
          'Redis service exposed without authentication',
          'Redis is accessible without authentication, allowing unauthorized data access and command execution.',
          Severity.CRITICAL, 'Linux System', domain,
          'Redis: no authentication detected',
          'Unauthenticated Redis can be exploited for remote code execution',
          'Enable Redis authentication (requirepass); bind to localhost only',
          ['https://redis.io/docs/management/security/']
        ));
      } else {
        findings.push(generateFinding(
          'Redis service exposed',
          'Redis database is accessible from the network.',
          Severity.MEDIUM, 'Linux System', domain,
          'Redis exposed on port 6379',
          'Network-accessible Redis increases attack surface',
          'Bind Redis to localhost; restrict network access via firewall',
          ['https://redis.io/docs/management/security/']
        ));
      }
    }

    // MongoDB
    if (output.includes('27017/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'MongoDB service exposed',
        'MongoDB is accessible from the network.',
        Severity.CRITICAL, 'Linux System', domain,
        'MongoDB exposed on port 27017',
        'MongoDB without authentication can expose entire databases',
        'Enable MongoDB authentication; bind to localhost',
        ['https://www.mongodb.com/docs/manual/core/security/']
      ));
    }

    // Elasticsearch
    if (output.includes('9200/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'Elasticsearch service exposed',
        'Elasticsearch is accessible from the network without apparent authentication.',
        Severity.CRITICAL, 'Linux System', domain,
        'Elasticsearch exposed on port 9200',
        'Unauthenticated Elasticsearch can expose sensitive search data',
        'Enable Elasticsearch security features; restrict network access',
        ['https://www.elastic.co/guide/en/elasticsearch/reference/current/security.html']
      ));
    }
  } catch (e) {
    errors.push(`Database scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Mail Service Analysis ────────────────────────────────────────────────────
async function scanMail(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script smtp-open-relay,smtp-enum-users,pop3-capabilities,imap-capabilities -p 25,587,143,993,110,995 ${domain}`,
      45000
    );

    if (!output) return;

    // SMTP open relay
    if (output.includes('Server may be an open relay') || output.includes('OPEN RELAY')) {
      findings.push(generateFinding(
        'SMTP open relay detected',
        'The SMTP server appears to be configured as an open relay, allowing spam and phishing.',
        Severity.CRITICAL, 'Linux System', domain,
        'SMTP: open relay detected',
        'Open relays can be exploited for spam, phishing, and email spoofing',
        'Configure SMTP relay authentication; restrict relay to authenticated users only',
        ['https://www.postfix.org/DEBUG_README.html#open_relay']
      ));
    }

    // SMTP user enumeration
    if (output.includes('EXPN') || output.includes('VRFY')) {
      findings.push(generateFinding(
        'SMTP user enumeration possible',
        'SMTP server supports VRFY or EXPN commands, allowing user enumeration.',
        Severity.MEDIUM, 'Linux System', domain,
        'SMTP: VRFY/EXPN commands available',
        'User enumeration helps attackers craft targeted brute-force attacks',
        'Disable VRFY and EXPN commands on the SMTP server',
        ['https://www.postfix.org/postconf.5.html#disable_vrfy_command']
      ));
    }

    // IMAP/POP3 without TLS
    if (output.includes('143/tcp') && output.includes('open') && !output.includes('993/tcp')) {
      findings.push(generateFinding(
        'IMAP service without TLS',
        'IMAP is running on port 143 without an encrypted alternative (port 993).',
        Severity.MEDIUM, 'Linux System', domain,
        'IMAP: port 143 open, port 993 not detected',
        'Unencrypted IMAP transmits credentials and data in plaintext',
        'Enable IMAPS (port 993) and disable unencrypted IMAP',
        ['https://www.cyberciti.biz/faq/how-to-configure-ssl-tls-for-postfix-imap-dovecot/']
      ));
    }

    if (output.includes('110/tcp') && output.includes('open') && !output.includes('995/tcp')) {
      findings.push(generateFinding(
        'POP3 service without TLS',
        'POP3 is running on port 110 without an encrypted alternative (port 995).',
        Severity.MEDIUM, 'Linux System', domain,
        'POP3: port 110 open, port 995 not detected',
        'Unencrypted POP3 transmits credentials and data in plaintext',
        'Enable POP3S (port 995) and disable unencrypted POP3',
        ['https://www.cyberciti.biz/faq/how-to-configure-ssl-tls-for-postfix-imap-dovecot/']
      ));
    }
  } catch (e) {
    errors.push(`Mail scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── DNS Security ─────────────────────────────────────────────────────────────
async function scanDns(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script dns-recursion,dns-zone-transfer,dnssec-dnskey -p 53 ${domain}`,
      45000
    );

    if (!output) return;

    // Zone transfer
    if (output.includes('Zone Transfer successful') || output.includes('XFR size')) {
      findings.push(generateFinding(
        'DNS zone transfer allowed',
        'The DNS server allows zone transfers, which can expose the entire DNS zone to attackers.',
        Severity.HIGH, 'Linux System', domain,
        'DNS zone transfer: allowed',
        'Zone transfers expose all DNS records including internal hosts',
        'Restrict zone transfers to authorized secondary DNS servers',
        ['https://www.acunetix.com/blog/articles/dns-zone-transfers-axfr/']
      ));
    }

    // Recursion
    if (output.includes('Recursion') && output.includes('available')) {
      findings.push(generateFinding(
        'DNS recursion enabled',
        'The DNS server allows recursive queries, which can be used for amplification attacks.',
        Severity.MEDIUM, 'Linux System', domain,
        'DNS recursion: enabled',
        'Open DNS recursion can be exploited for DDoS amplification attacks',
        'Restrict DNS recursion to authorized clients',
        ['https://www.acunetix.com/blog/articles/dns-enumeration/']
      ));
    }

    // DNSSEC
    if (output.includes('DNSKEY') && !output.includes('RRSIG')) {
      findings.push(generateFinding(
        'DNSSEC partially configured',
        'DNSKEY records exist but RRSIG records are missing, indicating incomplete DNSSEC.',
        Severity.MEDIUM, 'Linux System', domain,
        'DNSSEC: DNSKEY without RRSIG',
        'Incomplete DNSSEC does not protect against DNS spoofing',
        'Complete DNSSEC configuration with proper key signing',
        ['https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en']
      ));
    }
  } catch (e) {
    errors.push(`DNS scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── SSL/TLS Vulnerabilities ─────────────────────────────────────────────────
async function scanSslVulns(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap --script ssl-heartbleed,ssl-drown,ssl-poodle,ssl-ccs-injection,ssl-cert -p 443,8443 ${domain}`,
      60000
    );

    if (!output) return;

    // Heartbleed
    if (output.includes('VULNERABLE') && output.includes('heartbleed')) {
      findings.push(generateFinding(
        'Heartbleed vulnerability (CVE-2014-0160) detected',
        'The server is vulnerable to Heartbleed, allowing memory disclosure and private key theft.',
        Severity.CRITICAL, 'Linux System', domain,
        'Heartbleed: VULNERABLE',
        'Heartbleed allows reading server memory including private keys and credentials',
        'Immediately update OpenSSL to patched version; regenerate SSL certificates',
        ['https://www.heartbleed.com/']
      ));
    }

    // DROWN
    if (output.includes('VULNERABLE') && output.includes('drown')) {
      findings.push(generateFinding(
        'DROWN vulnerability (CVE-2016-0800) detected',
        'The server is vulnerable to DROWN attack via SSLv2.',
        Severity.CRITICAL, 'Linux System', domain,
        'DROWN: VULNERABLE',
        'DROWN allows decryption of TLS traffic by exploiting SSLv2',
        'Disable SSLv2; ensure private keys are not shared across servers',
        ['https://drownattack.com/']
      ));
    }

    // POODLE
    if (output.includes('VULNERABLE') && output.includes('poodle')) {
      findings.push(generateFinding(
        'POODLE vulnerability (CVE-2014-3566) detected',
        'The server is vulnerable to POODLE attack via SSLv3.',
        Severity.HIGH, 'Linux System', domain,
        'POODLE: VULNERABLE',
        'POODLE allows decryption of SSLv3 traffic',
        'Disable SSLv3; use TLS 1.2 or higher',
        ['https://www.openssl.org/~bodo/ssl-poodle.pdf']
      ));
    }

    // CRIME
    if (output.includes('compression')) {
      findings.push(generateFinding(
        'TLS compression enabled (CRIME vulnerability)',
        'TLS compression is enabled, which can be exploited via the CRIME attack.',
        Severity.HIGH, 'Linux System', domain,
        'TLS compression: enabled',
        'CRIME attack can decrypt TLS cookies by observing compression patterns',
        'Disable TLS compression in the server configuration',
        ['https://threatpost.com/crime-attack-uses-compression-to-break-tls/120237/']
      ));
    }

    // Ticketbleed
    if (output.includes('ticketbleed') || output.includes('session ticket')) {
      findings.push(generateFinding(
        'Ticketbleed vulnerability indicator',
        'Potential Ticketbleed (CVE-2016-9244) indicator detected.',
        Severity.HIGH, 'Linux System', domain,
        'Ticketbleed: potential indicator',
        'Ticketbleed can leak memory contents through session tickets',
        'Update SSL/TLS library; disable session tickets if not needed',
        ['https://ticketbleed.com/']
      ));
    }

    // Check for SSLv3 support in output
    if (output.includes('SSLv3')) {
      findings.push(generateFinding(
        'SSLv3 supported',
        'The server supports SSLv3, which has known vulnerabilities.',
        Severity.HIGH, 'Linux System', domain,
        'SSLv3: supported',
        'SSLv3 is deprecated and vulnerable to POODLE attack',
        'Disable SSLv3; enforce TLS 1.2 minimum',
        ['https://www.ssllabs.com/ssltest/']
      ));
    }
  } catch (e) {
    errors.push(`SSL scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Container/Cloud Detection ────────────────────────────────────────────────
async function scanContainers(domain: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const output = await runCommand(
      `nmap -p 2375,2376,6443,10250,10255,27017,5000,9090 ${domain} -sV`,
      45000
    );

    if (!output) return;

    // Docker API
    if (output.includes('2375/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'Docker API exposed',
        'Docker daemon API is accessible on port 2375 (unencrypted).',
        Severity.CRITICAL, 'Linux System', domain,
        'Docker API: port 2375 open',
        'Exposed Docker API allows container escape and host compromise',
        'Enable Docker TLS; restrict Docker socket access',
        ['https://docs.docker.com/engine/security/']
      ));
    }

    if (output.includes('2376/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'Docker API exposed with TLS',
        'Docker daemon API with TLS is accessible on port 2376.',
        Severity.HIGH, 'Linux System', domain,
        'Docker API: port 2376 open',
        'Even with TLS, Docker API should not be internet-accessible',
        'Restrict Docker API access to internal management networks',
        ['https://docs.docker.com/engine/security/']
      ));
    }

    // Kubernetes API
    if (output.includes('6443/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'Kubernetes API server exposed',
        'Kubernetes API server is accessible externally.',
        Severity.CRITICAL, 'Linux System', domain,
        'Kubernetes API: port 6443 open',
        'Exposed Kubernetes API can allow full cluster compromise',
        'Restrict Kubernetes API to authorized networks; enable RBAC',
        ['https://kubernetes.io/docs/concepts/security/overview/']
      ));
    }

    // Kubernetes kubelet
    if (output.includes('10250/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'Kubernetes kubelet API exposed',
        'Kubelet API is accessible externally, allowing container exec and file access.',
        Severity.CRITICAL, 'Linux System', domain,
        'Kubelet API: port 10250 open',
        'Exposed kubelet allows arbitrary command execution in containers',
        'Disable kubelet read-only/port; enable authentication',
        ['https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/']
      ));
    }

    // etcd
    if (output.includes('2379/tcp') && output.includes('open')) {
      findings.push(generateFinding(
        'etcd service exposed',
        'etcd is accessible externally, potentially exposing cluster secrets.',
        Severity.CRITICAL, 'Linux System', domain,
        'etcd: port 2379 open',
        'Exposed etcd contains all Kubernetes secrets and configuration',
        'Enable etcd client certificate authentication; restrict access',
        ['https://etcd.io/docs/latest/security/']
      ));
    }

    // Cloud metadata
    const cloudCheck = await runCommand(
      `curl -sk --max-time 5 http://169.254.169.254/latest/meta-data/ 2>/dev/null`,
      10000
    );

    if (cloudCheck && cloudCheck.length > 10) {
      findings.push(generateFinding(
        'Cloud metadata endpoint accessible',
        'The AWS/GCP/Azure metadata endpoint is accessible, which can be exploited via SSRF.',
        Severity.CRITICAL, 'Linux System', domain,
        `Cloud metadata: ${cloudCheck.substring(0, 200)}`,
        'Metadata endpoints expose instance credentials and configuration',
        'Use IMDSv2; block SSRF paths; restrict metadata access',
        ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html']
      ));
    }
  } catch (e) {
    errors.push(`Container scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────
export async function runLinuxScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await scanSsh(domain, findings, errors);
    await scanFtp(domain, findings, errors);
    await scanWebServer(domain, findings, errors);
    await scanDatabases(domain, findings, errors);
    await scanMail(domain, findings, errors);
    await scanDns(domain, findings, errors);
    await scanSslVulns(domain, findings, errors);
    await scanContainers(domain, findings, errors);

    const duration = Date.now() - startTime;
    return { module: 'linuxSystem', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'linuxSystem',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

// ─── Wrapper for MODULE_RUNNERS ───────────────────────────────────────────────
export async function runLinuxScanWrapper(domain: string): Promise<ScanResult> {
  return runLinuxScan(domain);
}
