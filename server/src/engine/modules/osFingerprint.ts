import * as net from 'net';
import * as tls from 'tls';
import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from '../modules/shared';

interface BannerInfo {
  service: string;
  banner: string;
  version?: string;
  os?: string;
  port: number;
}

// Well-known port to service mapping
const PORT_SERVICE_MAP: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPCBind',
  135: 'MSRPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  9200: 'Elasticsearch',
  27017: 'MongoDB',
};

// Banner grabbing patterns
const BANNER_PATTERNS: Record<string, { pattern: RegExp; name: string; versionGroup?: number; osGroup?: number }> = {
  SSH: {
    pattern: /SSH-([\d.]+)-?((?:OpenSSH|dropbear|libssh)[\d.]*)?/,
    name: 'OpenSSH',
    versionGroup: 2,
  },
  FTP: {
    pattern: /(vsftpd|proftpd|Pure-FTPd|FileZilla|WU-FTPD|ProFTPD)[\s\/]?([\d.]+)?/i,
    name: 'FTP Server',
    versionGroup: 2,
  },
  SMTP: {
    pattern: /(?:220|250)[\s-]+((?:Postfix|Exim|Sendmail|Microsoft ESMTP|Google|Amazon SES)[\s\/]?[\d.]*)/i,
    name: 'SMTP Server',
  },
  HTTP: {
    pattern: /(Apache|Nginx|IIS|LiteSpeed|Caddy|Cherokee|lighttpd|Jetty|WebLogic|Tomcat|Gunicorn|uWSGI|Phusion Passenger)[\s\/]?([\d.]+)?/i,
    name: 'Web Server',
    versionGroup: 2,
  },
  MySQL: {
    pattern: /([\d.]+)-((?:MariaDB|MySQL|Percona)[\s\/]?[\d.]*)/i,
    name: 'MySQL/MariaDB',
  },
  PostgreSQL: {
    pattern: /PostgreSQL[\s\/]?([\d.]+)/i,
    name: 'PostgreSQL',
    versionGroup: 1,
  },
  Redis: {
    pattern: /redis_version:([\d.]+)/i,
    name: 'Redis',
    versionGroup: 1,
  },
  MongoDB: {
    pattern: /MongoDB[\s\/]?([\d.]+)/i,
    name: 'MongoDB',
    versionGroup: 1,
  },
  VNC: {
    pattern: /RFB[\s\/]?([\d.]+)/i,
    name: 'VNC',
    versionGroup: 1,
  },
  Telnet: {
    pattern: /(?:欢迎|Welcome|login|Login)[\s:]+(.+)/i,
    name: 'Telnet',
  },
};

// TCP/IP fingerprinting - analyze response patterns
interface TcpFingerprint {
  initialTtl: number;
  windowSize: number;
  options: string[];
  mss?: number;
  dfBit: boolean;
  pushFlag: boolean;
  ttlGuess: string;
}

function tcpFingerprintToOs(fp: TcpFingerprint): { os: string; confidence: 'high' | 'medium' | 'low' } {
  // Simplified OS fingerprinting based on TCP/IP stack behavior
  const ttl = fp.initialTtl;
  const window = fp.windowSize;

  // TTL-based OS detection
  let osGuess = 'Unknown';
  if (ttl <= 64) {
    osGuess = 'Linux/Unix/macOS';
  } else if (ttl <= 128) {
    osGuess = 'Windows';
  } else if (ttl <= 255) {
    osGuess = 'Network Device (Router/Switch)';
  }

  // Window size refinement
  if (window === 5840 || window === 5792 || window === 8760) {
    if (osGuess.includes('Linux')) {
      return { os: 'Linux (Ubuntu/CentOS)', confidence: 'high' };
    }
  }
  if (window === 8192 || window === 16384 || window === 65535) {
    if (osGuess.includes('Windows')) {
      return { os: 'Windows Server', confidence: 'medium' };
    }
  }

  // MSS-based detection
  if (fp.mss === 1460) {
    return { os: osGuess === 'Unknown' ? 'Linux/Unix' : osGuess, confidence: 'medium' };
  }
  if (fp.mss === 1440) {
    return { os: 'Windows (Azure/Cloud)', confidence: 'low' };
  }
  if (fp.mss === 1380) {
    return { os: 'VPN/Tunnel Interface', confidence: 'low' };
  }

  return { os: osGuess, confidence: osGuess === 'Unknown' ? 'low' : 'medium' };
}

// Grab banner from a port
function grabBanner(host: string, port: number, timeout: number = 5000): Promise<BannerInfo | null> {
  return new Promise((resolve) => {
    const service = PORT_SERVICE_MAP[port] || `Port ${port}`;
    const socket = new net.Socket();

    socket.setTimeout(timeout);

    socket.connect(port, host, () => {
      // For HTTP/HTTPS ports, send a request
      if (port === 80 || port === 8080) {
        socket.write(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`);
      } else if (port === 443 || port === 8443) {
        // For TLS ports, try TLS handshake
        try {
          const tlsSocket = tls.connect({
            host,
            port,
            servername: host,
            rejectUnauthorized: false,
          }, () => {
            const cert = tlsSocket.getPeerCertificate();
            const cipher = tlsSocket.getCipher();
            tlsSocket.end();
            socket.destroy();
            const cn = cert?.subject?.CN;
            resolve({
              service: 'HTTPS',
              banner: `TLS ${cipher?.version || 'Unknown'} - ${cipher?.name || 'Unknown'}`,
              version: Array.isArray(cn) ? cn[0] : cn,
              port,
            });
          });
          tlsSocket.on('error', () => {
            socket.destroy();
            resolve(null);
          });
        } catch {
          socket.destroy();
          resolve(null);
        }
        return;
      }
    });

    let bannerData = Buffer.alloc(0);
    socket.on('data', (data: Buffer) => {
      bannerData = Buffer.concat([bannerData, data]);
      // If we got a response, wait a bit more for more data
      if (bannerData.length > 0) {
        setTimeout(() => {
          socket.destroy();
          const banner = bannerData.toString('ascii').trim();
          const parsed = BANNER_PATTERNS.HTTP?.pattern.exec(banner);
          resolve({
            service,
            banner: banner.substring(0, 512),
            version: parsed?.[2],
            port,
          });
        }, 500);
      }
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

// TCP/IP stack fingerprinting - simplified version using HTTP header analysis
function tcpStackFingerprint(host: string, port: number): Promise<TcpFingerprint | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(5000);

    socket.connect(port, host, () => {
      socket.write('HEAD / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n');

      let responseData = Buffer.alloc(0);
      socket.on('data', (data: Buffer) => {
        responseData = Buffer.concat([responseData, data]);
      });

      setTimeout(() => {
        socket.destroy();
        const response = responseData.toString('ascii');
        const fingerprint: TcpFingerprint = {
          initialTtl: 64,
          windowSize: 65535,
          options: [],
          dfBit: true,
          pushFlag: true,
          ttlGuess: 'Unknown',
        };

        // Infer OS from Server header
        const serverMatch = response.match(/Server:\s*(.+)/i);
        if (serverMatch) {
          const server = serverMatch[1].trim().toLowerCase();
          if (server.includes('apache') || server.includes('nginx') || server.includes('caddy')) {
            fingerprint.ttlGuess = 'Linux/Unix';
          } else if (server.includes('iis') || server.includes('microsoft')) {
            fingerprint.ttlGuess = 'Windows';
          }
        }

        resolve(fingerprint);
      }, 2000);
    });

    socket.on('error', () => {
      socket.destroy();
      resolve(null);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve(null);
    });
  });
}

// Check HTTP headers for server info
function checkHttpHeaders(host: string): Promise<Record<string, string>> {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: host,
      port: 443,
      path: '/',
      method: 'HEAD',
      rejectUnauthorized: false,
      timeout: 8000,
    }, (res) => {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(res.headers)) {
        if (typeof value === 'string') {
          headers[key.toLowerCase()] = value;
        } else if (Array.isArray(value)) {
          headers[key.toLowerCase()] = value.join(', ');
        }
      }
      res.destroy();
      resolve(headers);
    });

    req.on('error', () => resolve({}));
    req.on('timeout', () => { req.destroy(); resolve({}); });
    req.end();
  });
}

// Analyze HTTP headers for technology fingerprinting
function analyzeHttpHeaders(headers: Record<string, string>): { technologies: string[]; securityIssues: string[] } {
  const technologies: string[] = [];
  const securityIssues: string[] = [];

  // Server header analysis
  const server = headers['server'] || '';
  if (server) {
    technologies.push(`Server: ${server}`);

    // Check for outdated versions
    const apacheMatch = server.match(/Apache\/([\d.]+)/);
    if (apacheMatch) {
      const version = apacheMatch[1];
      const parts = version.split('.').map(Number);
      if (parts[0] < 2 || (parts[0] === 2 && parts[1] < 4)) {
        securityIssues.push(`Outdated Apache version: ${version}`);
      }
    }

    const nginxMatch = server.match(/nginx\/([\d.]+)/);
    if (nginxMatch) {
      const version = nginxMatch[1];
      const parts = version.split('.').map(Number);
      if (parts[0] < 1 || (parts[0] === 1 && parts[1] < 20)) {
        securityIssues.push(`Outdated Nginx version: ${version}`);
      }
    }
  }

  // X-AspNet-Version analysis
  const aspNetVersion = headers['x-aspnet-version'];
  if (aspNetVersion) {
    technologies.push(`ASP.NET: ${aspNetVersion}`);
    securityIssues.push('X-AspNet-Version header exposes version information');
  }

  // X-Generator analysis
  const generator = headers['x-generator'];
  if (generator) {
    technologies.push(`Generator: ${generator}`);
  }

  return { technologies, securityIssues };
}

// Check for information leakage in error pages
async function checkErrorPageLeakage(host: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  const errorPaths = [
    '/nonexistent-page-12345',
    '/error',
    '/debug',
    '/test',
    '/api/invalid',
  ];

  for (const path of errorPaths) {
    try {
      const result = await new Promise<{ statusCode: number; body: string }>((resolve) => {
        const req = https.request({
          hostname: host,
          port: 443,
          path,
          method: 'GET',
          rejectUnauthorized: false,
          timeout: 5000,
        }, (res) => {
          let body = '';
          res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
          res.on('end', () => resolve({ statusCode: res.statusCode || 0, body }));
        });
        req.on('error', () => resolve({ statusCode: 0, body: '' }));
        req.on('timeout', () => { req.destroy(); resolve({ statusCode: 0, body: '' }); });
        req.end();
      });

      // Check for technology disclosure in error pages
      const techLeaks = [
        { pattern: /Apache\/[\d.]+/i, name: 'Apache version' },
        { pattern: /nginx\/[\d.]+/i, name: 'Nginx version' },
        { pattern: /PHP[\s\/]?[\d.]+/i, name: 'PHP version' },
        { pattern: /ASP\.NET[\s\/]?[\d.]+/i, name: 'ASP.NET version' },
        { pattern: /Express[\s\/]?[\d.]+/i, name: 'Express version' },
        { pattern: /Node\.js[\s\/]?[\d.]+/i, name: 'Node.js version' },
        { pattern: /Python[\s\/]?[\d.]+/i, name: 'Python version' },
        { pattern: /Ruby[\s\/]?[\d.]+/i, name: 'Ruby version' },
        { pattern: /JSP[\s\/]?[\d.]+/i, name: 'JSP version' },
      ];

      for (const leak of techLeaks) {
        if (leak.pattern.test(result.body)) {
          findings.push(generateFinding(
            `Technology version disclosed in error page`,
            `The error page at ${path} leaks ${leak.name}.`,
            Severity.MEDIUM, 'Information Disclosure', host,
            `Path: ${path}\nLeaked: ${leak.name}`,
            'Technology versions help attackers target known vulnerabilities',
            'Configure custom error pages that do not reveal technology details',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
          break;
        }
      }

      // Check for stack traces
      const stackTracePatterns = [
        /at\s+[\w.]+\s+\([\w.]+:\d+:\d+\)/,
        /File "\/[\w\/]+\.py"/,
        /Traceback \(most recent call last\)/,
        /Exception in thread/i,
        /Server Error in .+ Application/i,
        /Microsoft .NET Framework Version/i,
      ];

      for (const pattern of stackTracePatterns) {
        if (pattern.test(result.body)) {
          findings.push(generateFinding(
            'Stack trace exposed in error page',
            `The error page at ${path} reveals a stack trace.`,
            Severity.HIGH, 'Information Disclosure', host,
            `Path: ${path}\nStack trace pattern detected`,
            'Stack traces reveal internal application structure and code paths',
            'Configure custom error pages and disable debug mode in production',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
          break;
        }
      }
    } catch {}
  }

  return findings;
}

export async function runOsFingerprintScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // === Banner Grabbing on Key Ports ===
    const portsToCheck = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443];
    const banners: BannerInfo[] = [];

    for (const port of portsToCheck) {
      try {
        const banner = await grabBanner(domain, port, 4000);
        if (banner) {
          banners.push(banner);

          // Analyze banner for security issues
          const bannerStr = banner.banner.toLowerCase();

          // Check for telnet
          if (port === 23) {
            findings.push(generateFinding(
              'Telnet service detected',
              `A Telnet service is running on port 23.`,
              Severity.HIGH, 'Service Detection', domain,
              `Port 23: Telnet detected`,
              'Telnet transmits data in cleartext including credentials',
              'Replace Telnet with SSH for secure remote access',
              ['https://www.ssh.com/ssh/telnet']
            ));
          }

          // Check for FTP
          if (port === 21) {
            if (bannerStr.includes('ftp')) {
              findings.push(generateFinding(
                'FTP service detected',
                `An FTP service is running on port 21.`,
                Severity.MEDIUM, 'Service Detection', domain,
                `Port 21: ${banner.banner}`,
                'FTP transmits data in cleartext',
                'Use SFTP or FTPS instead of plain FTP',
                ['https://filezilla-project.org/']
              ));
            }
          }

          // Check for Redis without auth
          if (port === 6379) {
            if (bannerStr.includes('redis') && !bannerStr.includes('auth')) {
              findings.push(generateFinding(
                'Redis service potentially without authentication',
                `Redis service detected on port 6379 without apparent authentication.`,
                Severity.CRITICAL, 'Service Detection', domain,
                `Port 6379: ${banner.banner}`,
                'Unauthenticated Redis can be exploited for RCE',
                'Enable Redis authentication and bind to localhost',
                ['https://redis.io/docs/management/security/']
              ));
            }
          }

          // Check for MongoDB without auth
          if (port === 27017) {
            findings.push(generateFinding(
              'MongoDB service detected',
              `MongoDB service detected on port 27017.`,
              Severity.HIGH, 'Service Detection', domain,
              `Port 27017: MongoDB detected`,
              'MongoDB is often configured without authentication by default',
              'Enable MongoDB authentication and restrict network access',
              ['https://www.mongodb.com/docs/manual/core/security/']
            ));
          }

          // Check for MSSQL
          if (port === 1433) {
            findings.push(generateFinding(
              'MSSQL service detected',
              `Microsoft SQL Server detected on port 1433.`,
              Severity.HIGH, 'Service Detection', domain,
              `Port 1433: MSSQL detected`,
              'Database services should not be directly accessible from the internet',
              'Restrict MSSQL to internal network only',
              []
            ));
          }

          // Check for MySQL
          if (port === 3306) {
            findings.push(generateFinding(
              'MySQL service exposed',
              `MySQL service detected on port 3306.`,
              Severity.HIGH, 'Service Detection', domain,
              `Port 3306: MySQL detected`,
              'Database services should not be directly accessible from the internet',
              'Restrict MySQL to internal network only',
              []
            ));
          }
        }
      } catch {}
    }

    // === TCP/IP Stack Fingerprinting ===
    try {
      const tcpFp = await tcpStackFingerprint(domain, 443);
      if (tcpFp) {
        const osInfo = tcpFingerprintToOs(tcpFp);
        if (osInfo.os !== 'Unknown') {
          findings.push(generateFinding(
            'Operating system fingerprinted',
            `TCP/IP stack analysis suggests: ${osInfo.os}`,
            Severity.INFO, 'Service Detection', domain,
            `OS guess: ${osInfo.os}\nConfidence: ${osInfo.confidence}`,
            'OS information helps attackers target platform-specific exploits',
            'Consider using a CDN or reverse proxy to hide origin server details',
            []
          ));
        }
      }
    } catch {}

    // === HTTP Header Analysis ===
    try {
      const headers = await checkHttpHeaders(domain);
      const headerAnalysis = analyzeHttpHeaders(headers);

      for (const tech of headerAnalysis.technologies) {
        findings.push(generateFinding(
          'Technology identified via HTTP headers',
          `HTTP header reveals technology: ${tech}`,
          Severity.INFO, 'Service Detection', domain,
          `Header info: ${tech}`,
          'Technology identification helps attackers target known vulnerabilities',
          'Remove unnecessary headers that expose technology information',
          []
        ));
      }

      for (const issue of headerAnalysis.securityIssues) {
        findings.push(generateFinding(
          'HTTP header security issue',
          issue,
          Severity.MEDIUM, 'Information Disclosure', domain,
          `Issue: ${issue}`,
          'Exposed information aids attackers',
          'Remove or customize headers to hide technology details',
          []
        ));
      }
    } catch {}

    // === Error Page Leakage ===
    try {
      const errorFindings = await checkErrorPageLeakage(domain);
      findings.push(...errorFindings);
    } catch {}

    // === Service Version Analysis ===
    for (const banner of banners) {
      if (banner.version) {
        // Check for known vulnerable versions
        const versionLower = banner.banner.toLowerCase();

        // Apache version checks
        if (versionLower.includes('apache')) {
          const match = banner.banner.match(/Apache\/([\d.]+)/);
          if (match) {
            const version = match[1];
            const parts = version.split('.').map(Number);
            if (parts[0] < 2 || (parts[0] === 2 && parts[1] < 4)) {
              findings.push(generateFinding(
                'Severely outdated Apache version',
                `Apache ${version} is end-of-life and has known vulnerabilities.`,
                Severity.CRITICAL, 'Service Detection', domain,
                `Detected version: ${version}`,
                'Outdated Apache versions have multiple known CVEs',
                'Upgrade to the latest Apache 2.4.x version',
                ['https://httpd.apache.org/security/vulnerabilities_24.html']
              ));
            }
          }
        }

        // Nginx version checks
        if (versionLower.includes('nginx')) {
          const match = banner.banner.match(/nginx\/([\d.]+)/);
          if (match) {
            const version = match[1];
            const parts = version.split('.').map(Number);
            if (parts[0] < 1 || (parts[0] === 1 && parts[1] < 20)) {
              findings.push(generateFinding(
                'Outdated Nginx version',
                `Nginx ${version} may contain known vulnerabilities.`,
                Severity.HIGH, 'Service Detection', domain,
                `Detected version: ${version}`,
                'Older Nginx versions have known security issues',
                'Upgrade to the latest stable Nginx version',
                ['https://nginx.org/en/security_advisories.html']
              ));
            }
          }
        }

        // SSH version checks
        if (banner.service === 'SSH') {
          const match = banner.banner.match(/SSH-[\d.]+-?(OpenSSH[\s\/]?[\d.]+)/);
          if (match) {
            const version = match[1];
            const versionNum = parseFloat(version.replace(/[^\d.]/g, ''));
            if (versionNum < 7.0) {
              findings.push(generateFinding(
                'Outdated OpenSSH version',
                `OpenSSH ${version} is outdated and may have vulnerabilities.`,
                Severity.HIGH, 'Service Detection', domain,
                `SSH banner: ${banner.banner}`,
                'Older OpenSSH versions have known vulnerabilities',
                'Upgrade to the latest OpenSSH version',
                ['https://www.openssh.com/security.html']
              ));
            }
          }
        }
      }
    }

    const duration = Date.now() - startTime;
    return { module: 'osFingerprint', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'osFingerprint', findings, duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
