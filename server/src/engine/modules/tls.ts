import * as tls from 'tls';
import * as https from 'https';
import * as http from 'http';
import * as net from 'net';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon', 'MD5', 'SEED', 'IDEA', 'CAMELLIA'];
const STRONG_KEY_EXCHANGES = ['ECDHE', 'DHE', 'X25519', 'X448'];

interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  subjectAltName?: string[];
  keyUsage?: string[];
  basicConstraints?: string;
  signatureAlgorithm?: string;
  publicKey?: { type: string; size?: number };
  raw?: Buffer;
}

function parseCertField(field: tls.Certificate | string | undefined): Record<string, string> {
  if (!field || typeof field === 'string') return {};
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(field)) {
    if (typeof value === 'string') result[key] = value;
  }
  return result;
}

async function probeSSLVersion(host: string, port: number, protocol: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let resolved = false;

    const done = (result: boolean) => {
      if (!resolved) {
        resolved = true;
        try { socket.destroy(); } catch {}
        resolve(result);
      }
    };

    socket.setTimeout(5000);
    socket.on('connect', () => {
      try {
        const tlsSocket = tls.connect({
          socket,
          servername: host,
          rejectUnauthorized: false,
          secureProtocol: protocol as any,
        } as any);
        tlsSocket.on('secureConnect', () => done(true));
        tlsSocket.on('error', () => done(false));
        tlsSocket.on('timeout', () => done(false));
      } catch {
        done(false);
      }
    });
    socket.on('error', () => done(false));
    socket.on('timeout', () => done(false));
    socket.connect(port, host);
  });
}

async function fetchUrl(url: string, timeout = 10000): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout }, (res) => {
      let body = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 1048576) { req.destroy(); reject(new Error('Response too large')); return; }
        body += chunk.toString();
      });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

export async function runTlsScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // === TLS CONNECT + Certificate Analysis ===
    let certInfo: CertificateInfo | null = null;
    let negotiatedProtocol = '';
    let cipherSuite = '';

    try {
      const certData = await new Promise<{
        cert: tls.PeerCertificate;
        protocol: string;
        cipher: { name: string; version: string };
      }>((resolve, reject) => {
        const socket = tls.connect({
          host: domain,
          port: 443,
          rejectUnauthorized: false,
          servername: domain,
          timeout: 10000,
        } as any);

        socket.on('secureConnect', () => {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol() || '';
          const cipher = socket.getCipher();
          socket.destroy();
          if (!cert || !cert.subject) {
            reject(new Error('No certificate presented'));
          } else {
            resolve({ cert, protocol, cipher });
          }
        });
        socket.on('error', reject);
        socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS handshake timeout')); });
      });

      negotiatedProtocol = certData.protocol;
      cipherSuite = certData.cipher.name;
      const cert = certData.cert;

      certInfo = {
        subject: parseCertField(cert.subject),
        issuer: parseCertField(cert.issuer),
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        serialNumber: cert.serialNumber,
        fingerprint256: cert.fingerprint256,
        subjectAltName: cert.subjectaltname?.split(',').map(s => s.trim()),
        publicKey: (cert as any).pubkey ? { type: 'RSA', size: (cert as any).bits } : undefined,
      };

      // Check for self-signed (issuer === subject)
      const isSelfSigned = certInfo.subject.CN === certInfo.issuer.CN &&
        certInfo.subject.O === certInfo.issuer.O &&
        certInfo.subject.OU === certInfo.issuer.OU;

      if (isSelfSigned) {
        findings.push(generateFinding(
          'Self-signed certificate',
          'The TLS certificate is self-signed, meaning it was not issued by a trusted Certificate Authority.',
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          "Subject: " + (certInfo.subject.CN || 'N/A') + ", Issuer: " + (certInfo.issuer.CN || 'N/A'),
          'Self-signed certificates trigger browser warnings and indicate lack of proper certificate management',
          'Obtain a certificate from a trusted Certificate Authority (e.g., Let\'s Encrypt)',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

      // Check expiration
      const now = new Date();
      const expiry = new Date(certInfo.validTo);
      const daysUntilExpiry = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry <= 0) {
        findings.push(generateFinding(
          'Certificate expired',
          "The TLS certificate expired " + Math.abs(daysUntilExpiry) + " days ago.",
          Severity.CRITICAL,
          'TLS/HTTPS',
          domain,
          "Expired on: " + certInfo.validTo + "",
          'Expired certificates cause browser warnings, break HTTPS, and may indicate abandoned infrastructure',
          'Renew the certificate immediately using your CA dashboard',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      } else if (daysUntilExpiry <= 30) {
        findings.push(generateFinding(
          'Certificate expiring within 30 days',
          "The TLS certificate will expire in " + daysUntilExpiry + " days.",
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          "Expires: " + certInfo.validTo + "",
          'Certificates expiring soon risk service disruption if not renewed',
          'Set up automatic certificate renewal (e.g., certbot with cron)',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      } else if (daysUntilExpiry <= 90) {
        findings.push(generateFinding(
          'Certificate expiring within 90 days',
          "The TLS certificate will expire in " + daysUntilExpiry + " days.",
          Severity.MEDIUM,
          'TLS/HTTPS',
          domain,
          "Expires: " + certInfo.validTo + "",
          'Plan certificate renewal to avoid last-minute issues',
          'Schedule certificate renewal and test the process',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

      // Check key size
      if (certInfo.publicKey?.size) {
        const keySize = certInfo.publicKey.size;
        if (keySize < 2048) {
          findings.push(generateFinding(
            'Weak certificate key size',
            "The certificate uses a " + keySize + "-bit key, which is below the recommended minimum of 2048 bits.",
            Severity.HIGH,
            'TLS/HTTPS',
            domain,
            "Key size: " + keySize + " bits",
            "A " + keySize + "-bit key can be brute-forced with modern computing resources",
            'Generate a new certificate with at least a 2048-bit RSA key or 256-bit ECDSA key',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
    } else if (keySize < 4096) {
          findings.push(generateFinding(
            'Certificate key size below 4096 bits',
            'The certificate uses a ' + keySize + '-bit key. While 2048-bit is acceptable, 4096-bit provides stronger long-term security.',
            Severity.LOW,
            'TLS/HTTPS',
            domain,
            'Key size: ' + keySize + ' bits',
            'Larger keys provide better resistance against advances in computing power',
            'Consider upgrading to 4096-bit RSA for high-security environments',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
        }
      }

      // Check signature algorithm
      const sigAlg = (certData.cert as any).signatureAlgorithm || '';
      if (sigAlg.includes('sha1') || sigAlg.includes('SHA-1')) {
        findings.push(generateFinding(
          'Certificate uses SHA-1 signature',
          'The certificate is signed with SHA-1, which is cryptographically weak and deprecated.',
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          "Signature algorithm: " + sigAlg + "",
          'SHA-1 collision attacks are practical; browsers have deprecated SHA-1 certificates',
          'Renew the certificate with SHA-256 or stronger signature algorithm',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

      // Check wildcard certificate
      const cn = certInfo.subject.CN || '';
      if (cn.startsWith('*.')) {
        findings.push(generateFinding(
          'Wildcard certificate detected',
          'The certificate is a wildcard certificate. While common, wildcard certificates increase the blast radius if the private key is compromised.',
          Severity.INFO,
          'TLS/HTTPS',
          domain,
          "Common Name: " + cn + "",
          'A compromised wildcard key grants access to all subdomains',
          'Consider using individual certificates for high-security subdomains',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('timeout') || msg.includes('TIMEOUT')) {
        findings.push(generateFinding(
          'No HTTPS (connection timeout)',
          'Could not establish a TLS connection to port 443; the connection timed out.',
          Severity.CRITICAL,
          'TLS/HTTPS',
          domain,
          'Port 443 connection timed out',
          'Without HTTPS, all traffic is transmitted in plaintext and vulnerable to interception',
          'Enable HTTPS on port 443 with a valid TLS certificate',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      } else {
        findings.push(generateFinding(
          'No HTTPS (connection error)',
          "Could not establish a TLS connection: " + msg + "",
          Severity.CRITICAL,
          'TLS/HTTPS',
          domain,
          msg,
          'Without HTTPS, all traffic is transmitted in plaintext and vulnerable to interception',
          'Enable HTTPS on port 443 with a valid TLS certificate',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    }

    // === Protocol Version Checks ===
    if (negotiatedProtocol) {
      if (negotiatedProtocol === 'TLSv1' || negotiatedProtocol === 'TLSv1.1') {
        findings.push(generateFinding(
          'Outdated TLS version',
          "The server negotiated " + negotiatedProtocol + ", which is deprecated and has known vulnerabilities.",
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          "Negotiated protocol: " + negotiatedProtocol + "",
          "" + negotiatedProtocol + " is vulnerable to BEAST, POODLE, and other attacks. Only TLS 1.2+ should be used.",
          'Disable TLSv1.0 and TLSv1.1 in server configuration',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

      if (negotiatedProtocol === 'TLSv1.2') {
        findings.push(generateFinding(
          'TLS 1.2 in use (not TLS 1.3)',
          'The server negotiated TLS 1.2. While still secure, TLS 1.3 offers improved performance and security.',
          Severity.INFO,
          'TLS/HTTPS',
          domain,
          `Negotiated protocol: TLS 1.2`,
          'TLS 1.3 removes legacy cipher suites and reduces handshake latency',
          'Consider enabling TLS 1.3 if supported by the server',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    }

    // === SSLv2/SSLv3 Probe ===
    try {
      const hasSSLv2 = await probeSSLVersion(domain, 443, 'SSLv2_method');
      if (hasSSLv2) {
        findings.push(generateFinding(
          'SSLv2 enabled',
          'The server accepts SSLv2 connections, which has critical vulnerabilities (DROWN attack).',
          Severity.CRITICAL,
          'TLS/HTTPS',
          domain,
          'SSLv2 handshake succeeded',
          'SSLv2 is completely broken and allows decryption of captured traffic',
          'Disable SSLv2 immediately in server configuration',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    } catch {}

    try {
      const hasSSLv3 = await probeSSLVersion(domain, 443, 'SSLv3_method');
      if (hasSSLv3) {
        findings.push(generateFinding(
          'SSLv3 enabled',
          'The server accepts SSLv3 connections, which is vulnerable to POODLE attack.',
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          'SSLv3 handshake succeeded',
          'SSLv3 is deprecated and vulnerable to padding oracle attacks',
          'Disable SSLv3 in server configuration',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    } catch {}

    // === Cipher Suite Analysis ===
    if (cipherSuite) {
      const hasWeakCipher = WEAK_CIPHERS.some(weak => cipherSuite.toUpperCase().includes(weak));
      if (hasWeakCipher) {
        findings.push(generateFinding(
          'Weak cipher suite negotiated',
          "The server negotiated a weak cipher suite: " + cipherSuite + "",
          Severity.HIGH,
          'TLS/HTTPS',
          domain,
          "Cipher suite: " + cipherSuite + "",
          'Weak ciphers can be broken to decrypt intercepted traffic',
          'Configure the server to only support strong cipher suites (AES-GCM, CHACHA20)',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }

      // Check for forward secrecy
      const hasForwardSecrecy = STRONG_KEY_EXCHANGES.some(ke => cipherSuite.includes(ke));
      if (!hasForwardSecrecy && cipherSuite) {
        findings.push(generateFinding(
          'Forward secrecy not detected',
          "The negotiated cipher suite (" + cipherSuite + ") does not appear to use forward secrecy.",
          Severity.MEDIUM,
          'TLS/HTTPS',
          domain,
          "Cipher suite: " + cipherSuite + "",
          'Without forward secrecy, a compromised server key can decrypt all past traffic',
          'Configure ECDHE or DHE key exchange to enable forward secrecy',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    }

    // === HTTP to HTTPS Redirect ===
    try {
      const httpResult = await fetchUrl("http://" + domain + "", 8000);
      const location = httpResult.headers.location || '';

      if (httpResult.statusCode >= 300 && httpResult.statusCode < 400) {
        if (!location.toLowerCase().startsWith('https://')) {
          findings.push(generateFinding(
            'HTTP to HTTPS redirect misconfigured',
            "The HTTP server redirects, but not to HTTPS (redirects to: " + location + ").",
            Severity.MEDIUM,
            'TLS/HTTPS',
            domain,
            "Status: " + httpResult.statusCode + ", Location: " + location,
            'Users may not be redirected to the secure version of the site',
            'Configure the redirect to point to the HTTPS URL',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
        }
      } else if (httpResult.statusCode === 200) {
        findings.push(generateFinding(
          'No HTTP to HTTPS redirect',
          'The HTTP version of the site returns a 200 response instead of redirecting to HTTPS.',
          Severity.MEDIUM,
          'TLS/HTTPS',
          domain,
          "HTTP status: " + httpResult.statusCode + "",
          'Users may access the site over insecure HTTP without being redirected',
          'Configure a 301 redirect from HTTP to HTTPS',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      }
    } catch (e) {
      // HTTP connection failure is acceptable - may not have port 80 open
    }

    // === HSTS Header Check ===
    try {
      const httpsResult = await fetchUrl("https://" + domain + "", 8000);
      const hstsHeader = httpsResult.headers['strict-transport-security'] as string;

      if (!hstsHeader) {
        findings.push(generateFinding(
          'Missing Strict-Transport-Security header',
          'The HTTPS response does not include the HSTS header.',
          Severity.MEDIUM,
          'TLS/HTTPS',
          domain,
          'No Strict-Transport-Security header found',
          'Without HSTS, browsers may allow users to access the site over HTTP',
          'Add Strict-Transport-Security header with max-age of at least 31536000',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
        ));
      } else {
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
        if (maxAge < 31536000) {
          findings.push(generateFinding(
            'HSTS max-age too short',
            "The HSTS max-age is " + maxAge + " seconds, which is below the recommended minimum of 31536000 (1 year).",
            Severity.LOW,
            'TLS/HTTPS',
            domain,
            "HSTS max-age: " + maxAge + "",
            'A short max-age reduces HSTS protection effectiveness',
            'Set HSTS max-age to at least 31536000 (1 year)',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
        }

        if (!hstsHeader.toLowerCase().includes('includesubdomains')) {
          findings.push(generateFinding(
            'HSTS missing includeSubDomains',
            'The HSTS header does not include the includeSubDomains directive.',
            Severity.LOW,
            'TLS/HTTPS',
            domain,
            "HSTS header: " + hstsHeader + "",
            'Subdomains may not be protected by HSTS',
            'Add includeSubDomains to the HSTS header',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
        }

        if (hstsHeader.toLowerCase().includes('preload')) {
          findings.push(generateFinding(
            'HSTS preload directive present',
            'The domain includes the HSTS preload directive. Verify the domain is submitted to the HSTS preload list.',
            Severity.INFO,
            'TLS/HTTPS',
            domain,
            'HSTS preload directive found',
            'The preload directive only works if the domain is submitted to browser preload lists',
            'Verify submission at https://hstspreload.org',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_for_Weak_TLS_Ciphers']
          ));
        }
      }
    } catch {}

    // AI-enhanced TLS analysis
    if (certInfo) {
      try {
        const { getAI } = await import('../../services/ai.service');
        const ai = getAI();
        const tlsAnalysis = await ai.analyzeTls({
          subject: certInfo.subject.CN || '',
          issuer: certInfo.issuer.CN || '',
          validFrom: certInfo.validFrom,
          validTo: certInfo.validTo,
          sans: certInfo.subjectAltName || [],
          protocol: negotiatedProtocol,
          cipher: cipherSuite,
        }, domain);
        if (tlsAnalysis.findings.length > 0) {
          for (const f of tlsAnalysis.findings) {
            findings.push(generateFinding(
              f.title || 'AI TLS Finding',
              f.description || '',
              (f.severity as Severity) || Severity.LOW,
              'TLS/HTTPS',
              domain,
              f.remediation || '',
              f.impact || '',
              f.remediation || '',
              []
            ));
          }
        }
      } catch {}
    }

    const duration = Date.now() - startTime;
    return {
      module: 'tls',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'tls',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
