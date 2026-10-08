import * as tls from 'tls';
import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from '../modules/shared';

interface CertInfo {
  subject: any;
  issuer: any;
  validFrom: Date;
  validTo: Date;
  fingerprint256: string;
  serialNumber: string;
  subjectAltName?: string[];
}

// Fetch certificate details using TLS handshake
function getCertInfo(hostname: string, port: number = 443, timeout: number = 10000): Promise<CertInfo | null> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout,
    }, () => {
      const cert = socket.getPeerCertificate(true) as any;
      socket.end();

      if (!cert || !cert.subject) {
        resolve(null);
        return;
      }

      // Parse subject alt names
      const altNames: string[] = [];
      if (cert.subjectaltname) {
        const sans = cert.subjectaltname.split(',');
        for (const san of sans) {
          altNames.push(san.trim().replace(/^DNS:/, '').replace(/^IP Address:/, ''));
        }
      }

      resolve({
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: new Date(cert.valid_from),
        validTo: new Date(cert.valid_to),
        fingerprint256: cert.fingerprint256 || '',
        serialNumber: cert.serialNumber || '',
        subjectAltName: altNames,
      });
    });

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

// Check for OCSP stapling
function checkOcspStapling(hostname: string, port: number = 443): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false,
      ALPNProtocols: ['http/1.1'],
    }, () => {
      try {
        const ocspResponse = (socket as any).getOCSPResponse?.();
        socket.end();
        resolve(ocspResponse && ocspResponse.length > 0);
      } catch {
        socket.end();
        resolve(false);
      }
    });

    socket.on('error', () => resolve(false));
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

// Check HTTP/2 support
function checkHttp2(hostname: string): Promise<{ supported: boolean; protocol?: string }> {
  return new Promise((resolve) => {
    // First do TLS handshake to check ALPN
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'],
      timeout: 8000,
    }, () => {
      const alpn = (socket as any).alpnProtocol;
      socket.end();
      resolve({
        supported: alpn === 'h2',
        protocol: alpn || undefined,
      });
    });

    socket.on('error', () => resolve({ supported: false }));
    socket.on('timeout', () => { socket.destroy(); resolve({ supported: false }); });
  });
}

// Check HTTP/3 (QUIC) support
function checkHttp3(hostname: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = https.request({
      hostname,
      port: 443,
      path: '/',
      method: 'HEAD',
      rejectUnauthorized: false,
      timeout: 8000,
    }, (res) => {
      const altSvc = res.headers['alt-svc'];
      res.destroy();
      resolve(!!altSvc && String(altSvc).includes('h3'));
    });

    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

// Check SNI support
function checkSni(hostname: string, port: number = 443): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: 8000,
    }, () => {
      const protocol = socket.getProtocol();
      socket.end();
      resolve(!!protocol);
    });

    socket.on('error', () => resolve(false));
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

// Cipher suite analysis
interface CipherInfo {
  name: string;
  protocol: string;
  bits: number;
  isAead: boolean;
  forwardSecrecy: boolean;
}

function analyzeCipherSuites(hostname: string, port: number = 443): Promise<CipherInfo[]> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false,
    }, () => {
      const cipher = socket.getCipher();
      socket.end();

      if (cipher) {
        resolve([{
          name: cipher.name,
          protocol: cipher.version || 'unknown',
          bits: 0, // bits not available in CipherNameAndProtocol
          isAead: cipher.name.includes('GCM') || cipher.name.includes('CHACHA20'),
          forwardSecrecy: cipher.name.includes('ECDHE') || cipher.name.includes('DHE'),
        }]);
      } else {
        resolve([]);
      }
    });

    socket.on('error', () => resolve([]));
    socket.on('timeout', () => { socket.destroy(); resolve([]); });
  });
}

// Analyze key exchange security
function analyzeKeyExchange(cipherName: string): {
  type: string;
  bits: number;
  secure: boolean;
  reason: string;
} {
  if (cipherName.includes('ECDHE')) {
    return { type: 'ECDHE', bits: 256, secure: true, reason: 'Ephemeral ECDH provides perfect forward secrecy' };
  }
  if (cipherName.includes('DHE')) {
    return { type: 'DHE', bits: 2048, secure: true, reason: 'Ephemeral DH provides perfect forward secrecy' };
  }
  if (cipherName.includes('RSA')) {
    return { type: 'RSA', bits: 2048, secure: false, reason: 'RSA key exchange does not provide forward secrecy' };
  }
  return { type: 'Unknown', bits: 0, secure: false, reason: 'Unable to determine key exchange type' };
}

export async function runTlsDeepScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // === Certificate Chain Analysis ===
    const certInfo = await getCertInfo(domain);
    if (certInfo) {
      const now = new Date();
      const daysUntilExpiry = Math.floor((certInfo.validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      if (daysUntilExpiry < 0) {
        findings.push(generateFinding(
          'SSL certificate expired',
          `The SSL certificate expired ${Math.abs(daysUntilExpiry)} days ago.`,
          Severity.CRITICAL, 'TLS/SSL', domain,
          `Expired: ${certInfo.validTo.toISOString()}`,
          'Expired certificates cause browser warnings and break HTTPS',
          'Renew the certificate immediately',
          ['https://letsencrypt.org/docs/renewal-certs/']
        ));
      } else if (daysUntilExpiry < 7) {
        findings.push(generateFinding(
          'SSL certificate expiring within 7 days',
          `The SSL certificate will expire in ${daysUntilExpiry} days.`,
          Severity.HIGH, 'TLS/SSL', domain,
          `Expires: ${certInfo.validTo.toISOString()} (${daysUntilExpiry} days)`,
          'Certificates expiring soon will cause service disruption',
          'Renew the certificate immediately',
          ['https://letsencrypt.org/docs/renewal-certs/']
        ));
      } else if (daysUntilExpiry < 30) {
        findings.push(generateFinding(
          'SSL certificate expiring within 30 days',
          `The SSL certificate will expire in ${daysUntilExpiry} days.`,
          Severity.MEDIUM, 'TLS/SSL', domain,
          `Expires: ${certInfo.validTo.toISOString()} (${daysUntilExpiry} days)`,
          'Plan certificate renewal to avoid service interruption',
          'Renew the certificate before expiration',
          []
        ));
      }

      // Self-signed certificate check
      const isSelfSigned = certInfo.subject.CN === certInfo.issuer.CN &&
        certInfo.subject.O === certInfo.issuer.O;
      if (isSelfSigned) {
        findings.push(generateFinding(
          'Self-signed SSL certificate',
          'The SSL certificate is self-signed, which causes browser trust warnings.',
          Severity.HIGH, 'TLS/SSL', domain,
          `Subject: ${certInfo.subject.CN}\nIssuer: ${certInfo.issuer.CN}`,
          'Self-signed certificates are not trusted by browsers',
          'Obtain a certificate from a trusted Certificate Authority',
          ['https://letsencrypt.org/']
        ));
      }

      // Wildcard certificate check
      const hasWildcard = certInfo.subjectAltName?.some(san => san.startsWith('*.'));
      if (hasWildcard) {
        findings.push(generateFinding(
          'Wildcard SSL certificate detected',
          'The domain uses a wildcard certificate (*.domain.com).',
          Severity.INFO, 'TLS/SSL', domain,
          `SAN entries: ${certInfo.subjectAltName?.join(', ')}`,
          'Wildcard certificates require careful management of private keys',
          'Ensure the wildcard certificate private key is properly secured',
          []
        ));
      }

      // Certificate details
      findings.push(generateFinding(
        'Certificate details collected',
        `Certificate: Subject: ${certInfo.subject.CN}, Issuer: ${certInfo.issuer.CN || certInfo.issuer.O}`,
        Severity.INFO, 'TLS/SSL', domain,
        `Serial: ${certInfo.serialNumber}\nFingerprint: ${certInfo.fingerprint256?.substring(0, 32)}...`,
        'Certificate details for reference',
        'Ensure certificate uses SHA-256 or stronger signature algorithm',
        [] as string[]
      ));
    }

    // === OCSP Stapling Check ===
    const hasOcsp = await checkOcspStapling(domain);
    if (!hasOcsp) {
      findings.push(generateFinding(
        'OCSP stapling status unknown',
        'OCSP stapling could not be verified. This does not necessarily mean it is disabled.',
        Severity.INFO, 'TLS/SSL', domain,
        'OCSP stapling check returned inconclusive',
        'OCSP stapling improves certificate validation performance',
        'Verify OCSP stapling is enabled by checking with openssl s_client -status',
        ['https://blog.cloudflare.com/ocsp-stapling/']
      ));
    }

    // === HTTP/2 Support ===
    const http2Result = await checkHttp2(domain);
    if (!http2Result.supported) {
      findings.push(generateFinding(
        'HTTP/2 not supported',
        'The server does not support HTTP/2 protocol.',
        Severity.INFO, 'TLS/SSL', domain,
        'ALPN negotiation did not result in h2',
        'HTTP/2 provides performance and security improvements',
        'Enable HTTP/2 support on the web server',
        ['https://http2.github.io/faq/']
      ));
    } else {
      findings.push(generateFinding(
        'HTTP/2 supported',
        'The server supports HTTP/2 protocol.',
        Severity.INFO, 'TLS/SSL', domain,
        `Protocol: ${http2Result.protocol}`,
        'HTTP/2 provides multiplexing, header compression, and server push',
        'No action needed',
        [] as string[]
      ));
    }

    // === HTTP/3 (QUIC) Support ===
    const http3Supported = await checkHttp3(domain);
    if (!http3Supported) {
      findings.push(generateFinding(
        'HTTP/3 (QUIC) not supported',
        'The server does not support HTTP/3 over QUIC.',
        Severity.INFO, 'TLS/SSL', domain,
        'Alt-Svc header does not include h3',
        'HTTP/3 provides improved performance over lossy networks',
        'Consider enabling HTTP/3 for performance benefits',
        []
      ));
    } else {
      findings.push(generateFinding(
        'HTTP/3 (QUIC) supported',
        'The server supports HTTP/3 over QUIC protocol.',
        Severity.INFO, 'TLS/SSL', domain,
        'Alt-Svc header includes h3',
        'HTTP/3 eliminates head-of-line blocking',
        'No action needed',
        [] as string[]
      ));
    }

    // === SNI Support ===
    const sniSupported = await checkSni(domain);
    if (!sniSupported) {
      findings.push(generateFinding(
        'SNI not supported',
        'The server does not support Server Name Indication (SNI).',
        Severity.MEDIUM, 'TLS/SSL', domain,
        'TLS handshake did not complete with SNI',
        'Without SNI, virtual hosting with different certificates is not possible',
        'Ensure the server supports SNI for modern TLS',
        []
      ));
    } else {
      findings.push(generateFinding(
        'SNI supported',
        'The server supports Server Name Indication (SNI).',
        Severity.INFO, 'TLS/SSL', domain,
        'SNI negotiation successful',
        'SNI allows multiple domains to share an IP with different certificates',
        'No action needed',
        [] as string[]
      ));
    }

    // === Cipher Suite Analysis ===
    const cipherInfo = await analyzeCipherSuites(domain);
    if (cipherInfo.length > 0) {
      const cipher = cipherInfo[0];

      const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
      const isWeak = weakCiphers.some(w => cipher.name.toUpperCase().includes(w));

      if (isWeak) {
        findings.push(generateFinding(
          'Weak cipher suite in use',
          `The server is using a weak cipher suite: ${cipher.name}`,
          Severity.CRITICAL, 'TLS/SSL', domain,
          `Cipher: ${cipher.name}\nProtocol: ${cipher.protocol}`,
          'Weak ciphers can be broken to decrypt traffic',
          'Configure the server to use only strong cipher suites',
          ['https://wiki.mozilla.org/Security/Server_Side_TLS']
        ));
      }

      if (!cipher.forwardSecrecy) {
        findings.push(generateFinding(
          'Forward secrecy not supported',
          `The cipher suite ${cipher.name} does not provide forward secrecy.`,
          Severity.HIGH, 'TLS/SSL', domain,
          `Cipher: ${cipher.name}\nForward secrecy: No`,
          'Without forward secrecy, past communications can be decrypted if the private key is compromised',
          'Configure cipher suites with ECDHE or DHE key exchange',
          ['https://wiki.mozilla.org/Security/Server_Side_TLS']
        ));
      }

      if (!cipher.isAead) {
        findings.push(generateFinding(
          'Non-AEAD cipher suite in use',
          `The cipher suite ${cipher.name} is not an AEAD cipher.`,
          Severity.MEDIUM, 'TLS/SSL', domain,
          `Cipher: ${cipher.name}\nAEAD: No`,
          'AEAD ciphers provide both confidentiality and integrity',
          'Prioritize GCM or ChaCha20 cipher suites',
          []
        ));
      }

      if (cipher.protocol === 'TLSv1' || cipher.protocol === 'TLSv1.1' || cipher.protocol === 'SSLv3') {
        findings.push(generateFinding(
          `Deprecated protocol ${cipher.protocol} in use`,
          `The server supports the deprecated ${cipher.protocol} protocol.`,
          Severity.HIGH, 'TLS/SSL', domain,
          `Negotiated protocol: ${cipher.protocol}`,
          `${cipher.protocol} has known vulnerabilities and is deprecated`,
          'Disable all protocols except TLS 1.2 and TLS 1.3',
          ['https://wiki.mozilla.org/Security/Server_Side_TLS']
        ));
      }

      const keyExchange = analyzeKeyExchange(cipher.name);
      if (!keyExchange.secure) {
        findings.push(generateFinding(
          'Insecure key exchange method',
          `The cipher suite uses ${keyExchange.type} key exchange: ${keyExchange.reason}`,
          Severity.HIGH, 'TLS/SSL', domain,
          `Key exchange: ${keyExchange.type}`,
          keyExchange.reason,
          'Use ECDHE or DHE key exchange for forward secrecy',
          []
        ));
      }

      findings.push(generateFinding(
        'Cipher suite analysis completed',
        `Server cipher: ${cipher.name} (${cipher.protocol})`,
        Severity.INFO, 'TLS/SSL', domain,
        `Cipher: ${cipher.name}\nProtocol: ${cipher.protocol}`,
        'Cipher suite details for reference',
        'No action needed',
        [] as string[]
      ));
    }

    // === TLS Compression Check ===
    try {
      const socket = tls.connect({
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      }, () => {
        const compressMethod = (socket as any).getCipher();
        socket.end();

        if (compressMethod && compressMethod.name && compressMethod.name.includes('COMPRESSION')) {
          findings.push(generateFinding(
            'TLS compression enabled',
            'TLS compression is enabled, which may be vulnerable to CRIME/BREACH attacks.',
            Severity.HIGH, 'TLS/SSL', domain,
            'Compression: enabled',
            'TLS compression can leak information about encrypted data',
            'Disable TLS compression on the server',
            ['https://community.qualys.com/t5/SSL-TLS/SSL-Labs-Roadmap-for-2016/td-p/30378']
          ));
        }
      });

      socket.on('error', () => {});
      socket.on('timeout', () => socket.destroy());
    } catch {}

    const duration = Date.now() - startTime;
    return { module: 'tlsDeep', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'tlsDeep', findings, duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
