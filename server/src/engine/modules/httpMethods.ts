import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, OWASP_TOP_10 } from './shared';
import { TargetProfile } from '../targetAnalysis';

// ─── HTTP Client ────────────────────────────────────────────────────────────
function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body: string = '',
  timeoutMs: number = 8000,
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; duration: number }> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    const mod = parsed.protocol === 'https:' ? https : http;
    const reqHeaders: Record<string, string> = {
      'User-Agent': 'CYBERGUARD-HTTPMethods/1.0',
      ...(body ? { 'Content-Length': Buffer.byteLength(body).toString() } : {}),
      ...headers,
    };
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: reqHeaders,
      timeout: timeoutMs,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 2097152) { req.destroy(); return; }
        data += chunk.toString();
      });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, duration: Date.now() - start }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function safeRequest(url: string, method: string = 'GET', headers: Record<string, string> = {}, body: string = '') {
  try { return await makeRequest(url, method, headers, body); }
  catch { return { statusCode: 0, headers: {}, body: '', duration: 0 }; }
}

// ─── Module ─────────────────────────────────────────────────────────────────

export async function runHttpMethodsScan(
  domain: string,
  profile?: TargetProfile,
): Promise<ScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;
  const endpoints = profile?.endpoints?.map(e => e.path)?.slice(0, 8) || ['/'];

  for (const path of endpoints) {
    const url = base + path;

    // 1) TRACE method — returns full request, enables XST (Cross-Site Tracing)
    const traceRes = await safeRequest(url, 'TRACE', {
      'X-CyberGuard-TRACE': 'TRACE-TEST-1337',
    });
    if (traceRes.statusCode === 200 && traceRes.body.includes('X-CyberGuard-TRACE')) {
      findings.push(generateFinding({
        title: 'TRACE Method Enabled — Cross-Site Tracing (XST)',
        description: `The server responds to TRACE requests at ${path}, echoing back the full HTTP request including headers. This enables Cross-Site Tracing attacks where an attacker can read cookies and auth headers from cross-origin JavaScript via TRACE + XMLHttpRequest.`,
        severity: Severity.HIGH,
        category: 'HTTP Method Security',
        affectedAsset: url,
        evidence: `TRACE ${url} → HTTP ${traceRes.statusCode}\nResponse body contains: ${traceRes.body.slice(0, 300)}`,
        impact: 'Attackers can steal HttpOnly cookies and authentication headers via cross-origin TRACE requests combined with XSS, bypassing HttpOnly protections.',
        remediation: `Disable the TRACE method in the web server configuration. In Apache: "TraceEnable off". In Nginx: no native support for TRACE. In IIS: remove TRACE from the allowed verbs via requestFiltering.`,
        references: [
          'https://owasp.org/www-community/attacks/Cross_Site_Tracing',
          'https://cwe.mitre.org/data/definitions/693.html',
        ],
      }));
    }

    // 2) OPTIONS method — reveals allowed methods, potentially dangerous ones
    const optionsRes = await safeRequest(url, 'OPTIONS');
    if (optionsRes.statusCode >= 200 && optionsRes.statusCode < 300) {
      const allow = (optionsRes.headers['allow'] as string) || '';
      const methods = allow.split(/,\s*/).map(m => m.toUpperCase()).filter(Boolean);
      const dangerous = methods.filter(m => ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'].includes(m));
      if (dangerous.length > 0) {
        findings.push(generateFinding({
          title: `Dangerous HTTP Methods Allowed: ${dangerous.join(', ')}`,
          description: `The server at ${path} responds to OPTIONS with Allow header listing dangerous methods: ${dangerous.join(', ')}. These methods can be abused to modify or delete resources, traverse filesystems, or perform administrative actions.`,
          severity: dangerous.some(m => ['PUT', 'DELETE', 'TRACE', 'CONNECT'].includes(m)) ? Severity.HIGH : Severity.MEDIUM,
          category: 'HTTP Method Security',
          affectedAsset: url,
          evidence: `OPTIONS ${url} → Allow: ${allow}\nDangerous methods: ${dangerous.join(', ')}`,
          impact: `Attackers can use ${dangerous.join(', ')} methods to ${dangerous.includes('PUT') ? 'upload malicious files or overwrite resources, ' : ''}${dangerous.includes('DELETE') ? 'delete resources, ' : ''}${dangerous.includes('TRACE') ? 'read auth headers via XST, ' : ''}${dangerous.includes('CONNECT') ? 'establish tunneling connections, ' : ''}${dangerous.includes('PROPFIND') ? 'enumerate the filesystem via WebDAV, ' : ''}without authentication.`,
          remediation: `Restrict HTTP methods to only those required: GET, POST, HEAD, and OPTIONS. Disable PUT, DELETE, TRACE, CONNECT, and all WebDAV methods (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK) unless explicitly needed.`,
          references: [
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-HTTP-Methods',
            'https://cwe.mitre.org/data/definitions/749.html',
          ],
        }));
      }
    }

    // 3) PUT method — can we upload/write files to the webroot?
    const putPayloads = [
      { path: '/cyberguard-test-put.txt', body: 'CYBERGUARD PUT TEST' },
      { path: '/images/cyberguard-test-put.jpg', body: '\xff\xd8\xff\xe0' + 'CYBERGUARD' }, // fake JPEG header
    ];
    for (const put of putPayloads) {
      const putUrl = base + put.path;
      const putRes = await safeRequest(putUrl, 'PUT', { 'Content-Type': 'text/plain' }, put.body);
      if (putRes.statusCode >= 200 && putRes.statusCode < 300) {
        // Verify it actually persisted
        const verifyRes = await safeRequest(putUrl, 'GET');
        if (verifyRes.statusCode === 200 && verifyRes.body.includes('CYBERGUARD')) {
          findings.push(generateFinding({
            title: 'Unauthenticated File Upload via PUT Method',
            description: `The server accepts PUT requests and persists the uploaded file. A malicious actor can upload webshells, defacement pages, or malicious scripts to ${put.path}.`,
            severity: Severity.CRITICAL,
            category: 'HTTP Method Security',
            affectedAsset: putUrl,
            evidence: `PUT ${putUrl} → HTTP ${putRes.statusCode}\nGET ${putUrl} (verify) → HTTP ${verifyRes.statusCode}, body contains uploaded content`,
            impact: 'Full remote code execution — attacker can upload a webshell (PHP/ASP/JSP) and execute arbitrary commands on the server.',
            remediation: 'Disable PUT method. If file upload is required, store uploads outside the webroot, validate file types server-side, and implement access controls.',
            references: [
              'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
            ],
          }));
          // Cleanup: DELETE the test file (best effort)
          await safeRequest(putUrl, 'DELETE');
        }
      }
    }

    // 4) DELETE method — can we remove resources?
    const delRes = await safeRequest(base + '/cyberguard-test-delete.txt', 'DELETE');
    if (delRes.statusCode >= 200 && delRes.statusCode < 300) {
      findings.push(generateFinding({
        title: 'DELETE Method Accepted Without Authentication',
        description: `The server accepts DELETE requests at ${path}. An attacker can remove arbitrary resources, causing denial of service and data loss.`,
        severity: Severity.HIGH,
        category: 'HTTP Method Security',
        affectedAsset: url,
        evidence: `DELETE ${url}/cyberguard-test-delete.txt → HTTP ${delRes.statusCode}`,
        impact: 'Attackers can delete any resource on the server, causing permanent data loss and denial of service.',
        remediation: 'Disable DELETE method. If resource deletion is required, implement proper authentication, authorization, and audit logging.',
        references: ['https://cwe.mitre.org/data/definitions/749.html'],
      }));
    }

    // 5) Verb tampering — does switching method bypass access controls?
    const getRes = await safeRequest(url, 'GET');
    if (getRes.statusCode === 403 || getRes.statusCode === 401) {
      // Try alternative methods to bypass
      const bypassMethods = ['POST', 'PUT', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE'];
      for (const altMethod of bypassMethods) {
        const altRes = await safeRequest(url, altMethod, altMethod === 'POST' ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}, altMethod === 'POST' ? '' : '');
        if (altRes.statusCode === 200 && altRes.body.length > 0) {
          findings.push(generateFinding({
            title: `HTTP Verb Tampering — ${altMethod} Bypasses Access Control`,
            description: `GET ${path} returns ${getRes.statusCode} but ${altMethod} returns 200 with content. The server applies access controls per HTTP method, allowing an attacker to bypass restrictions by switching the request method.`,
            severity: Severity.HIGH,
            category: 'HTTP Method Security',
            affectedAsset: url,
            evidence: `GET ${url} → ${getRes.statusCode}\n${altMethod} ${url} → ${altRes.statusCode}, body length: ${altRes.body.length}\nResponse snippet: ${altRes.body.slice(0, 300)}`,
            impact: 'Attackers can bypass access control and access protected resources by simply changing the HTTP method.',
            remediation: 'Apply access controls consistently across all HTTP methods. Use a centralized authorization middleware that checks permissions regardless of the request method.',
            references: [
              'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-HTTP-Methods',
              'https://cwe.mitre.org/data/definitions/288.html',
            ],
          }));
          break; // One finding per endpoint
        }
      }
    }

    // 6) HEAD — does it leak different info than GET?
    const headRes = await safeRequest(url, 'HEAD');
    if (headRes.statusCode === 200 && getRes.statusCode === 200) {
      const getContentLength = parseInt(String(getRes.headers['content-length'] || '0'), 10);
      const headContentLength = parseInt(String(headRes.headers['content-length'] || '0'), 10);
      if (getContentLength > 0 && headContentLength > 0 && Math.abs(getContentLength - headContentLength) > getContentLength * 0.5) {
        findings.push(generateFinding({
          title: 'Content-Length Mismatch Between GET and HEAD',
          description: `GET ${path} reports Content-Length: ${getContentLength} while HEAD reports Content-Length: ${headContentLength}. This discrepancy suggests server-side filtering or access control differences between methods.`,
          severity: Severity.LOW,
          category: 'HTTP Method Security',
          affectedAsset: url,
          evidence: `GET ${url} → Content-Length: ${getContentLength}\nHEAD ${url} → Content-Length: ${headContentLength}`,
          impact: 'May indicate hidden content or inconsistent access controls that could be exploited via method switching.',
          remediation: 'Ensure HEAD and GET return consistent responses. Remove method-based content filtering if not intentional.',
          references: ['https://cwe.mitre.org/data/definitions/200.html'],
        }));
      }
    }

    // 7) CONNECT — can we use the server as a proxy?
    const connectRes = await safeRequest(url, 'CONNECT', { 'Host': '127.0.0.1:443' });
    if (connectRes.statusCode === 200) {
      findings.push(generateFinding({
        title: 'CONNECT Method Accepted — Potential Open Proxy',
        description: `The server accepts CONNECT requests, which can be abused to tunnel traffic through the server, bypassing network restrictions and anonymizing attacker traffic.`,
        severity: Severity.HIGH,
        category: 'HTTP Method Security',
        affectedAsset: url,
        evidence: `CONNECT ${url} → HTTP ${connectRes.statusCode}`,
        impact: 'Attackers can use the server as an open proxy to tunnel malicious traffic, bypass IP-based restrictions, and obscure their origin.',
        remediation: 'Disable the CONNECT method entirely. If proxy functionality is required, implement strict authentication and destination filtering.',
        references: ['https://cwe.mitre.org/data/definitions/441.html'],
      }));
    }
  }

  return { module: 'httpMethods', findings, duration: 0, errors };
}
