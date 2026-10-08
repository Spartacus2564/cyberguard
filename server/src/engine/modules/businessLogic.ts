import { Finding, Severity, ScanResult } from '../../types';
import { generateFinding, isLoginPage, isGenericPage, isHtmlContent, followRedirectAndCheck } from './shared';
import { fetchUrl } from './shared';
import logger from '../../utils/logger';

// ─── Helper: safe HTTP GET ───
async function safeGet(
  url: string,
  headers: Record<string, string> = {},
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  try {
    const result = await fetchUrl(url, 8000, 'businessLogic');
    return {
      statusCode: result.statusCode,
      headers: result.headers as Record<string, string>,
      body: result.body,
    };
  } catch {
    return { statusCode: 0, headers: {}, body: '' };
  }
}

// ─── Helper: safe HTTP request with method ───
async function safeRequest(
  url: string,
  method: string,
  headers: Record<string, string> = {},
  body: string = '',
): Promise<{ statusCode: number; headers: Record<string, string>; body: string }> {
  const { default: http } = await import('http');
  const { default: https } = await import('https');
  return new Promise((resolve) => {
    const start = Date.now();
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      resolve({ statusCode: 0, headers: {}, body: '' });
      return;
    }
    const mod = parsed.protocol === 'https:' ? https : http;
    const reqHeaders: Record<string, string> = {
      'User-Agent': 'CYBERGUARD-BusinessLogic/1.0',
      Accept: 'application/json, text/html, */*',
      ...headers,
    };
    if (body) {
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(body).toString();
    }
    const req = mod.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers: reqHeaders,
        timeout: 8000,
        rejectUnauthorized: false,
      } as any,
      (res) => {
        let data = '';
        let totalBytes = 0;
        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > 2097152) {
            req.destroy();
            return;
          }
          data += chunk.toString();
        });
        res.on('end', () => {
          const h: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (v) h[k] = Array.isArray(v) ? v.join(', ') : v;
          }
          resolve({ statusCode: res.statusCode || 0, headers: h, body: data });
        });
      },
    );
    req.on('error', () => resolve({ statusCode: 0, headers: {}, body: '' }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: 0, headers: {}, body: '' });
    });
    if (body) req.write(body);
    req.end();
  });
}

// ─── Scan data extraction helpers ───

function extractEndpoints(scanData: any): { path: string; method: string; status: number; body: string; headers: Record<string, string> }[] {
  const endpoints: { path: string; method: string; status: number; body: string; headers: Record<string, string> }[] = [];

  if (!scanData) return endpoints;

  // Extract from crawl data
  if (scanData.crawl) {
    for (const page of scanData.crawl) {
      endpoints.push({
        path: page.url || '/',
        method: 'GET',
        status: page.statusCode || 200,
        body: page.body || '',
        headers: page.headers || {},
      });
      if (page.forms) {
        for (const form of page.forms) {
          endpoints.push({
            path: form.action || page.url,
            method: form.method?.toUpperCase() || 'POST',
            status: 200,
            body: '',
            headers: {},
          });
        }
      }
    }
  }

  // Extract from API security scan results
  if (scanData.apiSecurity) {
    for (const f of scanData.apiSecurity) {
      if (f.affectedAsset) {
        try {
          const u = new URL(f.affectedAsset);
          endpoints.push({
            path: u.pathname,
            method: 'GET',
            status: 200,
            body: f.evidence || '',
            headers: {},
          });
        } catch {
          endpoints.push({
            path: f.affectedAsset,
            method: 'GET',
            status: 200,
            body: f.evidence || '',
            headers: {},
          });
        }
      }
    }
  }

  // Extract from HTTP methods scan
  if (scanData.httpMethods) {
    for (const f of scanData.httpMethods) {
      if (f.affectedAsset) {
        endpoints.push({
          path: f.affectedAsset,
          method: 'GET',
          status: 200,
          body: f.evidence || '',
          headers: {},
        });
      }
    }
  }

  // Extract from active vuln scan
  if (scanData.activeVuln) {
    for (const f of scanData.activeVuln) {
      if (f.affectedAsset) {
        endpoints.push({
          path: f.affectedAsset,
          method: 'GET',
          status: 200,
          body: f.evidence || '',
          headers: {},
        });
      }
    }
  }

  return endpoints;
}

function extractHeadersFromFindings(scanData: any): Record<string, string>[] {
  const headerSets: Record<string, string>[] = [];
  if (!scanData) return headerSets;

  if (scanData.headers) {
    for (const f of scanData.headers) {
      if (f.evidence) {
        try {
          const parsed = JSON.parse(f.evidence);
          if (typeof parsed === 'object') headerSets.push(parsed);
        } catch {}
      }
    }
  }

  return headerSets;
}

// ─── Detection: BOLA/IDOR ───
async function detectBOLA(
  domain: string,
  endpoints: { path: string; method: string; status: number; body: string }[],
  findings: Finding[],
): Promise<void> {
  const base = `https://${domain}`;
  const idPatterns = [/\b\d{1,6}\b/, /\/([a-f0-9-]{36})\//i, /\/([a-f0-9]{32})\//i];
  const idEndpoints = endpoints.filter((e) =>
    idPatterns.some((p) => p.test(e.path)) &&
    (e.path.includes('/user') || e.path.includes('/admin') || e.path.includes('/profile') ||
     e.path.includes('/account') || e.path.includes('/order') || e.path.includes('/item') ||
     e.path.includes('/document') || e.path.includes('/file') || e.path.includes('/record')),
  );

  for (const ep of idEndpoints.slice(0, 5)) {
    // Test 1: Increment numeric IDs
    const numMatch = ep.path.match(/\/(\d{1,6})(\/|$)/);
    if (numMatch) {
      const originalId = parseInt(numMatch[1]);
      const altId = originalId + 1;
      const altPath = ep.path.replace(`/${originalId}`, `/${altId}`);
      const res = await safeGet(base + altPath);
      if (res.statusCode === 200 && res.body.length > 10) {
        findings.push(
          generateFinding({
            title: 'Potential BOLA/IDOR — Sequential ID Access',
            description: `Endpoint ${ep.path} appears to use sequential numeric IDs. Accessing ${altPath} returned HTTP ${res.statusCode} with data, suggesting the application may not verify object-level authorization between users.`,
            severity: Severity.HIGH,
            category: 'Business Logic',
            affectedAsset: base + ep.path,
            evidence: `Original: GET ${ep.path} → HTTP ${ep.status}\nManipulated: GET ${altPath} → HTTP ${res.statusCode}\nResponse length: ${res.body.length} bytes\nBody preview: ${res.body.slice(0, 200)}`,
            impact: 'An attacker can access other users\' data by manipulating object IDs in API requests, leading to unauthorized data disclosure.',
            remediation: 'Implement object-level authorization checks on every endpoint that accesses a resource by ID. Verify the requesting user owns or has permission to access the resource. Use non-sequential, random IDs (UUIDs) where possible.',
            references: [
              'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
              'https://cwe.mitre.org/data/definitions/639.html',
            ],
          }),
        );
      }
    }

    // Test 2: UUID/Hash ID manipulation — check for predictable patterns
    const uuidMatch = ep.path.match(/\/([a-f0-9-]{36})\//i);
    if (uuidMatch) {
      // Just flag the endpoint for review — don't actually try random UUIDs
      const evidence = ep.body.slice(0, 500);
      if (evidence.includes('user') || evidence.includes('email') || evidence.includes('data')) {
        findings.push(
          generateFinding({
            title: 'Potential BOLA/IDOR — UUID-Based Endpoint Identified',
            description: `Endpoint ${ep.path} uses UUID identifiers and may be vulnerable to Broken Object Level Authorization. Manual testing recommended to verify authorization controls.`,
            severity: Severity.MEDIUM,
            category: 'Business Logic',
            affectedAsset: base + ep.path,
            evidence: `Endpoint: ${ep.path}\nResponse preview: ${evidence.slice(0, 300)}`,
            impact: 'If authorization is not properly enforced, attackers can access other users\' resources by substituting UUIDs.',
            remediation: 'Ensure every API endpoint that accepts an object identifier verifies the requesting user has authorization to access that specific object. Implement row-level security in your database.',
            references: [
              'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            ],
          }),
        );
      }
    }
  }
}

// ─── Detection: Broken Function Level Authorization ───
async function detectBrokenFunctionAuth(
  domain: string,
  endpoints: { path: string; method: string; status: number; body: string }[],
  findings: Finding[],
): Promise<void> {
  const base = `https://${domain}`;
  const adminPaths = ['/admin', '/admin/', '/api/admin', '/api/admin/', '/internal', '/manage', '/dashboard', '/api/internal', '/api/manage'];
  const sensitiveMethods = ['PUT', 'DELETE', 'PATCH'];

  // Check if admin paths are accessible without authentication
  for (const adminPath of adminPaths) {
    // Follow redirects and check if final destination is a login page
    const redirectResult = await followRedirectAndCheck(base + adminPath, 8000);

    if (redirectResult.redirected && redirectResult.isLogin) {
      // Redirected to login page - this is expected behavior, not a vulnerability
      continue;
    }

    if (redirectResult.redirected && redirectResult.isGeneric) {
      // Redirected to a generic/error page - not a real admin panel
      continue;
    }

    if (redirectResult.statusCode === 200 && redirectResult.body.length > 20) {
      // Check if the response is actually a login page
      if (isLoginPage(redirectResult.body)) {
        continue;
      }
      // Check if it's a generic/error/placeholder page
      if (isGenericPage(redirectResult.body)) {
        continue;
      }
      // Check if it's HTML content that looks like a real page (not just a redirect)
      if (isHtmlContent({}, redirectResult.body)) {
        // It's HTML but not a login page and not generic - might be a real admin panel
        // Only report if it has meaningful content (more than just a redirect notice)
        if (redirectResult.body.length > 100 && !redirectResult.body.toLowerCase().includes('location:') && !redirectResult.body.toLowerCase().includes('redirect')) {
          findings.push(
            generateFinding({
              title: 'Broken Function Level Authorization -- Admin Panel Accessible',
              description: `The administrative endpoint at ${adminPath} is accessible without authentication${redirectResult.redirected ? ' (redirected to ' + redirectResult.finalUrl + ')' : ''}. This indicates missing function-level authorization controls.`,
              severity: Severity.CRITICAL,
              category: 'Business Logic',
              affectedAsset: base + adminPath,
              evidence: `GET ${adminPath} -> HTTP ${redirectResult.statusCode}${redirectResult.redirected ? ' (redirected to ' + redirectResult.finalUrl + ')' : ''}\nResponse length: ${redirectResult.body.length} bytes\nContent-Type: ${redirectResult.body.includes('<html') ? 'text/html' : 'unknown'}\nBody preview: ${redirectResult.body.slice(0, 300)}`,
              impact: 'Unprivileged users can access administrative functions, potentially modifying system settings, accessing sensitive data, or performing privileged operations.',
              remediation: 'Implement role-based access control (RBAC) on all administrative endpoints. Enforce authorization checks server-side on every function. Never rely solely on client-side hiding of admin UI.',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
                'https://cwe.mitre.org/data/definitions/269.html',
              ],
            }),
          );
          break;
        }
      }
    }
  }

  // Check if sensitive methods work on normal endpoints
  for (const ep of endpoints.slice(0, 5)) {
    if (ep.path.includes('/api/') || ep.path.includes('/rest/')) {
      for (const method of sensitiveMethods) {
        const res = await safeRequest(base + ep.path, method);
        if (res.statusCode === 200 || res.statusCode === 201 || res.statusCode === 204) {
          findings.push(
            generateFinding({
              title: `Broken Function Level Authorization — ${method} Allowed on ${ep.path}`,
              description: `The endpoint ${ep.path} accepts ${method} requests and returns HTTP ${res.statusCode}. Without proper authorization, any user could modify or delete resources.`,
              severity: Severity.HIGH,
              category: 'Business Logic',
              affectedAsset: base + ep.path,
              evidence: `${method} ${ep.path} → HTTP ${res.statusCode}\nResponse length: ${res.body.length} bytes`,
              impact: 'An attacker can modify or delete resources without authorization, leading to data loss or corruption.',
              remediation: 'Enforce authorization on every HTTP method. Restrict PUT/DELETE/PATCH to authorized roles only. Use method-level annotations or middleware to enforce access control.',
              references: [
                'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
              ],
            }),
          );
          break;
        }
      }
    }
  }
}

// ─── Detection: Mass Assignment ───
async function detectMassAssignment(
  domain: string,
  endpoints: { path: string; method: string; status: number; body: string }[],
  findings: Finding[],
): Promise<void> {
  const base = `https://${domain}`;
  const userEndpoints = endpoints.filter(
    (e) =>
      (e.path.includes('/user') || e.path.includes('/profile') || e.path.includes('/account') ||
       e.path.includes('/register') || e.path.includes('/signup') || e.path.includes('/update')) &&
      (e.method === 'POST' || e.method === 'PUT' || e.method === 'PATCH'),
  );

  const sensitiveFields = [
    { field: 'role', value: 'admin' },
    { field: 'isAdmin', value: true },
    { field: 'admin', value: true },
    { field: 'permission', value: 'superadmin' },
    { field: 'verified', value: true },
    { field: 'emailVerified', value: true },
  ];

  for (const ep of userEndpoints.slice(0, 3)) {
    for (const { field, value } of sensitiveFields) {
      const payload = JSON.stringify({ [field]: value });
      const res = await safeRequest(base + ep.path, 'POST', { 'Content-Type': 'application/json' }, payload);
      if (res.statusCode === 200 || res.statusCode === 201) {
        const bodyLower = res.body.toLowerCase();
        if (bodyLower.includes(field.toLowerCase()) || bodyLower.includes('admin') || bodyLower.includes('success')) {
          findings.push(
            generateFinding({
              title: `Mass Assignment — Privilege Escalation via ${field}`,
              description: `POST ${ep.path} accepted the '${field}' field in the request body and returned HTTP ${res.statusCode}. The application may be vulnerable to mass assignment, allowing users to set privileged attributes.`,
              severity: Severity.CRITICAL,
              category: 'Business Logic',
              affectedAsset: base + ep.path,
              evidence: `POST ${ep.path}\nPayload: { "${field}": ${JSON.stringify(value)} }\nResponse: HTTP ${res.statusCode}\nBody preview: ${res.body.slice(0, 300)}`,
              impact: 'Attackers can escalate privileges by including sensitive fields (role, isAdmin, etc.) in registration or profile update requests.',
              remediation: 'Use allow-lists (not deny-lists) for mass assignment. Define explicit DTOs for user input. Never bind request body directly to domain models. Framework-specific: use @Column({ select: false }) or similar.',
              references: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Parameter_Pollution',
                'https://cwe.mitre.org/data/definitions/915.html',
              ],
            }),
          );
          return;
        }
      }
    }
  }
}

// ─── Detection: Security Misconfiguration in APIs ───
async function detectAPIMisconfiguration(
  domain: string,
  scanData: any,
  findings: Finding[],
): Promise<void> {
  const base = `https://${domain}`;

  // Check for exposed debug/stack trace endpoints
  const debugPaths = ['/debug', '/trace', '/actuator', '/actuator/env', '/actuator/configprops', '/metrics', '/health', '/info', '/env', '/configprops', '/dump'];
  for (const path of debugPaths) {
    const res = await safeGet(base + path);
    if (res.statusCode === 200 && res.body.length > 20) {
      const hasSensitive = res.body.includes('password') || res.body.includes('secret') ||
        res.body.includes('key') || res.body.includes('token') || res.body.includes('env') ||
        res.body.includes('spring') || res.body.includes('datasource');
      if (hasSensitive) {
        findings.push(
          generateFinding({
            title: `Exposed Debug/Actuator Endpoint: ${path}`,
            description: `The endpoint ${path} is publicly accessible and exposes sensitive configuration data. This endpoint is typically used for debugging and should not be exposed in production.`,
            severity: Severity.CRITICAL,
            category: 'Business Logic',
            affectedAsset: base + path,
            evidence: `GET ${path} → HTTP ${res.statusCode}\nResponse contains sensitive data:\n${res.body.slice(0, 500)}`,
            impact: 'Attackers can extract database credentials, API keys, environment variables, and other secrets, leading to full system compromise.',
            remediation: 'Disable or restrict access to debug/actuator endpoints in production. Use Spring Security actuator endpoint exposure configuration. Implement IP allowlisting for management endpoints.',
            references: [
              'https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html',
              'https://cwe.mitre.org/data/definitions/215.html',
            ],
          }),
        );
        break;
      }
    }
  }

  // Check for CORS misconfiguration
  const res = await safeGet(base + '/api', { Origin: 'https://evil.com' });
  const acao = res.headers['access-control-allow-origin'];
  if (acao === '*' || acao === 'https://evil.com') {
    findings.push(
      generateFinding({
        title: 'CORS Misconfiguration — Origin Reflection',
        description: `The API reflects the attacker-controlled Origin header in Access-Control-Allow-Origin. The server responded with ACAO: ${acao} when requesting from https://evil.com.`,
        severity: Severity.HIGH,
        category: 'Business Logic',
        affectedAsset: base,
        evidence: `Request Origin: https://evil.com\nResponse ACAO: ${acao}\nCredentials: ${res.headers['access-control-allow-credentials'] || 'not set'}`,
        impact: 'Attackers on malicious websites can make cross-origin requests with credentials, potentially exfiltrating user data or performing actions on behalf of authenticated users.',
        remediation: 'Never use wildcard (*) with credentials. Whitelist specific trusted origins. Use a server-side allowlist rather than reflecting the Origin header.',
        references: [
          'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
          'https://cwe.mitre.org/data/definitions/942.html',
        ],
      }),
    );
  }

  // Check for missing rate limiting headers
  const rateHeaders = ['x-rate-limit-limit', 'x-ratelimit-limit', 'retry-after', 'x-rate-limit-remaining'];
  const hasRateHeaders = rateHeaders.some((h) => res.headers[h]);
  if (!hasRateHeaders && res.statusCode === 200) {
    // Only flag if we haven't already flagged rate limiting in apiSecurity module
    const existingRateLimit = scanData?.apiSecurity?.some((f: Finding) =>
      f.title?.toLowerCase().includes('rate limit'),
    );
    if (!existingRateLimit) {
      findings.push(
        generateFinding({
          title: 'No API Rate Limiting Headers Detected',
          description: 'The API does not return standard rate limiting headers. This may indicate missing rate limiting, which could allow brute force and denial of service attacks.',
          severity: Severity.LOW,
          category: 'Business Logic',
          affectedAsset: base,
          evidence: `Checked response headers for rate limiting indicators: ${rateHeaders.join(', ')} — none found.\nResponse headers: ${JSON.stringify(res.headers)}`,
          impact: 'Without rate limiting, the API is vulnerable to brute force attacks, credential stuffing, and resource exhaustion.',
          remediation: 'Implement rate limiting with standard headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After). Use progressive delays for repeated failed attempts.',
          references: [
            'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/',
          ],
        }),
      );
    }
  }
}

// ─── Detection: Insufficient Logging & Monitoring ───
async function detectInsufficientLogging(
  domain: string,
  scanData: any,
  findings: Finding[],
): Promise<void> {
  const base = `https://${domain}`;

  // Check for verbose error messages indicating lack of proper logging
  const errorIndicators = [
    'stack trace',
    'stacktrace',
    'at line',
    'at Object.',
    'at Function.',
    'File:',
    'Traceback',
    'Exception:',
    'Internal Server Error',
    'debug mode',
    'DEBUG = True',
    'APP_DEBUG',
  ];

  const allFindings: Finding[] = scanData ? (Object.values(scanData).flat().filter((f: any) => f && typeof f === 'object') as Finding[]) : [];

  let hasVerboseErrors = false;
  for (const f of allFindings) {
    if (typeof f === 'object' && f !== null && 'evidence' in f) {
      const evidence = String((f as any).evidence || '').toLowerCase();
      if (errorIndicators.some((indicator) => evidence.includes(indicator.toLowerCase()))) {
        hasVerboseErrors = true;
        break;
      }
    }
  }

  if (hasVerboseErrors) {
    findings.push(
      generateFinding({
        title: 'Verbose Error Messages — Insufficient Error Handling',
        description: 'The application returns verbose error messages with implementation details (stack traces, file paths, internal paths). This indicates that errors are not properly handled and sensitive information may be logged or exposed.',
        severity: Severity.MEDIUM,
        category: 'Business Logic',
        affectedAsset: base,
        evidence: 'Verbose error messages detected in scan results. Stack traces or implementation details are exposed to users.',
        impact: 'Attackers can extract information about the application framework, file structure, and internal logic to craft targeted attacks. Sensitive data may be included in error logs without proper sanitization.',
        remediation: 'Implement centralized error handling with custom error pages. Log detailed errors server-side only. Use structured logging with sanitization. Never expose stack traces to users in production.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/',
          'https://cwe.mitre.org/data/definitions/209.html',
        ],
      }),
    );
  }

  // Check for security-related headers that indicate monitoring
  const monitoringHeaders = ['x-request-id', 'x-trace-id', 'x-correlation-id', 'x-amzn-trace-id', 'server-timing'];
  const headerSet = extractHeadersFromFindings(scanData);
  const hasMonitoring = headerSet.some((h) =>
    monitoringHeaders.some((mh) => Object.keys(h).some((k) => k.toLowerCase() === mh)),
  );

  if (!hasMonitoring && allFindings.length > 3) {
    findings.push(
      generateFinding({
        title: 'No Request Tracing Headers Detected',
        description: 'The application does not return request tracing headers (X-Request-ID, X-Trace-ID, etc.). Without proper request identification, security incidents cannot be effectively investigated or correlated.',
        severity: Severity.LOW,
        category: 'Business Logic',
        affectedAsset: base,
        evidence: `Checked for monitoring headers: ${monitoringHeaders.join(', ')} — none found in ${headerSet.length} sampled responses.`,
        impact: 'Without request tracing, security teams cannot efficiently investigate incidents, correlate attacks, or perform forensic analysis.',
        remediation: 'Implement request tracing with unique IDs on every request. Use distributed tracing (OpenTelemetry, Jaeger). Log all authentication attempts, access control failures, and input validation errors.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/',
          'https://cwe.mitre.org/data/definitions/778.html',
        ],
      }),
    );
  }
}

// ─── Main module function ───

export async function businessLogic(
  assessmentId: string,
  domain: string,
  scanData: any,
  aiService: any,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  logger.info(`[BusinessLogic] Starting business logic analysis for ${domain}`);

  const endpoints = extractEndpoints(scanData);

  // Run all detectors in parallel
  await Promise.allSettled([
    detectBOLA(domain, endpoints, findings),
    detectBrokenFunctionAuth(domain, endpoints, findings),
    detectMassAssignment(domain, endpoints, findings),
    detectAPIMisconfiguration(domain, scanData, findings),
    detectInsufficientLogging(domain, scanData, findings),
  ]);

  logger.info(`[BusinessLogic] Completed: ${findings.length} findings for ${domain}`);
  return findings;
}

// ─── Wrapper for MODULE_RUNNERS ───
export async function runBusinessLogicScan(domain: string, scanData?: any): Promise<ScanResult> {
  const findings = await businessLogic('', domain, scanData || {}, null);
  return {
    module: 'businessLogic' as any,
    findings,
    duration: 0,
    errors: [],
  };
}
