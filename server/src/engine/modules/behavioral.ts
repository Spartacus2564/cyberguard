import * as https from 'https';
import * as http from 'http';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';
import { logExploit, logVuln, logRequest, logResponse, logDone } from '../scanLogger';

// ─── HTTP Client ───
function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body: string = ''
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; duration: number }> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    logRequest('behavioral', method, targetUrl, { note: body ? `body=${body.substring(0, 80)}` : undefined });
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers,
      timeout: 8000,
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
        logResponse('behavioral', targetUrl, res.statusCode || 0, { bodySnippet: data.substring(0, 60), duration: dur });
        resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, duration: dur });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

async function safeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body: string = ''
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; duration: number }> {
  try {
    return await makeRequest(targetUrl, method, headers, body);
  } catch {
    return { statusCode: 0, headers: {}, body: '', duration: 0 };
  }
}

// ─── Helpers ───
interface ResponseBaseline {
  statusCode: number;
  bodyLength: number;
  headers: Record<string, string>;
  duration: number;
}

function buildBaseline(res: { statusCode: number; headers: http.IncomingHttpHeaders; body: string; duration: number }): ResponseBaseline {
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) {
    if (v !== undefined) normalized[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  }
  return {
    statusCode: res.statusCode,
    bodyLength: res.body.length,
    headers: normalized,
    duration: res.duration,
  };
}

function bodySimilarity(a: string, b: string): number {
  if (a.length === 0 && b.length === 0) return 1;
  if (a.length === 0 || b.length === 0) return 0;
  const shorter = a.length < b.length ? a : b;
  const longer = a.length < b.length ? b : a;
  const shortSet = new Set(shorter);
  let matches = 0;
  for (const ch of longer) {
    if (shortSet.has(ch)) matches++;
  }
  return matches / longer.length;
}

// ─── 1. Response Baseline Anomaly Detection ───
async function testResponseAnomalies(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('behavioral', 'ResponseBaseline', baseUrl, 'Establishing response baseline and testing malformed inputs');
  try {
    // Establish baseline with 3 requests to main page
    const baselineResponses: ResponseBaseline[] = [];
    for (let i = 0; i < 3; i++) {
      const res = await safeRequest(baseUrl, 'GET', {}, '');
      if (res.statusCode > 0) {
        baselineResponses.push(buildBaseline(res));
      }
    }

    if (baselineResponses.length === 0) {
      errors.push('ResponseBaseline: Could not establish baseline');
      return;
    }

    const avgStatus = Math.round(baselineResponses.reduce((s, r) => s + r.statusCode, 0) / baselineResponses.length);
    const avgBodyLen = Math.round(baselineResponses.reduce((s, r) => s + r.bodyLength, 0) / baselineResponses.length);
    const avgDuration = Math.round(baselineResponses.reduce((s, r) => s + r.duration, 0) / baselineResponses.length);

    const baselineBody = baselineResponses[0];
    const baselineBodyContent = (await safeRequest(baseUrl)).body;

    // Malformed inputs to test
    const malformedInputs: { label: string; method: string; headers: Record<string, string>; body: string; url?: string }[] = [
      {
        label: 'invalid-json',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{invalid json[[[',
      },
      {
        label: 'broken-xml',
        method: 'POST',
        headers: { 'Content-Type': 'application/xml' },
        body: '<?xml version="1.0"?><broken><unclosed>',
      },
      {
        label: 'oversized-header',
        method: 'GET',
        headers: { 'X-Custom-Header': 'A'.repeat(8000) },
        body: '',
      },
      {
        label: 'null-byte',
        method: 'GET',
        headers: {},
        body: '',
        url: `${baseUrl}/%00`,
      },
      {
        label: 'unicode-path',
        method: 'GET',
        headers: {},
        body: '',
        url: `${baseUrl}/\u00e9\u00e8\u00ea`,
      },
      {
        label: 'empty-content-type',
        method: 'POST',
        headers: { 'Content-Type': '' },
        body: 'test data',
      },
      {
        label: 'double-content-type',
        method: 'POST',
        headers: { 'Content-Type': 'text/html, application/json' },
        body: '{"key":"value"}',
      },
    ];

    const errorIndicators = [
      'stack trace', 'stacktrace', 'at line', 'traceback', 'exception',
      'debug', 'internal server', 'debugging', 'var_dump', 'print_r',
      'mysql_', 'pg_', 'ORA-', 'SQLiteException', 'PDOException',
      'springframework', 'django', 'rails', 'laravel', 'express',
      '/usr/', '/var/', '/home/', 'C:\\', '/opt/',
    ];

    for (const input of malformedInputs) {
      try {
        const targetUrl = input.url || baseUrl;
        const res = await safeRequest(targetUrl, input.method, input.headers, input.body);

        if (res.statusCode === 0) continue;

        const hasErrorIndicator = errorIndicators.some(ind =>
          res.body.toLowerCase().includes(ind.toLowerCase())
        );

        // Compare with baseline
        const statusDiffers = res.statusCode !== avgStatus;
        const bodySizeDiffers = Math.abs(res.body.length - avgBodyLen) > avgBodyLen * 0.5;
        const isDebugging = hasErrorIndicator;

        if ((statusDiffers && isDebugging) || (bodySizeDiffers && isDebugging)) {
          findings.push(generateFinding(
            'Response Anomaly on Malformed Input',
            `Sending ${input.label} causes a response that differs from baseline and contains debug/error information, suggesting incomplete input validation.`,
            Severity.MEDIUM,
            'Behavioral Analysis',
            domain,
            `Input: ${input.label}, Status: ${res.statusCode} (baseline: ${avgStatus}), Body size: ${res.body.length} (baseline: ${avgBodyLen}), Debug indicators found`,
            'Malformed inputs that trigger debug responses may reveal internal application details and input handling weaknesses',
            'Implement consistent error handling; return generic error pages; validate and sanitize all input',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
          ));
        }

        // Check for stack traces or framework info specifically
        if (isDebugging) {
          const matchedIndicators = errorIndicators.filter(ind =>
            res.body.toLowerCase().includes(ind.toLowerCase())
          );
          findings.push(generateFinding(
            'Error Information Disclosure via Malformed Input',
            `The server exposes internal information (${matchedIndicators.slice(0, 3).join(', ')}) when receiving ${input.label}.`,
            Severity.LOW,
            'Behavioral Analysis',
            domain,
            `Input: ${input.label}, Matched indicators: ${matchedIndicators.join(', ')}`,
            'Information disclosure helps attackers map internal architecture and identify specific frameworks/versions',
            'Suppress debug output in production; use custom error pages',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
        }
      } catch {}
    }
  } catch (e) { errors.push(`ResponseBaseline: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── 2. Error Handling Fingerprinting ───
async function testErrorFingerprinting(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('behavioral', 'ErrorFingerprint', baseUrl, 'Fingerprinting error handling patterns');
  try {
    const errorTriggers: { label: string; method: string; path: string; headers: Record<string, string>; body: string }[] = [
      { label: '404-not-found', method: 'GET', path: '/nonexistent-page-' + Date.now(), headers: {}, body: '' },
      { label: '405-method', method: 'DELETE', path: '/', headers: {}, body: '' },
      { label: '500-long-url', method: 'GET', path: '/' + 'A'.repeat(2000), headers: {}, body: '' },
      { label: 'invalid-method', method: 'INVALID_HTTP_METHOD', path: '/', headers: {}, body: '' },
      { label: 'malformed-header', method: 'GET', path: '/', headers: { 'X-Bad\r\nHeader': 'injection' }, body: '' },
      { label: 'missing-host', method: 'GET', path: '/', headers: { 'Host': '' }, body: '' },
      { label: 'huge-body', method: 'POST', path: '/', headers: { 'Content-Type': 'text/plain' }, body: 'X'.repeat(50000) },
    ];

    const errorPatterns: { pattern: RegExp; category: string; severity: Severity }[] = [
      { pattern: /stack\s?trace|at\s+\w+\.\w+\(|Traceback \(most recent call|Exception in thread/i, category: 'Stack Trace', severity: Severity.MEDIUM },
      { pattern: /(?:Express|Flask|Django|Rails|Laravel|Spring|ASP\.NET|Fastify|Koa)\s*v?[\d.]+/i, category: 'Framework Version', severity: Severity.LOW },
      { pattern: /(?:mysql|postgresql|sqlite|oracle|mongodb|redis|elasticsearch)[_\s]?error|SQL\s?(?:syntax|error|query)|PDOException|SQLException/i, category: 'Database Error', severity: Severity.HIGH },
      { pattern: /(?:\/app\/|\/src\/|\/lib\/|\/var\/|\/usr\/|\/home\/|\/opt\/|\/etc\/|C:\\|\/usr\/local\/)/i, category: 'Internal Path', severity: Severity.MEDIUM },
      { pattern: /(?:phpinfo|php_version|Zend\s?Extension|X-Powered-By)/i, category: 'PHP Info', severity: Severity.LOW },
      { pattern: /(?:debug|trace|verbose)\s*(?:mode|output|log)/i, category: 'Debug Mode', severity: Severity.MEDIUM },
    ];

    const responsePatterns: { statusCode: number; body: string }[] = [];

    for (const trigger of errorTriggers) {
      try {
        const targetUrl = `${baseUrl}${trigger.path}`;
        const res = await safeRequest(targetUrl, trigger.method, trigger.headers, trigger.body);
        if (res.statusCode === 0) continue;

        responsePatterns.push({ statusCode: res.statusCode, body: res.body });
        const bodyLower = res.body.toLowerCase();

        // Check for information disclosure patterns
        for (const { pattern, category, severity } of errorPatterns) {
          if (pattern.test(res.body)) {
            const match = res.body.match(pattern);
            findings.push(generateFinding(
              `Error Handling Information Disclosure (${category})`,
              `Triggering "${trigger.label}" error exposes ${category} information: "${match ? match[0].substring(0, 60) : ''}"`,
              severity,
              'Behavioral Analysis',
              domain,
              `Trigger: ${trigger.label}, Category: ${category}, Match: ${match ? match[0].substring(0, 80) : 'N/A'}`,
              'Detailed error information reveals internal application structure, frameworks, and potential attack vectors',
              'Use custom error pages; log detailed errors server-side only; suppress framework default error handlers',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
            ));
          }
        }
      } catch {}
    }

    // Check if different error types produce different response patterns (verbose error handling)
    if (responsePatterns.length >= 2) {
      const uniqueStatuses = new Set(responsePatterns.map(r => r.statusCode));
      const uniqueSizes = new Set(responsePatterns.map(r => Math.round(r.body.length / 100) * 100));
      if (uniqueStatuses.size >= 3 || uniqueSizes.size >= 3) {
        findings.push(generateFinding(
          'Verbose Error Handling Patterns',
          `The application returns ${uniqueStatuses.size} different status codes and ${uniqueSizes.size} distinct body sizes across error conditions, indicating verbose error handling.`,
          Severity.LOW,
          'Behavioral Analysis',
          domain,
          `Status codes: ${Array.from(uniqueStatuses).join(', ')}, Body size patterns: ${Array.from(uniqueSizes).join(', ')}`,
          'Distinct error responses for different error types allow attackers to fingerprint the application and understand internal behavior',
          'Return consistent error responses for all client errors; use generic error pages',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
        ));
      }
    }
  } catch (e) { errors.push(`ErrorFingerprint: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── 3. Timing Side-Channel Detection ───
async function testTimingSideChannel(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('behavioral', 'TimingSideChannel', baseUrl, 'Measuring response timing for side-channel detection');
  try {
    // Measure baseline timing with multiple requests
    const baselineTimings: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await safeRequest(baseUrl, 'GET', {}, '');
      if (res.duration > 0) baselineTimings.push(res.duration);
    }
    if (baselineTimings.length === 0) {
      errors.push('TimingSideChannel: Could not measure baseline');
      return;
    }
    const avgBaseline = baselineTimings.reduce((a, b) => a + b, 0) / baselineTimings.length;

    // Characters that may trigger injection processing delays
    const specialCharSets: { label: string; chars: string }[] = [
      { label: 'single-quotes', chars: "'" },
      { label: 'double-quotes', chars: '"' },
      { label: 'semicolons', chars: ';' },
      { label: 'pipes', chars: '|' },
      { label: 'backticks', chars: '`' },
      { label: 'curly-braces', chars: '{}' },
      { label: 'sql-operators', chars: "' OR 1=1 --" },
      { label: 'regex-chars', chars: '(a+b)+' },
    ];

    // Injection points to test
    const injectionPoints: { label: string; buildUrl: (chars: string) => string }[] = [
      { label: 'query-param', buildUrl: (c) => `${baseUrl}?q=${encodeURIComponent(c)}` },
      { label: 'path-segment', buildUrl: (c) => `${baseUrl}/${encodeURIComponent(c)}` },
      { label: 'hash-like', buildUrl: (c) => `${baseUrl}?search=${encodeURIComponent(c)}` },
    ];

    const timingResults: { point: string; charSet: string; baseline: number; test: number; ratio: number }[] = [];

    for (const point of injectionPoints) {
      for (const charSet of specialCharSets) {
        try {
          const testUrl = point.buildUrl(charSet.chars.repeat(3));
          const testRes = await safeRequest(testUrl, 'GET', {}, '');
          if (testRes.duration > 0) {
            const ratio = testRes.duration / avgBaseline;
            timingResults.push({
              point: point.label,
              charSet: charSet.label,
              baseline: avgBaseline,
              test: testRes.duration,
              ratio,
            });

            // If special characters cause >2x baseline consistently
            if (ratio > 2 && testRes.duration > 200) {
              // Verify with a second request to reduce false positives
              const verifyRes = await safeRequest(testUrl, 'GET', {}, '');
              if (verifyRes.duration > 0) {
                const verifyRatio = verifyRes.duration / avgBaseline;
                if (verifyRatio > 1.8) {
                  findings.push(generateFinding(
                    'Potential Timing Side-Channel',
                    `Injection point "${point.label}" with ${charSet.label} causes ${ratio.toFixed(1)}x baseline response time, suggesting server-side processing of special characters.`,
                    Severity.MEDIUM,
                    'Behavioral Analysis',
                    domain,
                    `Point: ${point.label}, Chars: ${charSet.label}, Baseline: ${avgBaseline.toFixed(0)}ms, Test: ${testRes.duration}ms (ratio: ${ratio.toFixed(1)}x), Verify: ${verifyRes.duration}ms (ratio: ${verifyRatio.toFixed(1)}x)`,
                    'Timing side-channels can leak information about blind injection vulnerabilities (SQL, LDAP, command injection)',
                    'Implement constant-time comparisons; use generic response times; add random delays; avoid conditional logic based on input',
                    ['https://portswigger.net/web-security/sql-injection/blind']
                  ));
                  break; // Move to next injection point after finding
                }
              }
            }
          }
        } catch {}
      }
    }

    // Test login form timing specifically
    const loginEndpoints = ['/login', '/api/login', '/auth/login', '/api/auth/login', '/signin', '/api/signin'];
    for (const endpoint of loginEndpoints) {
      try {
        const normalRes = await safeRequest(`${baseUrl}${endpoint}`, 'POST', {
          'Content-Type': 'application/json',
        }, JSON.stringify({ email: 'test@test.com', password: 'normalpassword' }));
        if (normalRes.duration === 0) continue;

        const sqliRes = await safeRequest(`${baseUrl}${endpoint}`, 'POST', {
          'Content-Type': 'application/json',
        }, JSON.stringify({ email: "admin' OR '1'='1", password: 'test' }));

        if (sqliRes.duration > 0 && normalRes.duration > 0) {
          const loginRatio = sqliRes.duration / normalRes.duration;
          if (loginRatio > 2 && sqliRes.duration > 300) {
            findings.push(generateFinding(
              'Timing Anomaly on Login (Potential Blind Injection)',
              `Login endpoint ${endpoint} shows ${loginRatio.toFixed(1)}x timing difference when SQL injection payload is used, suggesting blind injection.`,
              Severity.HIGH,
              'Behavioral Analysis',
              domain,
              `Endpoint: ${endpoint}, Normal: ${normalRes.duration}ms, SQLi: ${sqliRes.duration}ms, Ratio: ${loginRatio.toFixed(1)}x`,
              'Blind injection via timing can be used to extract data character-by-character',
              'Use parameterized queries; implement query timeouts; normalize response times',
              ['https://portswigger.net/web-security/sql-injection/blind']
            ));
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`TimingSideChannel: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── 4. Response Tampering Detection ───
async function testResponseTampering(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('behavioral', 'ResponseTampering', baseUrl, 'Testing header-based response manipulation');
  try {
    // Get baseline response
    const baseline = await safeRequest(baseUrl, 'GET', {}, '');
    if (baseline.statusCode === 0) {
      errors.push('ResponseTampering: Could not get baseline');
      return;
    }

    // Headers that may bypass access controls or alter behavior
    const tamperHeaders: { headers: Record<string, string>; label: string; category: string }[] = [
      { headers: { 'X-Forwarded-For': '127.0.0.1' }, label: 'X-Forwarded-For localhost', category: 'IP-based access control bypass' },
      { headers: { 'X-Forwarded-For': '::1' }, label: 'X-Forwarded-For IPv6 loopback', category: 'IP-based access control bypass' },
      { headers: { 'X-Real-IP': '127.0.0.1' }, label: 'X-Real-IP localhost', category: 'IP-based access control bypass' },
      { headers: { 'X-Original-URL': '/admin' }, label: 'X-Original-URL admin', category: 'URL-based access control bypass' },
      { headers: { 'X-Rewrite-URL': '/admin' }, label: 'X-Rewrite-URL admin', category: 'URL-based access control bypass' },
      { headers: { 'X-Forwarded-Host': 'localhost' }, label: 'X-Forwarded-Host localhost', category: 'Host-based access control bypass' },
      { headers: { 'Authorization': '' }, label: 'Empty Authorization', category: 'Authentication bypass' },
      { headers: { 'Authorization': 'Bearer ' }, label: 'Empty Bearer token', category: 'Authentication bypass' },
      { headers: { 'Authorization': 'Bearer null' }, label: 'Null Bearer token', category: 'Authentication bypass' },
      { headers: { 'Authorization': 'Bearer undefined' }, label: 'Undefined Bearer token', category: 'Authentication bypass' },
    ];

    for (const { headers, label, category } of tamperHeaders) {
      try {
        const res = await safeRequest(baseUrl, 'GET', headers, '');
        if (res.statusCode === 0) continue;

        // Compare status code
        const statusDiffers = res.statusCode !== baseline.statusCode;

        // Compare body similarity
        const similarity = bodySimilarity(baseline.body.substring(0, 2000), res.body.substring(0, 2000));
        const bodyDiffers = similarity < 0.7 && Math.abs(res.body.length - baseline.body.length) > 100;

        // Check for sensitive content in the modified response
        const sensitivePatterns = [
          'admin', 'dashboard', 'settings', 'config', 'users',
          'email', 'phone', 'address', 'password', 'secret',
          'api_key', 'token', 'private', 'internal',
        ];
        const hasSensitive = sensitivePatterns.some(p =>
          res.body.toLowerCase().includes(p) && !baseline.body.toLowerCase().includes(p)
        );

        if (statusDiffers && (res.statusCode === 200 || res.statusCode === 302)) {
          findings.push(generateFinding(
            `Response Tampering via ${label}`,
            `Adding header "${Object.keys(headers)[0]}" changes the response from ${baseline.statusCode} to ${res.statusCode}, indicating header-based access control.`,
            Severity.HIGH,
            'Behavioral Analysis',
            domain,
            `Header: ${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join(', ')}, Baseline: ${baseline.statusCode}, Tampered: ${res.statusCode}`,
            'Header-based access control can be bypassed to access restricted resources',
            'Do not rely on client-supplied headers for access control; use server-side session validation',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/']
          ));
        }

        if (bodyDiffers && hasSensitive) {
          findings.push(generateFinding(
            `Sensitive Data Exposure via ${label}`,
            `Header "${Object.keys(headers)[0]}" causes the response to include sensitive content not present in the baseline.`,
            Severity.HIGH,
            'Behavioral Analysis',
            domain,
            `Header: ${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join(', ')}, Body similarity: ${(similarity * 100).toFixed(0)}%, Sensitive patterns found`,
            'Bypassing access controls via headers can expose sensitive data',
            'Validate headers server-side; do not trust proxy headers without verification',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/']
          ));
        }
      } catch {}
    }

    // Test HTTP method tampering
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE'];
    for (const method of methods) {
      try {
        if (method === 'GET') continue;
        const res = await safeRequest(baseUrl, method, {}, method === 'POST' || method === 'PUT' || method === 'PATCH' ? '{}' : '');
        if (res.statusCode === 200 && method !== 'OPTIONS' && method !== 'HEAD') {
          // Check if sensitive content is exposed via unexpected method
          const bodyLower = res.body.toLowerCase();
          const hasSensitive = ['admin', 'config', 'password', 'secret', 'internal'].some(p => bodyLower.includes(p));
          if (hasSensitive) {
            findings.push(generateFinding(
              `Sensitive Content via ${method} Method`,
              `The ${method} method returns sensitive content that is not available via GET, indicating improper access control.`,
              Severity.MEDIUM,
              'Behavioral Analysis',
              domain,
              `Method: ${method}, Status: ${res.statusCode}, Sensitive content detected`,
              'HTTP method tampering can bypass access controls and expose restricted functionality',
              'Restrict HTTP methods; return 405 for unsupported methods; validate method-based access control',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods']
            ));
          }
        }
      } catch {}
    }
  } catch (e) { errors.push(`ResponseTampering: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── 5. Information Leakage via Error Recovery ───
async function testErrorRecovery(domain: string, baseUrl: string, findings: Finding[], errors: string[]): Promise<void> {
  logExploit('behavioral', 'ErrorRecovery', baseUrl, 'Testing error recovery information leakage');
  try {
    // Test with oversized POST body
    try {
      const largeBody = JSON.stringify({ data: 'X'.repeat(100000) });
      const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/json' }, largeBody);
      if (res.statusCode > 0) {
        const bodyLower = res.body.toLowerCase();
        const leakIndicators = ['request too large', 'payload size', 'limit exceeded', 'memory', 'buffer', 'overflow'];
        const hasLeak = leakIndicators.some(i => bodyLower.includes(i));
        if (hasLeak && res.statusCode >= 400) {
          findings.push(generateFinding(
            'Error Recovery Information Disclosure (Large Body)',
            'Server error response to oversized POST body reveals internal error handling details.',
            Severity.LOW,
            'Behavioral Analysis',
            domain,
            `Body size: ${largeBody.length} bytes, Status: ${res.statusCode}, Response contains: ${leakIndicators.filter(i => bodyLower.includes(i)).join(', ')}`,
            'Detailed error messages during error recovery help attackers understand server limits and configurations',
            'Return generic error responses; limit request body size at the reverse proxy level',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/']
          ));
        }
      }
    } catch {}

    // Test with binary content in text field
    try {
      const binaryBody = 'field=' + encodeURIComponent('\x00\x01\x02\x03\xff\xfe');
      const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/x-www-form-urlencoded' }, binaryBody);
      if (res.statusCode >= 500 && res.statusCode > 0) {
        const bodyLower = res.body.toLowerCase();
        const hasTrace = ['stack', 'trace', 'exception', 'error', 'internal', 'debug'].some(i => bodyLower.includes(i));
        if (hasTrace) {
          findings.push(generateFinding(
            'Error Recovery Information Disclosure (Binary Input)',
            'Server exposes internal error details when processing binary content in text fields.',
            Severity.LOW,
            'Behavioral Analysis',
            domain,
            `Status: ${res.statusCode}, Binary input triggered detailed error response`,
            'Unhandled binary data may bypass input validation and trigger verbose error messages',
            'Implement proper input validation; use generic error pages',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
          ));
        }
      }
    } catch {}

    // Test with deeply nested JSON
    try {
      let nested = '"a"';
      for (let i = 0; i < 50; i++) {
        nested = `{"key":${nested}}`;
      }
      const res = await safeRequest(baseUrl, 'POST', { 'Content-Type': 'application/json' }, nested);
      if (res.statusCode >= 500 && res.statusCode > 0) {
        const bodyLower = res.body.toLowerCase();
        const hasDetail = ['recursion', 'depth', 'stack', 'overflow', 'parse', 'json'].some(i => bodyLower.includes(i));
        if (hasDetail) {
          findings.push(generateFinding(
            'Error Recovery Information Disclosure (Nested JSON)',
            'Server exposes parsing error details when processing deeply nested JSON.',
            Severity.LOW,
            'Behavioral Analysis',
            domain,
            `Status: ${res.statusCode}, Nesting depth: 50, Error details exposed`,
            'Detailed parsing errors reveal JSON parser behavior and potential DoS vectors',
            'Limit JSON nesting depth; implement parser timeouts; use generic error responses',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
          ));
        }
      }
    } catch {}

    // Check for debug headers
    try {
      const res = await safeRequest(baseUrl, 'GET', {}, '');
      if (res.statusCode > 0) {
        const debugHeaders = [
          'x-debug', 'x-debug-token', 'x-debug-token-link',
          'x-request-id', 'x-runtime', 'x-amzn-trace-id',
          'server-timing', 'x-aspnet-version', 'x-aspnetmvc-version',
          'x-powered-by', 'x-generator', 'x-drupal-cache',
          'x-rails-version', 'x-runtime-prefix', 'x-debug-mode',
        ];

        const foundDebugHeaders: string[] = [];
        for (const header of debugHeaders) {
          const value = res.headers[header];
          if (value !== undefined && value !== '') {
            foundDebugHeaders.push(`${header}: ${value}`);
          }
        }

        // Also check for unusual Server header patterns
        const serverHeader = (res.headers['server'] || '').toString();
        if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
          foundDebugHeaders.push(`server: ${serverHeader}`);
        }

        if (foundDebugHeaders.length > 0) {
          findings.push(generateFinding(
            'Debug/Development Headers Exposed',
            `The application exposes debug and development headers that may leak internal information.`,
            Severity.LOW,
            'Behavioral Analysis',
            domain,
            `Debug headers found: ${foundDebugHeaders.join('; ')}`,
            'Debug headers can expose server version, framework details, request tracing, and internal infrastructure',
            'Remove debug headers in production; suppress version information; disable debug mode',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
          ));
        }

        // Check for X-Request-Id patterns that may indicate internal infrastructure
        const xRequestId = (res.headers['x-request-id'] || '').toString();
        if (xRequestId) {
          // UUID pattern suggests request tracking
          const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(xRequestId);
          if (isUuid) {
            findings.push(generateFinding(
              'Request Tracking Header Exposed',
              'The application exposes X-Request-Id with a UUID pattern, indicating internal request tracking infrastructure.',
              Severity.INFO,
              'Behavioral Analysis',
              domain,
              `X-Request-Id: ${xRequestId}`,
              'Request tracking IDs can be used for log correlation attacks or to understand internal architecture',
              'Remove or obfuscate internal tracking headers in responses',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
            ));
          }
        }

        // Server-Timing header may expose internal durations
        const serverTiming = (res.headers['server-timing'] || '').toString();
        if (serverTiming && serverTiming.length > 0) {
          findings.push(generateFinding(
            'Server-Timing Header Exposed',
            'The application exposes Server-Timing header which may reveal internal processing durations.',
            Severity.INFO,
            'Behavioral Analysis',
            domain,
            `Server-Timing: ${serverTiming.substring(0, 200)}`,
            'Server-Timing headers can reveal database query times, cache hits, and internal processing bottlenecks',
            'Remove Server-Timing header or limit information in production',
            ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server-Timing']
          ));
        }
      }
    } catch {}
  } catch (e) { errors.push(`ErrorRecovery: ${e instanceof Error ? e.message : String(e)}`); }
}

// ─── Main Entry Point ───
export async function runBehavioralScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const baseUrl = `https://${domain}`;
    const httpUrl = `http://${domain}`;

    // Verify connectivity
    let connectivityOk = false;
    let activeBaseUrl = baseUrl;
    try { await makeRequest(baseUrl); connectivityOk = true; } catch {
      try { await makeRequest(httpUrl); connectivityOk = true; activeBaseUrl = httpUrl; } catch {}
    }
    if (!connectivityOk) {
      errors.push(`Could not connect to ${domain}`);
      const duration = Date.now() - startTime;
      return { module: 'behavioral', findings, duration, errors };
    }

    // Run all tests
    await Promise.allSettled([
      testResponseAnomalies(domain, activeBaseUrl, findings, errors),
      testErrorFingerprinting(domain, activeBaseUrl, findings, errors),
      testTimingSideChannel(domain, activeBaseUrl, findings, errors),
      testResponseTampering(domain, activeBaseUrl, findings, errors),
      testErrorRecovery(domain, activeBaseUrl, findings, errors),
    ]);

    const duration = Date.now() - startTime;
    logDone('behavioral', `Behavioral scan complete: ${findings.length} findings`, duration, findings.length);
    return { module: 'behavioral', findings, duration, errors };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'behavioral',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
