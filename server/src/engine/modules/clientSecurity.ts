import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  timeoutMs: number = 10000,
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try { parsed = new URL(targetUrl); } catch { reject(new Error('Invalid URL')); return; }
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: { 'User-Agent': 'CYBERGUARD-ClientSecurity/1.0', ...headers },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 5242880) { req.destroy(); return; }
        data += chunk.toString();
      });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

async function safe(url: string, method = 'GET', headers: Record<string, string> = {}) {
  try { return await makeRequest(url, method, headers); }
  catch { return { statusCode: 0, headers: {}, body: '' }; }
}

export async function runClientSecurityScan(domain: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;

  const res = await safe(base + '/');
  if (res.statusCode === 0) {
    errors.push('Could not reach target');
    return { module: 'clientSecurity', findings, duration: 0, errors };
  }

  const body = res.body;
  const hdrs = res.headers;

  // 1) Content-Security-Policy
  const csp = String(hdrs['content-security-policy'] || '');
  if (!csp) {
    findings.push(generateFinding({
      title: 'No Content-Security-Policy (CSP) Header',
      description: 'The server does not set a Content-Security-Policy header. Without CSP, the application relies solely on other mechanisms to prevent XSS, clickjacking, and data injection attacks.',
      severity: Severity.MEDIUM,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `No CSP header found. Response headers: ${Object.keys(hdrs).join(', ')}`,
      impact: 'No defense-in-depth against XSS, data injection, or content hijacking attacks.',
      remediation: 'Implement a strict CSP: Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\';',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
    }));
  }

  // 2) X-Frame-Options / frame-ancestors
  const xfo = String(hdrs['x-frame-options'] || '');
  const hasFrameAncestors = csp.includes('frame-ancestors');
  if (!xfo && !hasFrameAncestors) {
    findings.push(generateFinding({
      title: 'No Clickjacking Protection (Missing X-Frame-Options and frame-ancestors)',
      description: 'Neither X-Frame-Options nor CSP frame-ancestors directive is set. The application can be embedded in iframes on malicious sites, enabling clickjacking attacks.',
      severity: Severity.MEDIUM,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `X-Frame-Options: ${xfo || '(missing)'}\nCSP frame-ancestors: ${hasFrameAncestors ? 'present' : '(missing)'}`,
      impact: 'Attackers can embed the application in invisible iframes to trick users into clicking unintended actions (clickjacking).',
      remediation: 'Set X-Frame-Options: DENY and add frame-ancestors \'none\' to CSP.',
      references: ['https://owasp.org/www-community/attacks/Clickjacking'],
    }));
  }

  // 3) Referrer-Policy
  const rp = String(hdrs['referrer-policy'] || '');
  if (!rp) {
    findings.push(generateFinding({
      title: 'No Referrer-Policy Header',
      description: 'Without a Referrer-Policy header, browsers will send full URLs (including query parameters) as the Referer header to third-party sites, potentially leaking sensitive data like tokens, user IDs, or internal paths.',
      severity: Severity.LOW,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: 'Referrer-Policy header not found',
      impact: 'Sensitive information in URLs (tokens, IDs, internal paths) is leaked to third-party sites via the Referer header.',
      remediation: 'Set Referrer-Policy: strict-origin-when-cross-origin or Referrer-Policy: no-referrer',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'],
    }));
  }

  // 4) Permissions-Policy / Feature-Policy
  const pp = String(hdrs['permissions-policy'] || hdrs['feature-policy'] || '');
  if (!pp) {
    findings.push(generateFinding({
      title: 'No Permissions-Policy Header',
      description: 'Without a Permissions-Policy header, the browser grants default access to sensitive features like camera, microphone, geolocation, and payment APIs to the application and any embedded content.',
      severity: Severity.LOW,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: 'Permissions-Policy / Feature-Policy header not found',
      impact: 'Embedded content (iframes, ads) can access camera, microphone, and other sensitive browser features.',
      remediation: 'Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=()',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'],
    }));
  }

  // 5) Mixed content (HTTP resources on HTTPS page)
  const httpRe = /(?:src|href|action)\s*=\s*["']http:\/\//gi;
  const httpRefs: string[] = [];
  let hm;
  while ((hm = httpRe.exec(body)) !== null && httpRefs.length < 10) {
    httpRefs.push(hm[0]);
  }
  if (httpRefs.length > 0) {
    findings.push(generateFinding({
      title: `Mixed Content — ${httpRefs.length} HTTP Resource(s) on HTTPS Page`,
      description: `The HTTPS page loads ${httpRefs.length} resource(s) over plain HTTP. This enables man-in-the-middle attacks to inject malicious content, downgrade security, or steal credentials.`,
      severity: httpRefs.some(r => r.includes('src=')) ? Severity.MEDIUM : Severity.LOW,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `HTTP resources found:\n${httpRefs.map(r => `  ${r}`).join('\n')}`,
      impact: 'MITM attackers can modify HTTP resources to inject malicious JavaScript, steal cookies, or redirect users.',
      remediation: 'Replace all HTTP references with HTTPS. Use protocol-relative URLs (//) or upgrade all links to HTTPS.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
    }));
  }

  // 6) Third-party trackers / analytics leakage
  const trackers: { pattern: RegExp; name: string }[] = [
    { pattern: /google-analytics\.com|googletagmanager\.com|gtag/i, name: 'Google Analytics / GTM' },
    { pattern: /facebook\.net|facebook\.com\/tr|fbevents/i, name: 'Facebook Pixel' },
    { pattern: /hotjar\.com/i, name: 'Hotjar' },
    { pattern: /segment\.io|segment\.com/i, name: 'Segment' },
    { pattern: /amplitude\.com/i, name: 'Amplitude' },
    { pattern: /mixpanel\.com/i, name: 'Mixpanel' },
    { pattern: /clarity\.ms/i, name: 'Microsoft Clarity' },
    { pattern: /doubleclick\.net/i, name: 'DoubleClick' },
    { pattern: /adservice\.google/i, name: 'Google Ads' },
    { pattern: /twitter\.com\/i\/adsct|analytics\.twitter\.com/i, name: 'Twitter/X Ads' },
    { pattern: /tiktok\.com\/pixel/i, name: 'TikTok Pixel' },
    { pattern: /linkedin\.com\/px/i, name: 'LinkedIn Insight' },
    { pattern: /snap\.com\/pixel/i, name: 'Snapchat Pixel' },
  ];
  const foundTrackers: string[] = [];
  for (const t of trackers) {
    if (t.pattern.test(body)) foundTrackers.push(t.name);
  }
  if (foundTrackers.length > 2) {
    findings.push(generateFinding({
      title: `Multiple Third-Party Trackers Detected (${foundTrackers.length})`,
      description: `The page contains ${foundTrackers.length} third-party tracking scripts: ${foundTrackers.join(', ')}. This increases privacy risk, attack surface (supply chain), and potential data leakage to third parties.`,
      severity: Severity.LOW,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `Detected trackers: ${foundTrackers.join(', ')}`,
      impact: 'User behavior data is shared with multiple third parties, increasing privacy risk. Each tracker is an additional supply chain attack vector.',
      remediation: 'Audit tracker necessity. Implement Consent Management Platform (CMP) for GDPR/CCPA compliance. Use server-side tracking where possible.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/'],
    }));
  }

  // 7) Subresource Integrity check on CDN scripts
  const scriptRe = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let sm;
  const extScripts: string[] = [];
  while ((sm = scriptRe.exec(body)) !== null && extScripts.length < 15) {
    if (sm[1].startsWith('http') && !sm[1].includes(domain)) extScripts.push(sm[1]);
  }
  const hasSri = /integrity\s*=\s*["']sha/i.test(body);
  if (extScripts.length > 0 && !hasSri) {
    findings.push(generateFinding({
      title: 'External Scripts Without Subresource Integrity (SRI)',
      description: `${extScripts.length} external script(s) loaded without SRI hashes: ${extScripts.slice(0, 3).join(', ')}${extScripts.length > 3 ? '...' : ''}. A compromised CDN can inject malicious code.`,
      severity: Severity.MEDIUM,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `External scripts: ${extScripts.map(s => `  - ${s}`).join('\n')}`,
      impact: 'CDN compromise or MITM attack can inject arbitrary JavaScript into the application.',
      remediation: 'Add integrity="sha256-..." attributes to all third-party script tags. Use a CSP script-src with hashes.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    }));
  }

  // 8) Cookie security (from Set-Cookie headers)
  const setCookies = hdrs['set-cookie'];
  if (setCookies) {
    const cookies = Array.isArray(setCookies) ? setCookies : [setCookies];
    const issues: string[] = [];
    for (const c of cookies) {
      if (!c.toLowerCase().includes('httponly')) issues.push('missing HttpOnly');
      if (!c.toLowerCase().includes('secure')) issues.push('missing Secure');
      if (!c.toLowerCase().includes('samesite')) issues.push('missing SameSite');
    }
    if (issues.length > 0) {
      findings.push(generateFinding({
        title: 'Insecure Cookie Configuration',
        description: `Cookies are set without security flags: ${[...new Set(issues)].join(', ')}. This allows cookies to be accessed via JavaScript (XSS), sent over HTTP, and potentially used in CSRF attacks.`,
        severity: issues.includes('missing HttpOnly') ? Severity.MEDIUM : Severity.LOW,
        category: 'Client-Side Security',
        affectedAsset: base,
        evidence: `Set-Cookie headers:\n${cookies.map(c => `  ${c.slice(0, 200)}`).join('\n')}\nIssues: ${issues.join(', ')}`,
        impact: 'Without HttpOnly, cookies are accessible to XSS. Without Secure, cookies are sent over HTTP. Without SameSite, cookies are vulnerable to CSRF.',
        remediation: 'Set all cookies with: HttpOnly, Secure, SameSite=Strict (or Lax). Use short expiration times.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'],
      }));
    }
  }

  // 9) DOM XSS sinks
  const domSinks: { pattern: RegExp; name: string; severity: Severity }[] = [
    { pattern: /document\.write\s*\(/g, name: 'document.write()', severity: Severity.MEDIUM },
    { pattern: /innerHTML\s*=/g, name: 'innerHTML assignment', severity: Severity.MEDIUM },
    { pattern: /outerHTML\s*=/g, name: 'outerHTML assignment', severity: Severity.MEDIUM },
    { pattern: /\.html\s*\(/g, name: 'jQuery .html()', severity: Severity.MEDIUM },
    { pattern: /eval\s*\(/g, name: 'eval()', severity: Severity.HIGH },
    { pattern: /setTimeout\s*\(\s*["']/g, name: 'setTimeout with string', severity: Severity.HIGH },
    { pattern: /setInterval\s*\(\s*["']/g, name: 'setInterval with string', severity: Severity.HIGH },
    { pattern: /document\.location\s*=/g, name: 'document.location assignment', severity: Severity.MEDIUM },
    { pattern: /window\.location\s*=/g, name: 'window.location assignment', severity: Severity.MEDIUM },
  ];
  const foundSinks: { name: string; count: number; severity: Severity }[] = [];
  for (const s of domSinks) {
    const matches = body.match(s.pattern);
    if (matches && matches.length > 0) foundSinks.push({ name: s.name, count: matches.length, severity: s.severity });
  }
  if (foundSinks.length > 0) {
    const maxSeverity = foundSinks.some(s => s.severity === Severity.HIGH) ? Severity.HIGH : Severity.MEDIUM;
    findings.push(generateFinding({
      title: `DOM XSS Sinks Detected (${foundSinks.length} types)`,
      description: `The page contains ${foundSinks.length} types of DOM-based XSS sinks: ${foundSinks.map(s => `${s.name} (${s.count}x)`).join(', ')}. If user input reaches these sinks without sanitization, XSS vulnerabilities exist.`,
      severity: maxSeverity,
      category: 'Client-Side Security',
      affectedAsset: base,
      evidence: `DOM XSS sinks found:\n${foundSinks.map(s => `  ${s.name}: ${s.count} occurrences`).join('\n')}`,
      impact: 'DOM-based XSS can lead to session hijacking, credential theft, and arbitrary code execution in the user\'s browser.',
      remediation: 'Sanitize all user input before it reaches DOM sinks. Use textContent instead of innerHTML. Avoid eval() and string-based setTimeout/setInterval. Implement CSP with script-src.',
      references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS'],
    }));
  }

  return { module: 'clientSecurity', findings, duration: 0, errors };
}
