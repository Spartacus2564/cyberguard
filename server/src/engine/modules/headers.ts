import * as https from 'https';
import * as http from 'http';
import * as url from 'url';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl } from './shared';

function makeRequest(targetUrl: string, method: string = 'GET', headers: Record<string, string> = {}, body: string = ''): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method,
      headers,
      timeout: 10000,
      rejectUnauthorized: false,
    };
    const req = mod.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    if (body) req.write(body);
    req.end();
  });
}

function parseCspDirectives(csp: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  const parts = csp.split(';').map(s => s.trim()).filter(Boolean);
  for (const part of parts) {
    const [directive, ...values] = part.split(/\s+/);
    if (directive) {
      directives[directive.toLowerCase()] = values.map(v => v.toLowerCase());
    }
  }
  return directives;
}

function parseCookies(setCookieHeaders: string | string[] | undefined): Array<{ name: string; flags: string[]; raw: string }> {
  if (!setCookieHeaders) return [];
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  return headers.map(raw => {
    const parts = raw.split(';').map(s => s.trim());
    const nameValue = parts[0] || '';
    const name = nameValue.split('=')[0].trim();
    const flags = parts.slice(1).map(f => f.toLowerCase().split('=')[0].trim());
    return { name, flags, raw };
  });
}

export async function runHeadersScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let headers: http.IncomingHttpHeaders = {};
    let body = '';

    try {
      const result = await fetchUrl(`https://${domain}`, 10000);
      headers = result.headers;
      body = result.body;
    } catch (e) {
      try {
        const result = await fetchUrl(`http://${domain}`, 10000);
        headers = result.headers;
        body = result.body;
      } catch (e2) {
        errors.push(`Could not fetch ${domain}: ${e2 instanceof Error ? e2.message : String(e2)}`);
      }
    }

    // === Content-Security-Policy Deep Analysis ===
    const rawCsp = headers['content-security-policy'];
    const csp = Array.isArray(rawCsp) ? rawCsp[0] : rawCsp;

    if (!csp) {
      findings.push(generateFinding(
        'Missing Content-Security-Policy',
        'The response does not include a Content-Security-Policy header.',
        Severity.HIGH,
        'Security Headers',
        domain,
        'No Content-Security-Policy header found',
        'Without CSP, the site is vulnerable to XSS, data injection, and clickjacking attacks',
        'Implement a Content-Security-Policy header to restrict resource loading',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    } else {
      const directives = parseCspDirectives(csp);

      // Check for unsafe-inline in script-src
      const scriptSrc = directives['script-src'] || directives['default-src'] || [];
      if (scriptSrc.includes("'unsafe-inline'")) {
        findings.push(generateFinding(
          'CSP allows unsafe-inline scripts',
          'The Content-Security-Policy allows unsafe-inline scripts, which weakens XSS protection.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `script-src includes 'unsafe-inline'`,
          'unsafe-inline allows execution of inline scripts, defeating the purpose of CSP',
          'Use nonces or hashes instead of unsafe-inline for inline scripts',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      if (scriptSrc.includes("'unsafe-eval'")) {
        findings.push(generateFinding(
          'CSP allows unsafe-eval',
          'The Content-Security-Policy allows unsafe-eval, which permits eval() and similar code execution.',
          Severity.HIGH,
          'Security Headers',
          domain,
          `script-src includes 'unsafe-eval'`,
          'unsafe-eval allows dynamic code execution, enabling XSS attacks',
          'Remove unsafe-eval from the CSP and refactor code to avoid eval()',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for wildcard in script-src
      if (scriptSrc.includes('*') && !scriptSrc.includes("'none'")) {
        findings.push(generateFinding(
          'CSP script-src allows all sources',
          'The script-src directive includes a wildcard (*), allowing scripts from any origin.',
          Severity.HIGH,
          'Security Headers',
          domain,
          `script-src includes *`,
          'A wildcard in script-src completely defeats CSP XSS protection',
          'Whitelist specific trusted domains instead of using a wildcard',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for data: URIs in script-src
      if (scriptSrc.includes('data:')) {
        findings.push(generateFinding(
          'CSP allows data: URIs in scripts',
          'The script-src directive allows data: URIs, which can be used for XSS.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `script-src includes data:`,
          'data: URIs in script-src allow inline scripts disguised as data',
          'Remove data: from script-src and load scripts from trusted URLs only',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for object-src
      const objectSrc = directives['object-src'] || [];
      if (!objectSrc.includes("'none'") && objectSrc.length > 0) {
        findings.push(generateFinding(
          'CSP does not restrict object-src',
          'The CSP does not set object-src to none, allowing plugin content that can execute code.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `object-src: ${objectSrc.join(' ') || 'not set'}`,
          'Plugins (Flash, Java, etc.) loaded via object-src can execute arbitrary code',
          'Set object-src to none in the CSP',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for base-uri
      const baseUri = directives['base-uri'] || [];
      if (baseUri.length === 0) {
        findings.push(generateFinding(
          'CSP missing base-uri directive',
          'The CSP does not include a base-uri directive, allowing base tag injection.',
          Severity.LOW,
          'Security Headers',
          domain,
          'base-uri directive not found',
          'Missing base-uri allows attackers to inject <base> tags to redirect relative URLs',
          'Add base-uri \'self\' to the CSP',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for form-action
      const formAction = directives['form-action'] || [];
      if (formAction.length === 0) {
        findings.push(generateFinding(
          'CSP missing form-action directive',
          'The CSP does not include a form-action directive, allowing forms to submit to any URL.',
          Severity.LOW,
          'Security Headers',
          domain,
          'form-action directive not found',
          'Missing form-action allows phishing forms that submit credentials to attacker servers',
          'Add form-action \'self\' to the CSP',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for frame-ancestors
      const frameAncestors = directives['frame-ancestors'] || [];
      if (frameAncestors.length === 0) {
        findings.push(generateFinding(
          'CSP missing frame-ancestors directive',
          'The CSP does not include a frame-ancestors directive.',
          Severity.LOW,
          'Security Headers',
          domain,
          'frame-ancestors directive not found',
          'Missing frame-ancestors allows clickjacking via iframe embedding',
          'Add frame-ancestors \'self\' to restrict embedding',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for report-uri / report-to
      const reportUri = directives['report-uri'] || directives['report-to'] || [];
      if (reportUri.length === 0) {
        findings.push(generateFinding(
          'CSP missing violation reporting',
          'The CSP does not include report-uri or report-to for violation reporting.',
          Severity.LOW,
          'Security Headers',
          domain,
          'No CSP reporting directive found',
          'Without CSP reporting, you cannot detect or monitor CSP violations',
          'Add report-uri or report-to directive to collect CSP violation reports',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }

      // Check for upgrade-insecure-requests
      const upgradeInsecure = directives['upgrade-insecure-requests'] || [];
      if (upgradeInsecure.length === 0) {
        findings.push(generateFinding(
          'CSP missing upgrade-insecure-requests',
          'The CSP does not include upgrade-insecure-requests.',
          Severity.LOW,
          'Security Headers',
          domain,
          'upgrade-insecure-requests not found in CSP',
          'Mixed content may be loaded if upgrade-insecure-requests is not set',
          'Add upgrade-insecure-requests to automatically upgrade HTTP to HTTPS',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }
    }

    // === X-Content-Type-Options ===
    const rawXcto = headers['x-content-type-options'];
    const xcto = Array.isArray(rawXcto) ? rawXcto[0] : rawXcto;
    if (!xcto) {
      findings.push(generateFinding(
        'Missing X-Content-Type-Options',
        'The response does not include X-Content-Type-Options header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'No X-Content-Type-Options header found',
        'Without this header, browsers may MIME-sniff responses to execute code',
        'Add X-Content-Type-Options: nosniff',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    } else if (xcto.toLowerCase() !== 'nosniff') {
      findings.push(generateFinding(
        'Invalid X-Content-Type-Options value',
        `The X-Content-Type-Options header has an unexpected value: ${xcto}`,
        Severity.LOW,
        'Security Headers',
        domain,
        `X-Content-Type-Options: ${xcto}`,
        'The only valid value is nosniff',
        'Set X-Content-Type-Options to nosniff',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === X-Frame-Options ===
    const rawXfo = headers['x-frame-options'];
    const xfo = Array.isArray(rawXfo) ? rawXfo[0] : rawXfo;
    if (!xfo) {
      findings.push(generateFinding(
        'Missing X-Frame-Options',
        'The response does not include X-Frame-Options header.',
        Severity.MEDIUM,
        'Security Headers',
        domain,
        'No X-Frame-Options header found',
        'Without X-Frame-Options, the site may be embedded in iframes for clickjacking',
        'Add X-Frame-Options: DENY or SAMEORIGIN',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    } else {
      const xfoUpper = xfo.toUpperCase();
      if (xfoUpper === 'ALLOW-FROM') {
        findings.push(generateFinding(
          'Deprecated X-Frame-Options value',
          'The X-Frame-Options header uses ALLOW-FROM, which is deprecated and not supported by modern browsers.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `X-Frame-Options: ${xfo}`,
          'ALLOW-FROM is deprecated; use CSP frame-ancestors instead',
          'Replace X-Frame-Options ALLOW-FROM with CSP frame-ancestors directive',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }
    }

    // === Referrer-Policy ===
    const rawReferrer = headers['referrer-policy'];
    const referrer = Array.isArray(rawReferrer) ? rawReferrer[0] : rawReferrer;
    if (!referrer) {
      findings.push(generateFinding(
        'Missing Referrer-Policy',
        'The response does not include Referrer-Policy header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'No Referrer-Policy header found',
        'Without Referrer-Policy, sensitive URL information may leak via the Referer header',
        'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === Permissions-Policy ===
    const rawPp = headers['permissions-policy'] || headers['feature-policy'];
    const pp = Array.isArray(rawPp) ? rawPp[0] : rawPp;
    if (!pp) {
      findings.push(generateFinding(
        'Missing Permissions-Policy',
        'The response does not include Permissions-Policy header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'No Permissions-Policy header found',
        'Without Permissions-Policy, the browser defaults allow features like camera, microphone, geolocation',
        'Add Permissions-Policy to restrict browser features',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === CORS Analysis ===
    const rawAcao = headers['access-control-allow-origin'];
    const acao = Array.isArray(rawAcao) ? rawAcao[0] : rawAcao;
    if (acao) {
      if (acao === '*') {
        findings.push(generateFinding(
          'CORS allows all origins',
          'The Access-Control-Allow-Origin header is set to *, allowing any origin to make cross-origin requests.',
          Severity.HIGH,
          'Security Headers',
          domain,
          `Access-Control-Allow-Origin: ${acao}`,
          'A wildcard CORS policy allows any website to read responses, potentially leaking sensitive data',
          'Restrict CORS to specific trusted origins',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      } else {
        // Check if the origin matches the target domain
        const origins = acao.split(',').map((o: string) => o.trim());
        const suspiciousOrigins = origins.filter((o: string) =>
          o && !o.includes(domain) && !o.includes('null')
        );
        if (suspiciousOrigins.length > 0) {
          findings.push(generateFinding(
            'CORS includes non-standard origins',
            `The CORS policy includes origins that don't match the target domain: ${suspiciousOrigins.join(', ')}`,
            Severity.MEDIUM,
            'Security Headers',
            domain,
            `Access-Control-Allow-Origin: ${acao}`,
            'CORS origins that don\'t match the target domain may indicate misconfiguration',
            'Verify CORS origins are intentionally configured and restrict to trusted domains',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
          ));
        }
      }
    }

    // Check for credentials with wildcard CORS
    const rawAcac = headers['access-control-allow-credentials'];
    const acac = Array.isArray(rawAcac) ? rawAcac[0] : rawAcac;
    if (acac === 'true' && acao === '*') {
      findings.push(generateFinding(
        'CORS credentials with wildcard origin',
        'Access-Control-Allow-Credentials is true with a wildcard origin, which is a dangerous combination.',
        Severity.CRITICAL,
        'Security Headers',
        domain,
        `Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true`,
        'This combination allows any website to make authenticated cross-origin requests',
        'Remove the wildcard origin or set Access-Control-Allow-Credentials to false',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === Cookie Security (proper parsing) ===
    const cookies = parseCookies(headers['set-cookie'] as string | string[] | undefined);
    if (cookies.length > 0) {
      const insecureCookies: string[] = [];
      const sameSiteNoneCookies: string[] = [];
      for (const cookie of cookies) {
        const missingFlags: string[] = [];
        if (!cookie.flags.includes('secure')) missingFlags.push('Secure');
        if (!cookie.flags.includes('httponly')) missingFlags.push('HttpOnly');
        if (!cookie.flags.includes('samesite')) missingFlags.push('SameSite');
        if (missingFlags.length > 0) {
          insecureCookies.push(`${cookie.name} (missing: ${missingFlags.join(', ')})`);
        }
        const sameSiteMatch = cookie.flags.find(f => f.startsWith('samesite='));
        if (sameSiteMatch) {
          const value = sameSiteMatch.split('=')[1]?.toLowerCase();
          if (value === 'none') {
            sameSiteNoneCookies.push(cookie.name);
          }
        }
      }

      if (insecureCookies.length > 0) {
        findings.push(generateFinding(
          'Cookies missing security flags',
          `${insecureCookies.length} cookie(s) are missing security flags.`,
          Severity.MEDIUM,
          'Security Headers',
          domain,
          insecureCookies.join('; '),
          'Cookies without Secure/HttpOnly/SameSite flags are vulnerable to theft and CSRF',
          'Add Secure, HttpOnly, and SameSite flags to all cookies',
          ['https://owasp.org/www-community/Controls/SecureCookieAttribute']
        ));
      }

      if (sameSiteNoneCookies.length > 0) {
        findings.push(generateFinding(
          'Cookies with SameSite=None',
          `${sameSiteNoneCookies.length} cookie(s) have SameSite=None, which allows cross-site requests.`,
          Severity.MEDIUM,
          'Security Headers',
          domain,
          sameSiteNoneCookies.join(', '),
          'SameSite=None cookies are sent with cross-site requests, increasing CSRF attack surface',
          'Set SameSite=Lax or SameSite=Strict unless cross-site usage is required',
          ['https://owasp.org/www-community/SameSite']
        ));
      }
    }

    // === CORS Preflight Check ===
    try {
      const preflightResult = await fetchUrl("https://" + domain, 5000);
      const acao = preflightResult.headers['access-control-allow-origin'] as string;
      const acac = preflightResult.headers['access-control-allow-credentials'] as string;
      if (acao === '*' && acac === 'true') {
        findings.push(generateFinding(
          'CORS credentials with wildcard origin',
          'CORS allows credentials with wildcard origin, enabling credential theft from any domain.',
          Severity.CRITICAL,
          'Security Headers',
          domain,
          `Access-Control-Allow-Origin: ${acao}, Access-Control-Allow-Credentials: ${acac}`,
          'Any malicious website can make authenticated requests on behalf of users',
          'Restrict Access-Control-Allow-Origin to specific trusted domains',
          ['https://portswigger.net/web-security/cors']
        ));
      }
    } catch {
      // Preflight check failed, not critical
    }

    // === X-XSS-Protection (deprecated but still worth checking) ===
    const rawXxp = headers['x-xss-protection'];
    const xxp = Array.isArray(rawXxp) ? rawXxp[0] : rawXxp;
    if (xxp && xxp !== '0') {
      findings.push(generateFinding(
        'Deprecated X-XSS-Protection header',
        'The X-XSS-Protection header is set but is deprecated and can introduce vulnerabilities.',
        Severity.INFO,
        'Security Headers',
        domain,
        `X-XSS-Protection: ${xxp}`,
        'The X-XSS-Protection header is deprecated; modern browsers rely on CSP instead',
        'Remove X-XSS-Protection header and rely on Content-Security-Policy instead',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === Missing X-Content-Security-Policy (legacy IE) ===
    const rawXcsp = headers['x-content-security-policy'];
    const xcsp = Array.isArray(rawXcsp) ? rawXcsp[0] : rawXcsp;
    if (xcsp) {
      findings.push(generateFinding(
        'Legacy X-Content-Security-Policy header present',
        'The X-Content-Security-Policy header is a legacy IE header that should not be used.',
        Severity.INFO,
        'Security Headers',
        domain,
        `X-Content-Security-Policy: ${xcsp.substring(0, 100)}`,
        'Legacy headers may conflict with modern CSP',
        'Remove X-Content-Security-Policy and use Content-Security-Policy instead',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === Cache-Control for sensitive content ===
    const rawCc = headers['cache-control'];
    const cc = Array.isArray(rawCc) ? rawCc[0] : rawCc;
    if (cc && cc.includes('public')) {
      // Check if it's a page that shouldn't be cached (login, etc.)
      if (body.toLowerCase().includes('login') || body.toLowerCase().includes('password')) {
        findings.push(generateFinding(
          'Sensitive page may be cached',
          'A page containing login/password content has public cache headers.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `Cache-Control: ${cc}`,
          'Sensitive pages should not be cached by proxies or browsers',
          'Add Cache-Control: no-store, no-cache for sensitive pages',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
        ));
      }
    }

    // === Cross-Origin Isolation Headers ===
    const rawCoep = headers['cross-origin-embedder-policy'];
    const coep = Array.isArray(rawCoep) ? rawCoep[0] : rawCoep;
    if (!coep) {
      findings.push(generateFinding(
        'Missing Cross-Origin-Embedder-Policy',
        'The response does not include Cross-Origin-Embedder-Policy header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'Header not present',
        'Without COEP, the page cannot use cross-origin resources safely',
        'Add Cross-Origin-Embedder-Policy: require-corp',
        ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy']
      ));
    }

    const rawCoop = headers['cross-origin-opener-policy'];
    const coop = Array.isArray(rawCoop) ? rawCoop[0] : rawCoop;
    if (!coop) {
      findings.push(generateFinding(
        'Missing Cross-Origin-Opener-Policy',
        'The response does not include Cross-Origin-Opener-Policy header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'Header not present',
        'Without COOP, the page is vulnerable to cross-origin attacks via window.opener',
        'Add Cross-Origin-Opener-Policy: same-origin',
        ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy']
      ));
    }

    const rawCorp = headers['cross-origin-resource-policy'];
    const corp = Array.isArray(rawCorp) ? rawCorp[0] : rawCorp;
    if (!corp) {
      findings.push(generateFinding(
        'Missing Cross-Origin-Resource-Policy',
        'The response does not include Cross-Origin-Resource-Policy header.',
        Severity.LOW,
        'Security Headers',
        domain,
        'Header not present',
        'Without CORP, resources can be loaded by any cross-origin page',
        'Add Cross-Origin-Resource-Policy: same-origin',
        ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy']
      ));
    }

    // === X-Permitted-Cross-Domain-Policies ===
    const rawXpcdp = headers['x-permitted-cross-domain-policies'];
    const xpcdp = Array.isArray(rawXpcdp) ? rawXpcdp[0] : rawXpcdp;
    if (!xpcdp || xpcdp !== 'none') {
      findings.push(generateFinding(
        'Missing or permissive X-Permitted-Cross-Domain-Policies',
        'The X-Permitted-Cross-Domain-Policies header is missing or allows cross-domain policy files.',
        Severity.LOW,
        'Security Headers',
        domain,
        `X-Permitted-Cross-Domain-Policies: ${xpcdp || 'not set'}`,
        'Flash/PDF cross-domain policies can allow data leakage',
        'Add X-Permitted-Cross-Domain-Policies: none',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing']
      ));
    }

    // === CORS Origin Reflection Test ===
    try {
      const fakeOrigins = ['https://evil.com', 'https://attacker.example.com', 'null'];
      for (const origin of fakeOrigins) {
        try {
          const result = await makeRequest(`https://${domain}`, 'OPTIONS', {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Authorization',
          });
          const acao = result.headers['access-control-allow-origin'];
          const acac = result.headers['access-control-allow-credentials'];
          if (acao && (acao === '*' || acao === origin) && acac === 'true') {
            findings.push(generateFinding(
              'CORS Origin Reflection',
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
    } catch {}

    // === Missing HSTS includeSubDomains ===
    try {
      const rawHsts = headers['strict-transport-security'];
      const hsts = Array.isArray(rawHsts) ? rawHsts[0] : rawHsts;
      if (hsts && hsts.includes('max-age=') && !hsts.toLowerCase().includes('includesubdomains')) {
        findings.push(generateFinding(
          'HSTS missing includeSubDomains',
          'HSTS header is present but does not include the includeSubDomains directive.',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `Strict-Transport-Security: ${hsts}`,
          'Without includeSubDomains, subdomains remain vulnerable to downgrade attacks',
          'Add includeSubDomains and preload directives to HSTS header',
          ['https://owasp.org/www-project-secure-headers/#strict-transport-security-headers']
        ));
      }
      if (hsts) {
        const maxAgeMatch = hsts.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1], 10);
          if (maxAge < 15768000) {
            findings.push(generateFinding(
              'HSTS max-age too short',
              `The HSTS max-age is ${maxAge}s, less than the recommended 6 months (15768000s).`,
              Severity.LOW,
              'Security Headers',
              domain,
              `Strict-Transport-Security: ${hsts}`,
              'Short max-age means browsers forget HSTS policy quickly, allowing downgrade attacks',
              'Set HSTS max-age to at least 15768000 (6 months)',
              ['https://owasp.org/www-project-secure-headers/#strict-transport-security-headers']
            ));
          }
        }
      }
    } catch {}

    // === Referrer-Policy dangerous values ===
    try {
      const rawRp = headers['referrer-policy'];
      const rp = Array.isArray(rawRp) ? rawRp[0] : rawRp;
      if (rp && (rp === 'unsafe-url' || rp === 'no-referrer-when-downgrade')) {
        findings.push(generateFinding(
          'Dangerous Referrer-Policy value',
          `The Referrer-Policy is set to a permissive value: "${rp}".`,
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `Referrer-Policy: ${rp}`,
          'Unsafe values can leak sensitive URL data to third parties',
          'Use strict-origin-when-cross-origin or no-referrer instead',
          ['https://owasp.org/www-project-secure-headers/#referrer-policy-headers']
        ));
      }
    } catch {}

    // === Cross-Origin-Resource-Policy ===
    try {
      const rawCorp = headers['cross-origin-resource-policy'];
      const corp = Array.isArray(rawCorp) ? rawCorp[0] : rawCorp;
      if (!corp) {
        findings.push(generateFinding(
          'Missing Cross-Origin-Resource-Policy header',
          'No CORP header is set, allowing other origins to embed this resource (Spectre risk).',
          Severity.LOW,
          'Security Headers',
          domain,
          'Cross-Origin-Resource-Policy: not set',
          'Without CORP, resources can be loaded by any page (Spectre attacks)',
          'Add Cross-Origin-Resource-Policy: same-origin or same-site',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy']
        ));
      }
    } catch {}

    // === Feature-Policy / Permissions-Policy detailed ===
    const rawFp = headers['feature-policy'] || headers['permissions-policy'];
    const fp = Array.isArray(rawFp) ? rawFp[0] : rawFp;
    if (fp) {
      const dangerousFeatures = ['camera', 'microphone', 'geolocation', 'payment', 'usb'];
      const enabledFeatures: string[] = [];
      for (const feature of dangerousFeatures) {
        if (fp.toLowerCase().includes(feature) && !fp.toLowerCase().includes(`${feature}=(none)`)) {
          enabledFeatures.push(feature);
        }
      }
      if (enabledFeatures.length > 0) {
        findings.push(generateFinding(
          'Dangerous features enabled in Permissions-Policy',
          `The following sensitive features are enabled: ${enabledFeatures.join(', ')}.`,
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `Permissions-Policy: ${fp.substring(0, 200)}`,
          'Enabling camera, microphone, geolocation etc. can be exploited',
          'Restrict dangerous features using Permissions-Policy header',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
        ));
      }
    }

    // === X-Content-Type-Options missing ===
    try {
      const rawXcto = headers['x-content-type-options'];
      const xcto = Array.isArray(rawXcto) ? rawXcto[0] : rawXcto;
      if (!xcto || xcto.toLowerCase() !== 'nosniff') {
        findings.push(generateFinding(
          'Missing or invalid X-Content-Type-Options',
          'The X-Content-Type-Options header is missing or not set to "nosniff".',
          Severity.MEDIUM,
          'Security Headers',
          domain,
          `X-Content-Type-Options: ${xcto || 'not set'}`,
          'Without nosniff, browsers may MIME-sniff responses and execute content as scripts',
          'Add X-Content-Type-Options: nosniff',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
        ));
      }
    } catch {}

    // === Cross-Origin-Embedder-Policy ===
    try {
      const rawCoep = headers['cross-origin-embedder-policy'];
      const coep = Array.isArray(rawCoep) ? rawCoep[0] : rawCoep;
      if (!coep) {
        findings.push(generateFinding(
          'Missing Cross-Origin-Embedder-Policy header',
          'No COEP header is set, which may expose cross-origin resources to side-channel attacks.',
          Severity.LOW,
          'Security Headers',
          domain,
          'Cross-Origin-Embedder-Policy: not set',
          'Without COEP, the page can load cross-origin resources without CORS, enabling Spectre attacks',
          'Add Cross-Origin-Embedder-Policy: require-corp or credentialless',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy']
        ));
      }
    } catch {}

    // === Cross-Origin-Opener-Policy ===
    try {
      const rawCoop = headers['cross-origin-opener-policy'];
      const coop = Array.isArray(rawCoop) ? rawCoop[0] : rawCoop;
      if (!coop) {
        findings.push(generateFinding(
          'Missing Cross-Origin-Opener-Policy header',
          'No COOP header is set, which may allow cross-origin window interaction.',
          Severity.LOW,
          'Security Headers',
          domain,
          'Cross-Origin-Opener-Policy: not set',
          'Without COOP, cross-origin windows can reference each other (Spectre, window.name attacks)',
          'Add Cross-Origin-Opener-Policy: same-origin',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy']
        ));
      }
    } catch {}

    // === Expect-CT ===
    try {
      const rawEc = headers['expect-ct'];
      const ec = Array.isArray(rawEc) ? rawEc[0] : rawEc;
      if (!ec) {
        findings.push(generateFinding(
          'Missing Expect-CT header',
          'No Expect-CT header is set, which helps detect misissued certificates.',
          Severity.INFO,
          'Security Headers',
          domain,
          'Expect-CT: not set',
          'Expect-CT helps detect and enforce Certificate Transparency compliance',
          'Add Expect-CT: max-age=86400, enforce',
          ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT']
        ));
      }
    } catch {}

    // === X-Download-Options ===
    try {
      const rawXdo = headers['x-download-options'];
      const xdo = Array.isArray(rawXdo) ? rawXdo[0] : rawXdo;
      if (!xdo || xdo.toLowerCase() !== 'noopen') {
        findings.push(generateFinding(
          'Missing or invalid X-Download-Options',
          'The X-Download-Options header is missing or not set to "noopen".',
          Severity.LOW,
          'Security Headers',
          domain,
          `X-Download-Options: ${xdo || 'not set'}`,
          'Without noopen, IE may execute downloaded files directly, enabling malware execution',
          'Add X-Download-Options: noopen',
          ['https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/ms537345(v=vs.85)']
        ));
      }
    } catch {}

    // === Cache-Control for sensitive endpoints ===
    try {
      const rawCc = headers['cache-control'];
      const cc = Array.isArray(rawCc) ? rawCc[0] : rawCc;
      if (cc && (cc.includes('public') || !cc.includes('no-store'))) {
        if (body.toLowerCase().includes('login') || body.toLowerCase().includes('password') || body.toLowerCase().includes('token') || body.toLowerCase().includes('api-key')) {
          findings.push(generateFinding(
            'Sensitive content may be cached',
            'A page containing sensitive content has permissive cache headers.',
            Severity.MEDIUM,
            'Security Headers',
            domain,
            `Cache-Control: ${cc}`,
            'Sensitive pages should not be cached by proxies or browsers to prevent data leakage',
            'Add Cache-Control: no-store, no-cache, must-revalidate, private',
            ['https://owasp.org/www-community/Controls/SecureCookieAttribute']
          ));
        }
      }
    } catch {}

    // === X-Per-CPU-Core (internal header leak) ===
    try {
      const rawCpu = headers['x-per-cpu-core'];
      const cpu = Array.isArray(rawCpu) ? rawCpu[0] : rawCpu;
      if (cpu) {
        findings.push(generateFinding(
          'Internal Server Information Disclosure',
          `The X-Per-CPU-Core header reveals server hardware information: "${cpu}".`,
          Severity.LOW,
          'Security Headers',
          domain,
          `X-Per-CPU-Core: ${cpu}`,
          'Internal headers reveal server configuration and hardware details',
          'Remove internal server headers',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
    } catch {}

    // === X-Runtime / X-Request-ID (information disclosure) ===
    try {
      const rawRuntime = headers['x-runtime'];
      const runtime = Array.isArray(rawRuntime) ? rawRuntime[0] : rawRuntime;
      if (runtime) {
        findings.push(generateFinding(
          'Server Timing Information Disclosure',
          `The X-Runtime header reveals server processing time: "${runtime}".`,
          Severity.INFO,
          'Security Headers',
          domain,
          `X-Runtime: ${runtime}`,
          'Timing information can help attackers identify slow paths for DoS or blind injection',
          'Remove X-Runtime header in production',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
    } catch {}

    // AI-enhanced header analysis — deeper evaluation of CSP, CORS, and misconfigs
    try {
      const { getAI } = await import('../../services/ai.service');
      const ai = getAI();
      const headerAnalysis = await ai.analyzeHeaders(headers as Record<string, string>, domain, body);
      if (headerAnalysis.findings.length > 0) {
        for (const f of headerAnalysis.findings) {
          findings.push(generateFinding(
            f.title || 'AI Header Finding',
            f.description || '',
            (f.severity as Severity) || Severity.LOW,
            'Security Headers',
            domain,
            f.remediation || '',
            f.impact || '',
            f.remediation || '',
            []
          ));
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return {
      module: 'headers',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'headers',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
