import * as https from 'https';
import * as http from 'http';
import * as url from 'url';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, isSpaShell, detectBlazor } from '../modules/shared';
import { getCommonPaths, getRaftMediumDirectories, getRaftMediumFiles, getSensitivePaths } from './seclists';
import logger from '../../utils/logger';
import { getAI } from '../../services/ai.service';

interface CrawledPage {
  url: string;
  statusCode: number;
  title?: string;
  body?: string;
  forms: FormData[];
  links: string[];
  scripts: string[];
  meta: Record<string, string>;
  headers: Record<string, string>;
  hasLogin: boolean;
  hasAdmin: boolean;
  hasApi: boolean;
}

interface FormData {
  action: string;
  method: string;
  inputs: FormInput[];
  hasCsrfToken: boolean;
}

interface FormInput {
  name: string;
  type: string;
  required: boolean;
  maxLength?: number;
  autocomplete?: string;
}

// HTTP GET with size limit
function httpGet(
  targetUrl: string,
  timeout: number = 10000,
  maxBytes: number = 2097152 // 2MB
): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; redirectUrl?: string }> {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(targetUrl);
    const mod = parsedUrl.protocol === 'https:' ? https : http;

    const req = mod.get({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml',
      },
      timeout,
      rejectUnauthorized: false,
    }, (res) => {
      let body = '';
      let totalBytes = 0;

      // Handle redirects
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: '',
          redirectUrl: res.headers.location,
        });
        res.destroy();
        return;
      }

      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > maxBytes) {
          req.destroy();
          return;
        }
        body += chunk.toString();
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          body,
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// Extract links from HTML
function extractLinks(body: string, baseUrl: string, domain: string): string[] {
  const links: string[] = [];
  const parsedBase = new URL(baseUrl);

  // Extract href attributes
  const hrefPattern = /href=["']([^"']+)["']/gi;
  let match;
  while ((match = hrefPattern.exec(body)) !== null) {
    const href = match[1];
    try {
      // Resolve relative URLs
      const resolved = new URL(href, baseUrl);
      // Only include links to the same domain
      if (resolved.hostname === domain) {
        const normalized = resolved.origin + resolved.pathname;
        if (!links.includes(normalized)) {
          links.push(normalized);
        }
      }
    } catch {}
  }

  // Extract src attributes (scripts, images)
  const srcPattern = /src=["']([^"']+)["']/gi;
  while ((match = srcPattern.exec(body)) !== null) {
    const src = match[1];
    try {
      const resolved = new URL(src, baseUrl);
      if (resolved.hostname === domain) {
        const normalized = resolved.origin + resolved.pathname;
        if (!links.includes(normalized)) {
          links.push(normalized);
        }
      }
    } catch {}
  }

  return links;
}

// Extract forms from HTML
function extractForms(body: string, pageUrl: string): FormData[] {
  const forms: FormData[] = [];
  const formPattern = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let formMatch;

  while ((formMatch = formPattern.exec(body)) !== null) {
    const formHtml = formMatch[0];

    // Extract action
    const actionMatch = formHtml.match(/action=["']([^"']*)["']/i);
    const action = actionMatch ? actionMatch[1] : pageUrl;

    // Extract method
    const methodMatch = formHtml.match(/method=["']([^"']*)["']/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';

    // Extract inputs
    const inputs: FormInput[] = [];
    const inputPattern = /<input[^>]*>/gi;
    let inputMatch;

    while ((inputMatch = inputPattern.exec(formHtml)) !== null) {
      const inputHtml = inputMatch[0];
      const nameMatch = inputHtml.match(/name=["']([^"']*)["']/i);
      const typeMatch = inputHtml.match(/type=["']([^"']*)["']/i);
      const requiredMatch = inputHtml.match(/required/i);
      const maxlengthMatch = inputHtml.match(/maxlength=["'](\d+)["']/i);
      const autocompleteMatch = inputHtml.match(/autocomplete=["']([^"']*)["']/i);

      if (nameMatch) {
        inputs.push({
          name: nameMatch[1],
          type: typeMatch ? typeMatch[1] : 'text',
          required: !!requiredMatch,
          maxLength: maxlengthMatch ? parseInt(maxlengthMatch[1]) : undefined,
          autocomplete: autocompleteMatch ? autocompleteMatch[1].toLowerCase() : undefined,
        });
      }
    }

    // Check for CSRF tokens
    const hasCsrfToken = /csrf|token|_token|authenticity_token/i.test(formHtml);

    forms.push({
      action,
      method,
      inputs,
      hasCsrfToken,
    });
  }

  return forms;
}

// Extract metadata from HTML
function extractMeta(body: string): Record<string, string> {
  const meta: Record<string, string> = {};

  // Title
  const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) meta.title = titleMatch[1].trim();

  // Meta tags
  const metaPattern = /<meta[^>]+>/gi;
  let match;
  while ((match = metaPattern.exec(body)) !== null) {
    const tag = match[0];
    const nameMatch = tag.match(/name=["']([^"']*)["']/i) || tag.match(/property=["']([^"']*)["']/i);
    const contentMatch = tag.match(/content=["']([^"']*)["']/i);
    if (nameMatch && contentMatch) {
      meta[nameMatch[1].toLowerCase()] = contentMatch[1];
    }
  }

  return meta;
}

// Check for common paths — loaded from SecLists
function getCommonPathsToProbe(): string[] {
  const common = getCommonPaths();
  const raft = getRaftMediumDirectories();
  // Merge and dedupe, take top 500
  const merged = [...new Set([...common, ...raft])].slice(0, 500);
  return merged;
}

// Check for sensitive file paths — loaded from SecLists
function getSensitiveFilesToProbe(): string[] {
  return getSensitivePaths().slice(0, 2000);
}

// Check for robots.txt disallowed paths
function analyzeRobotsTxt(body: string): string[] {
  const disallowed: string[] = [];
  const lines = body.split('\n');
  let isDisallow = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('Disallow:')) {
      const path = trimmed.replace('Disallow:', '').trim();
      if (path && path !== '/') {
        disallowed.push(path);
      }
    }
  }

  return disallowed;
}

// Check for sensitive information in page
function checkSensitiveInfo(body: string, url: string): Finding[] {
  const findings: Finding[] = [];

  // Email addresses
  const emailPattern = /[\w.-]+@[\w.-]+\.\w{2,}/g;
  const emails = body.match(emailPattern);
  if (emails && emails.length > 0) {
    const uniqueEmails = [...new Set(emails)].slice(0, 5);
    findings.push(generateFinding(
      'Email addresses exposed in page',
      `Found ${uniqueEmails.length} email address(es) in the page.`,
      Severity.LOW,
      'Information Disclosure',
      url,
      `Emails found: ${uniqueEmails.join(', ')}`,
      'Exposed email addresses can be used for phishing and social engineering',
      'Remove or obfuscate email addresses from public pages',
      []
    ));
  }

  // Phone numbers
  const phonePattern = /[\+]?[(]?\d{1,4}[)]?[-\s./]?\d{1,4}[-\s./]?\d{1,9}/g;
  const phones = body.match(phonePattern);
  if (phones && phones.length > 0) {
    const filteredPhones = phones.filter(p => p.replace(/\D/g, '').length >= 7);
    if (filteredPhones.length > 0) {
      findings.push(generateFinding(
        'Phone numbers exposed in page',
        `Found ${filteredPhones.length} phone number(s) in the page.`,
        Severity.INFO,
        'Information Disclosure',
        url,
        `Phone numbers detected`,
        'Exposed phone numbers can be used for social engineering',
        'Consider using contact forms instead of displaying phone numbers',
        []
      ));
    }
  }

  // Internal IP addresses
  const ipPattern = /(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/g;
  const ips = body.match(ipPattern);
  if (ips && ips.length > 0) {
    findings.push(generateFinding(
      'Internal IP addresses exposed',
      `Found internal IP address(es) in the page.`,
      Severity.MEDIUM,
      'Information Disclosure',
      url,
      `Internal IPs: ${[...new Set(ips)].join(', ')}`,
      'Internal IP addresses reveal network topology',
      'Remove internal IP addresses from public-facing pages',
      []
    ));
  }

  // AWS keys
  const awsPattern = /(?:AKIA|ASIA)[A-Z0-9]{16}/g;
  const awsKeys = body.match(awsPattern);
  if (awsKeys && awsKeys.length > 0) {
    findings.push(generateFinding(
      'AWS access key exposed',
      'An AWS access key was found in the page content.',
      Severity.CRITICAL,
      'Sensitive Data Exposure',
      url,
      'AWS key pattern detected',
      'Exposed AWS keys can lead to cloud infrastructure compromise',
      'Revoke the exposed key immediately and use environment variables',
      ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html']
    ));
  }

  // Private keys
  const privateKeyPattern = /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g;
  if (privateKeyPattern.test(body)) {
    findings.push(generateFinding(
      'Private key exposed',
      'A private key (SSL/TLS or SSH) was found in the page content.',
      Severity.CRITICAL,
      'Sensitive Data Exposure',
      url,
      'Private key pattern detected',
      'Exposed private keys can be used to decrypt traffic or impersonate services',
      'Remove the private key from the web server immediately',
      []
    ));
  }

  // Database connection strings
  const dbPattern = /(?:mysql|postgres|mongodb|redis|mssql):\/\/[^\s"']+/gi;
  const dbStrings = body.match(dbPattern);
  if (dbStrings && dbStrings.length > 0) {
    findings.push(generateFinding(
      'Database connection string exposed',
      'A database connection string was found in the page content.',
      Severity.CRITICAL,
      'Sensitive Data Exposure',
      url,
      'Database connection string pattern detected',
      'Exposed connection strings can lead to database compromise',
      'Remove connection strings from public-facing pages',
      []
    ));
  }

  return findings;
}

// Crawl the site
async function crawlSite(
  domain: string,
  maxPages: number = 20,
  maxDepth: number = 3
): Promise<CrawledPage[]> {
  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [];
  const pages: CrawledPage[] = [];

  // Start with the homepage
  queue.push({ url: `https://${domain}`, depth: 0 });
  queue.push({ url: `http://${domain}`, depth: 0 });

  while (queue.length > 0 && pages.length < maxPages) {
    const { url: currentUrl, depth } = queue.shift()!;

    if (visited.has(currentUrl) || depth > maxDepth) continue;
    visited.add(currentUrl);

    try {
      const result = await httpGet(currentUrl, 8000);

      // Follow redirects
      if (result.redirectUrl) {
        try {
          const resolvedRedirect = new URL(result.redirectUrl, currentUrl);
          if (resolvedRedirect.hostname === domain && !visited.has(resolvedRedirect.href)) {
            queue.push({ url: resolvedRedirect.href, depth });
          }
        } catch {}
        continue;
      }

      if (result.statusCode !== 200) continue;

      const contentType = result.headers['content-type'] || '';
      if (!contentType.includes('text/html')) continue;

      const body = result.body;
      const links = extractLinks(body, currentUrl, domain);
      const forms = extractForms(body, currentUrl);
      const meta = extractMeta(body);

      // Detect login/admin forms
      const hasLogin = forms.some(f =>
        f.inputs.some(i => i.name.toLowerCase().includes('password') || i.type === 'password')
      );
      const hasAdmin = /admin|dashboard|manage|control/i.test(currentUrl) || hasLogin;
      const hasApi = /api|graphql|rest|endpoint/i.test(currentUrl);

      pages.push({
        url: currentUrl,
        statusCode: result.statusCode,
        title: meta.title,
        body,
        forms,
        links,
        scripts: [],
        meta,
        headers: result.headers as Record<string, string>,
        hasLogin,
        hasAdmin,
        hasApi,
      });

      // Add new links to queue
      for (const link of links) {
        if (!visited.has(link)) {
          queue.push({ url: link, depth: depth + 1 });
        }
      }
    } catch {}
  }

  return pages;
}

export async function runSiteCrawlScan(domain: string, openPorts: number[] = []): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // ── SPA DETECTION: check if target is a Single Page Application ──
    let isSPA = false;
    let blazorInfo: ReturnType<typeof detectBlazor> = { isBlazor: false, isDevExpress: false, version: '', framework: '' };
    try {
      const probeResult = await httpGet(`https://${domain}/`, 8000);
      if (probeResult.statusCode === 200 && isSpaShell(probeResult.body)) {
        isSPA = true;
        blazorInfo = detectBlazor(probeResult.body);
        const spaType = blazorInfo.isBlazor ? `Blazor Server + DevExpress XAF ${blazorInfo.version}` : 'Single Page Application';
        logger.info(`[SiteCrawl] SPA detected: ${spaType} — skipping 500+ path probe (all paths return same shell)`);
        findings.push(generateFinding(
          `Single Page Application detected (${spaType})`,
          `The target is a ${spaType} that returns the same HTML shell for every URL path. Traditional directory enumeration and path-based vulnerability testing are ineffective against SPAs.`,
          Severity.INFO,
          'Technology Detection',
          domain,
          `Framework: ${blazorInfo.framework || 'SPA'}, Version: ${blazorInfo.version || 'unknown'}, DevExpress: ${blazorInfo.isDevExpress}`,
          'SPAs have a different attack surface than traditional web apps — focus on API endpoints, SignalR hubs, and client-side vulnerabilities',
          'Test API endpoints directly, analyze JavaScript bundles, test for Blazor-specific vulnerabilities (Circuit impersonation, deserialization)',
          blazorInfo.isBlazor ? ['https://learn.microsoft.com/en-us/aspnet/core/blazor/security/server'] : []
        ));

        // Blazor-specific findings
        if (blazorInfo.isBlazor) {
          findings.push(generateFinding(
            'Blazor Server SignalR Hub exposed',
            'The application uses Blazor Server with a SignalR hub (_blazor endpoint) for real-time communication. The SignalR hub is a potential attack surface for denial-of-service, message injection, and circuit impersonation.',
            Severity.MEDIUM,
            'Blazor Security',
            `https://${domain}/_blazor`,
            'Blazor Server apps use WebSocket-based SignalR connections. The _blazor endpoint accepts negotiate, and hub connections should be secured with authentication tokens.',
            'Unauthorized SignalR connections could allow data exfiltration or UI manipulation',
            'Ensure SignalR hub requires authentication; validate circuit IDs; implement connection rate limiting',
            ['https://learn.microsoft.com/en-us/aspnet/core/blazor/security/server/threat-mitigation']
          ));
        }

        if (blazorInfo.isDevExpress) {
          findings.push(generateFinding(
            `DevExpress XAF v${blazorInfo.version || 'unknown'} disclosed`,
            'The application exposes DevExpress eXpressApp Framework version information in the HTML source code. This information disclosure helps attackers identify known vulnerabilities for the specific version.',
            Severity.LOW,
            'Information Disclosure',
            domain,
            `DevExpress Blazor Resources paths exposed: DevExpress.Blazor.Resources, DevExpress.ExpressApp.Blazor, DevExpress.Blazor.Themes.Fluent`,
            'Version disclosure enables targeted exploit development against known CVEs',
            'Remove version information from production HTML; use DevExpress obfuscation features',
            []
          ));
        }

        // Check for CSP issues in SPA
        try {
          const probeHeaders = await httpGet(`https://${domain}/`, 8000);
          const csp = probeHeaders.headers['content-security-policy'] || '';
          if (csp.includes('unsafe-inline') || csp.includes('unsafe-eval')) {
            const issues = [];
            if (csp.includes('unsafe-inline')) issues.push("'unsafe-inline' allows inline scripts");
            if (csp.includes('unsafe-eval')) issues.push("'unsafe-eval' allows eval()");
            findings.push(generateFinding(
              'Content-Security-Policy allows unsafe-inline/unsafe-eval',
              `The CSP header permits ${issues.join(' and ')}, significantly weakening XSS protection in this SPA.`,
              Severity.MEDIUM,
              'Security Headers',
              domain,
              `CSP: ${csp}`,
              `${issues.join(' and ')} can be exploited to bypass CSP and execute arbitrary JavaScript`,
              'Remove unsafe-inline and unsafe-eval from CSP; use nonces or hashes for inline scripts',
              ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            ));
          }
        } catch {}

        // Still crawl the site for a few pages (SPA may have some real pages)
        const pages = await crawlSite(domain, 3, 1);
        // Analyze crawled pages
        for (const page of pages) {
          for (const form of page.forms) {
            if (form.method === 'POST' && !form.hasCsrfToken) {
              findings.push(generateFinding(
                'Form without CSRF protection',
                `A POST form at ${page.url} does not appear to have CSRF token protection.`,
                Severity.MEDIUM,
                'CSRF',
                page.url,
                `Form action: ${form.action}\nInputs: ${form.inputs.map(i => i.name).join(', ')}`,
                'Forms without CSRF tokens are vulnerable to cross-site request forgery',
                'Implement CSRF tokens in all state-changing forms',
                ['https://owasp.org/www-community/attacks/csrf']
              ));
            }
          }
          const sensitiveFindings = checkSensitiveInfo(page.body || '', page.url);
          findings.push(...sensitiveFindings);
        }

        const duration = Date.now() - startTime;
        return { module: 'siteCrawl', findings, duration, errors };
      }
    } catch {
      // If probe fails, continue with normal crawl
    }

    // ── NORMAL (NON-SPA) CRAWL ──
    // Crawl the main site (ports 80/443)
    const pages = await crawlSite(domain, 10, 2);

    // Crawl discovered alt ports (8080, 3000, 5000, etc.)
    const altPorts = openPorts.filter(p => p !== 80 && p !== 443 && p >= 80 && p <= 65535);
    const altPages: CrawledPage[] = [];
    for (const port of altPorts.slice(0, 5)) {
      try {
        const scheme = [443, 8443, 9443, 10443, 2083, 2096, 7443].includes(port) ? 'https' : 'http';
        const altResult = await httpGet(`${scheme}://${domain}:${port}/`, 5000);
        if (altResult.statusCode > 0 && altResult.statusCode < 400) {
          const contentType = altResult.headers['content-type'] || '';
          if (contentType.includes('text/html')) {
            const body = altResult.body;
            const links = extractLinks(body, `${scheme}://${domain}:${port}/`, domain);
            const forms = extractForms(body, `${scheme}://${domain}:${port}/`);
            const meta = extractMeta(body);
            const hasLogin = forms.some(f => f.inputs.some(i => i.type === 'password'));
            altPages.push({
              url: `${scheme}://${domain}:${port}/`,
              statusCode: altResult.statusCode,
              title: meta.title,
              body,
              forms,
              links,
              scripts: [],
              meta,
              headers: altResult.headers as Record<string, string>,
              hasLogin,
              hasAdmin: hasLogin,
              hasApi: false,
            });
          }
          findings.push(generateFinding(
            `Web application discovered on port ${port}`,
            `A web application is hosted on non-standard port ${port}.`,
            Severity.INFO,
            'Service Discovery',
            `${scheme}://${domain}:${port}`,
            `Status: ${altResult.statusCode}, Content-Type: ${contentType}`,
            'Non-standard web ports may have weaker access controls or different security configurations',
            'Audit non-standard web ports for security misconfigurations and exposed admin panels',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/10-Enumerate_Applications_on_Webserver']
          ));
        }
      } catch {}
    }

    // Combine all pages for analysis
    const allPages = [...pages, ...altPages];

    // Directory/file discovery with SecLists wordlists
    const pathsToProbe = getCommonPathsToProbe();
    const BATCH_SIZE = 15;
    const discoveredPaths: Array<{ path: string; status: number; size: number }> = [];

    for (let i = 0; i < pathsToProbe.length; i += BATCH_SIZE) {
      const batch = pathsToProbe.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(async (p) => {
          try {
            const testUrl = `https://${domain}${p}`;
            const r = await httpGet(testUrl, 5000, 100000);
            if (r.statusCode > 0 && r.statusCode < 400) {
              return { path: p, status: r.statusCode, size: r.body.length };
            }
          } catch {}
          try {
            const testUrl = `http://${domain}${p}`;
            const r = await httpGet(testUrl, 5000, 100000);
            if (r.statusCode > 0 && r.statusCode < 400) {
              return { path: p, status: r.statusCode, size: r.body.length };
            }
          } catch {}
          return null;
        })
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          discoveredPaths.push(r.value);
        }
      }
    }

    // Flag discovered sensitive paths
    const sensitiveHits = discoveredPaths.filter(dp =>
      /\.(env|git|bak|old|sql|log|config|htaccess|htpasswd|ini|xml|yml|yaml|json|csv|txt)$/i.test(dp.path) ||
      /admin|phpmyadmin|adminer|cpanel|backup|debug|trace|server-status|server-info|swagger|graphql/i.test(dp.path)
    );

    if (sensitiveHits.length > 0) {
      const pathList = sensitiveHits.map(h => `${h.path} (${h.status}, ${h.size}b)`).join(', ');
      findings.push(generateFinding(
        `Sensitive paths discovered (${sensitiveHits.length} paths)`,
        `Directory enumeration found accessible sensitive paths on the target.`,
        Severity.HIGH,
        'Directory Enumeration',
        domain,
        `Sensitive paths: ${pathList}`,
        'Exposed sensitive paths can leak configuration, credentials, backups, and source code',
        'Restrict access to sensitive directories; remove from production',
        ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/07-Fingerprint_Web_Application']
      ));
    }

    // Report total discovered paths
    if (discoveredPaths.length > 0) {
      findings.push(generateFinding(
        `Directory enumeration: ${discoveredPaths.length} paths discovered`,
        `Probed ${pathsToProbe.length} paths and found ${discoveredPaths.length} accessible on the target.`,
        Severity.INFO,
        'Directory Enumeration',
        domain,
        `Discovered: ${discoveredPaths.slice(0, 30).map(d => `${d.path} (${d.status})`).join(', ')}${discoveredPaths.length > 30 ? '...' : ''}`,
        'Each discovered path is potential attack surface',
        'Audit all discovered paths for security misconfigurations',
        []
      ));
    }

    // Analyze crawled pages
    for (const page of allPages) {
      // Check forms for CSRF protection
      for (const form of page.forms) {
        if (form.method === 'POST' && !form.hasCsrfToken) {
          findings.push(generateFinding(
            'Form without CSRF protection',
            `A POST form at ${page.url} does not appear to have CSRF token protection.`,
            Severity.MEDIUM,
            'CSRF',
            page.url,
            `Form action: ${form.action}\nInputs: ${form.inputs.map(i => i.name).join(', ')}`,
            'Forms without CSRF tokens are vulnerable to cross-site request forgery',
            'Implement CSRF tokens in all state-changing forms',
            ['https://owasp.org/www-community/attacks/csrf']
          ));
        }
      }

      // Check for login forms without proper security
      const loginForms = page.forms.filter(f =>
        f.inputs.some(i => i.type === 'password')
      );
      for (const form of loginForms) {
        // Check for autocomplete="on" on password fields
        const passwordInput = form.inputs.find(i => i.type === 'password');
        if (passwordInput && passwordInput.autocomplete === 'on') {
          findings.push(generateFinding(
            'Password field with autocomplete enabled',
            `A password input at ${page.url} has autocomplete="on", allowing browsers to store the credential.`,
            Severity.LOW,
            'Authentication',
            page.url,
            `Form action: ${form.action}`,
            'Auto-saved passwords can be stolen by malware or anyone with physical access',
            'Set autocomplete="off" on password fields and use autocomplete="new-password" for change-password forms',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
          ));
        }

        // Check for plaintext password submission
        if (form.action && form.action.startsWith('http://')) {
          findings.push(generateFinding(
            'Password submitted over plaintext HTTP',
            `The login form at ${page.url} submits to a plaintext HTTP endpoint ${form.action}.`,
            Severity.CRITICAL,
            'Transport Layer Security',
            page.url,
            `Form action: ${form.action}`,
            'Credentials submitted over HTTP are transmitted in cleartext and can be intercepted',
            'Submit credentials only over HTTPS',
            ['https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts']
          ));
        }

        if (!form.hasCsrfToken) {
          findings.push(generateFinding(
            'Login form without CSRF protection',
            `The login form at ${page.url} does not have CSRF token protection.`,
            Severity.HIGH,
            'CSRF',
            page.url,
            `Form action: ${form.action}`,
            'Login forms without CSRF tokens are vulnerable to login CSRF attacks',
            'Implement CSRF tokens in login forms',
            ['https://owasp.org/www-community/attacks/csrf']
          ));
        }

        // Check if login form uses HTTPS
        if (page.url.startsWith('http://')) {
          findings.push(generateFinding(
            'Login form over HTTP',
            `The login form at ${page.url} is served over HTTP (not HTTPS).`,
            Severity.CRITICAL,
            'Transport Layer Security',
            page.url,
            'Login form served over insecure HTTP',
            'Credentials transmitted in cleartext can be intercepted',
            'Configure HTTPS for all pages, especially login forms',
            ['https://letsencrypt.org/']
          ));
        }
      }

      // Check for sensitive information exposure
      const sensitiveFindings = checkSensitiveInfo(page.body || '', page.url);
      findings.push(...sensitiveFindings);
    }

    // Check robots.txt
    try {
      const robotsResult = await httpGet(`https://${domain}/robots.txt`, 5000);
      if (robotsResult.statusCode === 200) {
        const disallowedPaths = analyzeRobotsTxt(robotsResult.body);
        if (disallowedPaths.length > 0) {
          findings.push(generateFinding(
            'robots.txt reveals hidden paths',
            `robots.txt reveals ${disallowedPaths.length} restricted path(s).`,
            Severity.INFO,
            'Information Disclosure',
            `https://${domain}/robots.txt`,
            `Disallowed paths: ${disallowedPaths.slice(0, 10).join(', ')}`,
            'robots.txt reveals directory structure to attackers',
            'Be aware that Disallow directives do not provide security',
            []
          ));
        }
      }
    } catch {}

    // Check for mixed content
    for (const page of allPages) {
      if (page.url.startsWith('https://') && page.body) {
        const httpResources = page.body.match(/http:\/\/[^"'\s]+/g);
        if (httpResources && httpResources.length > 0) {
          const uniqueResources = [...new Set(httpResources)].slice(0, 5);
          findings.push(generateFinding(
            'Mixed content detected',
            `The HTTPS page loads ${uniqueResources.length} resource(s) over HTTP.`,
            Severity.MEDIUM,
            'Transport Layer Security',
            page.url,
            `HTTP resources: ${uniqueResources.join(', ')}`,
            'Mixed content can be intercepted and modified by attackers',
            'Update all resource URLs to use HTTPS',
            ['https://developers.google.com/web/fundamentals/security/prevent-mixed-content']
          ));
          break;
        }
      }
    }

    // Summary
    if (allPages.length > 0) {
      const loginPages = allPages.filter(p => p.hasLogin);
      const adminPages = allPages.filter(p => p.hasAdmin);
      const apiPages = allPages.filter(p => p.hasApi);

      findings.push(generateFinding(
        'Site crawl completed',
        `Crawled ${allPages.length} page(s) on ${domain} (including ${altPages.length} alt-port page(s)).`,
        Severity.INFO,
        'Site Crawl',
        domain,
        `Pages crawled: ${allPages.length}\nLogin pages: ${loginPages.length}\nAdmin pages: ${adminPages.length}\nAPI endpoints: ${apiPages.length}\nAlt ports scanned: ${altPorts.length}`,
        'Comprehensive crawl reveals the attack surface',
        'Regularly audit site content and access controls',
        []
      ));
    }

    // AI-enhanced site analysis
    try {
      const ai = getAI();
      const techStack = findings.filter(f => f.category === 'Technology Detection' || f.category === 'Technology').map(f => f.title);
      const crawlPages = findings.filter(f => f.evidence?.includes('http')).map(f => ({
        url: f.affectedAsset,
        status: 200,
        contentLength: f.evidence?.length || 0,
        isSpa: isSPA,
      }));
      if (crawlPages.length > 0) {
        const aiResult = await ai.analyzeSiteCrawl(crawlPages, domain, techStack);
        if (aiResult.findings?.length) {
          for (const af of aiResult.findings) {
            findings.push(generateFinding(
              af.title || 'AI Site Analysis',
              af.description || '',
              (af.severity || 'INFO') as Severity,
              'AI Analysis',
              domain,
              af.remediation || '',
              af.impact || '',
              af.remediation || '',
              [],
            ));
          }
        }
      }
    } catch {}

    const duration = Date.now() - startTime;
    return {
      module: 'siteCrawl',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'siteCrawl',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
