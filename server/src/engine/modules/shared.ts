import { Finding, Severity } from '../../types';
import { randomUUID } from 'crypto';
import https from 'https';
import http from 'http';
import { logRequest, logResponse } from '../scanLogger';

interface FindingInput {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  affectedAsset: string;
  evidence: string;
  impact: string;
  remediation: string;
  references?: string[];
  compliance?: Record<string, string>;
  moduleName?: string;
}

const MODULE_CONFIDENCE: Record<string, number> = {
  kaliTools: 0.9, activeVuln: 0.85, modernAttacks: 0.8, exploitChain: 0.8,
  brokenAuth: 0.75, apiSecurity: 0.75, businessLogic: 0.7, supplyChain: 0.65,
  supplyChainIntel: 0.7, sourceAnalysis: 0.6, liveCve: 0.9, headers: 0.7,
  tls: 0.8, tlsDeep: 0.85, dns: 0.8, dnsDeep: 0.85, portScan: 0.85,
  cloudSecurity: 0.7, clientSecurity: 0.65, behavioral: 0.7,
  technology: 0.75, osFingerprint: 0.8, subdomains: 0.8,
};

function computeConfidence(finding: Finding, moduleName: string): number {
  let baseConfidence = MODULE_CONFIDENCE[moduleName] || 0.65;
  if (finding.evidence && finding.evidence.length > 200) baseConfidence += 0.05;
  if (finding.references && finding.references.some(r => r.includes('nvd.nist.gov'))) baseConfidence += 0.1;
  if (finding.evidence && (finding.evidence.includes('GET ') || finding.evidence.includes('POST '))) baseConfidence += 0.05;
  if (finding.severity === 'CRITICAL') baseConfidence += 0.05;
  if (finding.severity === 'INFO') baseConfidence -= 0.1;
  return Math.min(1.0, Math.max(0.1, baseConfidence));
}

export function generateFinding(input: FindingInput): Finding;
export function generateFinding(
  title: string,
  description: string,
  severity: Severity,
  category: string,
  affectedAsset: string,
  evidence: string,
  impact: string,
  remediation: string,
  references?: string[],
  compliance?: Record<string, string>,
  moduleName?: string
): Finding;
export function generateFinding(
  titleOrInput: string | FindingInput,
  description?: string,
  severity?: Severity,
  category?: string,
  affectedAsset?: string,
  evidence?: string,
  impact?: string,
  remediation?: string,
  references: string[] = [],
  compliance?: Record<string, string>,
  moduleName?: string
): Finding {
  let finding: Finding;
  if (typeof titleOrInput === 'object') {
    const i = titleOrInput;
    finding = {
      id: randomUUID(),
      title: i.title,
      description: i.description,
      severity: i.severity,
      category: i.category,
      affectedAsset: i.affectedAsset,
      evidence: i.evidence,
      impact: i.impact,
      remediation: i.remediation,
      references: i.references || [],
      detectedAt: new Date(),
      confidence: 0,
    };
    moduleName = i.moduleName || moduleName || '';
  } else {
    finding = {
      id: randomUUID(),
      title: titleOrInput,
      description: description!,
      severity: severity!,
      category: category!,
      affectedAsset: affectedAsset!,
      evidence: evidence!,
      impact: impact!,
      remediation: remediation!,
      references,
      detectedAt: new Date(),
      confidence: 0,
    };
  }
  finding.confidence = computeConfidence(finding, moduleName || '');
  return finding;
}

// ─── EVIDENCE ENRICHMENT ──────────────────────────────────────────────────────

export function enrichEvidence(
  finding: Finding,
  options: {
    tool?: string;
    requestMethod?: string;
    requestPath?: string;
    requestHeaders?: Record<string, string>;
    requestBody?: string;
    responseStatus?: number;
    responseHeaders?: Record<string, string>;
    responseBody?: string;
    payload?: string;
    baseline?: { status: number; bodyLength: number; responseTime: number };
    verification?: { steps: string[]; result: string };
  }
): Finding {
  const parts: string[] = [finding.evidence || ''];

  if (options.tool) {
    parts.push('\nTool: ' + options.tool);
  }

  if (options.requestMethod && options.requestPath) {
    parts.push('\nRequest: ' + options.requestMethod + ' ' + options.requestPath);
    if (options.requestHeaders) {
      const headerStr = Object.entries(options.requestHeaders)
        .filter(([k]) => !k.toLowerCase().includes('cookie') && !k.toLowerCase().includes('authorization'))
        .map(([k, v]) => '  ' + k + ': ' + v)
        .join('\n');
      if (headerStr) parts.push('Headers:\n' + headerStr);
    }
    if (options.requestBody) {
      parts.push('Body: ' + options.requestBody.slice(0, 500));
    }
  }

  if (options.responseStatus) {
    parts.push('\nResponse: HTTP ' + options.responseStatus);
    if (options.responseHeaders) {
      const interesting = ['content-type', 'server', 'x-powered-by', 'set-cookie', 'location'];
      const headerStr = interesting
        .filter(h => options.responseHeaders![h])
        .map(h => '  ' + h + ': ' + options.responseHeaders![h])
        .join('\n');
      if (headerStr) parts.push('Response Headers:\n' + headerStr);
    }
    if (options.responseBody) {
      parts.push('Response Body (preview): ' + options.responseBody.slice(0, 500));
    }
  }

  if (options.payload) {
    parts.push('\nPayload: ' + options.payload);
  }

  if (options.baseline) {
    parts.push('\nBaseline: HTTP ' + options.baseline.status + ', ' + options.baseline.bodyLength + ' bytes, ' + options.baseline.responseTime + 'ms');
  }

  if (options.verification) {
    parts.push('\nVerification:');
    options.verification.steps.forEach((s, i) => parts.push('  ' + (i + 1) + '. ' + s));
    parts.push('Result: ' + options.verification.result);
  }

  finding.evidence = parts.join('\n');
  return finding;
}

// ─── TARGET RATE LIMITING ─────────────────────────────────────────────────────
// Prevents overwhelming the target with too-fast requests

const requestTimestamps = new Map<string, number[]>();
const DEFAULT_DELAY_MS = 200;
const BURST_LIMIT = 10;

export async function respectRateLimit(host: string, delayMs: number = DEFAULT_DELAY_MS): Promise<void> {
  const now = Date.now();
  const timestamps = requestTimestamps.get(host) || [];
  const recent = timestamps.filter(t => now - t < 1000);

  if (recent.length >= BURST_LIMIT) {
    const waitTime = 1000 - (now - recent[0]) + delayMs;
    if (waitTime > 0) {
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  } else if (recent.length > 0) {
    const lastRequest = recent[recent.length - 1];
    const elapsed = now - lastRequest;
    if (elapsed < delayMs) {
      await new Promise(resolve => setTimeout(resolve, delayMs - elapsed));
    }
  }

  const updated = requestTimestamps.get(host) || [];
  updated.push(Date.now());
  requestTimestamps.set(host, updated.slice(-50));
}

export function cleanupRateLimits(): void {
  requestTimestamps.clear();
}

// ─── REDIRECT AND LOGIN PAGE DETECTION ────────────────────────────────────────
// Prevents false positives when endpoints redirect to login/main pages

/**
 * Patterns that indicate a login/authentication page
 */
const LOGIN_PAGE_PATTERNS = [
  /<title>[^<]*(log\s*in|sign\s*in|signin|login|authenticate|auth)[^<]*<\/title>/i,
  /<input[^>]*(password|passwd)[^>]*>/i,
  /<form[^>]*(login|signin|auth)[^>]*>/i,
  /<button[^>]*(log\s*in|sign\s*in|submit)[^>]*>/i,
  /class="[^"]*(login|signin|auth-form)[^"]*"/i,
  /id="[^"]*(login|signin|auth)[^"]*"/i,
  /action="[^"]*(login|signin|auth)[^"]*"/i,
  /Enter\s+(your\s+)?(password|credentials|username|email)/i,
  /(forgot|reset)\s+(your\s+)?password/i,
  /remember\s+me/i,
  /<meta[^>]*refresh[^>]*url=[^>]*(login|signin|auth)/i,
];

/**
 * Patterns that indicate a generic/error/placeholder page (NOT real content)
 */
const GENERIC_PAGE_PATTERNS = [
  /<title>[^<]*(404|not\s+found|error|under\s+maintenance|coming\s+soon|page\s+not\s+found)[^<]*<\/title>/i,
  /<h1[^>]*>[^<]*(404|not\s+found|error|oops)[^<]*<\/h1>/i,
  /<div[^>]*class="[^"]*(error|not-found|404)[^"]*"/i,
  /(the\s+page|resource)\s+(you\s+)?(requested|are\s+looking\s+for)\s+(could\s+not\s+be\s+found|does\s+not\s+exist)/i,
  /Welcome\s+to\s+(nginx|Apache|Microsoft)/i,
  /If\s+you\s+are\s+the\s+website\s+owner/i,
];

/**
 * Patterns that indicate a default/placeholder page from hosting provider
 */
const DEFAULT_HOSTING_PATTERNS = [
  /Powered\s+by\s+(cPanel|Plesk|DirectAdmin|Webmin)/i,
  /Default\s+Website\s+Page/i,
  /Your\s+account\s+has\s+been\s+suspended/i,
  /Domain\s+is\s+not\s+configured/i,
  /httpd.server\.admin/i,
  /CentOS\s+Apache/i,
  /Ubuntu\s+Apache/i,
];

/**
 * Check if a response body looks like a login page
 */
export function isLoginPage(body: string): boolean {
  if (!body || body.length < 50) return false;
  const lowerBody = body.toLowerCase();

  // Quick HTML check - skip non-HTML
  if (!lowerBody.includes('<html') && !lowerBody.includes('<!doctype') && !lowerBody.includes('<head')) {
    return false;
  }

  // Check login patterns
  let matchCount = 0;
  for (const pattern of LOGIN_PAGE_PATTERNS) {
    if (pattern.test(body)) {
      matchCount++;
      if (matchCount >= 2) return true; // Require 2+ matches to reduce false positives
    }
  }

  // Single strong match is enough
  if (/<input[^>]*type="password"/i.test(body)) return true;
  if (/<form[^>]*method="post"[^>]*>[\s\S]*password/i.test(body)) return true;

  return false;
}

/**
 * Check if a response body is a generic/error/placeholder page (not real content)
 */
export function isGenericPage(body: string): boolean {
  if (!body || body.length < 50) return true; // Empty/tiny = definitely generic
  for (const pattern of GENERIC_PAGE_PATTERNS) {
    if (pattern.test(body)) return true;
  }
  for (const pattern of DEFAULT_HOSTING_PATTERNS) {
    if (pattern.test(body)) return true;
  }
  return false;
}

// ─── SPA DETECTION ─────────────────────────────────────────────────────────
// Detects Single Page Applications (Blazor Server, React, Angular, Vue, etc.)
// SPAs return the same HTML shell for every URL — testing them with injection
// payloads is wasteful because the server just returns the SPA shell.

const SPA_SIGNATURES = [
  /DevExpress\.Blazor/i,
  /DevExpress\.ExpressApp/i,
  /_blazor/i,
  /blazor-server/i,
  /blazor\.webassembly/i,
  /<app[^>]*class="d-none"/i,
  /Blazor\.Circuit/i,
  /__next/i,               // Next.js
  /_next\/static/i,
  /__nuxt/i,               // Nuxt.js
  /_nuxt\//i,
  /ng-version/i,           // Angular
  /<div[^>]*id="root"[^>]*>/i,  // React
  /<div[^>]*id="app"[^>]*>/i,   // Vue/SPA
  /data-reactroot/i,       // React
  /window\.__NEXT_DATA__/i,
  /window\.__NUXT__/i,
];

/**
 * Check if a response body looks like a Single Page Application shell.
 * SPAs return the same HTML for every URL — injection payloads won't work.
 */
export function isSpaShell(body: string): boolean {
  if (!body || body.length < 200) return false;
  let matchCount = 0;
  for (const sig of SPA_SIGNATURES) {
    if (sig.test(body)) {
      matchCount++;
      if (matchCount >= 2) return true;
    }
  }
  return false;
}

/**
 * Check if the response body is the same as a known SPA shell hash.
 * Used to quickly skip duplicate SPA responses during scanning.
 */
const spaShellHashes = new Map<string, string>();

export function isDuplicateSpaResponse(body: string, domain: string): boolean {
  if (!body || body.length < 200) return false;
  // Use a fast hash: first 500 chars + length
  const fingerprint = body.substring(0, 500) + '|' + body.length;
  const key = domain;
  const existing = spaShellHashes.get(key);
  if (existing && existing === fingerprint) return true;
  if (!existing) spaShellHashes.set(key, fingerprint);
  return false;
}

export function resetSpaHashes(): void {
  spaShellHashes.clear();
}

// ─── BLAZOR / DEVEXPRESS XAF DETECTION ──────────────────────────────────────
export interface BlazorInfo {
  isBlazor: boolean;
  isDevExpress: boolean;
  version: string;
  framework: string;
}

export function detectBlazor(body: string): BlazorInfo {
  const info: BlazorInfo = { isBlazor: false, isDevExpress: false, version: '', framework: '' };
  if (!body) return info;

  if (/DevExpress\.Blazor|DevExpress\.ExpressApp|_blazor/i.test(body)) {
    info.isBlazor = true;
    info.isDevExpress = true;
    info.framework = 'blazor-server-xaf';
    const vMatch = body.match(/v(\d+\.\d+\.\d+\.\d+)/);
    if (vMatch) info.version = vMatch[1];
  } else if (/blazor|_blazor/i.test(body)) {
    info.isBlazor = true;
    info.framework = 'blazor';
  }
  return info;
}

/**
 * Check if a response is HTML content
 */
export function isHtmlContent(headers: http.IncomingHttpHeaders, body: string): boolean {
  const ct = (headers['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml')) return true;
  // Fallback: check body content
  const trimmed = body.trim().toLowerCase();
  return trimmed.startsWith('<!doctype') || trimmed.startsWith('<html');
}

/**
 * Check if a Content-Type matches what we'd expect for a given file path
 */
export function contentTypeMatchesFile(filePath: string, contentType: string): boolean {
  const ct = contentType.toLowerCase();
  const ext = filePath.split('.').pop()?.toLowerCase() || '';

  const expectedTypes: Record<string, string[]> = {
    'env': ['text/plain', 'application/octet-stream'],
    'git/head': ['text/plain'],
    'git/config': ['text/plain', 'application/xml'],
    'gitignore': ['text/plain'],
    'json': ['application/json', 'text/plain'],
    'sql': ['application/sql', 'application/octet-stream', 'text/plain'],
    'log': ['text/plain', 'application/octet-stream'],
    'xml': ['application/xml', 'text/xml', 'text/plain'],
    'bak': ['application/octet-stream', 'text/plain'],
    'php': ['text/html', 'application/x-httpd-php'], // PHP files render as HTML
  };

  for (const [key, types] of Object.entries(expectedTypes)) {
    if (filePath.toLowerCase().includes(key)) {
      return types.some(t => ct.includes(t));
    }
  }

  // Unknown file type - accept if not HTML (for file exposure checks)
  return true;
}

/**
 * Follow a redirect and check if the final destination is a login page
 * Returns: { redirected: boolean, isLogin: boolean, finalUrl: string, statusCode: number }
 */
export async function followRedirectAndCheck(
  url: string,
  timeout: number = 5000
): Promise<{ redirected: boolean; isLogin: boolean; finalUrl: string; statusCode: number; body: string; isGeneric: boolean }> {
  try {
    const result = await fetchUrl(url, timeout);
    const locationRaw = result.headers['location'] || result.headers['Location'] || '';
    const location = Array.isArray(locationRaw) ? locationRaw[0] : locationRaw;

    // Check if it's a redirect
    const isRedirect = result.statusCode >= 300 && result.statusCode < 400;

    if (isRedirect && location) {
      // Resolve the redirect URL
      let finalUrl = location;
      try {
        finalUrl = new URL(location, url).href;
      } catch {
        if (location.startsWith('/')) {
          const base = new URL(url);
          finalUrl = base.origin + location;
        } else {
          const base = new URL(url);
          finalUrl = base.origin + '/' + location;
        }
      }

      // Fetch the redirect target
      const finalResult = await fetchUrl(finalUrl, timeout);
      return {
        redirected: true,
        isLogin: isLoginPage(finalResult.body),
        finalUrl,
        statusCode: finalResult.statusCode,
        body: finalResult.body,
        isGeneric: isGenericPage(finalResult.body),
      };
    }

    return {
      redirected: false,
      isLogin: isLoginPage(result.body),
      finalUrl: url,
      statusCode: result.statusCode,
      body: result.body,
      isGeneric: isGenericPage(result.body),
    };
  } catch {
    return { redirected: false, isLogin: false, finalUrl: url, statusCode: 0, body: '', isGeneric: true };
  }
}

export const OWASP_TOP_10 = {
  A01: 'A01:2021 - Broken Access Control',
  A02: 'A02:2021 - Cryptographic Failures',
  A03: 'A03:2021 - Injection',
  A04: 'A04:2021 - Insecure Design',
  A05: 'A05:2021 - Security Misconfiguration',
  A06: 'A06:2021 - Vulnerable and Outdated Components',
  A07: 'A07:2021 - Identification and Authentication Failures',
  A08: 'A08:2021 - Software and Data Integrity Failures',
  A09: 'A09:2021 - Security Logging and Monitoring Failures',
  A10: 'A10:2021 - Server-Side Request Forgery',
} as const;

export const NIST_CSF = {
  PR: 'PR - Protect',
  DE: 'DE - Detect',
  RS: 'RS - Respond',
  RC: 'RC - Recover',
} as const;

const MAX_RESPONSE_BYTES = 1024 * 1024;

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

export async function fetchUrl(url: string, timeout = 10000, module = 'http'): Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string }> {
  // Rate limit to avoid overwhelming the target
  try {
    const urlObj = new URL(url);
    await respectRateLimit(urlObj.hostname);
  } catch { /* invalid URL, skip rate limiting */ }

  return new Promise((resolve, reject) => {
    const start = Date.now();
    logRequest(module, 'GET', url);
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': USER_AGENT }, timeout }, (res) => {
      let body = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_RESPONSE_BYTES) {
          req.destroy();
          reject(new Error('Response too large'));
          return;
        }
        body += chunk.toString();
      });
      res.on('end', () => {
        const dur = Date.now() - start;
        logResponse(module, url, res.statusCode || 0, { bodySnippet: body.substring(0, 80), duration: dur });
        resolve({
          statusCode: res.statusCode || 0,
          headers: res.headers,
          body,
        });
      });
    });

    req.on('error', (err) => {
      logResponse(module, url, 0, { bodySnippet: err.message });
      reject(err);
    });
    req.on('timeout', () => {
      req.destroy();
      logResponse(module, url, 0, { bodySnippet: 'timeout' });
      reject(new Error('Request timeout'));
    });
  });
}

export function fetchJson(url: string, timeout = 10000): Promise<unknown> {
  return fetchUrl(url, timeout).then((res) => {
    try {
      return JSON.parse(res.body);
    } catch {
      return null;
    }
  });
}

// ─── REDIRECT-AWARE FETCHING ──────────────────────────────────────────────────

export interface RedirectChainEntry { url: string; statusCode: number; location: string; }
export interface RedirectResult {
  finalUrl: string;
  finalStatus: number;
  finalBody: string;
  finalHeaders: http.IncomingHttpHeaders;
  chain: RedirectChainEntry[];
  isRedirect: boolean;
  isLogin: boolean;
  isGeneric: boolean;
  metaRedirect: string | null;
}

export async function fetchUrlFollowRedirects(
  url: string,
  timeout = 5000,
  maxRedirects = 5,
  module = 'http'
): Promise<RedirectResult> {
  const chain: RedirectChainEntry[] = [];
  let currentUrl = url;
  let currentResult = await fetchUrl(currentUrl, timeout, module);
  let depth = 0;

  while (currentResult.statusCode >= 300 && currentResult.statusCode < 400 && depth < maxRedirects) {
    const locationRaw = currentResult.headers['location'] || currentResult.headers['Location'] || '';
    const location = Array.isArray(locationRaw) ? locationRaw[0] : locationRaw;
    if (!location) break;

    chain.push({ url: currentUrl, statusCode: currentResult.statusCode, location });

    let nextUrl = location;
    try {
      nextUrl = new URL(location, currentUrl).href;
    } catch {
      if (location.startsWith('/')) {
        const base = new URL(currentUrl);
        nextUrl = base.origin + location;
      } else {
        const base = new URL(currentUrl);
        nextUrl = base.origin + '/' + location;
      }
    }

    currentUrl = nextUrl;
    currentResult = await fetchUrl(currentUrl, timeout, module);
    depth++;
  }

  const metaRedirect = detectMetaRedirect(currentResult.body);

  return {
    finalUrl: currentUrl,
    finalStatus: currentResult.statusCode,
    finalBody: currentResult.body,
    finalHeaders: currentResult.headers,
    chain,
    isRedirect: chain.length > 0,
    isLogin: isLoginPage(currentResult.body),
    isGeneric: isGenericPage(currentResult.body),
    metaRedirect,
  };
}

function detectMetaRedirect(body: string): string | null {
  if (!body) return null;
  const metaMatch = body.match(/<meta[^>]*http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'\s;]+)/i);
  if (metaMatch) return metaMatch[1];
  const jsMatch = body.match(/(?:window\.location\.href|location\.replace|location\.assign)\s*[=(]\s*["']([^"']+)/i);
  if (jsMatch) return jsMatch[1];
  return null;
}

// ─── STRUCTURED PROOF BUILDER ─────────────────────────────────────────────────

export interface HttpProof {
  request: { method: string; url: string; headers?: Record<string, string>; body?: string; };
  response: { status: number; headers: Record<string, string>; bodyPreview: string; bodyLength: number; };
  redirectChain?: RedirectChainEntry[];
  metaRedirect?: string | null;
  capturedAt: string;
}

export function buildProof(
  method: string,
  requestUrl: string,
  requestHeaders: Record<string, string> | undefined,
  requestBody: string | undefined,
  responseStatus: number,
  responseHeaders: http.IncomingHttpHeaders,
  responseBody: string,
  chain?: RedirectChainEntry[],
  metaRedirect?: string | null
): HttpProof {
  const interestingHeaders: Record<string, string> = {};
  const interestingKeys = ['server', 'x-powered-by', 'content-type', 'set-cookie', 'location', 'x-debug', 'x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
  for (const key of interestingKeys) {
    const val = responseHeaders[key];
    if (val) interestingHeaders[key] = Array.isArray(val) ? val.join(', ') : String(val);
  }

  return {
    request: { method, url: requestUrl, headers: requestHeaders, body: requestBody?.slice(0, 1000) },
    response: { status: responseStatus, headers: interestingHeaders, bodyPreview: responseBody.slice(0, 2000), bodyLength: responseBody.length },
    redirectChain: chain && chain.length > 0 ? chain : undefined,
    metaRedirect,
    capturedAt: new Date().toISOString(),
  };
}

export function formatProofAsText(proof: HttpProof): string {
  const lines: string[] = [];
  lines.push('=== PROOF OF VULNERABILITY ===');
  lines.push(`Captured: ${proof.capturedAt}`);
  lines.push('');
  lines.push(`>> REQUEST`);
  lines.push(`${proof.request.method} ${proof.request.url}`);
  if (proof.request.headers) {
    for (const [k, v] of Object.entries(proof.request.headers)) {
      lines.push(`  ${k}: ${v}`);
    }
  }
  if (proof.request.body) lines.push(`  Body: ${proof.request.body}`);
  lines.push('');
  lines.push(`<< RESPONSE (HTTP ${proof.response.status})`);
  for (const [k, v] of Object.entries(proof.response.headers)) {
    lines.push(`  ${k}: ${v}`);
  }
  lines.push(`  Body Length: ${proof.response.bodyLength} bytes`);
  lines.push(`  Body Preview:`);
  lines.push(proof.response.bodyPreview.split('\n').slice(0, 30).join('\n'));
  if (proof.redirectChain && proof.redirectChain.length > 0) {
    lines.push('');
    lines.push('>> REDIRECT CHAIN');
    for (const entry of proof.redirectChain) {
      lines.push(`  ${entry.statusCode} -> ${entry.location}`);
    }
  }
  if (proof.metaRedirect) {
    lines.push('');
    lines.push(`>> META REDIRECT TARGET: ${proof.metaRedirect}`);
  }
  lines.push('=== END PROOF ===');
  return lines.join('\n');
}
