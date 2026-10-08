import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import logger from '../utils/logger';

// ─────────────────────────────────────────────────────────────────────────────
// TARGET ANALYSIS — models how a manual penetration tester sees the target:
//   1. Discover real endpoints + parameters (crawl, JS analysis, robots/sitemap,
//      form parsing, known API/upload/admin paths)
//   2. Capture baseline responses (status, normalized body hash, headers,
//      latency) for each endpoint so attacks can be verified by differencing
//   3. Maintain session state (cookies, CSRF tokens) so tests run like a real
//      authenticated pentester
//   4. Fingerprint WAF + technology so payload selection adapts
// ─────────────────────────────────────────────────────────────────────────────

export interface BaselineResponse {
  status: number;
  bodyHash: string;
  bodyLength: number;
  hasBody: boolean;
  loadMs: number;
  headers: Record<string, string>;
}

export interface EndpointProfile {
  path: string;
  method: string;
  params: string[];
  isLogin: boolean;
  hasPassword: boolean;
  isAdmin: boolean;
  isApi: boolean;
  isUpload: boolean;
  baseline?: BaselineResponse;
}

export interface TargetProfile {
  domain: string;
  httpsBase: string;
  httpBase: string;
  usesHttps: boolean;
  redirectsToHttps: boolean;
  endpoints: EndpointProfile[];
  allParams: string[];
  cookies: string[];
  csrfParamNames: string[];
  techStack: string[];
  wafDetected: boolean;
  wafName: string | null;
  loginEndpoints: string[];
  adminEndpoints: string[];
  apiEndpoints: string[];
  uploadEndpoints: string[];
  jsFiles: string[];
  discoveredPaths: string[];
  serverHeaders: Record<string, string>;
  sitemapPaths: string[];
}

interface HttpResult {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  finalUrl: string;
  loadMs: number;
}

// ─── HTTP CLIENT (stateful, baseline-aware) ─────────────────────────────────

class TargetHttpClient {
  private cookieJar: string[] = [];

  constructor(public profile: Pick<TargetProfile, 'httpsBase' | 'httpBase' | 'usesHttps'>) {}

  async request(
    url: string,
    method: string = 'GET',
    requestHeaders: Record<string, string> = {},
    body: string = '',
    maxRedirects = 5,
    timeout = 8000,
  ): Promise<HttpResult> {
    const start = Date.now();
    let current = url;
    let lastResult: HttpResult | null = null;

    for (let i = 0; i <= maxRedirects; i++) {
      const parsed = new URL(current);
      const mod = parsed.protocol === 'https:' ? https : http;
      const headers: Record<string, string> = {
        'User-Agent': 'CYBERGUARD-Security-Scanner/1.0 (audit)',
        'Accept': 'text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        ...requestHeaders,
      };
      if (this.cookieJar.length > 0) headers['Cookie'] = this.cookieJar.join('; ');
      if (body && !headers['Content-Type']) headers['Content-Type'] = 'application/x-www-form-urlencoded';

      const result = await new Promise<{ statusCode: number; headers: http.IncomingHttpHeaders; body: string; finalUrl: string }>((resolve, reject) => {
        const req = mod.request({
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method,
          headers,
          timeout,
          rejectUnauthorized: false,
        }, (res) => {
          let data = '';
          let totalBytes = 0;
          res.on('data', (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes > 2097152) { req.destroy(); return; }
            data += chunk.toString();
          });
          res.on('end', () => resolve({ statusCode: res.statusCode || 0, headers: res.headers, body: data, finalUrl: current }));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        if (body) req.write(body);
        req.end();
      });

      // Capture Set-Cookie for stateful tests
      const sc = result.headers['set-cookie'];
      if (sc) {
        const cookies = Array.isArray(sc) ? sc : [sc];
        for (const c of cookies) {
          const nv = c.split(';')[0].trim();
          if (nv && !this.cookieJar.some(existing => existing.split('=')[0] === nv.split('=')[0])) {
            this.cookieJar.push(nv);
          }
        }
      }

      if (result.statusCode >= 300 && result.statusCode < 400 && result.headers.location) {
        let loc = result.headers.location as string;
        try { loc = new URL(loc, current).toString(); } catch { break; }
        current = loc;
        lastResult = { ...result, loadMs: Date.now() - start, finalUrl: current };
        // Only follow same-host redirects to avoid leaking cookies off-target
        if (new URL(current).hostname !== parsed.hostname) break;
        continue;
      }

      return { ...result, loadMs: Date.now() - start };
    }
    return lastResult || { statusCode: 0, headers: {}, body: '', finalUrl: current, loadMs: Date.now() - start };
  }

  async safeRequest(url: string, method: string = 'GET', headers: Record<string, string> = {}, body: string = ''): Promise<HttpResult> {
    try {
      return await this.request(url, method, headers, body);
    } catch {
      return { statusCode: 0, headers: {}, body: '', finalUrl: url, loadMs: 0 };
    }
  }

  getCookies(): string[] { return this.cookieJar; }
  reset() { this.cookieJar = []; }
}

// ─── HASHING / DIFFERENCING ─────────────────────────────────────────────────

const WS_RE = /\s+/g;
function normalizeBody(body: string): string {
  return body.replace(WS_RE, ' ').trim().toLowerCase();
}
function hashBody(body: string): string {
  return crypto.createHash('sha1').update(normalizeBody(body)).digest('hex').slice(0, 16);
}

/** Manual-pentest differencing: does an attack response deviate from baseline? */
export function differsFromBaseline(res: { statusCode: number; body: string; loadMs: number }, baseline?: BaselineResponse, opts: { skipStatus?: boolean; bodyStrict?: boolean } = {}): boolean {
  if (!baseline) return res.statusCode >= 400;
  if (!opts.skipStatus && res.statusCode !== baseline.status) return true;
  const length = res.body.length;
  const delta = Math.abs(length - baseline.bodyLength);
  const pctChanged = baseline.bodyLength > 0 ? delta / baseline.bodyLength : (delta > 100 ? 1 : 0);
  // Tolerate dynamic CSRF tokens / timestamps: require meaningful delta
  return pctChanged > 0.25 || !!(opts.bodyStrict && res.body.length > 0 && res.body.length !== baseline.bodyLength && hashBody(res.body) !== baseline.bodyHash);
}

// ─── PATH PRESETS (trimmed — avoid flooding the target) ─────────────────────

const CRAWL_SEEDS = ['/', '/index.html', '/home', '/dashboard'];
const ROBOTS_PATHS = ['/robots.txt', '/sitemap.xml', '/security.txt'];

const UNKNOWN_API_PATHS = [
  '/api', '/api/v1', '/api/v2', '/graphql', '/gql',
  '/api/users', '/api/login', '/api/auth', '/api/me', '/api/profile',
  '/api/status', '/api/health', '/api/config', '/api/version',
  '/v1', '/v2', '/rest',
];

const UNKNOWN_UPLOAD_PATHS = [
  '/upload', '/uploads', '/api/upload', '/api/files', '/api/v1/upload',
];

const UNKNOWN_ADMIN_PATHS = [
  '/admin', '/administrator', '/panel', '/console', '/manage',
  '/admin/login', '/wp-admin', '/phpmyadmin', '/jenkins', '/actuator', '/debug',
];

const UNKNOWN_LOGIN_PATHS = [
  '/login', '/signin', '/sign-in', '/auth', '/auth/login', '/authenticate',
  '/api/login', '/api/auth/login', '/account/login', '/user/login',
];

const COMMON_CONTENT_PATHS = [
  '/favicon.ico', '/robots.txt', '/sitemap.xml', '/health', '/status',
];

// ─── CONTENT/JS ANALYSIS ────────────────────────────────────────────────────

function extractLinks(html: string, base: string, domain: string): string[] {
  const links = new Set<string>();
  const re = /(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    let href = m[1];
    if (/^(javascript:|data:|mailto:|tel:|#)/i.test(href)) continue;
    try {
      const resolved = new URL(href, base).toString();
      const u = new URL(resolved);
      if (u.hostname === domain || u.hostname.endsWith('.' + domain)) {
        links.add(u.pathname + u.search);
      }
    } catch (e) {
      logger.debug('[TargetAnalysis] URL parse failed: ' + (e instanceof Error ? e.message : String(e)));
    }
  }
  return [...links].slice(0, 150);
}

function extractForms(html: string): { action: string; method: string; params: string[]; hasPassword: boolean }[] {
  const forms: { action: string; method: string; params: string[]; hasPassword: boolean }[] = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html)) !== null) {
    const formHtml = fm[0];
    const actionMatch = formHtml.match(/action=["']([^"']*)["']/i);
    const methodMatch = formHtml.match(/method=["']([^"']*)["']/i);
    const params: string[] = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(formHtml)) !== null) {
      const name = im[0].match(/name=["']([^"']*)["']/i);
      if (name) params.push(name[1].toLowerCase());
    }
    forms.push({
      action: actionMatch ? actionMatch[1] : '',
      method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
      params: [...new Set(params)],
      hasPassword: /type=["']password["']/i.test(formHtml),
    });
  }
  return forms;
}

/** Extract candidate endpoints + params from JS files (a pentester reads the JS). */
function analyzeJavaScript(code: string): { paths: string[]; params: string[] } {
  const paths = new Set<string>();
  const params = new Set<string>();
  const patterns: RegExp[] = [
    /url:\s*["']([^"']+)["']/gi,
    /(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']+)["']/gi,
    /url\s*\(\s*["']([^"']+)["']/gi,
    /apiPath\s*[:=]\s*["']([^"']+)["']/gi,
    /["'](\/api\/[^"']+)["']/gi,
    /["'](\/v\d+\/[^"']+)["']/gi,
    /["'](?:get|post|create|update|delete|list|fetch|load|search)\/?(?:[a-z0-9_/-]*)["']/gi,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(code)) !== null) {
      const p = m[1].trim();
      if (p.startsWith('/') && p.length < 200 && !p.startsWith('//')) {
        paths.add(p.split('?')[0]);
      }
    }
  }
  // Query params in strings like ?page=1 or "page"
  const qpRe = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
  let qm;
  while ((qm = qpRe.exec(code)) !== null) params.add(qm[1].toLowerCase());
  const keyRe = /["'](?:param|query|params?|data)\b[^"']*["']\s*[:=]\s*\{([^}]*)\}/gi;
  let km;
  while ((km = keyRe.exec(code)) !== null) {
    const keyRe2 = /["']([a-zA-Z_][a-zA-Z0-9_]*)["']\s*:/g;
    let m2;
    while ((m2 = keyRe2.exec(km[1])) !== null) params.add(m2[1].toLowerCase());
  }
  return { paths: [...paths].slice(0, 80), params: [...params].slice(0, 60) };
}

function classifyPath(path: string, method: string): { isLogin: boolean; isAdmin: boolean; isApi: boolean; isUpload: boolean } {
  const lower = path.toLowerCase();
  const isLogin = UNKNOWN_LOGIN_PATHS.some(p => lower.startsWith(p)) || /\/(login|signin|logon|authenticate)\b/.test(lower);
  const isAdmin = UNKNOWN_ADMIN_PATHS.some(p => lower.startsWith(p)) || /\/(admin|panel|manage|console|dashboard)\b/.test(lower);
  const isApi = lower.startsWith('/api') || lower.startsWith('/v1') || lower.startsWith('/v2') || lower.startsWith('/v3') || lower.includes('/graphql') || UNKNOWN_API_PATHS.some(p => lower.startsWith(p));
  const isUpload = UNKNOWN_UPLOAD_PATHS.some(p => lower.startsWith(p)) || /\/(upload|files|media|import|batch|attachments?)\b/.test(lower);
  return { isLogin, isAdmin, isApi, isUpload };
}

// ─── WAF FINGERPRINTING ────────────────────────────────────────────────────

const WAF_SIGNATURES: { name: string; patterns: RegExp[] }[] = [
  { name: 'Cloudflare', patterns: [/cf-ray/i, /__cfduid/i, /cloudflare/i, /cf_chl/i] },
  { name: 'AWS WAF / CloudFront', patterns: [/x-amz-cf-id/i, /x-amzn-waf/i, /x-amz-cf-pop/i] },
  { name: 'Akamai', patterns: [/akamai/i, /ak_bmsc/i, /x-akamai-transformed/i] },
  { name: 'Imperva Incapsula', patterns: [/incap_ses/i, /visid_incap/i, /imperva/i] },
  { name: 'F5 BIG-IP ASM', patterns: [/bigip/i, /ts[a-z0-9]{7}=/i, /x-cnection/i] },
  { name: 'Fortinet FortiWeb', patterns: [/fortigate/i, /fortiweb/i, /fhjselw/i] },
  { name: 'Barracuda', patterns: [/barracuda/i, /barra_counter_session/i] },
  { name: 'Sucuri', patterns: [/sucuri/i, /cloudproxy/i] },
  { name: 'Wordfence', patterns: [/wfvt_\d+/i, /wordfence/i] },
  { name: 'ModSecurity', patterns: [/mod_security/i, /modsecurity/i, /no such user/i] },
  { name: 'Citrix NetScaler', patterns: [/ns_af/i, /netscaler/i, /nsc_/i] },
];

function fingerprintWaf(res: HttpResult): { name: string | null; detected: boolean } {
  const headers = JSON.stringify(res.headers).toLowerCase();
  const body = res.body.toLowerCase();
  for (const waf of WAF_SIGNATURES) {
    if (waf.patterns.some(p => p.test(headers) || p.test(body))) {
      return { name: waf.name, detected: true };
    }
  }
  return { name: null, detected: false };
}

// ─── MAIN ANALYZER (optimized: parallel batching, single baseline) ───────────

const PROBE_BATCH = 8;

async function batchProbe(client: TargetHttpClient, urls: string[]): Promise<{ url: string; statusCode: number; body: string }[]> {
  const results: { url: string; statusCode: number; body: string }[] = [];
  for (let i = 0; i < urls.length; i += PROBE_BATCH) {
    const batch = urls.slice(i, i + PROBE_BATCH);
    const batchResults = await Promise.all(batch.map(async (u) => {
      try {
        const res = await client.safeRequest(u, 'GET', {}, '');
        return { url: u, statusCode: res.statusCode, body: res.body };
      } catch { return { url: u, statusCode: 0, body: '' }; }
    }));
    results.push(...batchResults);
  }
  return results;
}

export async function analyzeTarget(domain: string): Promise<TargetProfile> {
  const httpsBase = `https://${domain}`;
  const httpBase = `http://${domain}`;
  const client: TargetHttpClient = new TargetHttpClient({ httpsBase, httpBase, usesHttps: true });

  const endpoints = new Map<string, EndpointProfile>();
  const getKey = (path: string, method: string) => `${method}:${path}`;

  const addEndpoint = (path: string, method: string = 'GET', params: string[] = [], hasPassword = false) => {
    const clean = path.startsWith('/') ? path.split('?')[0] : '/' + path.split('?')[0];
    const key = getKey(clean, method);
    const cls = classifyPath(clean, method);
    if (!endpoints.has(key)) {
      endpoints.set(key, { path: clean, method, params: [...new Set(params)].slice(0, 40), ...cls, hasPassword });
    } else {
      const existing = endpoints.get(key)!;
      existing.params = [...new Set([...existing.params, ...params])].slice(0, 40);
      if (hasPassword) existing.hasPassword = true;
    }
  };

  const discoveredPaths: string[] = [];
  const jsFiles = new Set<string>();
  const cookiesSeen = new Set<string>();

  // 1) Root + crawl seeds (parallel, 4 requests)
  const seedResults = await batchProbe(client, CRAWL_SEEDS.map(s => httpsBase + s));
  for (const sr of seedResults) {
    if (sr.statusCode && sr.statusCode < 400) {
      const path = new URL(sr.url).pathname;
      addEndpoint(path, 'GET');
      // Extract forms and links
      for (const form of extractForms(sr.body)) {
        const action = form.action || path;
        let fullPath = action;
        try { fullPath = new URL(action, httpsBase).pathname; } catch (e) {
          logger.debug('[TargetAnalysis] URL parse failed: ' + (e instanceof Error ? e.message : String(e)));
        }
        addEndpoint(fullPath, form.method, form.params, form.hasPassword);
      }
      for (const link of extractLinks(sr.body, httpsBase + path, domain)) {
        addEndpoint(link.split('?')[0], 'GET');
      }
      // JS files
      const jsRe = /(?:src|href)\s*=\s*["']([^"']+\.js(?:[^"']*)?)["']/gi;
      let jm;
      while ((jm = jsRe.exec(sr.body)) !== null) {
        try {
          const u = new URL(jm[1], httpsBase + path);
          if (u.hostname === domain || u.hostname.endsWith('.' + domain)) jsFiles.add(u.toString().split('#')[0]);
        } catch (e) {
          logger.debug('[TargetAnalysis] URL parse failed: ' + (e instanceof Error ? e.message : String(e)));
        }
      }
    }
  }

  // 2) robots.txt / sitemap (3 requests)
  const robotsResults = await batchProbe(client, ROBOTS_PATHS.map(p => httpsBase + p));
  for (const rr of robotsResults) {
    if (rr.statusCode === 200) {
      if (rr.url.includes('robots')) {
        const disallowRe = /^Disallow:\s*(.+)$/gmi;
        let dm;
        while ((dm = disallowRe.exec(rr.body)) !== null) {
          const p = dm[1].trim();
          if (p && p !== '/') discoveredPaths.push((p.startsWith('/') ? p : '/' + p).split('*')[0]);
        }
      } else if (rr.url.includes('sitemap')) {
        const urlRe = /<loc>([^<]+)<\/loc>/gi;
        let um;
        while ((um = urlRe.exec(rr.body)) !== null) {
          try { discoveredPaths.push(new URL(um[1]).pathname); } catch (e) {
            logger.debug('[TargetAnalysis] URL parse failed: ' + (e instanceof Error ? e.message : String(e)));
          }
        }
      }
    }
  }

  // 3) Fetch top 5 JS files (parallel)
  const jsList = [...jsFiles].slice(0, 5);
  const jsResults = await batchProbe(client, jsList);
  const jsParams = new Set<string>();
  const jsPaths = new Set<string>();
  for (const jr of jsResults) {
    if (jr.statusCode === 200 && jr.body.length > 100) {
      const analysis = analyzeJavaScript(jr.body);
      analysis.paths.forEach(p => jsPaths.add(p.split('?')[0]));
      analysis.params.forEach(p => jsParams.add(p));
    }
  }
  for (const p of jsPaths) if (p.startsWith('/')) addEndpoint(p, 'GET');

  // 4) Probe known paths (parallel, ~65 paths → ~9 batches)
  const allProbePaths = [
    ...UNKNOWN_API_PATHS, ...UNKNOWN_UPLOAD_PATHS, ...UNKNOWN_ADMIN_PATHS,
    ...UNKNOWN_LOGIN_PATHS, ...COMMON_CONTENT_PATHS, ...discoveredPaths.slice(0, 10),
  ];
  const uniquePaths = [...new Set(allProbePaths)];
  const probeResults = await batchProbe(client, uniquePaths.map(p => httpsBase + p));
  for (const pr of probeResults) {
    if (pr.statusCode && pr.statusCode !== 404 && pr.statusCode !== 0) {
      const path = new URL(pr.url).pathname;
      addEndpoint(path, 'GET');
    }
  }

  // 5) Baselines — single request per endpoint, top 20 only
  const profileEndpoints = [...endpoints.values()].slice(0, 20);
  const baselineResults = await batchProbe(client, profileEndpoints.map(ep => httpsBase + ep.path));
  for (let i = 0; i < profileEndpoints.length; i++) {
    const ep = profileEndpoints[i];
    const br = baselineResults[i];
    if (br && br.statusCode) {
      ep.baseline = {
        status: br.statusCode,
        bodyHash: hashBody(br.body),
        bodyLength: br.body.length,
        hasBody: (br.body || '').trim().length > 0,
        loadMs: 0,
        headers: {},
      };
    }
  }

  // 6) WAF + tech fingerprint (2 requests)
  let rootRes: HttpResult | null = null;
  try { rootRes = await client.safeRequest(httpsBase + '/', 'GET', {}, ''); } catch (e) {
    logger.debug('[TargetAnalysis] Root request failed: ' + (e instanceof Error ? e.message : String(e)));
  }
  const wafResult = rootRes ? fingerprintWaf(rootRes) : { name: null as string | null, detected: false };
  let wafDetected = wafResult.detected;
  let wafName = wafResult.name;
  if (!wafDetected && rootRes) {
    try {
      const probe = await client.safeRequest(httpsBase + "/?id=<script>alert(1)</script>&__wafprobe=" + Date.now(), 'GET', {}, '');
      if (probe.statusCode === 403 || probe.statusCode === 406 || probe.statusCode === 429) {
        wafDetected = true;
        wafName = wafName || 'Generic WAF';
      }
    } catch (e) {
      logger.debug('[TargetAnalysis] WAF probe failed: ' + (e instanceof Error ? e.message : String(e)));
    }
  }

  // Extract tech from root response (synchronous from already-fetched data)
  const techStack: string[] = [];
  if (rootRes) {
    const combined = (rootRes.headers['server'] || '') + ' ' + (rootRes.headers['x-powered-by'] || '') + ' ' + rootRes.body.substring(0, 2000).toLowerCase();
    const techPatterns: [RegExp, string][] = [
      [/react/i, 'React'], [/next\.js/i, 'Next.js'], [/vue|nuxt/i, 'Vue/Nuxt'],
      [/angular/i, 'Angular'], [/jquery/i, 'jQuery'], [/wordpress/i, 'WordPress'],
      [/laravel/i, 'Laravel'], [/django/i, 'Django'], [/rails/i, 'Ruby on Rails'],
      [/asp\.net/i, 'ASP.NET'], [/spring|tomcat/i, 'Java/Spring'], [/node\.js|express/i, 'Node.js'],
      [/php/i, 'PHP'], [/nginx/i, 'Nginx'], [/apache/i, 'Apache'], [/iis/i, 'IIS'],
    ];
    for (const [re, name] of techPatterns) {
      if (re.test(combined)) techStack.push(name);
    }
  }

  // 7) Build profile
  const all = [...endpoints.values()];
  const allParams = [...new Set([...all.flatMap(e => e.params), ...jsParams])].slice(0, 60);
  const loginEndpoints = [...new Set(all.filter(e => e.isLogin).map(e => e.path))];
  const adminEndpoints = [...new Set(all.filter(e => e.isAdmin).map(e => e.path))];
  const apiEndpoints = [...new Set(all.filter(e => e.isApi).map(e => e.path))];
  const uploadEndpoints = [...new Set(all.filter(e => e.isUpload).map(e => e.path))];
  const csrfParamNames = [...new Set(allParams.filter(p => /csrf|token|nonce|authenticity|_token\b/i.test(p)))];

  const profile: TargetProfile = {
    domain, httpsBase, httpBase, usesHttps: true, redirectsToHttps: false,
    endpoints: all.slice(0, 60), allParams, cookies: client.getCookies(), csrfParamNames,
    techStack, wafDetected, wafName,
    loginEndpoints: loginEndpoints.slice(0, 15), adminEndpoints: adminEndpoints.slice(0, 15),
    apiEndpoints: apiEndpoints.slice(0, 20), uploadEndpoints: uploadEndpoints.slice(0, 10),
    jsFiles: jsList, discoveredPaths: discoveredPaths.slice(0, 50),
    serverHeaders: rootRes ? Object.fromEntries(Object.entries(rootRes.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(', ') : String(v || '')])) : {},
    sitemapPaths: discoveredPaths.slice(0, 50),
  };

  logger.info(`[TargetAnalysis] ${domain}: ${profile.endpoints.length} endpoints, ${profile.allParams.length} params, WAF=${profile.wafDetected ? profile.wafName : 'none'}`);
  return profile;
}

export function createTargetClient(profile: TargetProfile): TargetHttpClient {
  return new TargetHttpClient(profile);
}