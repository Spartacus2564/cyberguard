import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl, fetchUrlFollowRedirects, buildProof, formatProofAsText, respectRateLimit } from './shared';
import logger from '../../utils/logger';
import { getAI } from '../../services/ai.service';

const MODULE_NAME = 'deepDiscovery';

// ─── DISCOVERY WORDLISTS ────────────────────────────────────────────────────
// Curated from SecLists Discovery/Web-Content + real-world bug bounty findings
const COMMON_PATHS = [
  '/admin', '/admin/login', '/administrator', '/wp-admin', '/wp-login.php',
  '/login', '/signin', '/auth', '/sso', '/oauth', '/callback',
  '/api', '/api/v1', '/api/v2', '/api/v3', '/api/internal', '/api/admin',
  '/graphql', '/graphiql', '/graphql/console', '/playground', '/altair',
  '/swagger', '/swagger-ui', '/swagger.json', '/swagger.yaml', '/openapi.json',
  '/v1/api-docs', '/v2/api-docs', '/v3/api-docs', '/api-docs',
  '/docs', '/redoc', '/documentation', '/help', '/support',
  '/health', '/healthcheck', '/health-check', '/ready', '/live', '/status',
  '/metrics', '/prometheus', '/debug', '/debug/vars', '/debug/pprof',
  '/config', '/configuration', '/settings', '/setup', '/install',
  '/backup', '/backups', '/bak', '/old', '/new', '/temp', '/tmp',
  '/test', '/testing', '/staging', '/dev', '/development', '/sandbox',
  '/.env', '.env', '.env.local', '.env.production', '.env.staging',
  '.env.bak', '.env.old', '.env.save', '.env.backup', '.env.production.local',
  '/.git', '/.git/HEAD', '/.git/config', '/.gitignore', '/.gitattributes',
  '/.svn', '/.svn/entries', '/.svn/wc.db',
  '/.DS_Store', '/Thumbs.db', '/web.config', '/crossdomain.xml',
  '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
  '/.well-known/security.txt', '/.well-known/openid-configuration',
  '/.well-known/apple-app-site-association', '/.well-known/assetlinks.json',
  '/favicon.ico', '/apple-touch-icon.png', '/logo.png', '/banner.png',
  '/readme.md', '/README.md', '/CHANGELOG.md', '/LICENSE', '/TODO.md',
  '/server-status', '/server-info', '/nginx_status',
  '/phpinfo.php', '/info.php', '/test.php', '/i.php',
  '/elmah.axd', '/trace.axd', '/web.config',
  '/wp-content/debug.log', '/wp-content/uploads/',
  '/storage/logs/laravel.log', '/storage/framework/sessions/',
  '/logs', '/log', '/var/log', '/tmp/logs',
  '/uploads', '/upload', '/files', '/media', '/assets', '/static',
  '/images', '/img', '/css', '/js', '/scripts',
  '/cgi-bin', '/cgi-bin/test-cgi', '/cgi-bin/htimage',
  '/icons', '/icons/README', '/apache2-default',
  '/autoinst.html', '/ws_ftp.ini', '/.htaccess', '/.htpasswd',
  '/config.php', '/config.inc.php', '/configuration.php',
  '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old',
  '/database', '/db', '/sql', '/dump', '/export', '/import',
  '/phpmyadmin', '/pma', '/adminer', '/adminer.php',
  '/.bash_history', '/.ssh', '/.ssh/authorized_keys',
  '/etc/passwd', '/etc/shadow', '/proc/self/environ',
  '/actuator', '/actuator/env', '/actuator/health', '/actuator/beans',
  '/actuator/configprops', '/actuator/mappings', '/actuator/heapdump',
  '/management', '/manage', '/console', '/admin/console',
  '/sidekiq', '/sidekiq/overview', '/delayed_job',
  '/rabbitmq', '/mq', '/kafka', '/redis',
  '/elasticsearch', '/_search', '/_cat/indices', '/_cluster/health',
  '/kibana', '/app/kibana', '/app/discover',
  '/grafana', '/d', '/explore', '/api/dashboards',
  '/jenkins', '/jenkins/login', '/job/', '/script',
  '/gitlab', '/users/sign_in', '/api/v4/projects',
  '/bitbucket', '/dashboard', '/rest/api/latest',
  '/jira', '/login.jsp', '/rest/api/2/',
  '/confluence', '/pages/viewpage.action',
  '/drupal', '/user/login', '/admin/content',
  '/joomla', '/administrator/index.php',
  '/magento', '/admin', '/admin/dashboard',
  '/django', '/admin/login/', '/__debug__/',
  '/flask', '/_debugger', '/console',
  '/laravel', '/telescope', '/horizon', '/log-viewer',
  '/rails', '/rails/info', '/rails/mailers', '/sidekiq',
  '/spring', '/actuator', '/swagger-ui.html',
  '/express', '/_next', '/__webpack_hmr',
  '/.aws', '/.aws/credentials', '/.aws/config',
  '/.docker', '/.docker/config.json',
  '/.kube', '/.kube/config',
  '/terraform', '/.terraform',
  '/ansible', '/playbook.yml',
  '/ci', '/.circleci', '.github/workflows', '.gitlab-ci.yml',
  '/deploy', '/deployment', '/releases',
  '/package.json', '/package-lock.json', '/yarn.lock',
  '/composer.json', '/composer.lock',
  '/Gemfile', '/Gemfile.lock',
  '/requirements.txt', '/Pipfile', '/Pipfile.lock',
  '/pom.xml', '/build.gradle', '/build.gradle.kts',
  '/Cargo.toml', '/go.mod', '/go.sum',
  '/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile',
  '/Vagrantfile', '/ansible.cfg',
  '/Makefile', '/CMakeLists.txt',
  '/.editorconfig', '.eslintrc', '.prettierrc',
  '/tsconfig.json', '/webpack.config.js', '/vite.config.js',
  '/next.config.js', '/nuxt.config.js',
  '/angular.json', '/vue.config.js',
  '/ormconfig.json', '/knexfile.js',
  '/.circleci/config.yml', '.github/workflows/ci.yml',
  '/report', '/reports', '/audit',
  '/xmlrpc.php', '/xmlrpc.php?rsd',
  '/feed', '/rss', '/atom.xml',
  '/wp-json', '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts',
  '/api/users', '/api/user', '/api/me', '/api/profile',
  '/api/admin', '/api/config', '/api/version',
  '/api/health', '/api/status', '/api/info',
  '/api/debug', '/api/test', '/api/ping',
];

// JS/API endpoint patterns extracted from JavaScript bundles
const JS_API_PATTERNS = [
  /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.put\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.delete\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /\.patch\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]/g,
  /baseURL\s*[:=]\s*['"`]([^'"`]+)['"`]/g,
  /apiUrl\s*[:=]\s*['"`]([^'"`]+)['"`]/g,
  /endpoint\s*[:=]\s*['"`]([^'"`]+)['"`]/g,
  /url\s*[:=]\s*['"`](\/api[^'"`]+)['"`]/g,
  /path\s*[:=]\s*['"`](\/api[^'"`]+)['"`]/g,
  /route\s*[:=]\s*['"`](\/api[^'"`]+)['"`]/g,
  /['"`](\/api\/[a-zA-Z0-9/_-]+)['"`]/g,
  /['"`](\/v[0-9]+\/[a-zA-Z0-9/_-]+)['"`]/g,
  /['"`](https?:\/\/[^'"`]*api[^'"`]*)['"`]/g,
];

// Backup file extensions to try
const BACKUP_EXTENSIONS = ['.bak', '.old', '.backup', '.save', '.swp', '.swo', '~', '.orig', '.copy', '.tmp'];

// Common parameter names for API discovery
const COMMON_PARAMS = [
  'id', 'user_id', 'userId', 'account_id', 'accountId',
  'page', 'per_page', 'limit', 'offset', 'cursor',
  'q', 'query', 'search', 'keyword', 'term',
  'sort', 'order', 'direction', 'field',
  'format', 'type', 'action', 'method',
  'token', 'api_key', 'apiKey', 'key', 'secret',
  'redirect', 'redirect_uri', 'callback', 'return_url', 'next',
  'url', 'link', 'href', 'target',
  'file', 'path', 'filename', 'document', 'attachment',
  'name', 'email', 'password', 'code', 'otp',
  'status', 'state', 'active', 'enabled',
  'debug', 'verbose', 'trace', 'log',
];

async function discoverFromJavaScript(domain: string): Promise<string[]> {
  const discovered = new Set<string>();
  const baseUrl = `https://${domain}`;

  // Try to find and parse JavaScript files
  const jsPaths = ['/static/js/', '/assets/js/', '/js/', '/scripts/', '/dist/', '/build/'];

  // First, get the main page and extract JS file URLs
  try {
    const mainPage = await fetchUrl(baseUrl, 5000);
    const jsUrls = mainPage.body.match(/src\s*=\s*["']([^"']*\.js[^"']*?)["']/gi) || [];
    const scriptSrcs = jsUrls.map(m => {
      const match = m.match(/src\s*=\s*["']([^"']+)["']/i);
      return match ? match[1] : '';
    }).filter(Boolean);

    for (const src of scriptSrcs.slice(0, 10)) {
      const jsUrl = src.startsWith('http') ? src : `${baseUrl}${src.startsWith('/') ? '' : '/'}${src}`;
      try {
        const jsContent = await fetchUrl(jsUrl, 8000);
        if (jsContent.statusCode === 200 && jsContent.body.length > 100) {
          // Extract API endpoints from JavaScript
          for (const pattern of JS_API_PATTERNS) {
            let match;
            while ((match = pattern.exec(jsContent.body)) !== null) {
              const endpoint = match[1];
              if (endpoint && endpoint.startsWith('/') && !endpoint.includes('.js') && !endpoint.includes('.css')) {
                discovered.add(endpoint);
              }
            }
          }
          // Extract hardcoded URLs
          const urlMatches = jsContent.body.match(/["'](https?:\/\/[^"']+)["']/g) || [];
          for (const urlMatch of urlMatches) {
            const url = urlMatch.replace(/["']/g, '');
            if (url.includes(domain) || url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/')) {
              try {
                const urlObj = new URL(url);
                if (urlObj.pathname && urlObj.pathname !== '/') {
                  discovered.add(urlObj.pathname);
                }
              } catch {}
            }
          }
        }
      } catch {}
    }
  } catch {}

  return [...discovered];
}

async function wordlistFuzz(domain: string): Promise<{ path: string; status: number; size: number; contentType: string }[]> {
  const baseUrl = `https://${domain}`;
  const results: { path: string; status: number; size: number; contentType: string }[] = [];

  for (const path of COMMON_PATHS.slice(0, 120)) {
    try {
      await respectRateLimit(domain);
      const r = await fetchUrl(`${baseUrl}${path}`, 4000);
      const ct = (r.headers['content-type'] || '').toLowerCase();
      // Filter out boring responses (default pages, 404s, redirects to login)
      if (r.statusCode === 200 || r.statusCode === 401 || r.statusCode === 403) {
        if (r.body.length > 0 && !ct.includes('image') && !ct.includes('font')) {
          // Skip generic error pages
          const body = r.body.toLowerCase();
          if (!body.includes('page not found') && !body.includes('404') && !body.includes('does not exist')) {
            results.push({ path, status: r.statusCode, size: r.body.length, contentType: ct });
          }
        }
      }
    } catch {}
  }

  return results;
}

async function discoverBackupFiles(domain: string, discoveredPaths: string[]): Promise<{ path: string; status: number; size: number }[]> {
  const baseUrl = `https://${domain}`;
  const results: { path: string; status: number; size: number }[] = [];

  // Try backup extensions on interesting files
  const interestingFiles = discoveredPaths.filter(p =>
    p.endsWith('.php') || p.endsWith('.js') || p.endsWith('.json') ||
    p.endsWith('.yml') || p.endsWith('.yaml') || p.endsWith('.xml') ||
    p.endsWith('.conf') || p.endsWith('.cfg') || p.endsWith('.ini') ||
    p.includes('config') || p.includes('settings') || p.includes('.env')
  );

  for (const file of interestingFiles.slice(0, 20)) {
    for (const ext of BACKUP_EXTENSIONS.slice(0, 5)) {
      try {
        await respectRateLimit(domain);
        const r = await fetchUrl(`${baseUrl}${file}${ext}`, 4000);
        if (r.statusCode === 200 && r.body.length > 10) {
          results.push({ path: `${file}${ext}`, status: r.statusCode, size: r.body.length });
        }
      } catch {}
    }
  }

  return results;
}

async function discoverAPIEndpoints(domain: string): Promise<{ path: string; method: string; params: string[] }[]> {
  const baseUrl = `https://${domain}`;
  const endpoints: { path: string; method: string; params: string[] }[] = [];

  // Try common API versions and patterns
  const apiPrefixes = ['/api', '/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3'];
  const apiResources = [
    '/users', '/user', '/accounts', '/account', '/profile',
    '/orders', '/order', '/items', '/item', '/products', '/product',
    '/posts', '/post', '/articles', '/article', '/comments', '/comment',
    '/messages', '/message', '/notifications', '/notification',
    '/files', '/file', '/documents', '/document', '/uploads', '/upload',
    '/settings', '/config', '/preferences', '/options',
    '/auth', '/login', '/register', '/signup', '/logout', '/refresh',
    '/search', '/query', '/filter', '/autocomplete',
    '/admin', '/dashboard', '/reports', '/analytics',
    '/webhooks', '/webhook', '/events', '/logs',
  ];

  for (const prefix of apiPrefixes) {
    for (const resource of apiResources.slice(0, 15)) {
      const path = `${prefix}${resource}`;
      try {
        await respectRateLimit(domain);
        const r = await fetchUrl(`${baseUrl}${path}`, 4000);
        const ct = (r.headers['content-type'] || '').toLowerCase();
        const isApi = ct.includes('json') || r.body.startsWith('{') || r.body.startsWith('[');
        if (isApi && (r.statusCode === 200 || r.statusCode === 401 || r.statusCode === 403)) {
          endpoints.push({ path, method: 'GET', params: COMMON_PARAMS.slice(0, 5) });
        }
      } catch {}
    }
  }

  return endpoints;
}

export async function runDeepDiscovery(domain: string, priorFindings: Finding[] = []): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const baseUrl = `https://${domain}`;

  logger.info(`[${MODULE_NAME}] Starting deep discovery for ${domain}`);

  // ── 1. WORDLIST FUZZING ──────────────────────────────────────────────────
  logger.info(`[${MODULE_NAME}] Phase 1: Wordlist-based path discovery`);
  const fuzzResults = await wordlistFuzz(domain);
  logger.info(`[${MODULE_NAME}] Found ${fuzzResults.length} paths via wordlist fuzzing`);

  // Report interesting discoveries
  const interestingPaths = fuzzResults.filter(r =>
    r.status === 200 && (
      r.path.includes('admin') || r.path.includes('config') || r.path.includes('env') ||
      r.path.includes('debug') || r.path.includes('swagger') || r.path.includes('graphql') ||
      r.path.includes('actuator') || r.path.includes('backup') || r.path.includes('log') ||
      r.path.includes('phpinfo') || r.path.includes('test') || r.path.includes('dev') ||
      r.path.includes('.git') || r.path.includes('.env') || r.path.includes('console')
    )
  );

  for (const ep of interestingPaths.slice(0, 15)) {
    const proof = buildProof('GET', `${baseUrl}${ep.path}`, undefined, undefined, ep.status, {}, `(${ep.size} bytes, ${ep.contentType})`);
    findings.push(generateFinding(
      `Discovered Endpoint: ${ep.path}`,
      `Deep discovery found ${ep.path} accessible at HTTP ${ep.status} with ${ep.size} bytes of ${ep.contentType || 'unknown'} content.`,
      ep.path.includes('.env') || ep.path.includes('admin') || ep.path.includes('debug') ? Severity.HIGH : Severity.MEDIUM,
      'Discovery',
      domain,
      formatProofAsText(proof),
      'Hidden endpoints may expose sensitive data or administrative functions',
      'Restrict access to sensitive endpoints; implement authentication',
      ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
    ));
  }

  // ── 2. JAVASCRIPT ENDPOINT EXTRACTION ────────────────────────────────────
  logger.info(`[${MODULE_NAME}] Phase 2: JavaScript API endpoint extraction`);
  const jsEndpoints = await discoverFromJavaScript(domain);
  logger.info(`[${MODULE_NAME}] Found ${jsEndpoints.length} endpoints from JavaScript analysis`);

  if (jsEndpoints.length > 0) {
    findings.push(generateFinding(
      `API Endpoints from JavaScript: ${jsEndpoints.length} discovered`,
      `Extracted ${jsEndpoints.length} API endpoints from JavaScript bundles: ${jsEndpoints.slice(0, 10).join(', ')}${jsEndpoints.length > 10 ? ` and ${jsEndpoints.length - 10} more` : ''}`,
      Severity.MEDIUM,
      'Discovery',
      domain,
      `Endpoints discovered:\n${jsEndpoints.map(e => `  - ${e}`).join('\n')}`,
      'API endpoints in JavaScript may be undocumented and lack proper access controls',
      'Audit all discovered API endpoints for authentication and authorization',
      ['https://owasp.org/www-project-api-security/']
    ));

    // Test discovered JS endpoints
    for (const endpoint of jsEndpoints.slice(0, 20)) {
      try {
        await respectRateLimit(domain);
        const r = await fetchUrl(`${baseUrl}${endpoint}`, 4000);
        if (r.statusCode === 200 && r.body.length > 0) {
          const ct = (r.headers['content-type'] || '').toLowerCase();
          if (ct.includes('json') && (r.body.includes('password') || r.body.includes('secret') || r.body.includes('token') || r.body.includes('key') || r.body.includes('email'))) {
            const proof = buildProof('GET', `${baseUrl}${endpoint}`, undefined, undefined, r.statusCode, r.headers, r.body.slice(0, 1000));
            findings.push(generateFinding(
              `Sensitive Data Exposure: ${endpoint}`,
              `API endpoint ${endpoint} returns potentially sensitive data (passwords, tokens, or keys detected in response).`,
              Severity.HIGH,
              'Data Exposure',
              domain,
              formatProofAsText(proof),
              'Sensitive data exposure can lead to account takeover and data breach',
              'Implement proper access controls and data filtering on API responses',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/']
            ));
          }
        }
      } catch {}
    }
  }

  // ── 3. BACKUP FILE DISCOVERY ─────────────────────────────────────────────
  logger.info(`[${MODULE_NAME}] Phase 3: Backup file discovery`);
  const backupResults = await discoverBackupFiles(domain, fuzzResults.map(r => r.path).concat(jsEndpoints));
  logger.info(`[${MODULE_NAME}] Found ${backupResults.length} backup files`);

  for (const backup of backupResults.slice(0, 10)) {
    const proof = buildProof('GET', `${baseUrl}${backup.path}`, undefined, undefined, backup.status, {}, `(${backup.size} bytes)`);
    findings.push(generateFinding(
      `Backup File Exposed: ${backup.path}`,
      `Backup file ${backup.path} is publicly accessible (${backup.size} bytes). This may contain source code, credentials, or configuration data.`,
      Severity.HIGH,
      'Discovery',
      domain,
      formatProofAsText(proof),
      'Exposed backup files can leak source code, credentials, and configuration',
      'Remove backup files from production; restrict access via web server config',
      ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
    ));
  }

  // ── 4. API SURFACE MAPPING ───────────────────────────────────────────────
  logger.info(`[${MODULE_NAME}] Phase 4: API surface mapping`);
  const apiEndpoints = await discoverAPIEndpoints(domain);
  logger.info(`[${MODULE_NAME}] Mapped ${apiEndpoints.length} API endpoints`);

  if (apiEndpoints.length > 0) {
    findings.push(generateFinding(
      `API Surface Map: ${apiEndpoints.length} endpoints discovered`,
      `Comprehensive API surface mapping found ${apiEndpoints.length} endpoints across ${new Set(apiEndpoints.map(e => e.path.split('/').slice(0, 3).join('/'))).size} API groups.`,
      Severity.INFO,
      'Discovery',
      domain,
      `API endpoints:\n${apiEndpoints.map(e => `  ${e.method} ${e.path} [params: ${e.params.slice(0, 3).join(', ')}]`).join('\n')}`,
      'A complete API inventory is essential for security testing',
      'Document all API endpoints and implement proper access controls',
      ['https://owasp.org/www-project-api-security/']
    ));

    // Test for IDOR on discovered endpoints
    for (const endpoint of apiEndpoints.filter(e => e.path.includes('/users') || e.path.includes('/accounts') || e.path.includes('/profile')).slice(0, 5)) {
      try {
        await respectRateLimit(domain);
        const r1 = await fetchUrl(`${baseUrl}${endpoint.path}/1`, 4000);
        const r2 = await fetchUrl(`${baseUrl}${endpoint.path}/2`, 4000);
        if (r1.statusCode === 200 && r2.statusCode === 200 && r1.body !== r2.body && r1.body.length > 20) {
          const proof = buildProof('GET', `${baseUrl}${endpoint.path}/1`, undefined, undefined, 200, {}, r1.body.slice(0, 500));
          findings.push(generateFinding(
            `IDOR via API: ${endpoint.path}/[id]`,
            `Sequential IDs at ${endpoint.path} return different data, indicating Insecure Direct Object Reference.`,
            Severity.HIGH,
            'Broken Access Control',
            domain,
            formatProofAsText(proof),
            'IDOR allows unauthorized access to other users data',
            'Use UUIDs; validate ownership on every request',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References']
          ));
        }
      } catch {}
    }
  }

  // ── 5. SUBDOMAIN/VIRTUAL HOST BRUTE FORCE (conceptual) ──────────────────
  // Since we can't do DNS brute-force from HTTP, we test common subdomain-like paths
  logger.info(`[${MODULE_NAME}] Phase 5: Virtual host and subdomain path discovery`);
  const subdomainPaths = [
    '/.well-known/', '/cdn/', '/static/', '/assets/', '/media/',
    '/internal/', '/private/', '/secret/', '/hidden/', '/restricted/',
    '/staging.', '/dev.', '/test.', '/sandbox.', '/demo.',
  ];

  for (const path of subdomainPaths.slice(0, 10)) {
    try {
      await respectRateLimit(domain);
      const r = await fetchUrl(`${baseUrl}${path}`, 4000);
      if (r.statusCode === 200 && r.body.length > 50 && !r.body.includes('404')) {
        const proof = buildProof('GET', `${baseUrl}${path}`, undefined, undefined, r.statusCode, {}, `(${r.body.length} bytes)`);
        findings.push(generateFinding(
          `Hidden Path: ${path}`,
          `Path ${path} returns content (${r.body.length} bytes). This may be a hidden or restricted area.`,
          Severity.MEDIUM,
          'Discovery',
          domain,
          formatProofAsText(proof),
          'Hidden paths may expose sensitive functionality',
          'Restrict access to hidden paths',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces']
        ));
      }
    } catch {}
  }

  // AI-enhanced deep discovery analysis
  try {
    const ai = getAI();
    const discoveries = [
      ...fuzzResults.map((r: any) => ({ url: `https://${domain}${r.path}`, status: r.status, size: r.size || 0, type: r.contentType || 'unknown' })),
      ...jsEndpoints.map((e: string) => ({ url: `https://${domain}${e}`, status: 200, size: 0, type: 'javascript' })),
      ...backupResults.map((b: any) => ({ url: `https://${domain}${b.path}`, status: b.status, size: b.size || 0, type: 'backup' })),
    ];
    if (discoveries.length > 0) {
      const aiResult = await ai.analyzeDeepDiscovery(discoveries, domain);
      if (aiResult.findings?.length) {
        for (const af of aiResult.findings) {
          findings.push(generateFinding(
            af.title || 'AI Discovery Finding',
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
  logger.info(`[${MODULE_NAME}] Complete: ${findings.length} findings in ${(duration / 1000).toFixed(1)}s`);
  return { module: MODULE_NAME as any, findings, duration, errors };
}
