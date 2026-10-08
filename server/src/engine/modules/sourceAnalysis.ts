import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, isLoginPage, isGenericPage } from './shared';
import { logExploit } from '../scanLogger';

const TIMEOUT_MS = 8000;

async function safeFetch(url: string): Promise<{ status: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'CYBERGUARD-SourceAnalysis/1.0' },
    });
    const body = await res.text();
    return { status: res.status, body };
  } catch {
    return { status: 0, body: '' };
  } finally {
    clearTimeout(timer);
  }
}

interface SourceMapPayload {
  version?: number;
  file?: string;
  sources?: string[];
  sourcesContent?: string[];
  names?: string[];
  mappings?: string;
}

function parseSourceMap(body: string): SourceMapPayload | null {
  try {
    const parsed: unknown = JSON.parse(body);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'mappings' in (parsed as Record<string, unknown>)
    ) {
      return parsed as SourceMapPayload;
    }
  } catch {}
  return null;
}

function isSensitiveComment(text: string): boolean {
  return /(?:TODO|FIXME|HACK|XXX|SECRET|PASSWORD|TOKEN|API.?KEY|CREDENTIAL)/i.test(text);
}

async function testSourceMaps(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  const homePage = await safeFetch(base + '/');
  if (homePage.status !== 200 || !homePage.body) return findings;

  const jsPattern = /src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
  const jsFiles: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = jsPattern.exec(homePage.body)) !== null && jsFiles.length < 10) {
    jsFiles.push(match[1]);
  }

  for (const jsFile of jsFiles) {
    const mapUrl = jsFile.endsWith('.js') ? jsFile + '.map' : jsFile.replace('.js', '.js.map');
    let fullMapUrl: string;
    try {
      fullMapUrl = new URL(mapUrl, base).toString();
    } catch {
      continue;
    }

    const mapRes = await safeFetch(fullMapUrl);
    if (mapRes.status !== 200 || !mapRes.body) continue;

    const sourceMap = parseSourceMap(mapRes.body);
    if (!sourceMap) continue;

    logExploit('sourceAnalysis', 'SourceMapExposure', fullMapUrl);

    const sourceFiles = sourceMap.sources || [];
    const internalPaths = sourceFiles.filter(
      (s) => s && !s.startsWith('node_modules/') && !s.includes('webpack://')
    );
    const hasSensitiveComments = sourceMap.sourcesContent?.some((content) =>
      content ? isSensitiveComment(content) : false
    );

    const evidenceParts: string[] = [];
    evidenceParts.push(`Source map found at: ${fullMapUrl}`);
    if (internalPaths.length > 0) {
      evidenceParts.push(`Internal paths exposed (${internalPaths.length}): ${internalPaths.slice(0, 15).join(', ')}`);
    }
    if (sourceMap.file) {
      evidenceParts.push(`Bundled file: ${sourceMap.file}`);
    }
    if (hasSensitiveComments) {
      evidenceParts.push('Source content contains sensitive comments (TODO/FIXME/SECRET markers)');
    }

    findings.push(
      generateFinding(
        'Exposed Source Map with Internal Structure',
        `A JavaScript source map is publicly accessible at ${fullMapUrl}. This exposes the original source code directory structure, file paths, and potentially sensitive comments embedded in source files.`,
        Severity.MEDIUM,
        'Information Disclosure',
        fullMapUrl,
        evidenceParts.join('\n'),
        'Attackers can reconstruct the original source code, discover internal directory layout, identify custom logic, and extract sensitive information from comments.',
        'Remove .map files from production builds or restrict access via server configuration.',
        ['https://cwe.mitre.org/data/definitions/200.html']
      )
    );
  }

  return findings;
}

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/ },
  { name: 'Database URL', regex: /(mysql|postgres|mongodb|redis):\/\/[^\s"']+/ },
  { name: 'API Key', regex: /(api[_-]?key|apikey|api[_-]?secret)['":\s]*[=:]['"]\s*['"][^'"]{8,}/i },
  { name: 'JWT Secret', regex: /(jwt[_-]?secret|token[_-]?secret)['":\s]*[=:]['"]\s*['"][^'"]{8,}/i },
  { name: 'OAuth Client Secret', regex: /(client[_-]?secret|oauth[_-]?secret)['":\s]*[=:]['"]\s*['"][^'"]{8,}/i },
  { name: 'SMTP Credentials', regex: /(smtp[_-]?pass|mail[_-]?pass)['":\s]*[=:]['"]\s*['"][^'"]{8,}/i },
  { name: 'Encryption Key', regex: /(encryption[_-]?key|secret[_-]?key|master[_-]?key)['":\s]*[=:]['"]\s*['"][^'"]{8,}/i },
];

const CONFIG_PATHS = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.test',
  '/config.json',
  '/config.yml',
  '/config.yaml',
  '/settings.json',
  '/application.properties',
  '/application.yml',
];

async function testHardcodedSecrets(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const configPath of CONFIG_PATHS) {
    const res = await safeFetch(base + configPath);
    if (res.status !== 200 || !res.body) continue;

    const isHtml =
      res.body.includes('<!DOCTYPE') ||
      res.body.includes('<html');
    if (isHtml) continue;

    for (const pattern of SECRET_PATTERNS) {
      const matches = res.body.match(pattern.regex);
      if (matches) {
        logExploit('sourceAnalysis', 'HardcodedSecret', base + configPath, pattern.name);

        findings.push(
          generateFinding(
            `${pattern.name} Exposed in Configuration File`,
            `A ${pattern.name} was detected in the publicly accessible configuration file ${configPath}.`,
            Severity.CRITICAL,
            'Sensitive Data Exposure',
            base + configPath,
            `Secret type: ${pattern.name}\nFile: ${configPath}\nPattern match found in file content`,
            `Exposed ${pattern.name.toLowerCase()} can lead to unauthorized access, data breaches, and infrastructure compromise.`,
            'Remove secrets from configuration files. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.',
            ['https://cwe.mitre.org/data/definitions/798.html']
          )
        );
      }
    }
  }

  return findings;
}

const VERSION_CONTROL_PATHS = [
  { path: '/.git/HEAD', name: 'Git HEAD', severity: Severity.HIGH },
  { path: '/.git/config', name: 'Git Config', severity: Severity.HIGH },
  { path: '/.gitignore', name: 'Git Ignore', severity: Severity.LOW },
  { path: '/.svn/entries', name: 'SVN Entries', severity: Severity.HIGH },
  { path: '/.hg/', name: 'Mercurial Repository', severity: Severity.HIGH },
] as const;

async function testGitExposure(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const vc of VERSION_CONTROL_PATHS) {
    const res = await safeFetch(base + vc.path);
    if (res.status !== 200 || !res.body) continue;

    const isHtml = res.body.includes('<!DOCTYPE') || res.body.includes('<html');
    if (isHtml && vc.path !== '/.gitignore') continue;

    logExploit('sourceAnalysis', 'VersionControlExposure', base + vc.path);

    let description: string;
    let impact: string;
    const evidenceParts: string[] = [`Path: ${vc.path}`, `Content preview: ${res.body.substring(0, 500)}`];

    if (vc.path === '/.git/HEAD') {
      description = 'The Git HEAD file is publicly accessible, revealing the current branch and commit information of the repository.';
      impact = 'Attackers can enumerate the repository structure and potentially clone the full source code.';
    } else if (vc.path === '/.git/config') {
      description = 'The Git config file is publicly accessible, potentially exposing remote repository URLs and internal server addresses.';
      impact = 'Internal Git server URLs, developer usernames, and repository paths are disclosed, enabling targeted attacks on development infrastructure.';
      if (/url\s*=/.test(res.body)) {
        evidenceParts.push('Remote URLs detected in config');
      }
    } else if (vc.path === '/.gitignore') {
      description = 'The .gitignore file is accessible, revealing patterns of files excluded from version control.';
      impact = 'Sensitive file naming patterns and directory structure are disclosed.';
    } else if (vc.path === '/.svn/entries') {
      description = 'An SVN entries file is publicly accessible, exposing Subversion repository metadata.';
      impact = 'Full source code may be recoverable via SVN checkout; repository structure and developer information are exposed.';
    } else {
      description = 'A Mercurial (.hg) repository directory is publicly accessible.';
      impact = 'The full source code repository can be cloned via Mercurial, exposing all code, history, and secrets.';
    }

    findings.push(
      generateFinding(
        `Version Control System Exposure: ${vc.name}`,
        description,
        vc.severity,
        'Information Disclosure',
        base + vc.path,
        evidenceParts.join('\n'),
        impact,
        'Restrict public access to version control directories. Add deny rules for /.git/, /.svn/, /.hg/ in your web server configuration.',
        ['https://cwe.mitre.org/data/definitions/200.html']
      )
    );
  }

  return findings;
}

const CICD_CONFIGS = [
  { path: '/.github/workflows/', name: 'GitHub Actions Workflows', severity: Severity.HIGH },
  { path: '/.gitlab-ci.yml', name: 'GitLab CI Configuration', severity: Severity.HIGH },
  { path: '/.travis.yml', name: 'Travis CI Configuration', severity: Severity.MEDIUM },
  { path: '/.circleci/config.yml', name: 'CircleCI Configuration', severity: Severity.MEDIUM },
  { path: '/Jenkinsfile', name: 'Jenkins Pipeline', severity: Severity.HIGH },
  { path: '/azure-pipelines.yml', name: 'Azure Pipelines Configuration', severity: Severity.MEDIUM },
  { path: '/bitbucket-pipelines.yml', name: 'Bitbucket Pipelines Configuration', severity: Severity.MEDIUM },
] as const;

function extractConfigSecretRefs(content: string): string[] {
  const refs: string[] = [];
  const secretPatterns = [
    /\$\{\{\s*secrets\.\w+\s*\}\}/g,
    /\$\{?\w*SECRET\w*\}?/gi,
    /\$\{?\w*TOKEN\w*\}?/gi,
    /\$\{?\w*KEY\w*\}?/gi,
    /\$\{?\w*PASSWORD\w*\}?/gi,
    /VAULT_TOKEN/gi,
  ];
  for (const p of secretPatterns) {
    let m: RegExpExecArray | null;
    while ((m = p.exec(content)) !== null) {
      if (!refs.includes(m[0])) refs.push(m[0]);
    }
  }
  return refs;
}

function extractRepoUrls(content: string): string[] {
  const urls: string[] = [];
  const patterns = [
    /git\s+clone\s+([^\s"']+)/g,
    /repository[:\s]+([^\s"']+)/gi,
    /repo[:\s]+([^\s"']+)/gi,
    /origin[:\s]+([^\s"']+)/gi,
  ];
  for (const p of patterns) {
    let m: RegExpExecArray | null;
    while ((m = p.exec(content)) !== null) {
      const url = m[1];
      if (url.startsWith('http') || url.startsWith('git@')) {
        if (!urls.includes(url)) urls.push(url);
      }
    }
  }
  return urls;
}

async function testCicdExposure(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const config of CICD_CONFIGS) {
    const res = await safeFetch(base + config.path);
    if (res.status !== 200 || !res.body) continue;

    const isHtml = res.body.includes('<!DOCTYPE') || res.body.includes('<html');
    if (isHtml) continue;

    logExploit('sourceAnalysis', 'CICDExposure', base + config.path);

    const secretRefs = extractConfigSecretRefs(res.body);
    const repoUrls = extractRepoUrls(res.body);

    const evidenceParts: string[] = [
      `Config path: ${config.path}`,
      `Content size: ${res.body.length} bytes`,
    ];
    if (secretRefs.length > 0) {
      evidenceParts.push(`Secret references: ${secretRefs.join(', ')}`);
    }
    if (repoUrls.length > 0) {
      evidenceParts.push(`Repository URLs: ${repoUrls.join(', ')}`);
    }

    findings.push(
      generateFinding(
        `CI/CD Configuration Exposed: ${config.name}`,
        `The CI/CD configuration file ${config.path} is publicly accessible. This exposes build pipelines, deployment targets, environment variable references, and potentially secret identifiers.`,
        config.severity,
        'Information Disclosure',
        base + config.path,
        evidenceParts.join('\n'),
        'Exposed CI/CD configurations reveal internal build processes, deployment infrastructure, secret references, and repository URLs, enabling supply chain attacks.',
        'Restrict public access to CI/CD configuration files. Store secrets in a dedicated secrets manager and reference them indirectly.',
        ['https://cwe.mitre.org/data/definitions/200.html', 'https://cwe.mitre.org/data/definitions/610.html']
      )
    );
  }

  return findings;
}

const DEBUG_ENDPOINTS = [
  '/debug',
  '/debug/vars',
  '/debug/pprof',
  '/actuator',
  '/actuator/health',
  '/actuator/env',
  '/actuator/beans',
  '/swagger-ui.html',
  '/swagger.json',
  '/api-docs',
  '/openapi.json',
  '/redoc',
  '/phpinfo.php',
  '/info.php',
  '/test.php',
  '/server-status',
  '/server-info',
];

async function testDebugEndpoints(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const endpoint of DEBUG_ENDPOINTS) {
    const res = await safeFetch(base + endpoint);
    if (res.status !== 200 || !res.body) continue;

    // Skip if it's a login page (redirected to login)
    if (isLoginPage(res.body)) continue;

    // Skip if it's a generic error/placeholder page
    if (isGenericPage(res.body)) continue;

    const isSpaCatchAll =
      res.body.includes('__next') ||
      res.body.includes('__nuxt') ||
      res.body.includes('react-root') ||
      res.body.includes('vue-app');
    if (isSpaCatchAll && !endpoint.includes('swagger') && !endpoint.includes('openapi')) continue;

    const isJson = res.body.trimStart().startsWith('{') || res.body.trimStart().startsWith('[');
    const detectedType = isJson ? 'application/json' : 'text/html';

    logExploit('sourceAnalysis', 'DebugEndpoint', base + endpoint);

    let severity: Severity;
    if (endpoint.includes('/actuator/env') || endpoint.includes('/debug/pprof')) {
      severity = Severity.CRITICAL;
    } else if (endpoint.includes('/actuator') || endpoint.includes('/debug/vars') || endpoint.includes('/server-info')) {
      severity = Severity.HIGH;
    } else if (endpoint.includes('/swagger') || endpoint.includes('/openapi') || endpoint.includes('/api-docs') || endpoint.includes('/redoc')) {
      severity = Severity.MEDIUM;
    } else {
      severity = Severity.LOW;
    }

    findings.push(
      generateFinding(
        `Debug/Development Endpoint Accessible: ${endpoint}`,
        `The debug or development endpoint ${endpoint} is publicly accessible. This exposes runtime information, internal configuration, and API documentation intended for development use only.`,
        severity,
        'Security Misconfiguration',
        base + endpoint,
        `Endpoint: ${endpoint}\nStatus: ${res.status}\nContent-Type: ${detectedType}\nResponse size: ${res.body.length} bytes`,
        'Debug endpoints expose application internals, environment variables, thread dumps, and performance data that can be leveraged for further exploitation.',
        'Disable debug endpoints in production. Implement access controls or remove these endpoints entirely.',
        ['https://cwe.mitre.org/data/definitions/215.html']
      )
    );
  }

  return findings;
}

const BACKUP_PATTERNS = [
  '/backup/',
  '/backup.zip',
  '/backup.sql',
  '/db.sql',
  '/database.sql',
  '/dump.sql',
  '/db_backup.sql',
  '/backup.tar',
  '/backup.tar.gz',
  '/web.config.bak',
  '/web.config.old',
  '/config.old',
  '/config.bak',
  '/index.php.bak',
  '/index.html.bak',
  '/wp-config.php.bak',
];

async function testBackupFiles(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const backupPath of BACKUP_PATTERNS) {
    const res = await safeFetch(base + backupPath);
    if (res.status !== 200 || !res.body) continue;

    const isHtml = res.body.includes('<!DOCTYPE') || res.body.includes('<html');
    if (isHtml) continue;

    logExploit('sourceAnalysis', 'BackupFileExposure', base + backupPath);

    const isDatabase = backupPath.endsWith('.sql');
    const isArchive = backupPath.endsWith('.zip') || backupPath.endsWith('.tar') || backupPath.endsWith('.tar.gz');

    let severity: Severity;
    if (isDatabase) {
      severity = Severity.CRITICAL;
    } else if (isArchive) {
      severity = Severity.HIGH;
    } else {
      severity = Severity.MEDIUM;
    }

    findings.push(
      generateFinding(
        `Backup File Accessible: ${backupPath}`,
        `A backup file ${backupPath} is publicly accessible. ${isDatabase ? 'This appears to be a database dump containing application data.' : isArchive ? 'This appears to be an archive that may contain application source code and configuration.' : 'This backup file may contain sensitive configuration or application data.'}`,
        severity,
        'Sensitive Data Exposure',
        base + backupPath,
        `Path: ${backupPath}\nStatus: ${res.status}\nResponse size: ${res.body.length} bytes`,
        isDatabase
          ? 'Database dumps exposed publicly can leak all application data including user credentials, personal information, and business data.'
          : 'Exposed backup files may contain source code, configuration with secrets, and database credentials.',
        'Remove backup files from web-accessible directories. Store backups in secure, access-controlled storage.',
        ['https://cwe.mitre.org/data/definitions/530.html']
      )
    );
  }

  return findings;
}

export async function runSourceAnalysisScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const mapFindings = await testSourceMaps(domain);
    findings.push(...mapFindings);
  } catch (e) {
    errors.push(`Source map scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  try {
    const secretFindings = await testHardcodedSecrets(domain);
    findings.push(...secretFindings);
  } catch (e) {
    errors.push(`Hardcoded secrets scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  try {
    const gitFindings = await testGitExposure(domain);
    findings.push(...gitFindings);
  } catch (e) {
    errors.push(`Git exposure scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  try {
    const cicdFindings = await testCicdExposure(domain);
    findings.push(...cicdFindings);
  } catch (e) {
    errors.push(`CI/CD exposure scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  try {
    const debugFindings = await testDebugEndpoints(domain);
    findings.push(...debugFindings);
  } catch (e) {
    errors.push(`Debug endpoints scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  try {
    const backupFindings = await testBackupFiles(domain);
    findings.push(...backupFindings);
  } catch (e) {
    errors.push(`Backup files scan failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  return {
    module: 'sourceAnalysis',
    findings,
    duration: Date.now() - startTime,
    errors,
  };
}
