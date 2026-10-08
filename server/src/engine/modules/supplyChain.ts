import * as https from 'https';
import * as http from 'http';
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
      headers: { 'User-Agent': 'CYBERGUARD-SupplyChain/1.0', ...headers },
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

export async function runSupplyChainScan(domain: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;

  // 1) Check for npm/yarn/pnpm lockfiles and package.json exposed
  const lockPaths = [
    '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
    '/composer.json', '/composer.lock', '/Gemfile.lock', '/go.sum',
    '/Cargo.lock', '/poetry.lock', '/requirements.txt', '/Pipfile.lock',
    '/.npmrc', '/.yarnrc', '/.pnp.cjs',
  ];
  for (const lp of lockPaths) {
    const r = await safe(base + lp);
    if (r.statusCode === 200 && r.body.length > 10) {
      const isLock = lp.includes('lock') || lp.includes('sum') || lp.includes('.txt') || lp.includes('.cjs');
      findings.push(generateFinding({
        title: `Dependency Manifest Exposed: ${lp}`,
        description: `${isLock ? 'Lock file' : 'Dependency manifest'} ${lp} is publicly accessible (${r.body.length} bytes). This reveals exact dependency versions, enabling attackers to identify known vulnerable packages.`,
        severity: isLock ? Severity.MEDIUM : Severity.LOW,
        category: 'Supply Chain Security',
        affectedAsset: base + lp,
        evidence: `GET ${lp} → HTTP ${r.statusCode}, ${r.body.length} bytes\nContent preview: ${r.body.slice(0, 400)}`,
        impact: 'Attackers can enumerate exact dependency versions and cross-reference with CVE databases to find exploitable vulnerabilities.',
        remediation: 'Block public access to dependency files via web server configuration. In Nginx: location ~ (package|lock|composer|requirements) { deny all; }. Ensure CI/CD pipelines don\'t deploy these files.',
        references: ['https://owasp.org/www-project-dependency-check/'],
      }));
    }
  }

  // 2) Check for exposed CI/CD configs
  const cicdPaths = [
    '/.git/config', '/.git/HEAD', '/.gitignore',
    '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.bak',
    '/.dockerenv', '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
    '/Jenkinsfile', '/.gitlab-ci.yml', '/.github/workflows', '/bitbucket-pipelines.yml',
    '/.circleci/config.yml', '/.travis.yml', '/azure-pipelines.yml',
    '/Makefile', '/Procfile', '/Vagrantfile',
    '/terraform.tfstate', '/terraform.tfvars', '/.terraform',
    '/deploy.yml', '/deploy.sh', '/deploy/production',
    '/k8s/', '/helm/', '/.kube/',
  ];
  for (const cp of cicdPaths) {
    const r = await safe(base + cp);
    if (r.statusCode === 200 && r.body.length > 5) {
      // Skip SPA catch-all: if response is HTML, it's not a real config file
      const isSPA = r.body.includes('<!DOCTYPE html') || r.body.includes('<html') || r.body.includes('__next') || r.body.includes('__nuxt') || r.body.includes('react-root') || r.body.includes('vue-app');
      if (isSPA && !cp.includes('.env')) continue;

      let severity = Severity.LOW;
      let impact = 'Information disclosure about build/deployment infrastructure.';
      if (cp.includes('.git/')) {
        severity = Severity.HIGH;
        impact = 'Full source code repository can be cloned via git, exposing secrets, credentials, and proprietary code.';
      } else if (cp.includes('.env')) {
        severity = Severity.CRITICAL;
        impact = 'Environment variables with database credentials, API keys, and secrets are publicly exposed.';
      } else if (cp.includes('terraform') || cp.includes('tfstate')) {
        severity = Severity.HIGH;
        impact = 'Infrastructure-as-Code state files may contain plaintext secrets and reveal cloud infrastructure details.';
      } else if (cp.includes('Dockerfile') || cp.includes('docker-compose')) {
        severity = Severity.MEDIUM;
        impact = 'Container configuration may expose internal services, hardcoded credentials, and architecture details.';
      }
      findings.push(generateFinding({
        title: `CI/CD Configuration Exposed: ${cp}`,
        description: `The CI/CD or infrastructure configuration file ${cp} is publicly accessible (${r.body.length} bytes). This reveals build processes, deployment targets, secrets, and infrastructure details.`,
        severity,
        category: 'Supply Chain Security',
        affectedAsset: base + cp,
        evidence: `GET ${cp} → HTTP ${r.statusCode}, ${r.body.length} bytes\nContent preview: ${r.body.slice(0, 400)}`,
        impact,
        remediation: `Block public access to ${cp}. Move sensitive configuration to environment variables or secret managers (HashiCorp Vault, AWS Secrets Manager). Ensure .git directories are never deployed.`,
        references: ['https://cwe.mitre.org/data/definitions/200.html'],
      }));
    }
  }

  // 3) Check for exposed source maps
  const jsRes = await safe(base + '/');
  if (jsRes.statusCode === 200) {
    const jsRe = /src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
    let jm;
    const jsFiles: string[] = [];
    while ((jm = jsRe.exec(jsRes.body)) !== null && jsFiles.length < 5) {
      jsFiles.push(jm[1]);
    }
    for (const jsf of jsFiles) {
      const mapUrl = jsf.endsWith('.js') ? jsf + '.map' : jsf.replace('.js', '.js.map');
      try {
        const fullUrl = new URL(mapUrl, base).toString();
        const mapRes = await safe(fullUrl);
        if (mapRes.statusCode === 200 && mapRes.body.includes('mappings')) {
          findings.push(generateFinding({
            title: 'Source Map Exposed — Source Code Disclosure',
            description: `A JavaScript source map file is publicly accessible at ${mapUrl}. This allows anyone to reconstruct the original source code from the minified/bundled JavaScript, exposing business logic, API endpoints, and potential vulnerabilities.`,
            severity: Severity.MEDIUM,
            category: 'Supply Chain Security',
            affectedAsset: fullUrl,
            evidence: `GET ${mapUrl} → HTTP ${mapRes.statusCode}, contains source mappings`,
            impact: 'Full source code disclosure enables attackers to audit the codebase for vulnerabilities, discover hidden API endpoints, and understand authentication mechanisms.',
            remediation: 'Remove source maps from production builds. Configure build tools to not generate source maps for production, or restrict access via authentication.',
            references: ['https://cwe.mitre.org/data/definitions/200.html'],
          }));
          break;
        }
      } catch {}
    }
  }

  // 4) CDN / third-party dependency integrity (Subresource Integrity)
  if (jsRes.statusCode === 200) {
    const sriRe = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let sm;
    const cdnScripts: string[] = [];
    while ((sm = sriRe.exec(jsRes.body)) !== null && cdnScripts.length < 10) {
      const src = sm[1];
      if (src.startsWith('http') && !src.includes(domain)) cdnScripts.push(src);
    }
    const hasIntegrity = /integrity\s*=\s*["']sha/i.test(jsRes.body);
    if (cdnScripts.length > 0 && !hasIntegrity) {
      findings.push(generateFinding({
        title: 'Third-Party Scripts Loaded Without Subresource Integrity (SRI)',
        description: `The page loads ${cdnScripts.length} external script(s) from third-party CDNs without Subresource Integrity (SRI) hashes: ${cdnScripts.slice(0, 3).join(', ')}${cdnScripts.length > 3 ? '...' : ''}. If a CDN is compromised, malicious code will execute in users\' browsers.`,
        severity: Severity.MEDIUM,
        category: 'Supply Chain Security',
        affectedAsset: base,
        evidence: `External scripts without integrity attribute:\n${cdnScripts.map(s => `  - ${s}`).join('\n')}`,
        impact: 'A compromised CDN or man-in-the-middle attack can inject malicious JavaScript into the application, leading to data theft, session hijacking, or malware distribution.',
        remediation: 'Add SRI hashes (integrity="sha256-...") to all third-party script and link tags. Use a CSP header with script-src to restrict allowed sources.',
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
          'https://cwe.mitre.org/data/definitions/829.html',
        ],
      }));
    }
  }

  // 5) SRI hashes present but use weak algorithms (sha-1)
  if (jsRes.body.includes('integrity=')) {
    const sriWeak = /integrity\s*=\s*["']sha-1-/i.test(jsRes.body);
    if (sriWeak) {
      findings.push(generateFinding({
        title: 'Weak SRI Hash Algorithm (SHA-1)',
        description: 'The page uses SHA-1 based Subresource Integrity hashes, which are cryptographically weak and can be collision-attacked. SHA-256 or stronger should be used.',
        severity: Severity.LOW,
        category: 'Supply Chain Security',
        affectedAsset: base,
        evidence: 'Page contains integrity attributes using sha-1- prefix',
        impact: 'SHA-1 collisions can be generated, potentially allowing an attacker to serve a malicious file that passes SRI validation.',
        remediation: 'Replace SHA-1 SRI hashes with SHA-256 or SHA-384: integrity="sha256-..."',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
      }));
    }
  }

  return { module: 'supplyChain', findings, duration: 0, errors };
}
