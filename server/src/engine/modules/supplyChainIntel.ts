import { ScanResult, Finding, Severity, ScanModule } from '../../types';
import { generateFinding, fetchUrl } from './shared';
import { logExploit, logInfo } from '../scanLogger';

const MODULE = 'supplyChainIntel';

// Regex patterns for JavaScript bundle analysis
const API_KEY_RE = /api[_-]?key['":\s]*[=:]['"]\s*['"][a-zA-Z0-9]{20,}/;
const TOKEN_RE = /token['":\s]*[=:]['"]\s*['"][a-zA-Z0-9]{20,}/;
const SECRET_RE = /secret['":\s]*[=:]['"]\s*['"][a-zA-Z0-9]{20,}/;
const INTERNAL_URL_RE = /https?:\/\/(?:10\.|172\.(?:1[6-9]|2|3[01])\.|192\.168\.|localhost|127\.0\.0\.1)/;
const CRED_RE = /password['":\s]*[=:]['"]\s*['"][^'"]{6,}/;
const DEBUG_RE = /debug['":\s]*[=:]\s*true|console\.(log|debug|warn)|DEBUG\s*[=:]\s*true/;

// Known malicious third-party domains (abbreviated list)
const KNOWN_MALICIOUS_DOMAINS: ReadonlySet<string> = new Set([
  'websecuritytool.com',
  'pastebin.com',
  'raw.githubusercontent.com',
]);

const MAX_JS_FILES = 10;
const MAX_BODY_BYTES = 1048576;

interface JsBundleResult {
  fileUrl: string;
  exposedKeys: string[];
  internalUrls: string[];
  hardcodedCredentials: string[];
  debugIndicators: string[];
  hasSourceMap: boolean;
}

interface ThirdPartyDomain {
  domain: string;
  urls: string[];
  hasIntegrity: boolean;
  setsCookies: boolean;
}

// ---------------------------------------------------------------------------
// Helper: safe HTTP GET with timeout
// ---------------------------------------------------------------------------
async function safeGet(
  targetUrl: string,
  timeoutMs: number = 10000,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  try {
    const res = await fetchUrl(targetUrl, timeoutMs, MODULE);
    const hdrs: Record<string, string> = {};
    for (const [k, v] of Object.entries(res.headers)) {
      if (typeof v === 'string') hdrs[k] = v;
      else if (Array.isArray(v)) hdrs[k] = v.join(', ');
    }
    return { status: res.statusCode, headers: hdrs, body: res.body };
  } catch {
    return { status: 0, headers: {}, body: '' };
  }
}

// ---------------------------------------------------------------------------
// 1. JavaScript Bundle Analysis
// ---------------------------------------------------------------------------
async function testJsBundleAnalysis(domain: string, homepageHtml: string): Promise<JsBundleResult[]> {
  const results: JsBundleResult[] = [];
  const base = `https://${domain}`;

  // Extract JS file URLs from script tags and inline references
  const scriptRe = /<script[^>]+src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
  const jsUrls: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = scriptRe.exec(homepageHtml)) !== null && jsUrls.length < MAX_JS_FILES) {
    const src = match[1];
    try {
      const resolved = new URL(src, base).toString();
      jsUrls.push(resolved);
    } catch { /* skip malformed */ }
  }

  // Also check for source map references in the HTML
  const mapRe = /["']([^"']+\.js\.map)["']/gi;
  while ((match = mapRe.exec(homepageHtml)) !== null && jsUrls.length < MAX_JS_FILES) {
    const src = match[1];
    try {
      const resolved = new URL(src, base).toString();
      if (!jsUrls.includes(resolved)) jsUrls.push(resolved);
    } catch { /* skip malformed */ }
  }

  for (const jsUrl of jsUrls) {
    const { status, body } = await safeGet(jsUrl);
    if (status !== 200 || body.length === 0) continue;

    const exposedKeys: string[] = [];
    const internalUrls: string[] = [];
    const hardcodedCredentials: string[] = [];
    const debugIndicators: string[] = [];

    if (API_KEY_RE.test(body)) exposedKeys.push('API key');
    if (TOKEN_RE.test(body)) exposedKeys.push('token');
    if (SECRET_RE.test(body)) exposedKeys.push('secret');

    const internalMatches = body.match(INTERNAL_URL_RE);
    if (internalMatches) internalUrls.push(internalMatches[0]);

    const credMatch = body.match(CRED_RE);
    if (credMatch) hardcodedCredentials.push(credMatch[0].substring(0, 80));

    const debugMatch = body.match(DEBUG_RE);
    if (debugMatch) debugIndicators.push(debugMatch[0].substring(0, 60));

    const hasSourceMap = /[#@]\s*sourceMappingURL\s*=\s*["']?([^\s"']+)/.test(body);

    results.push({
      fileUrl: jsUrl,
      exposedKeys,
      internalUrls,
      hardcodedCredentials,
      debugIndicators,
      hasSourceMap,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// 2. Source Map Exposure
// ---------------------------------------------------------------------------
async function testSourceMapExposure(
  domain: string,
  jsBundles: JsBundleResult[],
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  for (const bundle of jsBundles) {
    // Derive map URL from JS URL
    let mapUrl = bundle.fileUrl;
    if (mapUrl.endsWith('.js')) {
      mapUrl += '.map';
    } else {
      mapUrl = mapUrl.replace(/\.js(\?.*)$/, '.js.map$1');
    }

    const { status, body } = await safeGet(mapUrl);
    if (status !== 200 || body.length === 0) continue;

    // Verify it is actually a source map
    if (!body.includes('"mappings"') && !body.includes('"sources"')) continue;

    const evidenceLines: string[] = [`Source map accessible at: ${mapUrl}`];

    // Check for internal file paths
    const pathMatches = body.match(/"sources"\s*:\s*\[([^\]]+)\]/);
    if (pathMatches) {
      const srcSnippet = pathMatches[1].substring(0, 300);
      evidenceLines.push(`Internal paths exposed: ${srcSnippet}`);
    }

    // Check for comments with sensitive info
    const commentRe = /\/\/.*(?:password|secret|key|token|TODO|FIXME|HACK|XXX).*$/gim;
    const sensitiveComments = body.match(commentRe);
    if (sensitiveComments && sensitiveComments.length > 0) {
      evidenceLines.push(`Sensitive comments found: ${sensitiveComments.slice(0, 3).join(' | ')}`);
    }

    logExploit(MODULE, 'Source Map Exposure', mapUrl);

    findings.push(generateFinding({
      title: 'JavaScript Source Map Exposed',
      description: `A source map file is publicly accessible at ${mapUrl}. Attackers can reconstruct the original, unminified source code from the bundled JavaScript, exposing business logic, internal API endpoints, and potential vulnerabilities.`,
      severity: Severity.MEDIUM,
      category: 'Supply Chain Security',
      affectedAsset: mapUrl,
      evidence: evidenceLines.join('\n'),
      impact: 'Full source code disclosure enables attackers to audit the codebase, discover hidden API endpoints, and understand authentication or authorization logic.',
      remediation: 'Remove source maps from production builds. If source maps are needed for error tracking, serve them behind authentication or restrict by IP.',
      references: ['https://cwe.mitre.org/data/definitions/200.html'],
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 3. Package Ecosystem Detection
// ---------------------------------------------------------------------------
async function testPackageDetection(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  const manifests: ReadonlyArray<{ path: string; name: string; isLock: boolean }> = [
    { path: '/package.json', name: 'package.json', isLock: false },
    { path: '/package-lock.json', name: 'package-lock.json', isLock: true },
    { path: '/yarn.lock', name: 'yarn.lock', isLock: true },
    { path: '/pnpm-lock.yaml', name: 'pnpm-lock.yaml', isLock: true },
    { path: '/requirements.txt', name: 'requirements.txt', isLock: false },
    { path: '/Pipfile.lock', name: 'Pipfile.lock', isLock: true },
    { path: '/Gemfile.lock', name: 'Gemfile.lock', isLock: true },
    { path: '/go.sum', name: 'go.sum', isLock: true },
    { path: '/pom.xml', name: 'pom.xml', isLock: false },
    { path: '/build.gradle', name: 'build.gradle', isLock: false },
  ];

  const exposedManifests: string[] = [];
  const exposedLocks: string[] = [];

  for (const m of manifests) {
    const { status, body } = await safeGet(base + m.path);
    if (status === 200 && body.length > 10) {
      if (m.isLock) {
        exposedLocks.push(m.name);
      } else {
        exposedManifests.push(m.name);
      }

      // Extract version info for known lock files
      if (m.name === 'package-lock.json') {
        const pkgRe = /"node_modules\/([^"]+)":\s*\{[^}]*"version":\s*"([^"]+)"/g;
        const vulnPkgRe = /"node_modules\/(lodash|express|request|axios|minimist|glob-parent|yargs-parser|ini|node-fetch|elliptic|plist|xml2js|tar|underscore)":\s*\{[^}]*"version":\s*"([^"]+)"/g;
        const vulnerablePkgs: string[] = [];
        let pkgMatch: RegExpExecArray | null;
        while ((pkgMatch = vulnPkgRe.exec(body)) !== null) {
          vulnerablePkgs.push(`${pkgMatch[1]}@${pkgMatch[2]}`);
        }
        if (vulnerablePkgs.length > 0) {
          logExploit(MODULE, 'Vulnerable Packages Detected', base + m.path, vulnerablePkgs.join(', '));
          findings.push(generateFinding({
            title: 'Potentially Vulnerable Packages in Lock File',
            description: `The package-lock.json contains packages with known vulnerability patterns: ${vulnerablePkgs.join(', ')}. Manual verification against CVE databases is recommended.`,
            severity: Severity.LOW,
            category: 'Supply Chain Security',
            affectedAsset: base + m.path,
            evidence: `Exposed lock file with ${body.length} bytes. Potential vulnerable packages: ${vulnerablePkgs.join(', ')}`,
            impact: 'Known vulnerable dependencies may allow exploitation through public CVEs.',
            remediation: 'Run npm audit or equivalent tool to identify and remediate vulnerable dependencies. Implement automated dependency scanning in CI/CD.',
            references: ['https://owasp.org/www-project-dependency-check/'],
          }));
        }
      }
    }
  }

  if (exposedManifests.length > 0 || exposedLocks.length > 0) {
    findings.push(generateFinding({
      title: `Package Ecosystem Files Exposed: ${[...exposedManifests, ...exposedLocks].join(', ')}`,
      description: `Dependency manifest and lock files are publicly accessible (${[...exposedManifests, ...exposedLocks].join(', ')}). These files reveal exact dependency versions, enabling attackers to identify known vulnerable packages and enumerate the technology stack.`,
      severity: Severity.MEDIUM,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: `Exposed manifests: ${exposedManifests.join(', ') || 'none'}\nExposed lock files: ${exposedLocks.join(', ') || 'none'}`,
      impact: 'Attackers can enumerate exact dependency versions, cross-reference with CVE databases, and target known vulnerabilities in specific package versions.',
      remediation: 'Block public access to package manifest and lock files via web server configuration. Ensure CI/CD pipelines do not deploy these files to production.',
      references: ['https://owasp.org/www-project-dependency-check/'],
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 4. SRI Hash Verification
// ---------------------------------------------------------------------------
async function testSriVerification(
  domain: string,
  homepageHtml: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  // Find all external script tags
  const scriptRe = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
  const externalScripts: Array<{ url: string; hasIntegrity: boolean }> = [];
  let match: RegExpExecArray | null;

  while ((match = scriptRe.exec(homepageHtml)) !== null) {
    const src = match[1];
    const tag = match[0];
    const hasIntegrity = /integrity\s*=\s*["']sha/i.test(tag);

    try {
      const parsed = new URL(src, base);
      if (parsed.hostname !== domain) {
        externalScripts.push({ url: parsed.toString(), hasIntegrity });
      }
    } catch { /* skip malformed */ }
  }

  // Find all external link tags (CSS)
  const linkRe = /<link[^>]+href\s*=\s*["']([^"']+\.css(?:\?[^"']*)?)["'][^>]*>/gi;
  while ((match = linkRe.exec(homepageHtml)) !== null) {
    const href = match[1];
    const tag = match[0];
    const hasIntegrity = /integrity\s*=\s*["']sha/i.test(tag);

    try {
      const parsed = new URL(href, base);
      if (parsed.hostname !== domain) {
        externalScripts.push({ url: parsed.toString(), hasIntegrity });
      }
    } catch { /* skip malformed */ }
  }

  const missingSri = externalScripts.filter(s => !s.hasIntegrity);
  if (missingSri.length > 0) {
    findings.push(generateFinding({
      title: 'External Resources Missing Subresource Integrity (SRI)',
      description: `${missingSri.length} external resource(s) are loaded without SRI hashes: ${missingSri.slice(0, 3).map(s => s.url).join(', ')}${missingSri.length > 3 ? '...' : ''}. A compromised CDN or man-in-the-middle attack could inject malicious code.`,
      severity: Severity.MEDIUM,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: `External resources without integrity attribute:\n${missingSri.map(s => `  - ${s.url}`).join('\n')}`,
      impact: 'A compromised CDN or MITM attack can inject malicious JavaScript/CSS into the application.',
      remediation: 'Add SRI hashes (integrity="sha256-...") to all third-party script and link tags. Use a CSP header with script-src to restrict allowed sources.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    }));
  }

  // Verify existing SRI hashes
  const sriScripts = externalScripts.filter(s => s.hasIntegrity);
  for (const sri of sriScripts.slice(0, 5)) {
    const { status } = await safeGet(sri.url);
    if (status !== 200) {
      findings.push(generateFinding({
        title: 'SRI-Protected Resource Unavailable',
        description: `An external resource loaded with SRI integrity checks returned HTTP ${status} when fetched: ${sri.url}. If the resource is genuinely unavailable, the page will fail to render. If it is available but unreachable from our scanner, the SRI hash may still be valid.`,
        severity: Severity.LOW,
        category: 'Supply Chain Security',
        affectedAsset: sri.url,
        evidence: `GET ${sri.url} returned HTTP ${status}`,
        impact: 'A broken external resource reference may cause functional degradation or could indicate CDN issues.',
        remediation: 'Ensure external resource URLs are correct and accessible. Consider self-hosting critical resources.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
      }));
    }
  }

  // Check for weak SRI algorithms
  const weakSriRe = /integrity\s*=\s*["']sha-1-/i;
  if (weakSriRe.test(homepageHtml)) {
    findings.push(generateFinding({
      title: 'Weak SRI Hash Algorithm (SHA-1)',
      description: 'The page uses SHA-1 based Subresource Integrity hashes, which are cryptographically weak and can be collision-attacked.',
      severity: Severity.LOW,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: 'Page contains integrity attributes using sha-1- prefix',
      impact: 'SHA-1 collisions can be generated, potentially allowing an attacker to serve a malicious file that passes SRI validation.',
      remediation: 'Replace SHA-1 SRI hashes with SHA-256 or SHA-384: integrity="sha256-..."',
      references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 5. Dependency Confusion Indicators
// ---------------------------------------------------------------------------
async function testDependencyConfusion(
  domain: string,
  homepageHtml: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  // Check for private package registry URLs in page source
  const registryRe = /(?:registry|npm|packages?\.(?:github|gitlab|bitbucket))\s*[:=]\s*["']([^"']+)["']/gi;
  const privateRegistryRe = /(?:https?:\/\/)?(?:npm\.private|registry\.(?:internal|local|corp)|packages?\.(?:internal|local|corp))/gi;

  const privateRegistries: string[] = [];
  let match: RegExpExecArray | null;

  while ((match = privateRegistryRe.exec(homepageHtml)) !== null) {
    privateRegistries.push(match[0]);
  }

  // Also check for scoped packages (@company/) that could be targeted
  const scopedPkgRe = /@([a-zA-Z0-9_-]+)\//g;
  const scopedPackages: string[] = [];
  const seenScopes = new Set<string>();
  while ((match = scopedPkgRe.exec(homepageHtml)) !== null) {
    const scope = match[1].toLowerCase();
    if (!seenScopes.has(scope) && !['types', 'angular', 'babel', 'emotion', 'mui', 'aws-cdk'].includes(scope)) {
      seenScopes.add(scope);
      scopedPackages.push(`@${scope}/`);
    }
  }

  if (privateRegistries.length > 0) {
    logExploit(MODULE, 'Private Registry URL Detected', domain, privateRegistries.join(', '));
    findings.push(generateFinding({
      title: 'Private Package Registry URL Exposed',
      description: `The page source contains references to private/internal package registry URLs: ${privateRegistries.join(', ')}. These URLs could be targeted for dependency confusion attacks.`,
      severity: Severity.HIGH,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: `Private registry references found:\n${privateRegistries.map(r => `  - ${r}`).join('\n')}`,
      impact: 'Attackers can publish malicious packages with the same names as private packages to public registries, potentially causing the build system to install the malicious version.',
      remediation: 'Use scoped packages with clear naming conventions. Configure package managers to prioritize private registries. Use lock files to pin exact versions.',
      references: ['https://medium.com/@alex.birsan/the-confused-deputy-attack-against-private-packages-a2f3894f8b2b'],
    }));
  }

  if (scopedPackages.length > 0) {
    findings.push(generateFinding({
      title: 'Scoped Private Packages Detected in Source',
      description: `The page source references scoped packages that may be private: ${scopedPackages.slice(0, 10).join(', ')}${scopedPackages.length > 10 ? '...' : ''}. These could be targets for dependency confusion attacks if not properly configured.`,
      severity: Severity.LOW,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: `Scoped packages referenced: ${scopedPackages.join(', ')}`,
      impact: 'Private scoped packages may be vulnerable to dependency confusion if not properly scoped on the registry.',
      remediation: 'Ensure private scoped packages are published only to private registries. Use lock files and verify package checksums.',
      references: ['https://medium.com/@alex.birsan/the-confused-deputy-attack-against-private-packages-a2f3894f8b2b'],
    }));
  }

  // Check if lock file is present (dependency confusion risk)
  const lockPaths = ['/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml', '/Pipfile.lock'];
  let lockFileFound = false;
  for (const lp of lockPaths) {
    const { status } = await safeGet(base + lp);
    if (status === 200) {
      lockFileFound = true;
      break;
    }
  }

  if (!lockFileFound) {
    findings.push(generateFinding({
      title: 'No Lock File Found - Dependency Confusion Risk',
      description: 'No package lock file (package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock) was found accessible on the server. Lock files are critical for preventing dependency confusion attacks and ensuring reproducible builds.',
      severity: Severity.MEDIUM,
      category: 'Supply Chain Security',
      affectedAsset: base,
      evidence: `Checked paths: ${lockPaths.join(', ')} - all returned non-200 status`,
      impact: 'Without lock files, dependency resolution is not pinned, increasing risk of dependency confusion attacks and non-reproducible builds.',
      remediation: 'Always commit and deploy lock files alongside application code. Configure CI/CD to use lock files for deterministic builds.',
      references: ['https://medium.com/@alex.birsan/the-confused-deputy-attack-against-private-packages-a2f3894f8b2b'],
    }));
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 6. Third-Party Script Risk
// ---------------------------------------------------------------------------
async function testThirdPartyRisk(
  domain: string,
  homepageHtml: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const base = `https://${domain}`;

  const domainMap = new Map<string, ThirdPartyDomain>();

  // Extract third-party script sources
  const scriptRe = /<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let match: RegExpExecArray | null;

  while ((match = scriptRe.exec(homepageHtml)) !== null) {
    const src = match[1];
    const tag = match[0];
    try {
      const parsed = new URL(src, base);
      if (parsed.hostname === domain) continue;

      const hasIntegrity = /integrity\s*=\s*["']sha/i.test(tag);

      if (!domainMap.has(parsed.hostname)) {
        domainMap.set(parsed.hostname, {
          domain: parsed.hostname,
          urls: [],
          hasIntegrity,
          setsCookies: false,
        });
      }
      const entry = domainMap.get(parsed.hostname)!;
      entry.urls.push(parsed.toString());
      if (hasIntegrity) entry.hasIntegrity = true;
    } catch { /* skip malformed */ }
  }

  // Extract third-party iframe sources
  const iframeRe = /<iframe[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi;
  while ((match = iframeRe.exec(homepageHtml)) !== null) {
    const src = match[1];
    try {
      const parsed = new URL(src, base);
      if (parsed.hostname === domain) continue;

      if (!domainMap.has(parsed.hostname)) {
        domainMap.set(parsed.hostname, {
          domain: parsed.hostname,
          urls: [],
          hasIntegrity: false,
          setsCookies: false,
        });
      }
      domainMap.get(parsed.hostname)!.urls.push(parsed.toString());
    } catch { /* skip malformed */ }
  }

  // Check each third-party domain
  for (const [, entry] of domainMap) {
    // Check for cookies being set
    try {
      const res = await safeGet(entry.urls[0]);
      const setCookie = res.headers['set-cookie'];
      if (setCookie && setCookie.length > 0) {
        entry.setsCookies = true;
      }
    } catch { /* ignore */ }

    // Check known malicious domains
    if (KNOWN_MALICIOUS_DOMAINS.has(entry.domain)) {
      logExploit(MODULE, 'Known Malicious Third-Party Domain', entry.domain);
      findings.push(generateFinding({
        title: `Known Risky Third-Party Domain: ${entry.domain}`,
        description: `The page loads resources from a third-party domain known to pose security risks: ${entry.domain}. Resources loaded from this domain could be used to inject malicious content.`,
        severity: Severity.HIGH,
        category: 'Supply Chain Security',
        affectedAsset: entry.urls[0],
        evidence: `Third-party domain ${entry.domain} is on the known risky domains list. URLs loaded: ${entry.urls.join(', ')}`,
        impact: 'Resources from known risky domains may be compromised or used for malicious purposes including data exfiltration, code injection, or tracking.',
        remediation: 'Remove or replace resources from known risky domains. Self-host critical resources. Implement a strict Content Security Policy.',
        references: ['https://cwe.mitre.org/data/definitions/829.html'],
      }));
    }

    // Check for missing SRI and cookie setting combination
    if (!entry.hasIntegrity && entry.setsCookies) {
      findings.push(generateFinding({
        title: `Third-Party Domain Sets Cookies Without SRI: ${entry.domain}`,
        description: `The third-party domain ${entry.domain} loads resources without Subresource Integrity (SRI) and sets cookies. A compromised resource from this domain could be used for session hijacking or tracking.`,
        severity: Severity.MEDIUM,
        category: 'Supply Chain Security',
        affectedAsset: entry.urls[0],
        evidence: `Domain: ${entry.domain}\nSRI: missing\nCookies: set\nURLs: ${entry.urls.join(', ')}`,
        impact: 'A compromised third-party resource without SRI that also sets cookies can be used to hijack user sessions or track users.',
        remediation: 'Add SRI hashes to all third-party resources. Review whether third-party domains need to set cookies. Use cookie attributes (SameSite, Secure, HttpOnly).',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
      }));
    } else if (!entry.hasIntegrity && entry.urls.length > 0) {
      findings.push(generateFinding({
        title: `Third-Party Script Missing SRI: ${entry.domain}`,
        description: `The page loads ${entry.urls.length} resource(s) from ${entry.domain} without SRI hashes. A compromised CDN or DNS hijack could inject malicious code.`,
        severity: Severity.LOW,
        category: 'Supply Chain Security',
        affectedAsset: entry.urls[0],
        evidence: `Domain: ${entry.domain}\nURLs: ${entry.urls.join(', ')}`,
        impact: 'A compromised third-party resource without SRI can inject arbitrary JavaScript.',
        remediation: 'Add SRI hashes to all third-party resources. Consider self-hosting critical resources.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
      }));
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------
export async function runSupplyChainIntelScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;

  logInfo(MODULE, `Starting supply chain intelligence scan for ${domain}`);

  // Fetch homepage HTML once
  let homepageHtml = '';
  try {
    const { status, body } = await safeGet(base);
    if (status === 200) {
      homepageHtml = body;
    } else {
      // Try HTTP
      const httpResult = await safeGet(`http://${domain}`);
      homepageHtml = httpResult.body;
    }
  } catch (e) {
    errors.push(`Failed to fetch homepage: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 1. JavaScript Bundle Analysis
  try {
    const jsBundles = await testJsBundleAnalysis(domain, homepageHtml);

    for (const bundle of jsBundles) {
      if (bundle.exposedKeys.length > 0) {
        logExploit(MODULE, 'Exposed API Keys in JS Bundle', bundle.fileUrl, bundle.exposedKeys.join(', '));
        findings.push(generateFinding({
          title: 'API Keys/Tokens Exposed in JavaScript Bundle',
          description: `The JavaScript file ${bundle.fileUrl} contains exposed API keys or tokens: ${bundle.exposedKeys.join(', ')}. These credentials can be extracted and abused by attackers.`,
          severity: Severity.HIGH,
          category: 'Supply Chain Security',
          affectedAsset: bundle.fileUrl,
          evidence: `Exposed sensitive values: ${bundle.exposedKeys.join(', ')}`,
          impact: 'Exposed API keys can be used to access protected services, drain quotas, or perform unauthorized actions.',
          remediation: 'Remove hardcoded API keys from client-side code. Use environment variables, server-side proxies, or secure vaults for sensitive credentials.',
          references: ['https://cwe.mitre.org/data/definitions/798.html'],
        }));
      }

      if (bundle.internalUrls.length > 0) {
        findings.push(generateFinding({
          title: 'Internal URLs Exposed in JavaScript Bundle',
          description: `The JavaScript file ${bundle.fileUrl} contains internal/private network URLs: ${bundle.internalUrls.join(', ')}. This exposes internal infrastructure details.`,
          severity: Severity.MEDIUM,
          category: 'Supply Chain Security',
          affectedAsset: bundle.fileUrl,
          evidence: `Internal URLs found: ${bundle.internalUrls.join(', ')}`,
          impact: 'Internal network information disclosure enables attackers to map internal infrastructure and target internal services.',
          remediation: 'Remove internal URLs from client-side code. Use environment-based configuration to inject appropriate URLs at build time.',
          references: ['https://cwe.mitre.org/data/definitions/200.html'],
        }));
      }

      if (bundle.hardcodedCredentials.length > 0) {
        logExploit(MODULE, 'Hardcoded Credentials in JS Bundle', bundle.fileUrl, bundle.hardcodedCredentials.join(', '));
        findings.push(generateFinding({
          title: 'Hardcoded Credentials in JavaScript Bundle',
          description: `The JavaScript file ${bundle.fileUrl} contains hardcoded credentials: ${bundle.hardcodedCredentials.join(', ')}. These can be extracted and used for unauthorized access.`,
          severity: Severity.CRITICAL,
          category: 'Supply Chain Security',
          affectedAsset: bundle.fileUrl,
          evidence: `Hardcoded credentials found: ${bundle.hardcodedCredentials.map(c => c.substring(0, 40) + '...').join(', ')}`,
          impact: 'Hardcoded credentials can be extracted from client-side code and used to gain unauthorized access to backend systems.',
          remediation: 'Remove all hardcoded credentials from client-side code. Use environment variables, secret managers, or server-side authentication flows.',
          references: ['https://cwe.mitre.org/data/definitions/798.html'],
        }));
      }

      if (bundle.debugIndicators.length > 0) {
        findings.push(generateFinding({
          title: 'Debug Mode Indicators in JavaScript Bundle',
          description: `The JavaScript file ${bundle.fileUrl} contains debug mode indicators: ${bundle.debugIndicators.join(', ')}. Debug code may leak sensitive information in production.`,
          severity: Severity.LOW,
          category: 'Supply Chain Security',
          affectedAsset: bundle.fileUrl,
          evidence: `Debug indicators: ${bundle.debugIndicators.join(', ')}`,
          impact: 'Debug code in production may leak sensitive information, internal state, or provide additional attack surface.',
          remediation: 'Strip debug code and console statements from production builds. Use build-time flags to disable debug features.',
          references: ['https://cwe.mitre.org/data/definitions/489.html'],
        }));
      }
    }
  } catch (e) {
    errors.push(`JS bundle analysis failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 2. Source Map Exposure
  try {
    const jsBundles = await testJsBundleAnalysis(domain, homepageHtml);
    const mapFindings = await testSourceMapExposure(domain, jsBundles);
    findings.push(...mapFindings);
  } catch (e) {
    errors.push(`Source map exposure test failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 3. Package Ecosystem Detection
  try {
    const pkgFindings = await testPackageDetection(domain);
    findings.push(...pkgFindings);
  } catch (e) {
    errors.push(`Package detection failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 4. SRI Hash Verification
  try {
    const sriFindings = await testSriVerification(domain, homepageHtml);
    findings.push(...sriFindings);
  } catch (e) {
    errors.push(`SRI verification failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 5. Dependency Confusion Indicators
  try {
    const depFindings = await testDependencyConfusion(domain, homepageHtml);
    findings.push(...depFindings);
  } catch (e) {
    errors.push(`Dependency confusion test failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 6. Third-Party Script Risk
  try {
    const tpFindings = await testThirdPartyRisk(domain, homepageHtml);
    findings.push(...tpFindings);
  } catch (e) {
    errors.push(`Third-party risk test failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  const duration = Date.now() - startTime;
  logInfo(MODULE, `Supply chain intelligence scan completed in ${duration}ms with ${findings.length} findings`);

  return {
    module: 'supplyChainIntel',
    findings,
    duration,
    errors,
  };
}
