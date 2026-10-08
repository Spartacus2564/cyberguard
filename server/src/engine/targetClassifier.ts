import { ScanResult, ScanModule } from '../types';
import logger from '../utils/logger';

// ─── TARGET CLASSIFICATION ────────────────────────────────────────────────────
// After Phase 1 recon, this determines WHAT the target is so we only run
// relevant attack modules. A real pentester does exactly this:
//   "Oh, this is a WordPress site with SSH open — I'll focus on web + SSH,
//    not on Active Directory."
// ──────────────────────────────────────────────────────────────────────────────

export type TargetType = 'web' | 'activeDirectory' | 'linux' | 'windows' | 'network' | 'mixed';

export interface TargetClassification {
  primary: TargetType;
  confidence: number;
  reasons: string[];
  services: DetectedService[];
  webTech: string[];
  osGuess: string | null;
  hasAD: boolean;
  hasWeb: boolean;
  hasSSH: boolean;
  hasSMB: boolean;
  hasRDP: boolean;
  hasLDAP: boolean;
  hasKerberos: boolean;
  hasWinRM: boolean;
  hasMSSQL: boolean;
  hasMySQL: boolean;
  hasPostgreSQL: boolean;
  hasRedis: boolean;
  openPorts: number[];
  recommendedModules: ScanModule[];
  excludedModules: ScanModule[];
}

export interface DetectedService {
  port: number;
  protocol: string;
  service: string;
  version?: string;
  banner?: string;
  host: string;
}

// ─── SERVICE SIGNATURES ──────────────────────────────────────────────────────
// Maps port numbers and banner patterns to service types

const PORT_SERVICE_MAP: Record<number, string> = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  80: 'http', 88: 'kerberos', 110: 'pop3', 111: 'rpcbind',
  135: 'msrpc', 139: 'netbios', 143: 'imap', 389: 'ldap',
  443: 'https', 445: 'smb', 464: 'kpasswd', 587: 'submission',
  636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1433: 'mssql',
  1434: 'mssql-m', 1521: 'oracle', 2049: 'nfs', 3000: 'http-alt',
  3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5601: 'kibana',
  5900: 'vnc', 5985: 'winrm', 5986: 'winrm-ssl', 6379: 'redis',
  6660: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt',
  8888: 'http-alt', 9090: 'http-alt', 9200: 'elasticsearch',
  9443: 'https-alt', 11211: 'memcached', 27017: 'mongodb',
};

const AD_PORTS = [88, 135, 139, 389, 445, 464, 636, 3268, 3269];
const WEB_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090];
const LINUX_PORTS = [22, 21, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017];
const WINDOWS_PORTS = [135, 139, 445, 3389, 5985, 5986, 1433, 995];

// ─── BANNER / RESPONSE ANALYSIS ──────────────────────────────────────────────

function analyzeBanner(banner: string): { os?: string; service?: string; version?: string } {
  const lower = banner.toLowerCase();
  const result: { os?: string; service?: string; version?: string } = {};

  // OS detection from banners
  if (/ubuntu|debian|centos|redhat|fedora|opensuse|arch/i.test(lower)) result.os = 'linux';
  if (/windows| microsoft|iis/i.test(lower)) result.os = 'windows';
  if (/openbsd|freebsd|netbsd/i.test(lower)) result.os = 'bsd';
  if (/cisco|juniper|fortinet/i.test(lower)) result.os = 'network';

  // Service detection
  if (/ssh|openssh/i.test(lower)) result.service = 'ssh';
  if (/ftp|vsftpd|proftpd|pure-ftpd/i.test(lower)) result.service = 'ftp';
  if (/apache|nginx|lighttpd|iis|tomcat/i.test(lower)) result.service = 'http';
  if (/mysql|mariadb/i.test(lower)) result.service = 'mysql';
  if (/postgres/i.test(lower)) result.service = 'postgresql';
  if (/redis/i.test(lower)) result.service = 'redis';
  if (/mssql|sql server/i.test(lower)) result.service = 'mssql';
  if (/smb|samba|netbios/i.test(lower)) result.service = 'smb';
  if (/ldap|active directory/i.test(lower)) result.service = 'ldap';
  if (/kerberos/i.test(lower)) result.service = 'kerberos';

  // Version extraction
  const versionMatch = banner.match(/(\d+\.\d+(?:\.\d+)?)/);
  if (versionMatch) result.version = versionMatch[1];

  return result;
}

function analyzeHttpResponse(headers: Record<string, string>, body: string): string[] {
  const tech: string[] = [];
  const combined = JSON.stringify(headers).toLowerCase() + ' ' + body.substring(0, 5000).toLowerCase();

  // Server header
  const server = headers['server'] || '';
  if (/apache/i.test(server)) tech.push('Apache');
  if (/nginx/i.test(server)) tech.push('Nginx');
  if (/iis/i.test(server)) tech.push('IIS');
  if (/cloudflare/i.test(server)) tech.push('Cloudflare');
  if (/openresty/i.test(server)) tech.push('OpenResty');
  if (/lighttpd/i.test(server)) tech.push('Lighttpd');

  // X-Powered-By
  const powered = headers['x-powered-by'] || '';
  if (/php/i.test(powered)) tech.push('PHP');
  if (/express/i.test(powered)) tech.push('Node.js/Express');
  if (/asp\.net/i.test(powered)) tech.push('ASP.NET');
  if (/perl/i.test(powered)) tech.push('Perl');
  if (/python|wsgi|gunicorn|uvicorn/i.test(powered)) tech.push('Python');

  // Body analysis
  if (/wordpress|wp-content|wp-includes/i.test(combined)) tech.push('WordPress');
  if (/drupal/i.test(combined)) tech.push('Drupal');
  if (/joomla/i.test(combined)) tech.push('Joomla');
  if (/shopify/i.test(combined)) tech.push('Shopify');
  if (/laravel/i.test(combined)) tech.push('Laravel');
  if (/django/i.test(combined)) tech.push('Django');
  if (/rails|ruby/i.test(combined)) tech.push('Ruby on Rails');
  if (/spring|java/i.test(combined)) tech.push('Java/Spring');
  if (/react|next\.js/i.test(combined)) tech.push('React/Next.js');
  if (/vue|nuxt/i.test(combined)) tech.push('Vue/Nuxt');
  if (/angular/i.test(combined)) tech.push('Angular');
  if (/jquery/i.test(combined)) tech.push('jQuery');
  if (/bootstrap/i.test(combined)) tech.push('Bootstrap');
  if (/tailwind/i.test(combined)) tech.push('Tailwind');
  if (/graphql/i.test(combined)) tech.push('GraphQL');
  if (/swagger|openapi/i.test(combined)) tech.push('OpenAPI/Swagger');

  return [...new Set(tech)];
}

// ─── MAIN CLASSIFIER ─────────────────────────────────────────────────────────

export function classifyTarget(
  domain: string,
  reconResults: ScanResult[],
  portScanResults?: ScanResult,
): TargetClassification {
  const reasons: string[] = [];
  const services: DetectedService[] = [];
  const openPorts: number[] = [];
  let hasAD = false, hasWeb = false, hasSSH = false, hasSMB = false;
  let hasRDP = false, hasLDAP = false, hasKerberos = false, hasWinRM = false;
  let hasMSSQL = false, hasMySQL = false, hasPostgreSQL = false, hasRedis = false;
  const webTech: string[] = [];
  let osGuess: string | null = null;

  // 1) Analyze port scan results
  if (portScanResults) {
    for (const f of portScanResults.findings) {
      const portMatch = f.affectedAsset.match(/:(\d+)/);
      if (!portMatch) continue;
      const port = parseInt(portMatch[1]);
      openPorts.push(port);

      const serviceGuess = f.description?.match(/Service:\s*(\S+)/i)?.[1] || PORT_SERVICE_MAP[port] || 'unknown';
      const banner = f.evidence || '';
      const bannerInfo = analyzeBanner(banner);

      services.push({
        port,
        protocol: 'tcp',
        service: serviceGuess,
        version: bannerInfo.version,
        banner: banner.substring(0, 200),
        host: domain,
      });

      // Classify services
      if (AD_PORTS.includes(port)) { hasAD = true; reasons.push(`AD port ${port} open (${serviceGuess})`); }
      if (WEB_PORTS.includes(port)) { hasWeb = true; reasons.push(`Web port ${port} open`); }
      if (port === 22) { hasSSH = true; reasons.push('SSH open'); }
      if (port === 445 || port === 139) { hasSMB = true; reasons.push('SMB open'); }
      if (port === 3389) { hasRDP = true; reasons.push('RDP open'); }
      if (port === 389 || port === 636 || port === 3268) { hasLDAP = true; reasons.push('LDAP open'); }
      if (port === 88) { hasKerberos = true; reasons.push('Kerberos open'); }
      if (port === 5985 || port === 5986) { hasWinRM = true; reasons.push('WinRM open'); }
      if (port === 1433) { hasMSSQL = true; reasons.push('MSSQL open'); }
      if (port === 3306) { hasMySQL = true; reasons.push('MySQL open'); }
      if (port === 5432) { hasPostgreSQL = true; reasons.push('PostgreSQL open'); }
      if (port === 6379) { hasRedis = true; reasons.push('Redis open'); }

      // OS guessing from banners
      if (bannerInfo.os && !osGuess) osGuess = bannerInfo.os;
    }
  }

  // 2) Analyze recon results for web technology
  const techResult = reconResults.find(r => r.module === 'technology');
  if (techResult) {
    for (const f of techResult.findings) {
      const tech = analyzeHttpResponse({}, f.description + ' ' + f.evidence);
      webTech.push(...tech);
    }
    if (webTech.length > 0) {
      hasWeb = true;
      reasons.push(`Web technologies detected: ${webTech.slice(0, 3).join(', ')}`);
    }
  }

  // 3) Analyze headers for web
  const headerResult = reconResults.find(r => r.module === 'headers');
  if (headerResult && headerResult.findings.length > 0) {
    hasWeb = true;
    reasons.push('HTTP security headers present (web server confirmed)');
  }

  // 4) Analyze TLS for web
  const tlsResult = reconResults.find(r => r.module === 'tls');
  if (tlsResult && tlsResult.findings.length > 0) {
    hasWeb = true;
    reasons.push('TLS certificate found (HTTPS confirmed)');
  }

  // 5) Analyze DNS for AD indicators
  const dnsResult = reconResults.find(r => r.module === 'dns');
  if (dnsResult) {
    for (const f of dnsResult.findings) {
      const desc = (f.description + ' ' + f.evidence).toLowerCase();
      if (/kerberos|kdc|ldap|srv|ad\./i.test(desc)) {
        hasAD = true;
        reasons.push('DNS AD indicators found');
      }
    }
  }

  // 6) Determine primary target type and confidence
  let primary: TargetType = 'network';
  let confidence = 0.5;

  const adScore = (hasLDAP ? 3 : 0) + (hasKerberos ? 3 : 0) + (hasSMB ? 2 : 0) + (hasWinRM ? 2 : 0);
  const webScore = (hasWeb ? 3 : 0) + (webTech.length > 0 ? 2 : 0);
  const linuxScore = (hasSSH ? 2 : 0) + (hasMySQL ? 1 : 0) + (hasPostgreSQL ? 1 : 0) + (hasRedis ? 1 : 0);
  const windowsScore = (hasRDP ? 3 : 0) + (hasWinRM ? 3 : 0) + (hasMSSQL ? 2 : 0) + (hasSMB ? 1 : 0);

  if (osGuess === 'linux') {
    reasons.push('OS fingerprint suggests Linux');
  } else if (osGuess === 'windows') {
    reasons.push('OS fingerprint suggests Windows');
  }

  const scores = { activeDirectory: adScore, web: webScore, linux: linuxScore + (osGuess === 'linux' ? 2 : 0), windows: windowsScore + (osGuess === 'windows' ? 2 : 0) };
  const maxScore = Math.max(...Object.values(scores), 1);

  if (adScore >= 4) {
    primary = 'activeDirectory';
    confidence = Math.min(0.95, 0.6 + (adScore / maxScore) * 0.35);
    reasons.push(`Strong AD indicators (${adScore} points)`);
  } else if (windowsScore >= 4 || (osGuess === 'windows' && windowsScore >= 2)) {
    primary = 'windows';
    confidence = Math.min(0.9, 0.5 + (windowsScore / maxScore) * 0.4);
    reasons.push(`Windows target detected (${windowsScore} points)`);
  } else if (webScore >= 3) {
    primary = 'web';
    confidence = Math.min(0.95, 0.6 + (webScore / maxScore) * 0.35);
    reasons.push(`Web application detected (${webScore} points)`);
  } else if (linuxScore >= 2 || osGuess === 'linux') {
    primary = 'linux';
    confidence = Math.min(0.9, 0.5 + (linuxScore / maxScore) * 0.4);
    reasons.push(`Linux target detected (${linuxScore} points)`);
  } else if (openPorts.length > 0) {
    primary = 'network';
    confidence = 0.6;
    reasons.push(`${openPorts.length} open ports detected`);
  }

  // Mixed: if multiple categories score highly
  if ((adScore >= 3 && webScore >= 3) || (linuxScore >= 2 && webScore >= 3)) {
    primary = 'mixed';
    confidence = 0.7;
    reasons.push('Mixed target — multiple service types detected');
  }

  // 7) Select recommended modules based on classification
  const recommendedModules = selectModules(primary, { hasWeb, hasAD, hasSSH, hasSMB, hasRDP, hasLDAP, hasKerberos, hasWinRM, hasMSSQL, hasMySQL, hasPostgreSQL, hasRedis, webTech, openPorts });
  const allModules: ScanModule[] = ['dns', 'tls', 'headers', 'webConfig', 'technology', 'subdomains', 'emailSecurity', 'portScan', 'cveCorrelation', 'activeVuln', 'dnsDeep', 'tlsDeep', 'osFingerprint', 'subdomainTakeover', 'siteCrawl', 'serviceAudit', 'advancedAttacks', 'brokenAuth', 'httpMethods', 'apiSecurity', 'supplyChain', 'cloudSecurity', 'clientSecurity', 'kaliTools', 'businessLogic', 'activeDirectory', 'networkPentest', 'windowsSystem', 'linuxSystem'];
  const excludedModules = allModules.filter(m => !recommendedModules.includes(m));

  logger.info(`[Classifier] ${domain}: primary=${primary} confidence=${confidence.toFixed(2)} services=${services.length} reasons=${reasons.length}`);

  return {
    primary,
    confidence,
    reasons,
    services,
    webTech: [...new Set(webTech)],
    osGuess,
    hasAD, hasWeb, hasSSH, hasSMB, hasRDP, hasLDAP, hasKerberos, hasWinRM,
    hasMSSQL, hasMySQL, hasPostgreSQL, hasRedis,
    openPorts: [...new Set(openPorts)].sort((a, b) => a - b),
    recommendedModules,
    excludedModules,
  };
}

// ─── MODULE SELECTION ────────────────────────────────────────────────────────
// Based on target type, select ONLY relevant modules.
// This is what makes the scanner smart — it doesn't run AD modules on a
// WordPress site, and doesn't run WordPress modules on a Linux server.

interface ServiceFlags {
  hasWeb: boolean;
  hasAD: boolean;
  hasSSH: boolean;
  hasSMB: boolean;
  hasRDP: boolean;
  hasLDAP: boolean;
  hasKerberos: boolean;
  hasWinRM: boolean;
  hasMSSQL: boolean;
  hasMySQL: boolean;
  hasPostgreSQL: boolean;
  hasRedis: boolean;
  webTech: string[];
  openPorts: number[];
}

function selectModules(primary: TargetType, flags: ServiceFlags): ScanModule[] {
  const modules = new Set<ScanModule>();

  // ── UNIVERSAL: Always run recon on any target ──
  modules.add('dns');
  modules.add('portScan');
  modules.add('osFingerprint');

  // ── WEB TARGET ──
  if (primary === 'web' || primary === 'mixed' || flags.hasWeb) {
    // Core web recon
    modules.add('tls');
    modules.add('tlsDeep');
    modules.add('headers');
    modules.add('webConfig');
    modules.add('technology');
    modules.add('subdomains');
    modules.add('emailSecurity');
    modules.add('dnsDeep');

    // Web attacks
    modules.add('activeVuln');
    modules.add('siteCrawl');
    modules.add('advancedAttacks');
    modules.add('brokenAuth');
    modules.add('httpMethods');
    modules.add('apiSecurity');
    modules.add('businessLogic');
    modules.add('clientSecurity');

    // Web infrastructure
    modules.add('subdomainTakeover');
    modules.add('supplyChain');
    modules.add('cloudSecurity');
    modules.add('serviceAudit');

    // CVE correlation for detected technologies
    modules.add('cveCorrelation');

    // New modules (Feature #1-8)
    modules.add('liveCve');          // Real-time CVE intelligence
    modules.add('modernAttacks');    // JWT/OAuth/Smuggling/IDOR/GraphQL
    modules.add('behavioral');       // Behavioral anomaly detection
    modules.add('supplyChainIntel'); // JS bundle + source map + SRI
    modules.add('sourceAnalysis');   // Secrets + git + CI/CD exposure
    modules.add('exploitChain');     // Multi-vuln chain validation

    // External tools for web
    modules.add('kaliTools');
  }

  // ── ACTIVE DIRECTORY TARGET ──
  if (primary === 'activeDirectory' || (flags.hasAD && (primary === 'mixed' || primary === 'windows'))) {
    modules.add('activeDirectory');
    modules.add('networkPentest');

    // If web is also present, add web modules
    if (flags.hasWeb || primary === 'mixed') {
      modules.add('tls');
      modules.add('tlsDeep');
      modules.add('headers');
      modules.add('webConfig');
      modules.add('technology');
      modules.add('activeVuln');
      modules.add('kaliTools');
    }
  }

  // ── WINDOWS TARGET ──
  if (primary === 'windows' || (flags.hasSMB && !flags.hasAD)) {
    modules.add('windowsSystem');
    modules.add('networkPentest');

    // Windows often has web services too
    if (flags.hasWeb) {
      modules.add('tls');
      modules.add('tlsDeep');
      modules.add('headers');
      modules.add('webConfig');
      modules.add('technology');
      modules.add('activeVuln');
      modules.add('kaliTools');
    }
  }

  // ── LINUX TARGET ──
  if (primary === 'linux') {
    modules.add('linuxSystem');
    modules.add('networkPentest');

    // Linux often has web services
    if (flags.hasWeb) {
      modules.add('tls');
      modules.add('tlsDeep');
      modules.add('headers');
      modules.add('webConfig');
      modules.add('technology');
      modules.add('activeVuln');
      modules.add('kaliTools');
    }

    // Database-specific checks
    if (flags.hasMySQL || flags.hasPostgreSQL || flags.hasRedis) {
      modules.add('serviceAudit');
    }
  }

  // ── NETWORK / UNKNOWN ──
  if (primary === 'network') {
    modules.add('networkPentest');
    modules.add('kaliTools');
    modules.add('serviceAudit');

    // If we found web ports, add web modules
    if (flags.hasWeb) {
      modules.add('tls');
      modules.add('tlsDeep');
      modules.add('headers');
      modules.add('webConfig');
      modules.add('technology');
      modules.add('activeVuln');
      modules.add('siteCrawl');
    }

    // Service-specific
    if (flags.hasSSH) modules.add('linuxSystem');
    if (flags.hasSMB || flags.hasRDP) modules.add('windowsSystem');
    if (flags.hasAD) modules.add('activeDirectory');
  }

  // ── ALWAYS: CVE correlation if we have technology info ──
  if (modules.has('technology') || flags.webTech.length > 0) {
    modules.add('cveCorrelation');
  }

  // ── ALWAYS: Exploitation on every target type ──
  modules.add('exploitation');

  return [...modules].sort((a, b) => {
    // Sort by phase order: recon first, then attacks, then service
    const phaseOrder: Record<string, number> = {
      dns: 1, tls: 2, tlsDeep: 3, headers: 4, webConfig: 5, technology: 6,
      subdomains: 7, emailSecurity: 8, portScan: 9, dnsDeep: 10, osFingerprint: 11,
      activeVuln: 20, siteCrawl: 21, advancedAttacks: 22, brokenAuth: 23,
      httpMethods: 24, apiSecurity: 25, businessLogic: 26, subdomainTakeover: 27,
      clientSecurity: 28, supplyChain: 29, cloudSecurity: 30, serviceAudit: 31,
      cveCorrelation: 32, exploitation: 33,
      deepDiscovery: 34, adaptiveReasoning: 35,
      activeDirectory: 40, networkPentest: 41,
      windowsSystem: 42, linuxSystem: 43, kaliTools: 50,
    };
    return (phaseOrder[a] || 99) - (phaseOrder[b] || 99);
  });
}

// ─── FORMAT CLASSIFICATION FOR LOGGING ────────────────────────────────────────

export function formatClassification(c: TargetClassification): string {
  const lines = [
    `Target Type: ${c.primary.toUpperCase()} (confidence: ${(c.confidence * 100).toFixed(0)}%)`,
    `Services: ${c.services.length} detected on ports: ${c.openPorts.join(', ') || 'none'}`,
  ];
  if (c.osGuess) lines.push(`OS Guess: ${c.osGuess}`);
  if (c.webTech.length > 0) lines.push(`Web Tech: ${c.webTech.join(', ')}`);
  lines.push(`Reasons: ${c.reasons.join('; ')}`);
  lines.push(`Modules: ${c.recommendedModules.length} selected, ${c.excludedModules.length} excluded`);
  return lines.join('\n');
}
