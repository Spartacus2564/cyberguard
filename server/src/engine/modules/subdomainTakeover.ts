import * as dns from 'dns';
import * as https from 'https';
import * as http from 'http';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from '../modules/shared';

const resolve4 = promisify(dns.resolve4);
const resolveCname = promisify(dns.resolveCname);
const resolveTxt = promisify(dns.resolveTxt);

// Cloud services that can be hijacked via dangling CNAMEs
interface CloudServiceFingerprint {
  cnamePattern: RegExp;
  name: string;
  vulnerableMessage: string;
  remediation: string;
  verification?: (subdomain: string) => Promise<boolean>;
}

const CLOUD_SERVICES: CloudServiceFingerprint[] = [
  {
    cnamePattern: /\.s3\.amazonaws\.com$/i,
    name: 'AWS S3 Bucket',
    vulnerableMessage: 'Subdomain points to an S3 bucket that may not exist or be properly configured.',
    remediation: 'Verify S3 bucket exists and is configured, or remove the DNS record.',
    verification: async (subdomain: string) => {
      try {
        const bucket = subdomain.split('.')[0];
        const result = await httpGet(`https://${bucket}.s3.amazonaws.com/`);
        return result.statusCode === 200 || result.statusCode === 403;
      } catch { return false; }
    },
  },
  {
    cnamePattern: /\.cloudfront\.net$/i,
    name: 'AWS CloudFront',
    vulnerableMessage: 'Subdomain points to a CloudFront distribution that may not exist.',
    remediation: 'Verify CloudFront distribution exists and is active, or remove the DNS record.',
  },
  {
    cnamePattern: /\.herokuapp\.com$/i,
    name: 'Heroku',
    vulnerableMessage: 'Subdomain points to a Heroku app that may not exist.',
    remediation: 'Verify Heroku app exists, or remove the DNS record.',
    verification: async (subdomain: string) => {
      try {
        const result = await httpGet(`https://${subdomain}`);
        return result.statusCode !== 503;
      } catch { return false; }
    },
  },
  {
    cnamePattern: /\.azurewebsites\.net$/i,
    name: 'Azure App Service',
    vulnerableMessage: 'Subdomain points to an Azure App Service that may not exist.',
    remediation: 'Verify Azure App Service exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.azure-api\.net$/i,
    name: 'Azure API Management',
    vulnerableMessage: 'Subdomain points to an Azure API Management instance that may not exist.',
    remediation: 'Verify Azure API Management instance exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.trafficmanager\.net$/i,
    name: 'Azure Traffic Manager',
    vulnerableMessage: 'Subdomain points to an Azure Traffic Manager profile that may not exist.',
    remediation: 'Verify Traffic Manager profile exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.blob\.core\.windows\.net$/i,
    name: 'Azure Blob Storage',
    vulnerableMessage: 'Subdomain points to an Azure Blob Storage account that may not exist.',
    remediation: 'Verify Azure Storage account exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.github\.io$/i,
    name: 'GitHub Pages',
    vulnerableMessage: 'Subdomain points to a GitHub Pages site that may not exist.',
    remediation: 'Verify GitHub Pages repository exists, or remove the DNS record.',
    verification: async (subdomain: string) => {
      try {
        const result = await httpGet(`https://${subdomain}`);
        return !result.body.includes('There isn\'t a GitHub Pages site here.');
      } catch { return false; }
    },
  },
  {
    cnamePattern: /\.gitlab\.io$/i,
    name: 'GitLab Pages',
    vulnerableMessage: 'Subdomain points to a GitLab Pages site that may not exist.',
    remediation: 'Verify GitLab Pages project exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.bitbucket\.io$/i,
    name: 'Bitbucket Pages',
    vulnerableMessage: 'Subdomain points to a Bitbucket Pages site that may not exist.',
    remediation: 'Verify Bitbucket Pages site exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.shopify\.com$/i,
    name: 'Shopify',
    vulnerableMessage: 'Subdomain points to a Shopify store that may not exist.',
    remediation: 'Verify Shopify store exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.squarespace\.com$/i,
    name: 'Squarespace',
    vulnerableMessage: 'Subdomain points to a Squarespace site that may not exist.',
    remediation: 'Verify Squarespace site exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.wordpress\.com$/i,
    name: 'WordPress.com',
    vulnerableMessage: 'Subdomain points to a WordPress.com site that may not exist.',
    remediation: 'Verify WordPress.com site exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.surge\.sh$/i,
    name: 'Surge.sh',
    vulnerableMessage: 'Subdomain points to a Surge.sh site that may not exist.',
    remediation: 'Verify Surge.sh project exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.netlify\.com$/i,
    name: 'Netlify',
    vulnerableMessage: 'Subdomain points to a Netlify site that may not exist.',
    remediation: 'Verify Netlify site exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.vercel\.app$/i,
    name: 'Vercel',
    vulnerableMessage: 'Subdomain points to a Vercel deployment that may not exist.',
    remediation: 'Verify Vercel project exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.firebaseapp\.com$/i,
    name: 'Firebase Hosting',
    vulnerableMessage: 'Subdomain points to a Firebase app that may not exist.',
    remediation: 'Verify Firebase app exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.web\.app$/i,
    name: 'Firebase Web App',
    vulnerableMessage: 'Subdomain points to a Firebase web app that may not exist.',
    remediation: 'Verify Firebase web app exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.appspot\.com$/i,
    name: 'Google App Engine',
    vulnerableMessage: 'Subdomain points to a Google App Engine app that may not exist.',
    remediation: 'Verify App Engine app exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.googlehosted\.com$/i,
    name: 'Google Sites',
    vulnerableMessage: 'Subdomain points to a Google Sites page that may not exist.',
    remediation: 'Verify Google Sites page exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.amazonaws\.com$/i,
    name: 'AWS Service',
    vulnerableMessage: 'Subdomain points to an AWS resource that may not exist.',
    remediation: 'Verify AWS resource exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.cloudflare\.net$/i,
    name: 'Cloudflare',
    vulnerableMessage: 'Subdomain points to a Cloudflare resource that may not exist.',
    remediation: 'Verify Cloudflare configuration, or remove the DNS record.',
  },
  {
    cnamePattern: /\.fastly\.net$/i,
    name: 'Fastly CDN',
    vulnerableMessage: 'Subdomain points to a Fastly CDN resource that may not exist.',
    remediation: 'Verify Fastly configuration, or remove the DNS record.',
  },
  {
    cnamePattern: /\.pantheon\.io$/i,
    name: 'Pantheon',
    vulnerableMessage: 'Subdomain points to a Pantheon site that may not exist.',
    remediation: 'Verify Pantheon site exists, or remove the DNS record.',
  },
  {
    cnamePattern: /\.ghost\.io$/i,
    name: 'Ghost',
    vulnerableMessage: 'Subdomain points to a Ghost site that may not exist.',
    remediation: 'Verify Ghost site exists, or remove the DNS record.',
  },
];

// Common subdomain prefixes to check
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
  'admin', 'portal', 'cpanel', 'whm', 'api', 'dev', 'staging',
  'test', 'beta', 'demo', 'sandbox', 'preview', 'preprod',
  'cdn', 'static', 'assets', 'media', 'images', 'img',
  'blog', 'forum', 'support', 'help', 'docs', 'wiki',
  'shop', 'store', 'payment', 'checkout', 'billing',
  'app', 'mobile', 'm', 'web', 'portal', 'dashboard',
  'vpn', 'remote', 'gateway', 'proxy', 'lb',
  'ns1', 'ns2', 'ns3', 'ns4', 'dns', 'dns1', 'dns2',
  'mx1', 'mx2', 'mx3', 'email', 'smtp1', 'smtp2',
  'backup', 'db', 'database', 'redis', 'mongo', 'mysql',
  'git', 'gitlab', 'jenkins', 'ci', 'cd', 'deploy',
  'monitor', 'grafana', 'prometheus', 'kibana', 'elastic',
  'k8s', 'kubernetes', 'docker', 'registry',
];

// HTTP GET helper
function httpGet(url: string, timeout: number = 8000): Promise<{ statusCode: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout, rejectUnauthorized: false }, (res) => {
      let body = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 524288) { res.destroy(); return; }
        body += chunk.toString();
      });
      res.on('end', () => resolve({
        statusCode: res.statusCode || 0,
        body,
        headers: res.headers,
      }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// Check if a subdomain has a dangling CNAME
async function checkDanglingCname(
  subdomain: string,
  domain: string
): Promise<{
  vulnerable: boolean;
  service?: CloudServiceFingerprint;
  cname?: string;
  responseStatus?: number;
  verified?: boolean;
} | null> {
  try {
    const cnames = await resolveCname(subdomain);
    if (!cnames || cnames.length === 0) return null;

    const cname = cnames[0];

    // Check if CNAME points to a known cloud service
    for (const service of CLOUD_SERVICES) {
      if (service.cnamePattern.test(cname)) {
        // Try to verify if the resource actually exists
        let isVulnerable = true;
        if (service.verification) {
          isVulnerable = await service.verification(subdomain);
        } else {
          // Try to connect to the subdomain
          try {
            const result = await httpGet(`https://${subdomain}`, 6000);
            // If we get a 404 or error page from the cloud provider, it's likely dangling
            if (result.statusCode === 404 || result.body.includes('not found') || result.body.includes('NoSuchBucket')) {
              isVulnerable = true;
            } else if (result.statusCode === 200) {
              isVulnerable = false;
            }
          } catch {
            // Connection failed - might be dangling
            isVulnerable = true;
          }
        }

        if (isVulnerable) {
          return {
            vulnerable: true,
            service,
            cname,
            verified: true,
          };
        }
      }
    }

    return null;
  } catch {
    return null;
  }
}

// Check for orphaned NS records (NS pointing to non-existent nameservers)
async function checkOrphanedNs(subdomain: string, domain: string): Promise<boolean> {
  try {
    const nsRecords = await new Promise<string[]>((resolve, reject) => {
      dns.resolveNs(subdomain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });

    if (nsRecords.length === 0) return false;

    // Check if any NS records point to non-existent servers
    for (const ns of nsRecords) {
      try {
        await resolve4(ns);
      } catch {
        // NS record points to non-existent server - potential takeover
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

// Check for dangling MX records
async function checkDanglingMx(subdomain: string): Promise<boolean> {
  try {
    const mxRecords = await new Promise<dns.MxRecord[]>((resolve, reject) => {
      dns.resolveMx(subdomain, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });

    if (mxRecords.length === 0) return false;

    // Check if MX records point to non-existent servers
    for (const mx of mxRecords) {
      try {
        await resolve4(mx.exchange);
      } catch {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

// Check for subdomain takeovers via dangling CNAMEs
async function checkSubdomainTakeover(domain: string): Promise<{
  findings: Finding[];
  enumeratedSubdomains: string[];
}> {
  const findings: Finding[] = [];
  const enumeratedSubdomains: string[] = [];

  // First check common subdomains
  const subdomainsToCheck = COMMON_SUBDOMAINS.map(s => `${s}.${domain}`);

  // Also try to enumerate via crt.sh (Certificate Transparency logs)
  try {
    const result = await httpGet(`https://crt.sh/?q=%.${domain}&output=json`, 15000);
    if (result.statusCode === 200) {
      const certs = JSON.parse(result.body);
      for (const cert of certs) {
        if (cert.name_value) {
          const names = cert.name_value.split('\n');
          for (const name of names) {
            const cleaned = name.trim().toLowerCase();
            if (cleaned.endsWith(`.${domain}`) && !cleaned.includes('*')) {
              if (!subdomainsToCheck.includes(cleaned)) {
                subdomainsToCheck.push(cleaned);
              }
            }
          }
        }
      }
    }
  } catch {}

  // Check each subdomain for dangling CNAMEs
  for (const subdomain of subdomainsToCheck.slice(0, 20)) { // Limit to 20 for speed
    enumeratedSubdomains.push(subdomain);

    try {
      const result = await checkDanglingCname(subdomain, domain);
      if (result && result.vulnerable && result.service) {
        findings.push(generateFinding(
          `Potential subdomain takeover: ${subdomain}`,
          `The subdomain ${subdomain} has a dangling CNAME pointing to ${result.service.name}.`,
          Severity.CRITICAL,
          'Subdomain Takeover',
          domain,
          `Subdomain: ${subdomain}\nCNAME: ${result.cname}\nService: ${result.service.name}`,
          result.service.vulnerableMessage,
          result.service.remediation,
          ['https://github.com/EdOverflow/can-i-take-over-xyz']
        ));
      }
    } catch {}

    // Check for orphaned NS records
    try {
      const isOrphanedNs = await checkOrphanedNs(subdomain, domain);
      if (isOrphanedNs) {
        findings.push(generateFinding(
          `Orphaned NS record: ${subdomain}`,
          `The subdomain ${subdomain} has NS records pointing to non-existent nameservers.`,
          Severity.HIGH,
          'Subdomain Takeover',
          domain,
          `Subdomain: ${subdomain} has dangling NS records`,
          'Orphaned NS records can be claimed by attackers',
          'Remove or update NS records for unused subdomains',
          ['https://github.com/EdOverflow/can-i-take-over-xyz']
        ));
      }
    } catch {}
  }

  return { findings, enumeratedSubdomains };
}

// Check for CNAME-based subdomain takeover via shared infrastructure
async function checkSharedInfrastructure(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Check for domain CNAME to shared infrastructure
    const cnames = await resolveCname(domain);
    for (const cname of cnames) {
      // Check if CNAME points to a CDN or load balancer that could be hijacked
      const sharedInfraPatterns = [
        { pattern: /\.cloudfront\.net$/i, name: 'CloudFront' },
        { pattern: /\.azureedge\.net$/i, name: 'Azure CDN' },
        { pattern: /\.akamai\.net$/i, name: 'Akamai' },
        { pattern: /\.fastly\.net$/i, name: 'Fastly' },
        { pattern: /\.cloudflare\.net$/i, name: 'Cloudflare' },
        { pattern: /\.edgekey\.net$/i, name: 'Akamai Edge' },
      ];

      for (const infra of sharedInfraPatterns) {
        if (infra.pattern.test(cname)) {
          // These are generally safe, but check for misconfiguration
          findings.push(generateFinding(
            'Domain uses shared infrastructure',
            `Domain CNAME points to ${infra.name}: ${cname}`,
            Severity.INFO,
            'Subdomain Takeover',
            domain,
            `CNAME: ${cname}\nInfrastructure: ${infra.name}`,
            'Shared infrastructure is generally safe but should be monitored',
            'Ensure proper access controls and monitor for unauthorized changes',
            []
          ));
          break;
        }
      }
    }
  } catch {}

  return findings;
}

export async function runSubdomainTakeoverScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  let enumeratedSubdomains: string[] = [];

  try {
    // Check for dangling CNAMEs
    const result = await checkSubdomainTakeover(domain);
    findings.push(...result.findings);
    enumeratedSubdomains = result.enumeratedSubdomains;

    // Check shared infrastructure
    const infraFindings = await checkSharedInfrastructure(domain);
    findings.push(...infraFindings);

    // Summary finding
    if (enumeratedSubdomains.length > 0) {
      findings.push(generateFinding(
        'Subdomain enumeration completed',
        `Enumerated ${enumeratedSubdomains.length} subdomains for ${domain}.`,
        Severity.INFO,
        'Subdomain Takeover',
        domain,
        `Subdomains checked: ${enumeratedSubdomains.length}`,
        'Comprehensive subdomain enumeration helps identify attack surface',
        'Regularly audit subdomains and remove unused DNS records',
        []
      ));
    }

    const duration = Date.now() - startTime;
    return {
      module: 'subdomainTakeover',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'subdomainTakeover',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
