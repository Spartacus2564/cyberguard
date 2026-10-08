import * as https from 'https';
import * as http from 'http';
import * as dns from 'dns';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding } from './shared';

const resolve4 = promisify(dns.resolve4);
const resolveCname = promisify(dns.resolveCname);

function makeRequest(
  targetUrl: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  timeoutMs: number = 8000,
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
      headers: { 'User-Agent': 'CYBERGUARD-CloudSecurity/1.0', ...headers },
      timeout: timeoutMs,
      rejectUnauthorized: false,
    } as http.RequestOptions & { rejectUnauthorized?: boolean }, (res) => {
      let data = '';
      let totalBytes = 0;
      res.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > 2097152) { req.destroy(); return; }
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

// Cloud provider detection signatures
const CLOUD_SIGNATURES = {
  aws: {
    headers: ['x-amz-request-id', 'x-amz-id-2', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-amz-apigw-id'],
    body: ['amazonaws.com', 's3.amazonaws.com', 'cloudfront.net', 'aws'],
    cname: ['.amazonaws.com', '.cloudfront.net', '.elasticbeanstalk.com', '.elb.amazonaws.com'],
  },
  gcp: {
    headers: ['x-goog-generation', 'x-goog-metageneration', 'x-goog-stored-content-length'],
    body: ['googleapis.com', 'google cloud', 'gcloud', 'firebase'],
    cname: ['.googleusercontent.com', '.cloudfunctions.net', '.appspot.com', '.run.app'],
  },
  azure: {
    headers: ['x-ms-request-id', 'x-ms-version', 'x-ms-correlation-request-id'],
    body: ['azurewebsites.net', 'azurewebsites', 'windows.net', 'microsoft'],
    cname: ['.azurewebsites.net', '.azurewebsites.windows.net', '.blob.core.windows.net', '.azure-api.net', '.azureedge.net'],
  },
  cloudflare: {
    headers: ['cf-ray', 'cf-cache-status', 'cf-connecting-ip'],
    body: ['cloudflare', 'cloudflare.com'],
    cname: ['.cloudflare.net'],
  },
  fastly: {
    headers: ['x-fastly-request-id', 'x-served-by', 'x-cache'],
    body: ['fastly'],
    cname: ['.fastly.net', '.fastlylb.net'],
  },
  heroku: {
    headers: ['x-request-id', 'x-runtime'],
    body: ['heroku', 'herokuapp.com'],
    cname: ['.herokussl.com', '.herokuapp.com'],
  },
};

export async function runCloudSecurityScan(domain: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  const base = `https://${domain}`;

  // 1) Fetch main page for header/body analysis
  const mainRes = await safe(base + '/');
  const hdrs = mainRes.headers;
  const bodyLower = mainRes.body.toLowerCase();
  const headerStr = JSON.stringify(hdrs).toLowerCase();
  const combined = bodyLower + ' ' + headerStr;

  // 2) Detect cloud provider from headers, body, and DNS
  const detectedProviders: string[] = [];

  for (const [provider, sigs] of Object.entries(CLOUD_SIGNATURES)) {
    const headerMatch = sigs.headers.some(h => headerStr.includes(h));
    const bodyMatch = sigs.body.some(b => bodyLower.includes(b));
    if (headerMatch || bodyMatch) {
      detectedProviders.push(provider);
    }
  }

  // DNS CNAME check for cloud providers
  try {
    const cnames = await resolveCname(domain);
    for (const cname of cnames) {
      for (const [provider, sigs] of Object.entries(CLOUD_SIGNATURES)) {
        if (sigs.cname.some(c => cname.toLowerCase().includes(c))) {
          if (!detectedProviders.includes(provider)) {
            detectedProviders.push(provider);
          }
        }
      }
    }
  } catch {}

  // 3) Report detected cloud providers
  if (detectedProviders.length > 0) {
    const providerList = detectedProviders.join(', ');
    findings.push(generateFinding({
      title: `Cloud infrastructure detected: ${providerList}`,
      description: `The target is hosted on cloud infrastructure (${providerList}). Cloud environments have unique attack surfaces including metadata endpoints, IAM role abuse, and storage bucket misconfigurations.`,
      severity: Severity.INFO,
      category: 'Cloud Security',
      affectedAsset: domain,
      evidence: `Detected providers: ${providerList}\nHeader signatures: ${Object.entries(CLOUD_SIGNATURES).filter(([k]) => detectedProviders.includes(k)).map(([k, v]) => `${k}: ${v.headers.filter(h => headerStr.includes(h)).join(', ')}`).join('; ')}`,
      impact: 'Cloud infrastructure may have exposed metadata endpoints, misconfigured IAM roles, or public storage buckets if SSRF or misconfiguration exists.',
      remediation: 'Enforce IMDSv2 (AWS), restrict metadata access, audit IAM roles and storage bucket permissions, enable cloud security monitoring.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage',
        'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
      ],
    }));

    // AWS-specific checks
    if (detectedProviders.includes('aws')) {
      // Check for exposed S3 bucket references in page
      const s3Refs = combined.match(/s3[.:\/\-][^\s"']{5,80}/gi);
      if (s3Refs && s3Refs.length > 0) {
        findings.push(generateFinding({
          title: 'AWS S3 bucket references exposed in page content',
          description: `The page contains ${s3Refs.length} AWS S3 bucket reference(s). If bucket permissions are misconfigured (public read/write), sensitive data may be exposed.`,
          severity: Severity.LOW,
          category: 'Cloud Security',
          affectedAsset: base,
          evidence: `S3 references found: ${s3Refs.slice(0, 5).join(', ')}`,
          impact: 'Misconfigured S3 buckets can expose sensitive files, backups, or user data to the public internet.',
          remediation: 'Audit all S3 bucket permissions. Use AWS Access Analyzer. Block public access by default. Enable S3 access logging.',
          references: ['https://cwe.mitre.org/data/definitions/538.html'],
        }));
      }
    }

    // GCP-specific checks
    if (detectedProviders.includes('gcp')) {
      const gcsRefs = combined.match(/storage\.googleapis\.com[^\s"']{5,80}/gi);
      if (gcsRefs && gcsRefs.length > 0) {
        findings.push(generateFinding({
          title: 'GCP Cloud Storage references exposed',
          description: 'The application references Google Cloud Storage buckets. Misconfigured buckets may expose sensitive data.',
          severity: Severity.LOW,
          category: 'Cloud Security',
          affectedAsset: base,
          evidence: `GCS references: ${gcsRefs.slice(0, 3).join(', ')}`,
          impact: 'Publicly accessible GCS buckets can leak sensitive data.',
          remediation: 'Audit GCS bucket ACLs. Use Uniform Bucket-Level Access. Enable access logging.',
          references: ['https://cloud.google.com/storage/docs/best-practices'],
        }));
      }
    }
  }

  // 4) Cloud-specific SSRF risk assessment
  // Note: Direct metadata endpoint testing from scanner is always unreachable (scanner is not on target's VPC).
  // SSRF via the application is tested by activeVuln.ts. Here we report the risk.
  if (detectedProviders.length > 0) {
    findings.push(generateFinding({
      title: `Cloud SSRF risk — ${detectedProviders.join(' and ')} metadata endpoints`,
      description: `Target runs on ${detectedProviders.join(' and ')}. If an SSRF vulnerability exists in the application, an attacker could access cloud metadata endpoints (169.254.169.254) to steal IAM credentials, API keys, and instance data.`,
      severity: Severity.MEDIUM,
      category: 'Cloud Security',
      affectedAsset: domain,
      evidence: `Cloud provider(s): ${detectedProviders.join(', ')}\nMetadata endpoints: ${detectedProviders.includes('aws') ? 'http://169.254.169.254/latest/meta-data/' : ''}${detectedProviders.includes('gcp') ? 'http://metadata.google.internal/computeMetadata/v1/' : ''}${detectedProviders.includes('azure') ? 'http://169.254.169.254/metadata/instance' : ''}`,
      impact: 'SSRF to cloud metadata can result in full cloud account compromise — IAM role assumption, S3 access, database credential theft.',
      remediation: 'Enforce IMDSv2 (AWS hop limit=1), block SSRF vulnerabilities, use cloud provider firewall rules to restrict metadata access, implement egress filtering.',
      references: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery',
        'https://ssrf.cloudtopology.com/',
      ],
    }));
  }

  // 5) CDN-specific security checks
  if (detectedProviders.includes('cloudflare')) {
    // Check if Cloudflare WAF is in use
    const cfWaf = headerStr.includes('cf-ray');
    if (cfWaf) {
      // Check for origin IP exposure risk
      findings.push(generateFinding({
        title: 'Cloudflare CDN detected — origin IP exposure risk',
        description: 'The site uses Cloudflare CDN. If the origin server IP is discoverable (via DNS history, email headers, or subdomains), attackers can bypass Cloudflare protection.',
        severity: Severity.INFO,
        category: 'Cloud Security',
        affectedAsset: domain,
        evidence: 'CF-Ray header present, Cloudflare CDN confirmed',
        impact: 'Bypassing Cloudflare exposes the origin server to direct attacks.',
        remediation: 'Ensure origin server IP is not leaked via DNS, email headers, or subdomains. Use Cloudflare Origin Rules.',
        references: ['https://blog.sucuri.net/2020/02/bypassing-cloudflare-using-viewdns-info.html'],
      }));
    }
  }

  return { module: 'cloudSecurity', findings, duration: 0, errors };
}
