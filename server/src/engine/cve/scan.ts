import * as dns from 'dns';
import * as http from 'http';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchUrl } from '../modules/shared';
import { extractTechnologies, findCvesForTechnology, TechnologyFingerprint } from './database';

const resolveTxt = promisify(dns.resolveTxt);

export async function runCveScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const detectedTechs: TechnologyFingerprint[] = [];

  try {
    // Fetch the target page
    let headers: http.IncomingHttpHeaders = {};
    let body = '';
    let cookies: string[] = [];

    try {
      const result = await fetchUrl(`https://${domain}`, 10000);
      headers = result.headers;
      body = result.body;

      // Extract cookies from Set-Cookie header
      const setCookie = result.headers['set-cookie'];
      if (setCookie) {
        cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
      }
    } catch (e) {
      try {
        const result = await fetchUrl(`http://${domain}`, 10000);
        headers = result.headers;
        body = result.body;
        const setCookie = result.headers['set-cookie'];
        if (setCookie) {
          cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        }
      } catch (e2) {
        errors.push(`Could not fetch ${domain}: ${e2 instanceof Error ? e2.message : String(e2)}`);
      }
    }

    // Get DNS TXT records
    let txtRecords: string[] = [];
    try {
      const records = await resolveTxt(domain);
      txtRecords = records.flat();
    } catch {}

    // Detect all technologies
    const techs = extractTechnologies(headers as Record<string, string | string[] | undefined>, body, cookies, txtRecords);
    detectedTechs.push(...techs);

    // Check for technologies with known CVEs
    for (const tech of techs) {
      const cves = findCvesForTechnology(tech.name, tech.version);
      if (cves.length > 0) {
        // Sort by severity (CRITICAL first)
        const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        cves.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        for (const cve of cves) {
          findings.push(generateFinding(
            `${tech.name} vulnerability: ${cve.title}`,
            `${cve.description} (CVSS: ${cve.cvss})`,
            cve.severity as Severity,
            'CVE Correlation',
            domain,
            `${tech.name} ${tech.version || '(version unknown)'} - ${cve.id}`,
            `Known vulnerability in ${tech.name} ${tech.version || ''} - CVSS score: ${cve.cvss}`,
            cve.remediation,
            cve.references,
            { [cve.id]: cve.severity }
          ));
        }
      }
    }

    // Also check for technology disclosure without CVE correlation
    // These are informational findings about detected technologies
    if (techs.length > 0) {
      const techSummary = techs.map(t => `${t.name}${t.version ? ' ' + t.version : ''}`).join(', ');
      findings.push(generateFinding(
        'Technology stack identified',
        `${techs.length} technology(ies) were identified from publicly visible indicators.`,
        Severity.INFO,
        'CVE Correlation',
        domain,
        `Detected: ${techSummary}`,
        'Technology identification helps attackers target known vulnerabilities',
        'Keep all detected technologies updated to the latest stable versions',
        []
      ));
    }

    // Check for common misconfigurations that indicate vulnerable versions
    const server = Array.isArray(headers['server']) ? headers['server'][0] : headers['server'];
    if (server) {
      // Check for very old Apache versions
      const apacheMatch = server.match(/Apache\/([\d.]+)/);
      if (apacheMatch) {
        const version = apacheMatch[1];
        const major = parseInt(version.split('.')[0]);
        const minor = parseInt(version.split('.')[1]);
        if (major === 2 && minor < 4) {
          findings.push(generateFinding(
            'Outdated Apache version detected',
            `Apache ${version} is severely outdated and contains multiple known vulnerabilities.`,
            Severity.CRITICAL,
            'CVE Correlation',
            domain,
            `Server: ${server}`,
            'Apache 2.2.x reached end-of-life in 2018',
            'Upgrade to Apache 2.4.x or later immediately',
            ['https://httpd.apache.org/security/vulnerabilities_24.html']
          ));
        }
      }

      // Check for old Nginx versions
      const nginxMatch = server.match(/nginx\/([\d.]+)/);
      if (nginxMatch) {
        const version = nginxMatch[1];
        const parts = version.split('.').map(Number);
        if (parts[0] < 1 || (parts[0] === 1 && parts[1] < 20)) {
          findings.push(generateFinding(
            'Outdated Nginx version detected',
            `Nginx ${version} is outdated and may contain known vulnerabilities.`,
            Severity.HIGH,
            'CVE Correlation',
            domain,
            `Server: ${server}`,
            'Nginx versions before 1.20 have known security issues',
            'Upgrade to the latest stable Nginx version',
            ['https://nginx.org/en/security_advisories.html']
          ));
        }
      }

      // Check for old IIS versions
      const iisMatch = server.match(/Microsoft-IIS\/([\d.]+)/);
      if (iisMatch) {
        const version = iisMatch[1];
        const major = parseInt(version.split('.')[0]);
        if (major < 10) {
          findings.push(generateFinding(
            'Outdated IIS version detected',
            `IIS ${version} is outdated and may contain known vulnerabilities.`,
            Severity.HIGH,
            'CVE Correlation',
            domain,
            `Server: ${server}`,
            'Older IIS versions have known security issues',
            'Upgrade to the latest IIS version or migrate to a supported platform',
            ['https://docs.microsoft.com/en-us/lifecycle/products/internet-information-services-iis']
          ));
        }
      }
    }

    // Check X-Powered-By for version info
    const poweredBy = Array.isArray(headers['x-powered-by']) ? headers['x-powered-by'][0] : headers['x-powered-by'];
    if (poweredBy) {
      const phpMatch = poweredBy.match(/PHP\/([\d.]+)/);
      if (phpMatch) {
        const version = phpMatch[1];
        const major = parseInt(version.split('.')[0]);
        const minor = parseInt(version.split('.')[1]);
        if (major < 8 || (major === 8 && minor === 0)) {
          findings.push(generateFinding(
            'Outdated PHP version detected',
            `PHP ${version} is outdated and contains multiple known vulnerabilities.`,
            Severity.HIGH,
            'CVE Correlation',
            domain,
            `X-Powered-By: ${poweredBy}`,
            'PHP 7.x reached end-of-life in November 2022',
            'Upgrade to PHP 8.1 or later',
            ['https://www.php.net/supported-versions.php']
          ));
        }
      }
    }

    const duration = Date.now() - startTime;
    return {
      module: 'cveCorrelation',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'cveCorrelation',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
