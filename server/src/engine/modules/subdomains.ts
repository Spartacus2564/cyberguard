import * as dns from 'dns';
import { promisify } from 'util';
import { ScanResult, Finding, Severity } from '../../types';
import { generateFinding, fetchJson } from './shared';
import { getSubdomainWordlist } from './seclists';

const resolve4 = promisify(dns.resolve4);
const resolveTxt = promisify(dns.resolveTxt);

function getIpClass(ip: string): string {
  const parts = ip.split('.');
  if (parts[0] === '10') return '10.x.x.x';
  if (parts[0] === '192' && parts[1] === '168') return '192.168.x.x';
  if (parts[0] === '172' && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) return '172.16-31.x.x';
  return `${parts[0]}.x.x.x`;
}

export async function runSubdomainScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Fetch subdomains from crt.sh certificate transparency logs
    let subdomains: string[] = [];
    try {
      const crtShUrl = `https://crt.sh/?q=%.${domain}&output=json`;
      const crtData = await fetchJson(crtShUrl, 20000);

      if (Array.isArray(crtData)) {
        const subdomainSet = new Set<string>();
        for (const entry of crtData) {
          const name = entry.name_value || entry.common_name || '';
          const names = name.split('\n').map((n: string) => n.trim().toLowerCase());
          for (const n of names) {
            // Only include subdomains of our target domain
            if (n.endsWith(`.${domain}`) || n === domain) {
              // Remove wildcards
              const clean = n.replace(/^\*\./, '');
              if (clean) subdomainSet.add(clean);
            }
          }
        }
        subdomains = Array.from(subdomainSet).sort();
      }
    } catch (e) {
      errors.push(`crt.sh query failed: ${e instanceof Error ? e.message : String(e)}`);
    }

    // DNS brute-force with SecLists subdomains wordlist
    const bruteSubdomains = new Set<string>();
    const BATCH_SIZE = 20;
    const allBruteWords = getSubdomainWordlist();
    // Remove subdomains already found via crt.sh
    const wordlist = allBruteWords.filter(w => !subdomains.includes(`${w}.${domain}`));

    for (let i = 0; i < wordlist.length; i += BATCH_SIZE) {
      const batch = wordlist.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(async (word) => {
          const fqdn = `${word}.${domain}`;
          try {
            const ips = await resolve4(fqdn);
            if (ips.length > 0) return fqdn;
          } catch {}
          return null;
        })
      );
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) {
          bruteSubdomains.add(r.value);
        }
      }
    }

    // Merge brute-force results with crt.sh results
    const allSubdomains = new Set([...subdomains, ...bruteSubdomains]);
    const newBruteSubs = [...bruteSubdomains].filter(s => !subdomains.includes(s));

    if (newBruteSubs.length > 0) {
      findings.push(
        generateFinding(
          `DNS brute-force discovered ${newBruteSubs.length} additional subdomain(s)`,
          `Subdomain brute-force found subdomains not listed in certificate transparency logs.`,
          Severity.MEDIUM,
          'Subdomain Discovery',
          domain,
          `Brute-force findings: ${newBruteSubs.slice(0, 20).join(', ')}${newBruteSubs.length > 20 ? '...' : ''}`,
          'Subdomains not in CT logs may have weaker security monitoring and different access controls',
          'Audit all discovered subdomains, especially those not in CT logs',
          ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Enumerate_Subdomains']
        )
      );
    }

    subdomains = Array.from(allSubdomains).sort();

    if (subdomains.length === 0) {
      findings.push(
        generateFinding(
          'No subdomains discovered',
          'No subdomains were found via certificate transparency logs or DNS brute-force.',
          Severity.INFO,
          'Subdomain Discovery',
          domain,
          'crt.sh and DNS brute-force returned no results',
          'This may mean no subdomains exist or they are not logged in CT',
          'No action required if no subdomains exist',
          []
        )
      );
    } else {
      const ipMap: Map<string, string[]> = new Map();
      const wildcardSubdomains: string[] = [];

      for (const sub of subdomains) {
        findings.push(
          generateFinding(
            'Subdomain discovered',
            `A subdomain was found via certificate transparency logs.`,
            Severity.INFO,
            'Subdomain Discovery',
            sub,
            `Discovered via crt.sh CT logs`,
            'Each subdomain is a potential attack surface',
            'Audit all discovered subdomains for security issues and decommission unused ones',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Enumerate_Subdomains']
          )
        );

        // DNS lookup for each subdomain
        try {
          const ips = await resolve4(sub);
          ipMap.set(sub, ips);

          // Check for wildcard DNS (subdomain resolves to same IPs as many others)
          // We'll flag if a subdomain resolves but we'll analyze ranges after
        } catch {
          // Subdomain may not have A records, that's fine
        }
      }

      // Analyze IP ranges for shadow IT detection
      const ipClasses: Map<string, string[]> = new Map();
      for (const [sub, ips] of ipMap) {
        for (const ip of ips) {
          const ipClass = getIpClass(ip);
          if (!ipClasses.has(ipClass)) ipClasses.set(ipClass, []);
          ipClasses.get(ipClass)!.push(sub);
        }
      }

      if (ipClasses.size > 1) {
        const ranges = Array.from(ipClasses.entries())
          .map(([range, subs]) => `${range} (${subs.length} subdomains)`)
          .join('; ');
        findings.push(
          generateFinding(
            'Subdomains point to different IP ranges',
            'Discovered subdomains resolve to different IP address ranges, indicating potential shadow IT.',
            Severity.MEDIUM,
            'Subdomain Discovery',
            domain,
            `IP ranges: ${ranges}`,
            'Multiple IP ranges may indicate decentralized infrastructure or unauthorized services',
            'Review all IP ranges and ensure all infrastructure is authorized and managed',
            ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Enumerate_Subdomains']
          )
        );
      }

      // Check for wildcard DNS patterns (heuristic: many subdomains on same IPs)
      for (const [ipClass, subs] of ipClasses) {
        if (subs.length >= 5) {
          findings.push(
            generateFinding(
              'Potential wildcard DNS record',
              `Multiple subdomains (${subs.length}) resolve to the same IP range (${ipClass}).`,
              Severity.LOW,
              'Subdomain Discovery',
              domain,
              `Subdomains on ${ipClass}: ${subs.slice(0, 10).join(', ')}${subs.length > 10 ? '...' : ''}`,
              'Wildcard DNS can expose unintended subdomains',
              'Verify whether a wildcard DNS record is intentional and audit all resolving subdomains',
              ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Enumerate_Subdomains']
            )
          );
          break; // One finding per domain is enough
        }
      }

      // Also check for wildcard DNS by looking for '*' records
      try {
        const txtRecords = await resolveTxt(domain);
        const flatTxt = txtRecords.flat();
        if (flatTxt.some(r => r.includes('*'))) {
          // This is a rough heuristic; proper wildcard detection would use dns.resolve with type '*'
        }
      } catch {
        // Ignore
      }
    }

    const duration = Date.now() - startTime;
    return {
      module: 'subdomains',
      findings,
      duration,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    return {
      module: 'subdomains',
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
