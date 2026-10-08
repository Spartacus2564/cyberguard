import { ScanResult, ScanModule, Finding, Severity } from '../../types';
import { fetchLiveCves, fetchRecentCves } from '../../services/cveIntel.service';
import { extractTechnologies } from '../cve/database';
import { fetchUrl, generateFinding } from './shared';
import { logExploit, logInfo, logDone } from '../scanLogger';
import * as dns from 'dns';
import { promisify } from 'util';
import { getAI } from '../../services/ai.service';

const resolveTxt = promisify(dns.resolveTxt);

function severityRank(s: string): number {
  switch (s) {
    case 'CRITICAL': return 0;
    case 'HIGH': return 1;
    case 'MEDIUM': return 2;
    case 'LOW': return 3;
    default: return 4;
  }
}

export async function runLiveCveScan(domain: string): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const errors: string[] = [];
  const module = 'liveCve';

  try {
    logInfo(module, `Starting live CVE scan for ${domain}`);

    let headers: Record<string, string | string[] | undefined> = {};
    let body = '';
    let cookies: string[] = [];

    try {
      const result = await fetchUrl(`https://${domain}`, 10000, module);
      headers = result.headers as Record<string, string | string[] | undefined>;
      body = result.body;
      const setCookie = result.headers['set-cookie'];
      if (setCookie) {
        cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
      }
    } catch {
      try {
        const result = await fetchUrl(`http://${domain}`, 10000, module);
        headers = result.headers as Record<string, string | string[] | undefined>;
        body = result.body;
        const setCookie = result.headers['set-cookie'];
        if (setCookie) {
          cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
        }
      } catch (e2) {
        errors.push(`Could not fetch ${domain}: ${e2 instanceof Error ? e2.message : String(e2)}`);
      }
    }

    let txtRecords: string[] = [];
    try {
      const records = await resolveTxt(domain);
      txtRecords = records.flat();
    } catch { /* no TXT records */ }

    const techs = extractTechnologies(headers, body, cookies, txtRecords);
    logInfo(module, `Detected ${techs.length} technologies: ${techs.map(t => t.name).join(', ')}`);

    const allCveIds = new Map<string, Finding>();

    // Fetch live CVEs for each detected technology
    for (const tech of techs) {
      try {
        const liveCves = await fetchLiveCves(tech.name, tech.version);
        for (const cve of liveCves) {
          if (allCveIds.has(cve.id)) continue;
          logExploit(module, 'CVE Match', domain, `${cve.id} (${cve.severity}) - ${tech.name} ${tech.version || ''}`);

          const finding = generateFinding({
            title: `Live CVE: ${cve.title || cve.id}`,
            description: cve.description || `Vulnerability ${cve.id} affects ${tech.name}${tech.version ? ' ' + tech.version : ''}.`,
            severity: cve.severity as Severity,
            category: 'Live CVE Intelligence',
            affectedAsset: domain,
            evidence: `${tech.name} ${tech.version || '(version unknown)'} - ${cve.id} (CVSS: ${cve.cvss}) [Source: ${cve.source}]`,
            impact: `Detected via real-time CVE intelligence. CVSS score: ${cve.cvss}. ${cve.description?.substring(0, 200) || 'No description available.'}`,
            remediation: `Investigate and patch ${tech.name}${tech.version ? ' ' + tech.version : ''} for ${cve.id}. Verify if this vulnerability is exploitable in the current configuration.`,
            references: cve.references.length > 0 ? cve.references : [`https://nvd.nist.gov/vuln/detail/${cve.id}`],
          });

          allCveIds.set(cve.id, finding);
        }
      } catch (err) {
        errors.push(`Failed to fetch live CVEs for ${tech.name}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // Fetch recent CVEs from last 30 days
    try {
      const recentCves = await fetchRecentCves(30);
      for (const cve of recentCves) {
        if (allCveIds.has(cve.id)) continue;

        // Check if recent CVE matches any detected technology
        const matchesTech = techs.some(t => {
          const nameLower = t.name.toLowerCase();
          const cveDescLower = (cve.description || '').toLowerCase();
          const cveTitleLower = (cve.title || '').toLowerCase();
          return cveDescLower.includes(nameLower) || cveTitleLower.includes(nameLower);
        });

        if (matchesTech) {
          logExploit(module, 'Recent CVE Match', domain, `${cve.id} (${cve.severity})`);

          const matchedTech = techs.find(t => {
            const nameLower = t.name.toLowerCase();
            const cveDescLower = (cve.description || '').toLowerCase();
            const cveTitleLower = (cve.title || '').toLowerCase();
            return cveDescLower.includes(nameLower) || cveTitleLower.includes(nameLower);
          });

          const techLabel = matchedTech ? `${matchedTech.name} ${matchedTech.version || ''}` : 'technology stack';

          const finding = generateFinding({
            title: `Recent CVE: ${cve.title || cve.id}`,
            description: cve.description || `Recent vulnerability ${cve.id} potentially affects ${techLabel}.`,
            severity: cve.severity as Severity,
            category: 'Live CVE Intelligence',
            affectedAsset: domain,
            evidence: `${techLabel} - ${cve.id} (CVSS: ${cve.cvss}) [Source: ${cve.source}, Published: ${cve.publishedDate}]`,
            impact: `Recently disclosed CVE (last 30 days). CVSS score: ${cve.cvss}. May not yet have patches available.`,
            remediation: `Assess exposure to ${cve.id}. Apply vendor patches or mitigations when available. Monitor for updates.`,
            references: cve.references.length > 0 ? cve.references : [`https://nvd.nist.gov/vuln/detail/${cve.id}`],
          });

          allCveIds.set(cve.id, finding);
        }
      }
    } catch (err) {
      errors.push(`Failed to fetch recent CVEs: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Convert map to array and sort by severity (CRITICAL first)
    findings.push(...Array.from(allCveIds.values()).sort((a, b) => severityRank(a.severity) - severityRank(b.severity)));

    // AI-enhanced CVE relevance scoring and exploitability assessment
    try {
      const ai = getAI();
      const cveFindings = findings.filter(f => f.title.includes('CVE-'));
      if (cveFindings.length > 0) {
        // Score CVSS for top findings using AI
        const topCves = cveFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 5);
        for (const cve of topCves) {
          try {
            const cvssScore = await ai.scoreFindingCvss(cve);
            if (cvssScore > 0) {
              cve.cvssScore = cvssScore;
              cve.description = `CVSS Score: ${cvssScore}/10 - ${cve.description}`;
            }
          } catch {}
        }
        // Use AI to assess exploitability and relevance
        const techStack = [...new Set(cveFindings.flatMap(f => f.title.match(/CVE-\d{4}-\d+/g) || []))];
        const aiResult = await ai.reasonAboutVulnerabilities(techStack, cveFindings);
        if (aiResult.versionSpecificRisks.length > 0) {
          for (const risk of aiResult.versionSpecificRisks) {
            findings.push(generateFinding(
              `AI CVE Relevance: ${risk}`,
              `AI assessed CVE relevance and identified version-specific risk: ${risk}. This CVE may be more/less relevant than generic scoring suggests.`,
              Severity.HIGH,
              'AI CVE Analysis',
              domain,
              'Verify the specific version match and test exploitability in your environment',
              'Generic CVE scores may not reflect your specific version/configuration',
              'Test with safe PoC or consult vendor advisory for exact version impact',
              [],
            ));
          }
        }
        if (aiResult.zeroDayIndicators.length > 0) {
          for (const indicator of aiResult.zeroDayIndicators) {
            findings.push(generateFinding(
              `AI Zero-Day Indicator: ${indicator}`,
              `AI detected potential zero-day indicator from CVE analysis: ${indicator}. This may indicate actively exploited or weaponized vulnerabilities.`,
              Severity.CRITICAL,
              'AI CVE Analysis',
              domain,
              'Immediately investigate and prioritize patching. Check for active exploitation in the wild.',
              'Zero-day indicators suggest active exploitation - highest priority for remediation',
              'Apply emergency patches. Implement WAF rules. Monitor for exploitation attempts.',
              [],
            ));
          }
        }
      }
    } catch {}

    logDone(module, `Live CVE scan complete: ${findings.length} findings`, Date.now() - startTime, findings.length);

    return {
      module: 'liveCve' as ScanModule,
      findings,
      duration: Date.now() - startTime,
      errors,
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    logDone(module, `Live CVE scan failed`, duration);
    return {
      module: 'liveCve' as ScanModule,
      findings,
      duration,
      errors: [...errors, error instanceof Error ? error.message : String(error)],
    };
  }
}
