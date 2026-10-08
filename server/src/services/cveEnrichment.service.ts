import { Finding, Severity } from '../types';

// Cache for enriched CVEs (in-memory, 1 hour TTL)
const enrichmentCache = new Map<string, { data: CveEnrichment; expiresAt: number }>();
const CACHE_TTL = 60 * 60 * 1000;

interface CveEnrichment {
  cveId: string;
  description: string;
  severity: string;
  cvssScore: number;
  publishedDate: string;
  lastModifiedDate: string;
  references: string[];
  affectedSoftware: string[];
}

interface NvdCveResponse {
  vulnerabilities?: Array<{
    cve: {
      descriptions?: Array<{ lang: string; value: string }>;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
        cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
        cvssMetricV2?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      };
      published?: string;
      lastModified?: string;
      references?: Array<{ url: string }>;
      configurations?: Array<{
        nodes?: Array<{
          cpeMatch?: Array<{
            criteria?: string;
            versionStartIncluding?: string;
            versionEndExcluding?: string;
          }>;
        }>;
      }>;
    };
  }>;
}

/**
 * Fetch CVE details from NVD API 2.0
 */
async function fetchFromNvd(cveId: string): Promise<CveEnrichment | null> {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'CyberGuard/1.0' }
    });
    if (!response.ok) return null;
    const data: NvdCveResponse = await response.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    const description = vuln.descriptions?.find((d) => d.lang === 'en')?.value || '';
    const metrics = vuln.metrics?.cvssMetricV31?.[0] || vuln.metrics?.cvssMetricV30?.[0] || vuln.metrics?.cvssMetricV2?.[0];
    const cvssScore = metrics?.cvssData?.baseScore || 0;
    const severity = metrics?.cvssData?.baseSeverity || 'UNKNOWN';

    return {
      cveId,
      description,
      severity,
      cvssScore,
      publishedDate: vuln.published || '',
      lastModifiedDate: vuln.lastModified || '',
      references: (vuln.references || []).map((r) => r.url).slice(0, 5),
      affectedSoftware: extractAffectedSoftware(vuln),
    };
  } catch {
    return null;
  }
}

interface NvdVulnConfig {
  configurations?: Array<{
    nodes?: Array<{
      cpeMatch?: Array<{
        criteria?: string;
        versionStartIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  }>;
}

function extractAffectedSoftware(vuln: NvdVulnConfig): string[] {
  const software: string[] = [];
  const configs = vuln.configurations || [];
  for (const config of configs) {
    for (const node of config.nodes || []) {
      for (const match of node.cpeMatch || []) {
        if (match.criteria) {
          const parts = match.criteria.split(':');
          if (parts.length >= 5) {
            software.push(`${parts[3]} ${parts[4]} ${match.versionStartIncluding || ''}-${match.versionEndExcluding || ''}`.trim());
          }
        }
      }
    }
  }
  return [...new Set(software)].slice(0, 10);
}

/**
 * Enrich a finding with CVE data from NVD
 */
export async function enrichFindingWithCve(finding: Finding): Promise<Finding> {
  const cveMatch = finding.evidence?.match(/(CVE-\d{4}-\d+)/) || finding.title?.match(/(CVE-\d{4}-\d+)/);
  if (!cveMatch) return finding;

  const cveId = cveMatch[1];

  // Check if already enriched (has real description, not just CVE ID)
  if (finding.description && finding.description.length > 50 && !finding.description.includes('This vulnerability will be enriched')) {
    return finding;
  }

  // Check cache
  const cached = enrichmentCache.get(cveId);
  if (cached && cached.expiresAt > Date.now()) {
    return applyEnrichment(finding, cached.data);
  }

  // Fetch from NVD
  try {
    const enrichment = await fetchFromNvd(cveId);
    if (!enrichment) {
      // If NVD fails, try to at least provide a basic description
      return applyBasicEnrichment(finding, cveId);
    }

    // Cache it
    enrichmentCache.set(cveId, { data: enrichment, expiresAt: Date.now() + CACHE_TTL });

    return applyEnrichment(finding, enrichment);
  } catch {
    return applyBasicEnrichment(finding, cveId);
  }
}

/**
 * Basic enrichment when NVD is unavailable — at least provide useful context
 */
function applyBasicEnrichment(finding: Finding, cveId: string): Finding {
  // If description is just the nmap line, improve it
  if (finding.description && finding.description.length < 50) {
    finding.description = `${cveId} — Severity: ${finding.severity}\n\nA vulnerability was detected by automated scanning. The NVD enrichment service was unavailable, but this CVE is known to affect the target.\n\nRefer to the NVD link below for full details.`;
  }
  // Make sure evidence has the NVD link
  if (finding.references && !finding.references.some(r => r.includes('nvd.nist.gov'))) {
    finding.references.push(`https://nvd.nist.gov/vuln/detail/${cveId}`);
  }
  return finding;
}

function applyEnrichment(finding: Finding, enrichment: CveEnrichment): Finding {
  // Update title with CVE ID and short summary from NVD
  if (enrichment.description && enrichment.description.length > 10) {
    const shortDesc = enrichment.description.split('.')[0];
    finding.title = `${enrichment.cveId}: ${shortDesc}`;
  } else {
    finding.title = enrichment.cveId;
  }

  // Build a proper detailed description
  const descParts: string[] = [];
  descParts.push(`**${enrichment.cveId}** — CVSS ${enrichment.cvssScore} (${enrichment.severity})`);
  descParts.push('');
  descParts.push(enrichment.description);
  if (enrichment.affectedSoftware.length > 0) {
    descParts.push('');
    descParts.push(`Affected software: ${enrichment.affectedSoftware.join(', ')}`);
  }
  if (enrichment.publishedDate) {
    descParts.push(`Published: ${enrichment.publishedDate.split('T')[0]}`);
  }
  finding.description = descParts.join('\n');

  // Update CVSS score
  if (enrichment.cvssScore > 0) {
    finding.cvssScore = enrichment.cvssScore;
    if (enrichment.cvssScore >= 9.0) finding.severity = Severity.CRITICAL;
    else if (enrichment.cvssScore >= 7.0) finding.severity = Severity.HIGH;
    else if (enrichment.cvssScore >= 4.0) finding.severity = Severity.MEDIUM;
    else if (enrichment.cvssScore > 0) finding.severity = Severity.LOW;
  }

  // Enrich evidence with NVD details
  const enrichedEvidence = [
    finding.evidence,
    '',
    `--- NVD Enrichment ---`,
    `Description: ${enrichment.description.slice(0, 500)}`,
    `CVSS Score: ${enrichment.cvssScore} (${enrichment.severity})`,
    `Published: ${enrichment.publishedDate}`,
    `Modified: ${enrichment.lastModifiedDate}`,
    enrichment.affectedSoftware.length > 0 ? `Affected: ${enrichment.affectedSoftware.join(', ')}` : '',
    enrichment.references.length > 0 ? `References:\n${enrichment.references.map(r => `  - ${r}`).join('\n')}` : '',
  ].filter(Boolean).join('\n');

  finding.evidence = enrichedEvidence;
  finding.references = [...new Set([...finding.references, ...enrichment.references])];

  return finding;
}

/**
 * Batch enrich multiple findings with CVE data
 */
export async function enrichFindings(findings: Finding[]): Promise<Finding[]> {
  // Process in batches of 5 to avoid rate limiting
  const enriched: Finding[] = [];
  for (let i = 0; i < findings.length; i += 5) {
    const batch = findings.slice(i, i + 5);
    const results = await Promise.allSettled(batch.map(f => enrichFindingWithCve(f)));
    enriched.push(...results.map((r, idx) => r.status === 'fulfilled' ? r.value : batch[idx]));
  }
  return enriched;
}
