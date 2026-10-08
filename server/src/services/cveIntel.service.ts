import logger from '../utils/logger';

export interface LiveCveResult {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  title: string;
  description: string;
  publishedDate: string;
  references: string[];
  source: string;
}

interface CacheEntry {
  data: LiveCveResult[];
  timestamp: number;
}

const CACHE_TTL_MS = 60 * 60 * 1000;
const cache = new Map<string, CacheEntry>();
const USER_AGENT = 'CyberGuard-CVE-Intel/1.0';

function getFromCache(key: string): LiveCveResult[] | null {
  const entry = cache.get(key);
  if (!entry) {
    logger.debug(`Cache miss: ${key}`);
    return null;
  }
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    logger.debug(`Cache expired: ${key}`);
    return null;
  }
  logger.debug(`Cache hit: ${key}`);
  return entry.data;
}

function setCache(key: string, data: LiveCveResult[]): void {
  cache.set(key, { data, timestamp: Date.now() });
}

function normalizeSeverity(input: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  const upper = input.toUpperCase();
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW') {
    return upper;
  }
  return 'LOW';
}

function severityRank(s: string): number {
  switch (s) {
    case 'CRITICAL': return 0;
    case 'HIGH': return 1;
    case 'MEDIUM': return 2;
    case 'LOW': return 3;
    default: return 4;
  }
}

function sortBySeverity(results: LiveCveResult[]): LiveCveResult[] {
  return results.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

function deduplicateById(results: LiveCveResult[]): LiveCveResult[] {
  const seen = new Map<string, LiveCveResult>();
  for (const r of results) {
    const existing = seen.get(r.id);
    if (!existing || severityRank(r.severity) < severityRank(existing.severity)) {
      seen.set(r.id, r);
    }
  }
  return [...seen.values()];
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 15000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    return resp;
  } finally {
    clearTimeout(timer);
  }
}

function buildNvdQuery(technology: string, version?: string): string {
  const term = version ? `${technology} ${version}` : technology;
  return `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=50`;
}

interface NvdVulnerability {
  cve: {
    id: string;
    descriptions: Array<{ lang: string; value: string }>;
    published: string;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
      cvssMetricV2?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
    };
    references?: Array<{ url: string }>;
  };
}

function parseNvdResponse(data: NvdVulnerability[]): LiveCveResult[] {
  const results: LiveCveResult[] = [];
  for (const vuln of data) {
    const cve = vuln.cve;
    const desc = cve.descriptions.find(d => d.lang === 'en')?.value ?? '';
    const metrics = cve.metrics;
    let cvss = 0;
    let severity = 'LOW';
    if (metrics?.cvssMetricV31?.length) {
      cvss = metrics.cvssMetricV31[0].cvssData.baseScore;
      severity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
    } else if (metrics?.cvssMetricV30?.length) {
      cvss = metrics.cvssMetricV30[0].cvssData.baseScore;
      severity = metrics.cvssMetricV30[0].cvssData.baseSeverity;
    } else if (metrics?.cvssMetricV2?.length) {
      cvss = metrics.cvssMetricV2[0].cvssData.baseScore;
      severity = metrics.cvssMetricV2[0].cvssData.baseSeverity;
    }
    results.push({
      id: cve.id,
      severity: normalizeSeverity(severity),
      cvss,
      title: cve.id,
      description: desc,
      publishedDate: cve.published,
      references: (cve.references ?? []).map(r => r.url),
      source: 'NVD',
    });
  }
  return results;
}

async function fetchNvd(technology: string, version?: string): Promise<LiveCveResult[]> {
  try {
    const url = buildNvdQuery(technology, version);
    const resp = await fetchWithTimeout(url, {
      headers: { 'User-Agent': USER_AGENT },
    });
    if (!resp.ok) {
      logger.warn(`NVD API returned ${resp.status} for ${technology}`);
      return [];
    }
    const json = await resp.json() as { vulnerabilities?: NvdVulnerability[] };
    return parseNvdResponse(json.vulnerabilities ?? []);
  } catch (err) {
    logger.error(`NVD fetch failed for ${technology}`, { error: (err as Error).message });
    return [];
  }
}

interface GhAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  published_at: string;
  html_advisory_permalink: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string;
    first_patched_version: { identifier: string } | null;
  }>;
}

function parseGhAdvisoryResponse(data: GhAdvisory[]): LiveCveResult[] {
  const results: LiveCveResult[] = [];
  for (const adv of data) {
    const id = adv.cve_id ?? adv.ghsa_id;
    results.push({
      id,
      severity: normalizeSeverity(adv.severity),
      cvss: adv.severity === 'critical' ? 9.5 : adv.severity === 'high' ? 7.5 : adv.severity === 'medium' ? 5.0 : 2.5,
      title: adv.summary || id,
      description: adv.description || adv.summary,
      publishedDate: adv.published_at,
      references: [adv.html_advisory_permalink],
      source: 'GitHub Advisory',
    });
  }
  return results;
}

async function fetchGitHubAdvisories(technology: string): Promise<LiveCveResult[]> {
  try {
    const url = `https://api.github.com/advisories?affects=${encodeURIComponent(technology)}&per_page=50`;
    const resp = await fetchWithTimeout(url, {
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'application/vnd.github+json',
      },
    });
    if (!resp.ok) {
      logger.warn(`GitHub Advisory API returned ${resp.status} for ${technology}`);
      return [];
    }
    const json = await resp.json() as GhAdvisory[];
    return parseGhAdvisoryResponse(json);
  } catch (err) {
    logger.error(`GitHub Advisory fetch failed for ${technology}`, { error: (err as Error).message });
    return [];
  }
}

interface OsvQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  published: string;
  modified: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    versions?: string[];
  }>;
  references?: Array<{ type: string; url: string }>;
}

function parseOsvSeverity(sevArr?: Array<{ type: string; score: string }>): { severity: string; cvss: number } {
  if (!sevArr?.length) {
    return { severity: 'LOW', cvss: 0 };
  }
  const sev = sevArr[0];
  const scoreMatch = sev.score.match(/(\d+(\.\d+)?)/);
  const cvss = scoreMatch ? parseFloat(scoreMatch[1]) : 0;
  if (cvss >= 9.0) return { severity: 'CRITICAL', cvss };
  if (cvss >= 7.0) return { severity: 'HIGH', cvss };
  if (cvss >= 4.0) return { severity: 'MEDIUM', cvss };
  return { severity: 'LOW', cvss };
}

function parseOsvResponse(data: OsvVulnerability[]): LiveCveResult[] {
  const results: LiveCveResult[] = [];
  for (const vuln of data) {
    const { severity, cvss } = parseOsvSeverity(vuln.severity);
    const refs = (vuln.references ?? []).map(r => r.url).filter(u => u.startsWith('http'));
    results.push({
      id: vuln.id,
      severity: normalizeSeverity(severity),
      cvss,
      title: vuln.summary || vuln.id,
      description: vuln.details || vuln.summary || '',
      publishedDate: vuln.published || vuln.modified,
      references: refs.length ? refs : [],
      source: 'OSV.dev',
    });
  }
  return results;
}

async function fetchOsv(technology: string, version?: string): Promise<LiveCveResult[]> {
  const ecosystems = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'composer', 'RubyGems'];
  const allResults: LiveCveResult[] = [];

  const queries: OsvQuery[] = ecosystems.map(ecosystem => ({
    package: { name: technology, ecosystem },
    ...(version ? { version } : {}),
  }));

  try {
    const resp = await fetchWithTimeout('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT,
      },
      body: JSON.stringify({ queries }),
    });
    if (!resp.ok) {
      logger.warn(`OSV API returned ${resp.status}`);
      return [];
    }
    const json = await resp.json() as { results: Array<{ vulns?: OsvVulnerability[] }> };
    for (const result of json.results ?? []) {
      if (result.vulns) {
        allResults.push(...parseOsvResponse(result.vulns));
      }
    }
    return allResults;
  } catch (err) {
    logger.error(`OSV fetch failed for ${technology}`, { error: (err as Error).message });
    return [];
  }
}

export async function fetchLiveCves(technology: string, version?: string): Promise<LiveCveResult[]> {
  const cacheKey = `live:${technology}:${version ?? 'all'}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const [nvdResults, ghResults, osvResults] = await Promise.all([
    fetchNvd(technology, version),
    fetchGitHubAdvisories(technology),
    fetchOsv(technology, version),
  ]);

  const all = [...nvdResults, ...ghResults, ...osvResults];
  const deduped = deduplicateById(all);
  const sorted = sortBySeverity(deduped);

  setCache(cacheKey, sorted);
  logger.info(`Fetched ${sorted.length} CVEs for ${technology} ${version ?? ''}`, {
    nvd: nvdResults.length,
    github: ghResults.length,
    osv: osvResults.length,
    total: sorted.length,
  });

  return sorted;
}

export async function fetchCvesByKeyword(keyword: string): Promise<LiveCveResult[]> {
  const cacheKey = `keyword:${keyword}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const [nvdResults, ghResults] = await Promise.all([
    fetchNvd(keyword),
    fetchGitHubAdvisories(keyword),
  ]);

  const all = [...nvdResults, ...ghResults];
  const deduped = deduplicateById(all);
  const sorted = sortBySeverity(deduped);

  setCache(cacheKey, sorted);
  logger.info(`Keyword search "${keyword}" returned ${sorted.length} results`);

  return sorted;
}

export async function fetchRecentCves(daysBack: number = 30): Promise<LiveCveResult[]> {
  const cacheKey = `recent:${daysBack}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const startDate = new Date();
  startDate.setDate(startDate.getDate() - daysBack);
  const startDateStr = startDate.toISOString().split('T')[0];

  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startDateStr}T00:00:00.000&resultsPerPage=100`;
    const resp = await fetchWithTimeout(url, {
      headers: { 'User-Agent': USER_AGENT },
    });
    if (!resp.ok) {
      logger.warn(`NVD recent CVEs API returned ${resp.status}`);
      return [];
    }
    const json = await resp.json() as { vulnerabilities?: NvdVulnerability[] };
    const results = parseNvdResponse(json.vulnerabilities ?? []);
    const sorted = sortBySeverity(results);

    setCache(cacheKey, sorted);
    logger.info(`Fetched ${sorted.length} recent CVEs from last ${daysBack} days`);
    return sorted;
  } catch (err) {
    logger.error('Failed to fetch recent CVEs', { error: (err as Error).message });
    return [];
  }
}
