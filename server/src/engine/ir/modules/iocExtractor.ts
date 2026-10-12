import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, basename } from 'path';
import { IRModuleResult, IOC, IOCType, Evidence, IRScanContext, Severity, Finding } from '../../../types';
import { logInfo, logDone } from '../../scanLogger';
import { generateFinding } from '../../modules/shared';

const MODULE_NAME = 'iocExtractor';

const IOC_PATTERNS: Record<IOCType, RegExp[]> = {
  ip: [
    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
  ],
  domain: [
    /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  ],
  url: [
    /\bhttps?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
  ],
  hash: [
    /\b[a-fA-F0-9]{32}\b/g,
    /\b[a-fA-F0-9]{40}\b/g,
    /\b[a-fA-F0-9]{64}\b/g,
  ],
  email: [
    /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  ],
  'registry-key': [
    /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s\r\n]+/gi,
    /HK(LM|CU|CR|U|CC)\\[^\s\r\n]+/gi,
  ],
  'file-path': [
    /[A-Za-z]:\\[^\s\r\n"<>|*?]+/g,
    /\/[^\s\r\n"<>|*?]+/g,
  ],
  mutex: [
    /(?:Global|Local)\\[^\s\r\n]{3,}/g,
  ],
  cve: [
    /CVE-\d{4}-\d{4,7}/gi,
  ],
  'mitre-technique': [
    /T\d{4}(?:\.\d{3})?/g,
  ],
};

const KNOWN_MALICIOUS: Record<string, { type: IOCType; tags: string[]; mitre: string[] }> = {
  'cmd.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1059.003'] },
  'powershell.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1059.001'] },
  'wscript.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1059.005'] },
  'cscript.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1059.005'] },
  'mshta.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1218.005'] },
  'regsvr32.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1218.010'] },
  'rundll32.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1218.011'] },
  'certutil.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1105'] },
  'bitsadmin.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1197'] },
  'wmic.exe': { type: 'file-path', tags: ['lolbin'], mitre: ['T1047'] },
};

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.club', '.work', '.date'];

function extractIOCsFromText(text: string, source: string, evidenceId: string): IOC[] {
  const iocs: IOC[] = [];
  const seen = new Set<string>();

  for (const [type, patterns] of Object.entries(IOC_PATTERNS)) {
    for (const pattern of patterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        const value = match[0].trim();
        const key = `${type}:${value}`;
        
        if (seen.has(key)) continue;
        if (value.length < 3 || value.length > 500) continue;
        
        if (type === 'ip' && isPrivateIP(value)) continue;
        if (type === 'domain' && isBenignDomain(value)) continue;
        
        seen.add(key);
        
        const known = KNOWN_MALICIOUS[value.toLowerCase()] || KNOWN_MALICIOUS[basename(value).toLowerCase()];
        
        iocs.push({
          id: `ioc-${createHash('sha1').update(key).digest('hex').slice(0, 8)}`,
          caseId: '', // Will be set by caller
          type: type as IOCType,
          value,
          description: known ? `Known suspicious: ${known.tags.join(', ')}` : `Extracted from ${source}`,
          confidence: known ? 0.9 : 0.5,
          source,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          mitreTechniques: known?.mitre || [],
          tags: known?.tags || [type],
          relatedFindings: [],
        });
      }
    }
  }

  return iocs;
}

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127 ||
    parts[0] === 0 ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

function isBenignDomain(domain: string): boolean {
  const benign = [
    'microsoft.com', 'google.com', 'amazon.com', 'github.com', 'cloudflare.com',
    'windowsupdate.com', 'office.com', 'live.com', 'bing.com', 'yahoo.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'adobe.com', 'oracle.com',
    'vmware.com', 'citrix.com', 'docker.com', 'kubernetes.io', 'redhat.com',
  ];
  
  const lower = domain.toLowerCase();
  if (benign.some(b => lower.endsWith(b))) return true;
  
  for (const tld of SUSPICIOUS_TLDS) {
    if (lower.endsWith(tld)) return false;
  }
  
  return false;
}

function createHash(algorithm: string) {
  return require('crypto').createHash(algorithm);
}

export async function runIOCExtraction(context: IRScanContext): Promise<IRModuleResult> {
  const startTime = Date.now();
  const result: IRModuleResult = {
    iocs: [],
    findings: [],
    errors: [],
  };

  logInfo(MODULE_NAME, `Extracting IOCs for case ${context.caseId}`);

  const evidenceDir = join(process.cwd(), 'evidence', context.caseId);
  if (!existsSync(evidenceDir)) {
    result.errors.push('Evidence directory not found');
    return result;
  }

  const manifestPath = join(evidenceDir, 'evidence-manifest.json');
  if (!existsSync(manifestPath)) {
    result.errors.push('Evidence manifest not found');
    return result;
  }

  const evidenceList: Evidence[] = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const allIOCs: IOC[] = [];
  const seenValues = new Set<string>();

  for (const evidence of evidenceList) {
    try {
      let content = '';
      
      if (evidence.type === 'log-files' || evidence.type === 'registry' || evidence.type === 'file-system') {
        content = readFileSync(evidence.path, 'utf8');
      } else if (evidence.type === 'memory-dump') {
        try {
          const { execFileSync } = require('child_process');
          content = execFileSync('strings', ['-n', '6', evidence.path], { 
            timeout: 120000, 
            maxBuffer: 100 * 1024 * 1024 
          }).toString();
        } catch {
          content = readFileSync(evidence.path, 'utf8').slice(0, 1000000);
        }
      } else if (evidence.type === 'pcap') {
        try {
          const { execFileSync } = require('child_process');
          content = execFileSync('tshark', ['-r', evidence.path, '-T', 'fields', '-e', 'dns.qry.name', '-e', 'http.host', '-e', 'ip.src', '-e', 'ip.dst'], { 
            timeout: 60000 
          }).toString();
        } catch {
          continue;
        }
      } else {
        continue;
      }

      const extracted = extractIOCsFromText(content, evidence.source, evidence.id);
      
      for (const ioc of extracted) {
        ioc.caseId = context.caseId;
        const dedupKey = `${ioc.type}:${ioc.value}`;
        
        if (!seenValues.has(dedupKey)) {
          seenValues.add(dedupKey);
          allIOCs.push(ioc);
        }
      }
    } catch (e) {
      result.errors.push(`Failed to process ${evidence.id}: ${e}`);
    }
  }

  // Enrich IOCs with context
  for (const ioc of allIOCs) {
    if (ioc.type === 'ip') {
      ioc.tags.push('network');
      if (!ioc.mitreTechniques.includes('T1071')) ioc.mitreTechniques.push('T1071');
    }
    if (ioc.type === 'domain') {
      ioc.tags.push('network');
      if (!ioc.mitreTechniques.includes('T1071.001')) ioc.mitreTechniques.push('T1071.001');
    }
    if (ioc.type === 'hash') {
      ioc.tags.push('file');
      if (!ioc.mitreTechniques.includes('T1552')) ioc.mitreTechniques.push('T1552');
    }
  }

  result.iocs = allIOCs;

  // Generate findings for high-confidence IOCs
  const highConfidence = allIOCs.filter(i => i.confidence > 0.7);
  for (const ioc of highConfidence.slice(0, 30)) {
    result.findings!.push(generateFinding({
      title: `IOC Identified: ${ioc.type.toUpperCase()}`,
      description: `${ioc.value} - ${ioc.description}`,
      severity: ioc.confidence > 0.85 ? 'high' : 'medium',
      category: 'ioc',
      target: context.targetScope[0] || 'unknown',
      evidence: { ioc: ioc.id, type: ioc.type, mitre: ioc.mitreTechniques },
      references: ioc.mitreTechniques.map(t => `https://attack.mitre.org/techniques/${t}/`),
    }));
  }

  // Write IOC output
  const outputDir = join(process.cwd(), 'ir-output', context.caseId);
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(join(outputDir, 'iocs.json'), JSON.stringify(allIOCs, null, 2));

  // Export STIX bundle
  const stixBundle = generateSTIXBundle(allIOCs, context.caseId);
  writeFileSync(join(outputDir, 'iocs-stix.json'), JSON.stringify(stixBundle, null, 2));

  logDone(MODULE_NAME, `Extracted ${allIOCs.length} IOCs (${highConfidence.length} high-confidence) in ${Date.now() - startTime}ms`);
  return result;
}

function generateSTIXBundle(iocs: IOC[], caseId: string) {
  const objects = [];
  
  for (const ioc of iocs) {
    const stixType = mapIOCTypeToSTIX(ioc.type);
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${ioc.id}`,
      created: new Date(ioc.firstSeen).toISOString(),
      modified: new Date(ioc.lastSeen).toISOString(),
      name: `IOC: ${ioc.value}`,
      description: ioc.description,
      indicator_types: ['malicious-activity'],
      pattern: `[${stixType}:value = '${escapeSTIX(ioc.value)}']`,
      pattern_type: 'stix',
      valid_from: new Date(ioc.firstSeen).toISOString(),
      labels: ioc.tags,
      external_references: ioc.mitreTechniques.map(t => ({
        source_name: 'mitre-attack',
        external_id: t,
        url: `https://attack.mitre.org/techniques/${t}/`,
      })),
    });
  }
  
  return {
    type: 'bundle',
    id: `bundle--${createHash('sha1').update(caseId).digest('hex').slice(0, 16)}`,
    spec_version: '2.1',
    objects,
  };
}

function mapIOCTypeToSTIX(type: IOCType): string {
  const map: Record<IOCType, string> = {
    ip: 'ipv4-addr',
    domain: 'domain-name',
    url: 'url',
    hash: 'file',
    email: 'email-addr',
    'registry-key': 'windows-registry-key',
    'file-path': 'file',
    mutex: 'mutex',
    cve: 'vulnerability',
    'mitre-technique': 'attack-pattern',
  };
  return map[type] || 'artifact';
}

function escapeSTIX(value: string): string {
  return value.replace(/'/g, "\\'");
}

export interface IOCExtractorModule {
  run: typeof runIOCExtraction;
}

export const iocExtractor: IOCExtractorModule = {
  run: runIOCExtraction,
};

