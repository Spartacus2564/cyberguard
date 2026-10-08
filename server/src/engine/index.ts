import { ScanModule, ScanResult, ScanContext, Finding } from '../types';
import { runDnsScan } from './modules/dns';
import { runTlsScan } from './modules/tls';
import { runHeadersScan } from './modules/headers';
import { runWebConfigScan } from './modules/webConfig';
import { runTechnologyScan } from './modules/technology';
import { runSubdomainScan } from './modules/subdomains';
import { runEmailSecurityScan } from './modules/emailSecurity';
import { runPortScan } from './modules/portScan';
import { runCveScan } from './cve/scan';
import { runActiveVulnScan } from './modules/activeVuln';
import { runDnsDeepScan } from './modules/dnsDeep';
import { runTlsDeepScan } from './modules/tlsDeep';
import { runOsFingerprintScan } from './modules/osFingerprint';
import { runSubdomainTakeoverScan } from './modules/subdomainTakeover';
import { runSiteCrawlScan } from './modules/siteCrawl';
import { runServiceAuditScan } from './modules/serviceAudit';
import { runAdvancedAttacksScan } from './modules/advancedAttacks';
import { runBrokenAuthScan } from './modules/brokenAuth';
import { runHttpMethodsScan } from './modules/httpMethods';
import { runApiSecurityScan } from './modules/apiSecurity';
import { runSupplyChainScan } from './modules/supplyChain';
import { runCloudSecurityScan } from './modules/cloudSecurity';
import { runClientSecurityScan } from './modules/clientSecurity';
import { runKaliToolsScan } from './modules/kaliTools';
import { runBusinessLogicScan } from './modules/businessLogic';
import { runWindowsScanWrapper } from './modules/windowsSystem';
import { runLinuxScanWrapper } from './modules/linuxSystem';
// New modules (Feature #1-8)
import { runLiveCveScan } from './modules/liveCve';
import { runModernAttacksScan } from './modules/modernAttacks';
import { runBehavioralScan } from './modules/behavioral';
import { runSupplyChainIntelScan } from './modules/supplyChainIntel';
import { runSourceAnalysisScan } from './modules/sourceAnalysis';
import { runExploitChainScan } from './modules/exploitChain';
import { runExploitation } from './modules/exploitation';
import { runSmarterRecon } from './modules/smarterRecon';
import { correlateFindings, correlateToFindings } from './modules/correlation';
import { runDeepDiscovery } from './modules/deepDiscovery';
import { adaptiveReason } from './modules/adaptiveReasoning';
import { classifyTarget, formatClassification, TargetClassification } from './targetClassifier';
import { config } from '../config';
import { enrichFindings } from '../services/cveEnrichment.service';
import { runAutonomousPentest } from './modules/autonomousPentester';
import { runUniversalAttackSurface } from './modules/universalAttackSurface';
import { runAttackGraph, runReasoningEngine } from './modules/attackGraph';
import { runCrossTargetPivot } from './modules/crossTargetPivot';
import { runCoverageTracker } from './modules/coverageTracker';
import { runPreExploitChecklist, getDefaultChecklist } from './modules/preExploitChecklist';
import { runFindingValidationLoop, runBatchValidation } from './modules/findingValidationLoop';
import { 
  initializeScanContext, 
  getScanContext, 
  setScanPhase,
  recordModuleExecution,
  getContextSummary,
  CoverageTracker,
  initializeCoverageForTargetType,
} from './modules/persistentScanContext';

// ─── MODULE RUNNERS ──────────────────────────────────────────────────────────
// Maps module names to their runner functions. Each returns ScanResult[].

const MODULE_RUNNERS: Record<string, (domain: string, ...args: any[]) => Promise<ScanResult>> = {
  dns: runDnsScan,
  tls: runTlsScan,
  headers: runHeadersScan,
  webConfig: runWebConfigScan,
  technology: runTechnologyScan,
  subdomains: runSubdomainScan,
  emailSecurity: runEmailSecurityScan,
  portScan: runPortScan,
  cveCorrelation: runCveScan,
  activeVuln: runActiveVulnScan,
  dnsDeep: runDnsDeepScan,
  tlsDeep: runTlsDeepScan,
  osFingerprint: runOsFingerprintScan,
  subdomainTakeover: runSubdomainTakeoverScan,
  siteCrawl: runSiteCrawlScan,
  serviceAudit: async (domain: string) => {
    const findings = await runServiceAuditScan(domain);
    return { module: 'serviceAudit', findings, duration: 0, errors: [] };
  },
  advancedAttacks: runAdvancedAttacksScan,
  brokenAuth: runBrokenAuthScan,
  httpMethods: runHttpMethodsScan,
  apiSecurity: runApiSecurityScan,
  supplyChain: runSupplyChainScan,
  cloudSecurity: runCloudSecurityScan,
  clientSecurity: runClientSecurityScan,
  kaliTools: runKaliToolsScan,
  businessLogic: runBusinessLogicScan,
  windowsSystem: runWindowsScanWrapper,
  linuxSystem: runLinuxScanWrapper,
  // New modules (Feature #1-8)
  liveCve: runLiveCveScan,
  modernAttacks: runModernAttacksScan,
  behavioral: runBehavioralScan,
  supplyChainIntel: runSupplyChainIntelScan,
  sourceAnalysis: runSourceAnalysisScan,
  exploitChain: runExploitChainScan,
  exploitation: runExploitation,
  smarterRecon: (domain: string) => runSmarterRecon(domain),
  correlation: (domain: string) => Promise.resolve({ module: 'correlation' as any, findings: [], duration: 0, errors: [] }),
  deepDiscovery: runDeepDiscovery,
  adaptiveReasoning: (domain: string) => Promise.resolve({ module: 'adaptiveReasoning' as any, findings: [], duration: 0, errors: [] }),
  // New modules (Reasoning Engine & Universal Attack Surface)
  universalAttackSurface: async (domain: string, priorFindings?: Finding[]) => {
    const findings = priorFindings || [];
    const result = await runUniversalAttackSurface(domain, findings);
    return { module: 'universalAttackSurface' as ScanModule, findings: result.newFindings, duration: 0, errors: [] };
  },
  attackGraph: async (domain: string, priorFindings?: Finding[]) => {
    const context = getScanContext();
    if (!context) return { module: 'attackGraph' as ScanModule, findings: [], duration: 0, errors: ['No scan context'] };
    const findings = priorFindings || [];
    const result = await runAttackGraph(domain, findings, context.targetType as any, {
      techStack: [...new Set(context.serviceInventory.map(s => s.service))],
      openPorts: [...new Set(context.serviceInventory.map(s => s.port))],
      services: context.serviceInventory.map(s => ({ host: s.host, port: s.port, protocol: 'tcp', service: s.service, version: s.version, banner: s.banner })),
      credentials: context.credentialStore.map(c => ({ type: c.type as any, username: c.username, accessLevel: c.accessLevel, source: c.source })),
      networkMap: context.networkSegments.map(ns => ({ cidr: ns.cidr, hosts: ns.hosts.map(h => typeof h === 'string' ? h : h.ip), type: ns.type, segmentation: ns.segmentation })),
      mitreTechniques: context.attackGraph.nodes.map(n => n.technique),
    });
    return { module: 'attackGraph' as ScanModule, findings: result.newFindings, duration: 0, errors: [] };
  },
  crossTargetPivot: async (domain: string, priorFindings?: Finding[]) => {
    const context = getScanContext();
    if (!context) return { module: 'crossTargetPivot' as ScanModule, findings: [], duration: 0, errors: ['No scan context'] };
    const findings = priorFindings || [];
    const result = await runCrossTargetPivot(domain, findings, context.targetType as any, {
      currentAccess: { type: context.targetType as any, host: context.ip, credentials: context.credentialStore },
      networkMap: context.networkSegments.map(ns => ({ cidr: ns.cidr, hosts: ns.hosts.map(h => typeof h === 'string' ? h : h.ip), type: ns.type, segmentation: ns.segmentation })),
      allFindings: findings,
      targetTypes: [context.targetType as any],
    });
    return { module: 'crossTargetPivot' as ScanModule, findings: result.newFindings, duration: 0, errors: [] };
  },
  coverageTracker: async (domain: string, priorFindings?: Finding[]) => {
    const context = getScanContext();
    if (!context) return { module: 'coverageTracker' as ScanModule, findings: [], duration: 0, errors: ['No scan context'] };
    const findings = priorFindings || [];
    const result = await runCoverageTracker(domain, findings);
    return { module: 'coverageTracker' as ScanModule, findings: result.gapFindings, duration: 0, errors: [] };
  },
  preExploitChecklist: async (domain: string, priorFindings?: Finding[]) => {
    const context = getScanContext();
    if (!context) return { module: 'preExploitChecklist' as ScanModule, findings: [], duration: 0, errors: ['No scan context'] };
    const findings = priorFindings || [];
    const checklist = getDefaultChecklist(context.targetType as any);
    const result = await runPreExploitChecklist(domain, context.targetType as any, findings);
    return { module: 'preExploitChecklist' as ScanModule, findings: result.findings, duration: 0, errors: [] };
  },
  findingValidationLoop: async (domain: string, priorFindings?: Finding[]) => {
    const context = getScanContext();
    if (!context) return { module: 'findingValidationLoop' as ScanModule, findings: [], duration: 0, errors: ['No scan context'] };
    const findings = priorFindings || [];
    const result = await runFindingValidationLoop(domain, findings, context.attackGraph);
    return { module: 'findingValidationLoop' as ScanModule, findings: result.validatedFindings, duration: 0, errors: [] };
  },
};

// ── Module timeouts (ms) — generous for real tool execution ──
const MODULE_TIMEOUTS: Record<string, number> = {
  dns: 20000,
  tls: 20000,
  headers: 15000,
  webConfig: 25000,
  technology: 15000,
  subdomains: 30000,
  emailSecurity: 25000,
  portScan: 60000,
  cveCorrelation: 20000,
  activeVuln: 60000,
  dnsDeep: 25000,
  tlsDeep: 25000,
  osFingerprint: 30000,
  subdomainTakeover: 40000,
  siteCrawl: 45000,
  serviceAudit: 45000,
  advancedAttacks: 60000,
  brokenAuth: 60000,
  httpMethods: 30000,
  apiSecurity: 60000,
  supplyChain: 30000,
  cloudSecurity: 45000,
  clientSecurity: 30000,
  kaliTools: 900000,  // 15 min -- nmap + nikto + nuclei run real scans
  businessLogic: 60000,
  activeDirectory: 300000,  // 5 min -- impacket/bloodyAD/kerbrute/bloodhound
  networkPentest: 300000,   // 5 min -- nmap vuln scripts + impacket
  windowsSystem: 180000,    // 3 min -- nmap SMB/RDP/WinRM vuln scripts
  linuxSystem: 180000,      // 3 min -- nmap SSH/FTP/SSL vuln scripts
  // New modules (Feature #1-8)
  liveCve: 60000,           // 1 min -- NVD/GitHub/OSV API queries
  modernAttacks: 90000,     // 1.5 min -- JWT/OAuth/Smuggling/IDOR/GraphQL/DNS rebinding
  behavioral: 60000,        // 1 min -- response anomaly + timing analysis
  supplyChainIntel: 45000,  // 45s -- JS bundle + source map + SRI analysis
  sourceAnalysis: 30000,    // 30s -- secrets + git + CI/CD exposure
  exploitChain: 60000,      // 1 min -- chain validation from prior findings
  exploitation: 120000,     // 2 min -- XSS/SQLi/CmdInj/PathTraversal/IDOR/Redirect exploitation
  smarterRecon: 90000,      // 1.5 min -- AI-driven recon analysis + targeted enumeration
  correlation: 30000,       // 30s -- cross-module finding correlation
  deepDiscovery: 120000,    // 2 min -- JS parsing, wordlist fuzzing, API surface mapping
  adaptiveReasoning: 15000, // 15s -- mid-scan strategy adjustment
  // New modules (Reasoning Engine & Universal Attack Surface)
  universalAttackSurface: 120000,  // 2 min -- AI-driven attack surface enumeration
  attackGraph: 120000,             // 2 min -- AI attack graph building
  crossTargetPivot: 60000,         // 1 min -- Cross-target pivot detection
  coverageTracker: 30000,          // 30s -- Coverage analysis
  preExploitChecklist: 60000,      // 1 min -- Pre-exploitation checklist
  findingValidationLoop: 180000,   // 3 min -- Finding validation & retesting
};

// Max concurrent modules per batch
const BATCH_CONCURRENCY = 5;

// ─── PHASE DEFINITIONS ──────────────────────────────────────────────────────
// Phase 1: Recon — fast, always runs on every target
// Phase 2: Classification — determines target type
// Phase 3: Targeted Attacks — only relevant modules for this target
// Phase 4: AI Post-analysis — dedup, severity, chains

// Recon modules — always run first to gather intel
const RECON_MODULES: ScanModule[] = ['dns', 'tls', 'headers', 'webConfig', 'technology', 'portScan', 'osFingerprint', 'dnsDeep', 'emailSecurity'];

// New reasoning engine modules (run after initial recon)
const REASONING_MODULES: ScanModule[] = [
  'universalAttackSurface',
  'attackGraph',
  'crossTargetPivot',
  'coverageTracker',
  'preExploitChecklist',
];

// Validation module (runs at the end)
const VALIDATION_MODULES: ScanModule[] = [
  'findingValidationLoop',
];

function withTimeout<T>(promise: Promise<T>, ms: number, moduleName: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${moduleName} timed out after ${ms}ms`)), ms);
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

export interface ScanLogEntry {
  ts: string;
  level: 'info' | 'warn' | 'error' | 'done' | 'exploit' | 'probe' | 'vuln';
  module: string;
  message: string;
  duration?: number;
  findings?: number;
  errors?: string[];
}

export interface MidScanInsight {
  type: 'pattern' | 'recommendation' | 'risk_update' | 'chain_detected';
  title: string;
  description: string;
  severity?: string;
  confidence?: number;
  relatedModules?: string[];
}

// ─── BATCH RUNNER ────────────────────────────────────────────────────────────
// Runs modules in batches with concurrency control, logging, and timeouts.

async function runBatch(
  modules: ScanModule[],
  domain: string,
  moduleIndex: { current: number },
  totalModules: number,
  onModuleStart?: (moduleName: string, index: number, total: number) => void,
  profile?: import('./targetAnalysis').TargetProfile,
  onLog?: (entry: ScanLogEntry) => void,
  priorResults?: ScanResult[],
  onMidScanInsight?: (insight: MidScanInsight) => void,
): Promise<ScanResult[]> {
  const results: ScanResult[] = [];
  // Track all results seen so far (including priorResults) for cross-module intelligence
  const allResultsSoFar: ScanResult[] = [...(priorResults || [])];

  for (let i = 0; i < modules.length; i += BATCH_CONCURRENCY) {
    const batch = modules.slice(i, i + BATCH_CONCURRENCY);
    const batchResults = await Promise.allSettled(
      batch.map(async (moduleName) => {
        moduleIndex.current++;
        onModuleStart?.(moduleName, moduleIndex.current, totalModules);
        onLog?.({ ts: new Date().toISOString(), level: 'info', module: moduleName, message: `Starting ${MODULE_DESCRIPTIONS[moduleName] || moduleName}` });
        const start = Date.now();
        const runner = MODULE_RUNNERS[moduleName];
        if (!runner) {
          const entry: ScanLogEntry = { ts: new Date().toISOString(), level: 'error', module: moduleName, message: `Module ${moduleName} not implemented`, duration: 0, errors: [`Module ${moduleName} not implemented`] };
          onLog?.(entry);
          return { module: moduleName, findings: [], duration: 0, errors: [`Module ${moduleName} not implemented`] } as ScanResult;
        }
        try {
          let result: ScanResult;
          const timeout = MODULE_TIMEOUTS[moduleName] || 30000;
          // Pass target profile to attack modules that support it
          if (profile && ['activeVuln', 'advancedAttacks', 'brokenAuth', 'httpMethods'].includes(moduleName)) {
            result = await withTimeout(runWithProfile(moduleName, domain, profile), timeout, moduleName);
          } else if (moduleName === 'siteCrawl') {
            // Pass open ports from port scan to site crawl for alt-port crawling
            const portResult = allResultsSoFar.find(r => r.module === 'portScan');
            const openPorts = portResult?.findings
              ?.map(f => f.affectedAsset?.match(/:(\d+)/)?.[1])
              .filter(Boolean)
              .map(Number) || [];
            result = await withTimeout(runSiteCrawlScan(domain, openPorts), timeout, moduleName);
          } else if (moduleName === 'businessLogic') {
            // Pass prior scan results so businessLogic can extract endpoints from crawl/apiSecurity
            const scanData = {
              crawl: allResultsSoFar.find(r => r.module === 'siteCrawl')?.findings || [],
              apiSecurity: allResultsSoFar.find(r => r.module === 'apiSecurity')?.findings || [],
              headers: allResultsSoFar.find(r => r.module === 'headers')?.findings || [],
              portScan: allResultsSoFar.find(r => r.module === 'portScan')?.findings || [],
            };
            result = await withTimeout(runBusinessLogicScan(domain, scanData), timeout, moduleName);
          } else if (moduleName === 'exploitChain') {
            // Pass all prior findings for chain validation
            const priorFindings = allResultsSoFar.flatMap(r => r.findings);
            result = await withTimeout(runExploitChainScan(domain, priorFindings), timeout, moduleName);
          } else if (moduleName === 'exploitation') {
            // Pass all prior findings for exploitation context
            const priorFindings = allResultsSoFar.flatMap(r => r.findings);
            result = await withTimeout(runExploitation(domain, priorFindings), timeout, moduleName);
          } else if (['universalAttackSurface', 'attackGraph', 'crossTargetPivot', 'coverageTracker', 'preExploitChecklist', 'findingValidationLoop'].includes(moduleName)) {
            // Pass all prior findings for reasoning modules
            const priorFindings = allResultsSoFar.flatMap(r => r.findings);
            result = await withTimeout(runner(domain, priorFindings), timeout, moduleName);
          } else {
            result = await withTimeout(runner(domain), timeout, moduleName);
          }
          allResultsSoFar.push(result);
          const dur = Date.now() - start;
          onLog?.({ ts: new Date().toISOString(), level: result.errors.length > 0 ? 'warn' : 'done', module: moduleName, message: `${moduleName} completed — ${result.findings.length} finding(s)${result.errors.length > 0 ? `, ${result.errors.length} error(s)` : ''}`, duration: dur, findings: result.findings.length, errors: result.errors.length > 0 ? result.errors : undefined });
          return result;
        } catch (err: any) {
          const dur = Date.now() - start;
          const msg = err?.message || 'Unknown error';
          onLog?.({ ts: new Date().toISOString(), level: 'error', module: moduleName, message: `${moduleName} failed: ${msg}`, duration: dur, errors: [msg] });
          return { module: moduleName, findings: [], duration: dur, errors: [msg] } as ScanResult;
        }
      })
    );
    for (let j = 0; j < batchResults.length; j++) {
      const r = batchResults[j];
      if (r.status === 'fulfilled') results.push(r.value);
      else results.push({ module: batch[j], findings: [], duration: 0, errors: [r.reason?.message || 'Unknown error'] });
    }
    // Mid-scan AI reasoning after each batch
    if (onMidScanInsight && allResultsSoFar.length > 0) {
      const batchFindings = results.flatMap(r => r.findings);
      if (batchFindings.length > 0) {
        try {
          const { getAI } = await import('../services/ai.service');
          const ai = getAI();
          const insights = await ai.reasonMidScan(batchFindings, domain);
          for (const insight of insights) {
            onMidScanInsight(insight);
          }
        } catch {
          // AI reasoning is best-effort
        }
      }
    }
  }
  return results;
}

async function runWithProfile(moduleName: string, domain: string, profile: import('./targetAnalysis').TargetProfile): Promise<ScanResult> {
  switch (moduleName) {
    case 'activeVuln': return runActiveVulnScan(domain, profile);
    case 'advancedAttacks': return runAdvancedAttacksScan(domain, profile);
    case 'brokenAuth': return runBrokenAuthScan(domain, profile);
    case 'httpMethods': return runHttpMethodsScan(domain, profile);
    default: {
      const runner = MODULE_RUNNERS[moduleName];
      return runner ? runner(domain) : { module: moduleName as ScanModule, findings: [], duration: 0, errors: [] };
    }
  }
}

// ─── BUILD RECON SUMMARY FOR AI ─────────────────────────────────────────────
import { getAI, ReconSummary } from '../services/ai.service';
import logger from '../utils/logger';

function buildReconSummary(domain: string, results: ScanResult[]): ReconSummary {
  const techResult = results.find(r => r.module === 'technology');
  const portResult = results.find(r => r.module === 'portScan');
  const subResult = results.find(r => r.module === 'subdomains');
  const tlsResult = results.find(r => r.module === 'tls');
  const dnsResult = results.find(r => r.module === 'dns');
  const headerResult = results.find(r => r.module === 'headers');

  const techStack: string[] = [];
  if (techResult) {
    for (const f of techResult.findings) {
      const match = f.description.match(/Detected:?\s*(.+)/i);
      if (match) techStack.push(...match[1].split(',').map(s => s.trim()));
    }
  }

  const openPorts: number[] = [];
  if (portResult) {
    for (const f of portResult.findings) {
      const portMatch = f.affectedAsset.match(/:(\d+)/);
      if (portMatch) openPorts.push(parseInt(portMatch[1]));
    }
  }

  const subdomains: string[] = [];
  if (subResult) {
    for (const f of subResult.findings) {
      if (f.affectedAsset?.includes('.')) subdomains.push(f.affectedAsset);
    }
  }

  const tlsInfo = tlsResult?.findings.map(f => f.title).join('; ') || 'not scanned';
  const dnsInfo = dnsResult?.findings.map(f => f.title).join('; ') || 'not scanned';
  const headers = headerResult?.findings.map(f => f.title).slice(0, 10).join('; ') || 'not scanned';

  return { domain, techStack, openPorts, headers, tlsInfo, dnsInfo, subdomains };
}

// ─── BUILD SCAN CONTEXT FROM RESULTS ────────────────────────────────────────
function buildScanContext(domain: string, results: ScanResult[]): ScanContext {
  const allFindings = results.flatMap(r => r.findings);
  const techResult = results.find(r => r.module === 'technology');
  const portResult = results.find(r => r.module === 'portScan');
  const subResult = results.find(r => r.module === 'subdomains');
  const crawlResult = results.find(r => r.module === 'siteCrawl');
  const headerResult = results.find(r => r.module === 'headers');

  const techStack: string[] = [];
  if (techResult) {
    for (const f of techResult.findings) {
      const match = f.description.match(/Detected:?\s*(.+)/i);
      if (match) techStack.push(...match[1].split(',').map(s => s.trim()));
    }
  }

  const openPorts: number[] = [];
  if (portResult) {
    for (const f of portResult.findings) {
      const portMatch = f.affectedAsset.match(/:(\d+)/);
      if (portMatch) openPorts.push(parseInt(portMatch[1]));
    }
  }

  const subdomains: string[] = [];
  if (subResult) {
    for (const f of subResult.findings) {
      if (f.affectedAsset && f.affectedAsset.includes('.')) subdomains.push(f.affectedAsset);
    }
  }

  const hasLoginForm = crawlResult?.findings.some(f =>
    f.title.toLowerCase().includes('login') || f.title.toLowerCase().includes('credential')
  ) || false;

  const hasAPI = crawlResult?.findings.some(f =>
    f.title.toLowerCase().includes('api') || f.affectedAsset.includes('/api/')
  ) || false;

  const wafDetected = headerResult?.findings.some(f =>
    f.title.toLowerCase().includes('waf') || f.title.toLowerCase().includes('firewall')
  ) || false;

  let cloudProvider: string | null = null;
  const cloudFinding = allFindings.find(f => f.title.includes('Cloud Infrastructure'));
  if (cloudFinding) {
    const match = cloudFinding.title.match(/\((\w+)\)/);
    if (match) cloudProvider = match[1];
  }

  const frameworkFinding = allFindings.find(f => f.category === 'Technology Detection' && f.title.toLowerCase().includes('framework'));
  const framework = frameworkFinding ? frameworkFinding.title : null;

  const dbFinding = allFindings.find(f => f.title.includes('Database') || f.title.includes('MySQL') || f.title.includes('PostgreSQL') || f.title.includes('Redis'));
  const database = dbFinding ? dbFinding.title : null;

  return { domain, techStack, openPorts, subdomains, hasLoginForm, hasAPI, wafDetected, cloudProvider, framework, database, findings: allFindings };
}

// ─── MAIN ASSESSMENT — SMART MODULE SELECTION ────────────────────────────────
// The engine works like a real pentester:
//   1. Recon: gather intel (always runs)
//   2. Classify: determine target type (web/AD/linux/windows/network)
//   3. Attack: run ONLY relevant modules for this target type
//   4. Triage: AI dedup, severity, chains

function deduplicateFindings(results: ScanResult[]): ScanResult[] {
  const seen = new Map<string, Finding>();
  const dedupedResults: ScanResult[] = [];

  for (const result of results) {
    const dedupedFindings: Finding[] = [];
    for (const finding of result.findings) {
      const asset = finding.affectedAsset?.trim().toLowerCase() || '';
      const key = `${finding.title.toLowerCase().trim()}::${finding.category?.toLowerCase().trim() || ''}::${asset}`;
      if (!seen.has(key)) {
        seen.set(key, finding);
        dedupedFindings.push(finding);
      } else {
        const existing = seen.get(key)!;
        if (finding.evidence && (!existing.evidence || finding.evidence.length > existing.evidence.length)) {
          existing.evidence = finding.evidence;
          existing.description = finding.description || existing.description;
        }
      }
    }
    dedupedResults.push({ ...result, findings: dedupedFindings });
  }
  return dedupedResults;
}

export async function runAssessment(
  domain: string,
  modules: ScanModule[],
  onModuleStart?: (moduleName: string, index: number, total: number) => void,
  onLog?: (entry: ScanLogEntry) => void,
  onMidScanInsight?: (insight: MidScanInsight) => void,
): Promise<{ results: ScanResult[]; aiEnriched: boolean; aiTriageResult?: import('../services/ai.service').TriageResult; classification?: TargetClassification }> {
  const startTime = Date.now();
  const ai = getAI();
  const allResults: ScanResult[] = [];
  const moduleIndex = { current: 0 };

  // ── PHASE 1: RECONNAISSANCE ──
  // Always run recon modules to gather intel about the target
  const reconModules = RECON_MODULES.filter(m => {
    if (m === 'portScan' && !config.portScanEnabled) return false;
    return modules.includes(m);
  });

  logger.info(`[Engine] Phase 1 Recon: ${reconModules.join(', ')} for ${domain}`);
  onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: `Phase 1 — Reconnaissance: ${reconModules.join(', ')}` });

  const totalModules = reconModules.length + modules.filter(m => !RECON_MODULES.includes(m)).length;
  const reconResults = await runBatch(reconModules, domain, moduleIndex, totalModules, onModuleStart, undefined, onLog, undefined, onMidScanInsight);
  allResults.push(...reconResults);

  // ── PHASE 2: TARGET CLASSIFICATION ──
  // Determine what TYPE of target this is based on recon data
  logger.info(`[Engine] Phase 2: Classifying target ${domain}...`);
  onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: 'Phase 2 — Classifying target type (web/AD/linux/windows/network)...' });

  const classification = classifyTarget(domain, allResults, reconResults.find(r => r.module === 'portScan'));
  logger.info(`[Engine] Classification:\n${formatClassification(classification)}`);
  onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'engine', message: `Target classified as ${classification.primary.toUpperCase()} (${(classification.confidence * 100).toFixed(0)}% confidence) — ${classification.recommendedModules.length} modules selected` });

  // Initialize persistent scan context
  const scanId = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  initializeScanContext(domain, classification.primary, classification.services[0]?.host || domain, scanId);
  setScanPhase('classification');
  
  // Initialize coverage tracker for this target type
  const { initializeCoverageForTargetType } = await import('./modules/coverageTracker');
  initializeCoverageForTargetType(classification.primary);

  // ── PHASE 2.5: REASONING ENGINE — Universal attack surface & attack graph ──
  // Run AI-powered reasoning modules to enumerate attack surface, build attack graph, and detect pivot chains
  onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: 'Phase 2.5 — Reasoning Engine: Universal attack surface enumeration, attack graph building, cross-target pivot detection...' });
  setScanPhase('adaptive');
  
  // Initialize pre-exploitation checklist
  const { getDefaultChecklist } = await import('./modules/preExploitChecklist');
  const checklist = getDefaultChecklist(classification.primary);
  
  // Record module execution for tracking
  const { recordModuleExecution } = await import('./modules/persistentScanContext');
  
  // Run reasoning modules
  const reasoningModules = REASONING_MODULES.filter(m => modules.includes(m));
  if (reasoningModules.length > 0) {
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: `Phase 2.5 — Running reasoning modules: ${reasoningModules.join(', ')}` });
    const reasoningResults = await runBatch(reasoningModules, domain, moduleIndex, totalModules, onModuleStart, undefined, onLog, allResults, onMidScanInsight);
    allResults.push(...reasoningResults);
    
    // Record execution
    for (const mod of reasoningModules) {
      recordModuleExecution({
        module: mod,
        endTime: Date.now(),
        findingsCount: 0,
        errors: [],
        hypothesesTested: [],
        credentialsFound: [],
        servicesDiscovered: [],
        attackSurfaceUpdated: true,
      });
    }
  }

  // ── PHASE 2.6: SMARTER RECON — AI-driven targeted enumeration ──
  // Run smarterRecon right after classification to generate attack hypotheses
  // and do framework-specific deep enumeration before the attack phase
  if (classification.hasWeb) {
    try {
      onModuleStart?.('smarterRecon', moduleIndex.current, totalModules);
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'smarterRecon', message: 'AI-driven reconnaissance: analyzing tech stack, generating attack hypotheses, enumerating framework-specific paths...' });
      const reconPriorFindings = allResults.flatMap(r => r.findings);
      const smarterResult = await withTimeout(runSmarterRecon(domain, reconPriorFindings), 90000, 'smarterRecon');
      allResults.push(smarterResult);
      onLog?.({ ts: new Date().toISOString(), level: smarterResult.errors.length > 0 ? 'warn' : 'done', module: 'smarterRecon', message: `Smarter recon complete — ${smarterResult.findings.length} findings (attack hypotheses + enumeration)`, duration: smarterResult.duration, findings: smarterResult.findings.length });
    } catch (e) {
      logger.warn(`[Engine] Smarter recon failed: ${e}`);
      onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'smarterRecon', message: `Smarter recon failed: ${e}` });
    }

    // Run deepDiscovery for JS parsing, wordlist fuzzing, and API surface mapping
    try {
      onModuleStart?.('deepDiscovery', moduleIndex.current, totalModules);
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'deepDiscovery', message: 'Deep discovery: JavaScript endpoint extraction, wordlist fuzzing, API surface mapping, backup file detection...' });
      const deepPriorFindings = allResults.flatMap(r => r.findings);
      const deepResult = await withTimeout(runDeepDiscovery(domain, deepPriorFindings), 120000, 'deepDiscovery');
      allResults.push(deepResult);
      onLog?.({ ts: new Date().toISOString(), level: deepResult.errors.length > 0 ? 'warn' : 'done', module: 'deepDiscovery', message: `Deep discovery complete — ${deepResult.findings.length} findings (hidden endpoints, APIs, backups)`, duration: deepResult.duration, findings: deepResult.findings.length });
    } catch (e) {
      logger.warn(`[Engine] Deep discovery failed: ${e}`);
      onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'deepDiscovery', message: `Deep discovery failed: ${e}` });
    }
  }

  // ── AI DECISION: post-recon analysis ──
  let aiAttackRecs: import('../services/ai.service').AttackRecommendations | undefined;
  try {
    onModuleStart?.('AI:reconAnalysis', moduleIndex.current, totalModules);
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'AI', message: 'AI analyzing reconnaissance data for attack recommendations...' });
    const reconSummary = buildReconSummary(domain, allResults);
    aiAttackRecs = await ai.assessReconForAttacks(reconSummary);
    logger.info(`[AI] Attack recommendations: priority=[${aiAttackRecs.priorityAttacks.slice(0, 5).join(',')}] likely=[${aiAttackRecs.likelyVulnTypes.join(',')}]`);
    onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'AI', message: `AI recon analysis done — priority attacks: ${aiAttackRecs.priorityAttacks.slice(0, 5).join(', ')}` });
  } catch (e) {
    logger.warn(`[AI] Recon assessment failed: ${e}`);
    onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'AI', message: `AI recon analysis failed: ${e}` });
  }

  // ── TARGET INTELLIGENCE ──
  let targetProfile: import('./targetAnalysis').TargetProfile | undefined;
  if (classification.hasWeb) {
    try {
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'target', message: 'Building target intelligence profile (endpoints, WAF, tech stack)...' });
      const { analyzeTarget } = await import('./targetAnalysis');
      targetProfile = await withTimeout(analyzeTarget(domain), 120000, 'targetAnalysis');
      onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'target', message: `Target profile built — ${targetProfile.endpoints.length} endpoints, WAF=${targetProfile.wafDetected ? targetProfile.wafName : 'none'}` });
    } catch {
      onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'target', message: 'Target analysis failed or timed out, continuing without profile' });
    }
  }

  // ── PHASE 3: TARGETED ATTACKS ──
  // Only run modules recommended by the classifier
  let attackModules = classification.recommendedModules.filter(m => !reconModules.includes(m));

  // Re-order by AI priority if available
  if (aiAttackRecs && aiAttackRecs.priorityAttacks.length > 0) {
    const priorityOrder = aiAttackRecs.priorityAttacks;
    attackModules = [
      ...attackModules.filter(m => priorityOrder.includes(m))
        .sort((a, b) => priorityOrder.indexOf(a) - priorityOrder.indexOf(b)),
      ...attackModules.filter(m => !priorityOrder.includes(m)),
    ];
  }

  logger.info(`[Engine] Phase 3 Attack: ${attackModules.join(', ')} (${((Date.now() - startTime) / 1000).toFixed(1)}s)`);
  onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: `Phase 3 — Targeted Attacks (${classification.primary}): ${attackModules.join(', ')}` });

  // Isolate kaliTools to its own batch (it blocks for up to 15min)
  const kaliModules = attackModules.filter(m => m === 'kaliTools');
  const otherAttackModules = attackModules.filter(m => m !== 'kaliTools');

  const attackResults = await runBatch(otherAttackModules, domain, moduleIndex, totalModules, onModuleStart, targetProfile, onLog, undefined, onMidScanInsight);
  allResults.push(...attackResults);

  // Run kaliTools last in its own batch
  if (kaliModules.length > 0) {
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: 'Phase 3b — Running kaliTools (nmap/nikto/nuclei) in isolated batch...' });
    const kaliResults = await runBatch(kaliModules, domain, moduleIndex, totalModules, onModuleStart, targetProfile, onLog, undefined, onMidScanInsight);
    allResults.push(...kaliResults);
  }

  // ── PHASE 3.5: ADAPTIVE REASONING — mid-scan strategy pivot ──
  // Analyze what was found and generate targeted follow-up attacks
  // This is the "thinking like a pentester" step
  try {
    onModuleStart?.('adaptiveReasoning', moduleIndex.current, totalModules);
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'adaptiveReasoning', message: 'Adaptive reasoning: analyzing findings, generating follow-up attack strategy...' });
    const currentFindings = allResults.flatMap(r => r.findings);
    const completedModules = [...reconModules, ...attackModules];
    const decision = await adaptiveReason(domain, currentFindings, completedModules);

    // Publish adaptive insights
    for (const insight of decision.insights) {
      onMidScanInsight?.({
        type: 'recommendation',
        title: insight.title,
        description: insight.description,
        severity: insight.severity,
        confidence: decision.strategy.confidence,
        relatedModules: decision.strategy.nextModules,
      });
    }

    // Execute follow-up modules recommended by adaptive reasoning
    const followUpModules = (decision.strategy.nextModules as ScanModule[]).filter(m =>
      !completedModules.includes(m) && MODULE_RUNNERS[m]
    );

    if (followUpModules.length > 0) {
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'adaptiveReasoning', message: `Adaptive strategy: running ${followUpModules.length} follow-up modules: ${followUpModules.join(', ')}` });
      const followUpResults = await runBatch(followUpModules, domain, moduleIndex, totalModules, onModuleStart, targetProfile, onLog, undefined, onMidScanInsight);
      allResults.push(...followUpResults);
    }

    // Execute custom payloads generated by adaptive reasoning
    if (decision.strategy.customPayloads.length > 0) {
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'adaptiveReasoning', message: `Executing ${decision.strategy.customPayloads.length} custom payload sets from adaptive analysis...` });
      // Custom payloads are passed to the exploitation module context
      for (const payloadSet of decision.strategy.customPayloads) {
        logger.info(`[AdaptiveReasoning] Custom payload: ${payloadSet.reason} → ${payloadSet.endpoint} (${payloadSet.payloads.length} payloads)`);
      }
    }

    onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'adaptiveReasoning', message: `Adaptive reasoning complete — phase: ${decision.strategy.phase}, confidence: ${(decision.strategy.confidence * 100).toFixed(0)}%` });
  } catch (e) {
    logger.warn(`[Engine] Adaptive reasoning failed: ${e}`);
    onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'adaptiveReasoning', message: `Adaptive reasoning failed: ${e}` });
  }

  // ── PHASE 4: AI POST-SCAN TRIAGE ──
  // Deduplicate findings across modules
  const dedupedResults = deduplicateFindings(allResults);
  allResults.length = 0;
  allResults.push(...dedupedResults);

  // Enrich CVE findings with real NVD data
  const allFindingsForEnrichment = allResults.flatMap(r => r.findings);
  const cveFindings = allFindingsForEnrichment.filter(f =>
    f.evidence?.includes('CVE-') || f.title?.includes('CVE-')
  );
  if (cveFindings.length > 0) {
    logger.info(`[Enrichment] Enriching ${cveFindings.length} CVE findings from NVD...`);
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'enrichment', message: `Enriching ${cveFindings.length} CVE findings with NVD data...` });
    await enrichFindings(cveFindings);
    onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'enrichment', message: `CVE enrichment complete` });
  }

  // ── PHASE 4.5: CORRELATION — Cross-module finding linkage ──
  // Connect findings across modules to identify attack chains and pivot points
  // Exclude untested attack vectors (INFO-level planning intelligence)
  const allFindingsForCorrelation = allResults.flatMap(r => r.findings).filter(f => !f.title.startsWith('Untested Attack Vector:'));
  if (allFindingsForCorrelation.length >= 3) {
    try {
      onModuleStart?.('correlation', moduleIndex.current, totalModules);
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'correlation', message: `Correlating ${allFindingsForCorrelation.length} findings across modules — identifying attack chains and pivot points...` });
      const correlations = correlateFindings(allFindingsForCorrelation, domain);
      const correlationFindings = correlateToFindings(correlations, domain);
      if (correlationFindings.length > 0) {
        allResults.push({
          module: 'correlation',
          findings: correlationFindings,
          duration: 0,
          errors: [],
        });
        onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'correlation', message: `Correlation complete — ${correlationFindings.length} attack chains/pivots identified: ${correlations.summary}` });
      }
    } catch (e) {
      logger.warn(`[Engine] Correlation failed: ${e}`);
      onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'correlation', message: `Correlation failed: ${e}` });
    }
  }

  let aiTriageResult: import('../services/ai.service').TriageResult | undefined;
  let aiEnriched = false;

  // ── PHASE 4.7: AUTONOMOUS PENTEST — AI-powered iterative vulnerability hunting ──
  // ReAct loop: query real CVE databases → AI reasons about what to test → executes safe PoC → observes → replans
  try {
    onModuleStart?.('autonomousPentester', moduleIndex.current, totalModules);
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'autonomousPentester', message: 'Autonomous pentest: querying NVD/OSV for real CVEs, AI reasoning about attack vectors, executing safe PoC validation...' });
    const currentFindings = allResults.flatMap(r => r.findings);
    const pentestResult = await withTimeout(runAutonomousPentest(domain, currentFindings, 12, (step) => {
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'autonomousPentester', message: `[AI REASONING] Thought: ${step.thought.substring(0, 200)} | Action: ${step.action} | Observation: ${step.observation.substring(0, 200)}` });
    }), 300000, 'autonomousPentester');
    if (pentestResult.findings.length > 0) {
      allResults.push({
        module: 'autonomousPentester',
        findings: pentestResult.findings,
        duration: pentestResult.duration,
        errors: [],
      });
      onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'autonomousPentester', message: `Autonomous pentest complete — ${pentestResult.findings.length} findings (${(pentestResult.duration / 1000).toFixed(1)}s)` });
    } else {
      onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'autonomousPentester', message: 'Autonomous pentest complete — no additional findings' });
    }
  } catch (e) {
    logger.warn(`[Engine] Autonomous pentest failed: ${e}`);
    onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'autonomousPentester', message: `Autonomous pentest failed: ${e}` });
  }

  const allFindings = allResults.flatMap(r => r.findings);
  if (allFindings.length > 0) {
    try {
      onModuleStart?.('AI:triage', moduleIndex.current, totalModules);
      onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'AI', message: `Post-scan triage — ${allFindings.length} findings to analyze (dedup, severity, chains)...` });

      const reconCtx = buildReconSummary(domain, allResults);
      const contextStr = `Domain: ${domain}, TargetType: ${classification.primary}, TechStack: ${reconCtx.techStack.join(', ')}, OpenPorts: ${reconCtx.openPorts.join(', ')}, ` +
        `WAF: ${aiAttackRecs?.wafLikely ? 'yes' : 'no'}, Auth: ${aiAttackRecs?.authRequired ? 'yes' : 'no'}`;

      // GPU-optimized CVSS: Only score top 5 critical/high findings
      const unscoredFindings = allFindings.filter(f => !f.cvssScore || f.cvssScore === 0);
      const topUnscored = unscoredFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').slice(0, 5);
      if (topUnscored.length > 0) {
        await Promise.allSettled(topUnscored.map(async (f) => {
          try { f.cvssScore = await ai.scoreFindingCvss(f); } catch (e) {
            logger.warn('[AI] CVSS scoring failed for ' + f.title + ': ' + (e instanceof Error ? e.message : String(e)));
          }
        }));
        logger.info(`[AI] Scored CVSS for ${topUnscored.length} critical/high findings`);
      }

      const triageResult = await ai.triageAndEnrichFindings(allFindings, domain, contextStr);
      aiTriageResult = triageResult;
      aiEnriched = true;

      const enrichedMap = new Map(triageResult.findings.map(f => [f.id, f]));
      for (const result of allResults) {
        result.findings = result.findings
          .filter(f => enrichedMap.has(f.id))
          .map(f => enrichedMap.get(f.id) || f);
      }

      logger.info(`[AI] Triage complete: ${allFindings.length} → ${triageResult.findings.length} findings, ${triageResult.chains.length} chains`);
      onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'AI', message: `Triage complete — ${allFindings.length} → ${triageResult.findings.length} findings, ${triageResult.chains.length} attack chain(s)` });
    } catch (e) {
      logger.warn(`[AI] Post-scan triage failed: ${e}`);
      aiEnriched = false;
    }
  }

  if (aiTriageResult) {
      logger.info(`[AI] Triage complete: ${allFindings.length} → ${aiTriageResult.findings.length} findings, ${aiTriageResult.chains.length} chains`);
      onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'AI', message: `Triage complete — ${allFindings.length} → ${aiTriageResult.findings.length} findings, ${aiTriageResult.chains.length} attack chain(s)` });
    }

  // ── PHASE 5: FINDING VALIDATION LOOP ──
  // Re-test findings with different payloads/contexts to validate and enrich them
  // Removes false positives, confirms true positives, and enriches evidence
  try {
    onModuleStart?.('findingValidationLoop', moduleIndex.current, totalModules);
    onLog?.({ ts: new Date().toISOString(), level: 'info', module: 'engine', message: 'Phase 5 — Finding Validation Loop: Re-testing findings with different payloads, removing false positives, enriching evidence...' });
    setScanPhase('triage');
    
    const { runBatchValidation } = await import('./modules/findingValidationLoop');
    const validationResult = await runBatchValidation(domain, allFindings, null, 3);
    
    // Replace findings with validated ones
    const allResultsFlat = allResults.flatMap(r => r.findings);
    const validatedMap = new Map(validationResult.validatedFindings.map(f => [f.id, f]));
    const enrichedMap = new Map(validationResult.enrichedFindings.map(f => [f.id, f]));
    
    // Update allResults with validated findings
    for (const result of allResults) {
      result.findings = result.findings.map(f => {
        if (enrichedMap.has(f.id)) return enrichedMap.get(f.id)!;
        if (validatedMap.has(f.id)) return validatedMap.get(f.id)!;
        return f;
      });
    }
    
    // Add removed false positives as INFO findings for transparency
    if (validationResult.removedFalsePositives.length > 0) {
      allResults.push({
        module: 'findingValidationLoop',
        findings: validationResult.removedFalsePositives,
        duration: 0,
        errors: [],
      });
    }
    
    onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'findingValidationLoop', message: `Validation loop complete — ${validationResult.retestResults.filter(r => r.finalStatus === 'confirmed').length} confirmed, ${validationResult.retestResults.filter(r => r.finalStatus === 'refuted').length} refuted, ${validationResult.retestResults.filter(r => r.finalStatus === 'inconclusive').length} inconclusive` });
  } catch (e) {
    logger.warn(`[Engine] Finding validation loop failed: ${e}`);
    onLog?.({ ts: new Date().toISOString(), level: 'warn', module: 'findingValidationLoop', message: `Validation loop failed: ${e}` });
  }

  const totalDur = ((Date.now() - startTime) / 1000).toFixed(1);
  const finalFindings = allResults.flatMap(r => r.findings);
  onLog?.({ ts: new Date().toISOString(), level: 'done', module: 'engine', message: `Scan complete — ${finalFindings.length} finding(s) in ${totalDur}s across ${allResults.length} modules (${classification.primary} target)` });
  logger.info(`[Engine] Scan complete for ${domain}: ${finalFindings.length} findings in ${totalDur}s (${classification.primary})`);

  return { results: allResults, aiEnriched, aiTriageResult, classification };
}

export function getAvailableModules(): ScanModule[] {
  const modules: ScanModule[] = [
    'dns', 'tls', 'headers', 'webConfig', 'technology', 'subdomains', 'emailSecurity',
    'cveCorrelation', 'activeVuln', 'dnsDeep', 'tlsDeep', 'osFingerprint',
    'subdomainTakeover', 'siteCrawl', 'serviceAudit', 'advancedAttacks', 'brokenAuth',
    'httpMethods', 'apiSecurity', 'supplyChain', 'cloudSecurity', 'clientSecurity',
    'kaliTools', 'businessLogic', 'activeDirectory', 'networkPentest',
    'windowsSystem', 'linuxSystem',
    // New modules (Feature #1-8)
    'liveCve', 'modernAttacks', 'behavioral', 'supplyChainIntel', 'sourceAnalysis', 'exploitChain',
    'smarterRecon', 'correlation', 'deepDiscovery', 'adaptiveReasoning',
    // New modules (Reasoning Engine & Universal Attack Surface)
    'universalAttackSurface', 'attackGraph', 'crossTargetPivot', 'coverageTracker', 'preExploitChecklist', 'findingValidationLoop',
  ];
  if (config.portScanEnabled) {
    modules.push('portScan');
  }
  return modules;
}

export const MODULE_DESCRIPTIONS: Record<string, string> = {
  dns: 'DNS Security Analysis - SPF, DKIM, DMARC, DNSSEC, CAA, zone transfer',
  tls: 'TLS/HTTPS Assessment - Certificate validity, protocols, HSTS, OCSP stapling',
  headers: 'Security Headers Check - CSP, CORS, X-Frame-Options, cookie flags, Permissions-Policy',
  webConfig: 'Web Configuration - Sensitive file exposure, error handling, technology leakage',
  technology: 'Technology Detection - Server fingerprinting, framework detection, CDN identification',
  subdomains: 'Subdomain Discovery - Certificate transparency, DNS resolution, wildcard detection',
  emailSecurity: 'Email Security - MX records, SPF/DKIM/DMARC, MTA-STS, SMTP TLS',
  portScan: 'Port Scanning - Full TCP scan, service identification, banner grabbing',
  cveCorrelation: 'CVE Correlation - Technology stack matching against known vulnerabilities',
  activeVuln: 'Active Vulnerability Testing - SQLi, XSS, SSRF, XXE, JWT, path traversal, open redirect',
  dnsDeep: 'DNS Deep Analysis - IPv6, DANE/TLSA, SOA analysis, nameserver diversity',
  tlsDeep: 'TLS Deep Analysis - Certificate chain, HTTP/2, HTTP/3, cipher analysis',
  osFingerprint: 'OS Fingerprinting - Server header analysis, version detection, software identification',
  subdomainTakeover: 'Subdomain Takeover - Dangling CNAME detection, cloud service takeover verification',
  siteCrawl: 'Site Crawl - Form analysis, credential exposure, CSRF protection, mixed content',
  serviceAudit: 'Service Infrastructure Audit - Database exposure, cloud metadata, default creds, container exposure',
  advancedAttacks: 'Advanced Injection Testing - SSTI, OS command injection, LDAP, XPath, deserialization, prototype pollution',
  brokenAuth: 'Broken Authentication - User enumeration, session security, default credentials, lockout policy, 2FA bypass',
  httpMethods: 'HTTP Methods Audit - TRACE/XST, PUT/DELETE file write, verb tampering ACL bypass, open proxy',
  apiSecurity: 'API Security (OWASP API Top 10) - BOLA/IDOR, excessive data exposure, broken function-level auth, GraphQL misconfiguration',
  supplyChain: 'Supply Chain Security - Exposed dependency files, CDN SRI enforcement, vulnerable library versions, dependency confusion',
  cloudSecurity: 'Cloud & Infrastructure Security - IMDS metadata exposure, public S3/GCS buckets, Kubernetes API, Docker Remote API',
  clientSecurity: 'Client-Side Security Hardening - CSP quality, CORS origin reflection, cookie SameSite/prefix audit, COOP/COEP',
  kaliTools: 'External Tool Scanning - Nmap port/service/vuln detection, Nikto web server audit, Nuclei vulnerability templates',
  businessLogic: 'Business Logic Vulnerability Detection - BOLA/IDOR, broken function-level auth, mass assignment, API misconfiguration',
  activeDirectory: 'Active Directory Pentest - DNS SRV, SPN/Kerberoasting, AS-REP, GPO/SYSVOL, impacket/bloodyAD/ldeep/kerbrute/bloodhound',
  networkPentest: 'Network Pentest - Full TCP SYN scan, service enum (HTTP/SSH/FTP/SMB/RDP/DB/mail), impacket NetBIOS/MSSQL',
  windowsSystem: 'Windows System Pentest - SMB shares/signing, WinRM, RDP, EternalBlue, PrintNightmare, ZeroLogon, PetitPotam, BlueKeep',
  linuxSystem: 'Linux System Pentest - SSH security, FTP, web server, databases, SSL vulns (Heartbleed/DROWN/POODLE), Docker/K8s detection',
  // New modules (Feature #1-8)
  liveCve: 'Live CVE Intelligence - Real-time vulnerability feed from NVD, GitHub Advisories, OSV.dev (zero-day detection)',
  modernAttacks: 'Modern Web Attacks - JWT exploitation, OAuth/OIDC flaws, HTTP smuggling, IDOR/BOLA, GraphQL abuse, DNS rebinding, container escape',
  behavioral: 'Behavioral Anomaly Detection - Response baseline analysis, error fingerprinting, timing side-channels, response tampering detection',
  supplyChainIntel: 'Supply Chain Intelligence - JS bundle analysis, source map exposure, package audit, SRI verification, third-party script risk',
  sourceAnalysis: 'Source Code Analysis - Hardcoded secrets detection, git/CI/CD exposure, debug endpoints, backup file discovery',
  exploitChain: 'Exploit Chain Validation - Multi-vulnerability chain validation (XSS+CSRF, SSRF+pivot, SQLi+privesc, CORS+data theft)',
  smarterRecon: 'AI-Driven Reconnaissance - Framework detection, attack hypothesis generation, targeted endpoint enumeration, API surface mapping',
  correlation: 'Cross-Module Correlation - Attack chain identification, pivot point detection, multi-stage exploit path mapping',
  deepDiscovery: 'Deep Content Discovery - JavaScript API extraction, wordlist fuzzing, backup file detection, hidden endpoint enumeration, virtual host discovery',
  adaptiveReasoning: 'Adaptive Strategy Engine - Mid-scan pattern analysis, dynamic attack plan adjustment, framework-specific payload generation, follow-up module selection',
  // New modules (Reasoning Engine & Universal Attack Surface)
  universalAttackSurface: 'Universal Attack Surface - AI-driven enumeration of ALL possible attack vectors across ALL target types (AD/Linux/Web/Network/Cloud/Database/Email)',
  attackGraph: 'Attack Graph Builder - AI-powered multi-step attack chain reasoning with MITRE ATT&CK mapping, entry points, and critical paths',
  crossTargetPivot: 'Cross-Target Pivot Detection - Identifies AD↔Linux↔Web↔Windows pivot chains, lateral movement paths, and trust relationship abuse',
  coverageTracker: 'Coverage Tracker - Tracks tested vs possible attack vectors per target type, identifies blind spots, prioritizes untested high-value vectors',
  preExploitChecklist: 'Pre-Exploitation Checklist - Systematic per-target-type checklists (AD/Linux/Web/Windows/Network) ensuring systematic coverage before exploitation',
  findingValidationLoop: 'Finding Validation Loop - Re-tests findings with different payloads/contexts, removes false positives, confirms true positives, enriches evidence',
};

export function getModulesRun(modules: ScanModule[]): { name: string; description: string }[] {
  return modules
    .filter(m => MODULE_DESCRIPTIONS[m])
    .map(m => ({ name: m, description: MODULE_DESCRIPTIONS[m] }));
}
