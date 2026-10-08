import { AsyncLocalStorage } from 'node:async_hooks';
import { Finding, Severity, ScanResult, ScanModule } from '../../types';
import { logInfo } from '../scanLogger';
import { MitreCoverage } from '../../services/reasoningTypes';

const MODULE_NAME = 'persistentScanContext';

// ─── PERSISTENT SCAN CONTEXT ────────────────────────────────────────────────
// Shared memory across ALL modules - persists throughout the entire scan
// Enables cross-module intelligence, hypothesis tracking, and adaptive decisions

export interface PersistentScanContext {
  // Target identification
  domain: string;
  targetType: string;
  ip: string;
  
  // Network topology
  networkSegments: NetworkSegment[];
  trustRelationships: TrustRelationship[];
  
  // Service inventory (ALL discovered services across modules)
  serviceInventory: ServiceRecord[];
  
  // Credential store (ALL credentials found across modules)
  credentialStore: CredentialRecord[];
  
  // Vulnerability hypotheses (tracked across modules)
  hypotheses: Hypothesis[];
  
  // Attack graph (built incrementally)
  attackGraph: AttackGraphState;
  
  // Coverage tracking (what's been tested vs what's possible)
  coverageTracker: CoverageTracker;
  
  // Module execution history
  moduleHistory: ModuleExecution[];
  
  // Pivot chains discovered
  pivotChains: PivotChainState[];
  
  // Scan metadata
  scanStartTime: number;
  scanId: string;
  currentPhase: ScanPhase;
}

export interface NetworkSegment {
  cidr: string;
  hosts: HostInfo[];
  type: 'dmz' | 'internal' | 'management' | 'database' | 'unknown';
  segmentation: 'none' | 'firewall' | 'vlan' | 'acl';
}

export interface HostInfo {
  ip: string;
  hostname?: string;
  os?: string;
  services: ServiceRecord[];
  targetTypes: string[];
  compromiseLevel: 'none' | 'recon' | 'foothold' | 'user' | 'admin' | 'system' | 'domain-admin';
  credentials: string[]; // credential IDs
  pivotPotential: string[];
}

export interface TrustRelationship {
  from: { type: string; host: string; domain?: string };
  to: { type: string; host: string; domain?: string };
  type: 'kerberos' | 'ldap' | 'smb' | 'ssh' | 'winrm' | 'dcom' | 'wmi' | 'database' | 'api' | 'custom';
  direction: 'one-way' | 'two-way';
  strength: 'weak' | 'medium' | 'strong';
  evidence: string;
}

export interface ServiceRecord {
  id: string;
  host: string;
  port: number;
  protocol: string;
  service: string;
  version?: string;
  banner?: string;
  targetType: string;
  discoveredBy: ScanModule;
  discoveredAt: number;
  tested: boolean;
  vulnerabilities: string[]; // finding IDs
  credentials: string[]; // credential IDs
  attackSurface: string[]; // MITRE techniques applicable
}

export interface CredentialRecord {
  id: string;
  type: 'domain' | 'local' | 'database' | 'api' | 'ssh' | 'web' | 'certificate' | 'token' | 'hash';
  username: string;
  secret?: string; // encrypted
  hash?: string;
  source: string; // finding/module that found it
  accessLevel: 'user' | 'admin' | 'system' | 'domain-admin' | 'enterprise-admin';
  validOn: string[]; // hosts where valid
  testedOn: string[]; // hosts tested against
  discoveredAt: number;
  lastUsed?: number;
  confidence: number;
}

export interface Hypothesis {
  id: string;
  statement: string;
  category: 'recon' | 'initial-access' | 'execution' | 'persistence' | 'privilege-escalation' | 'defense-evasion' | 'credential-access' | 'discovery' | 'lateral-movement' | 'collection' | 'exfiltration' | 'impact';
  confidence: number;
  status: 'open' | 'testing' | 'confirmed' | 'refuted' | 'stale';
  evidence: string[];
  testsRun: TestRecord[];
  createdAt: number;
  updatedAt: number;
  mitreTechnique: string;
  module: ScanModule;
  priority: number;
}

export interface TestRecord {
  module: ScanModule;
  action: string;
  payload: string;
  result: 'success' | 'failure' | 'inconclusive' | 'error';
  output: string;
  timestamp: number;
  findingId?: string;
}

export interface AttackGraphState {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  entryPoints: string[];
  criticalPaths: AttackGraphPath[];
  mitreCoverage: MitreCoverage;
  lastUpdated: number;
}

export interface AttackGraphNode {
  id: string;
  type: 'recon' | 'initial-access' | 'execution' | 'persistence' | 'privilege-escalation' | 'defense-evasion' | 'credential-access' | 'discovery' | 'lateral-movement' | 'collection' | 'exfiltration' | 'impact';
  title: string;
  description: string;
  technique: string;
  prerequisites: string[];
  outcomes: string[];
  confidence: number;
  evidence: string[];
  host?: string;
  targetType?: string;
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  condition: string;
  probability: number;
  technique: string;
}

export interface AttackGraphPath {
  nodes: string[];
  totalProbability: number;
  impact: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  mitrePath: string[];
}

export interface CoverageTracker {
  targetType: string;
  vectors: CoverageVector[];
  totalVectors: number;
  testedVectors: number;
  coveragePercent: number;
  lastUpdated: number;
}

export interface CoverageVector {
  id: string;
  category: string;
  technique: string;
  title: string;
  applicable: boolean;
  tested: boolean;
  testedBy: ScanModule[];
  findings: string[]; // finding IDs
  confidence: number;
  priority: number;
}

export interface ModuleExecution {
  module: ScanModule;
  startTime: number;
  endTime: number;
  findingsCount: number;
  errors: string[];
  hypothesesTested: string[];
  credentialsFound: string[];
  servicesDiscovered: string[];
  attackSurfaceUpdated: boolean;
}

export interface PivotChainState {
  id: string;
  steps: PivotStepState[];
  totalProbability: number;
  finalAccess: { type: string; host: string; level: string };
  mitrePath: string[];
  status: 'hypothesized' | 'testing' | 'confirmed' | 'failed';
  discoveredAt: number;
}

export interface PivotStepState {
  from: { type: string; host: string };
  to: { type: string; host: string };
  technique: string;
  method: string;
  requirements: string[];
  confidence: number;
  tested: boolean;
  result?: 'success' | 'failed';
}

export type ScanPhase = 'recon' | 'classification' | 'attack' | 'adaptive' | 'triage' | 'complete';

// ─── CONTEXT MANAGEMENT ────────────────────────────────────────────────────

const scanContextStorage = new AsyncLocalStorage<{ context: PersistentScanContext | null }>();
let fallbackContext: PersistentScanContext | null = null;

function currentContext(): PersistentScanContext | null {
  const store = scanContextStorage.getStore();
  return store ? store.context : fallbackContext;
}

export function withScanContext<T>(operation: () => Promise<T>): Promise<T> {
  return scanContextStorage.run({ context: null }, operation);
}

export function initializeScanContext(domain: string, targetType: string, ip: string, scanId: string): PersistentScanContext {
  const context: PersistentScanContext = {
    domain,
    targetType,
    ip,
    networkSegments: [],
    trustRelationships: [],
    serviceInventory: [],
    credentialStore: [],
    hypotheses: [],
    attackGraph: {
      nodes: [],
      edges: [],
      entryPoints: [],
      criticalPaths: [],
      mitreCoverage: { covered: [], missing: [], coveragePercent: 0 },
      lastUpdated: Date.now(),
    },
    coverageTracker: {
      targetType,
      vectors: [],
      totalVectors: 0,
      testedVectors: 0,
      coveragePercent: 0,
      lastUpdated: Date.now(),
    },
    moduleHistory: [],
    pivotChains: [],
    scanStartTime: Date.now(),
    scanId,
    currentPhase: 'recon',
  };
  
  const store = scanContextStorage.getStore();
  if (store) store.context = context;
  else fallbackContext = context;
  logInfo(MODULE_NAME, `Initialized persistent scan context for ${domain} (${scanId})`);
  return context;
}

export function getScanContext(): PersistentScanContext | null {
  return currentContext();
}

export function updateScanContext(updates: Partial<PersistentScanContext>): void {
  const context = currentContext();
  if (context) Object.assign(context, updates);
}

export function setScanPhase(phase: ScanPhase): void {
  if (currentContext()) {
    currentContext()!.currentPhase = phase;
    logInfo(MODULE_NAME, `Scan phase changed to: ${phase}`);
  }
}

// ─── SERVICE INVENTORY ────────────────────────────────────────────────────

export function addServiceRecord(record: Omit<ServiceRecord, 'id' | 'discoveredAt'>): string {
  if (!currentContext()) return '';
  
  const id = `svc-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const fullRecord: ServiceRecord = {
    ...record,
    id,
    discoveredAt: Date.now(),
  };
  
  currentContext()!.serviceInventory.push(fullRecord);
  updateCoverageForService(fullRecord);
  logInfo(MODULE_NAME, `Added service: ${record.service} on ${record.host}:${record.port}`);
  return id;
}

export function getServicesByHost(host: string): ServiceRecord[] {
  if (!currentContext()) return [];
  return currentContext()!.serviceInventory.filter(s => s.host === host);
}

export function getServicesByType(targetType: string): ServiceRecord[] {
  if (!currentContext()) return [];
  return currentContext()!.serviceInventory.filter(s => s.targetType === targetType);
}

export function markServiceTested(serviceId: string, module: ScanModule, findingId?: string): void {
  if (!currentContext()) return;
  const service = currentContext()!.serviceInventory.find(s => s.id === serviceId);
  if (service) {
    service.tested = true;
    if (findingId && !service.vulnerabilities.includes(findingId)) {
      service.vulnerabilities.push(findingId);
    }
    updateCoverageForService(service);
  }
}

function updateCoverageForService(service: ServiceRecord): void {
  if (!currentContext()) return;
  
  const tracker = currentContext()!.coverageTracker;
  const technique = service.attackSurface[0] || 'unknown';
  
  let vector = tracker.vectors.find(v => v.technique === technique && v.category === service.targetType);
  if (!vector) {
    vector = {
      id: `cov-${technique}-${service.targetType}`,
      category: service.targetType,
      technique,
      title: `${service.service} (${technique})`,
      applicable: true,
      tested: false,
      testedBy: [],
      findings: [],
      confidence: 0.5,
      priority: 5,
    };
    tracker.vectors.push(vector);
    tracker.totalVectors++;
  }
  
  if (service.tested && !vector.tested) {
    vector.tested = true;
    vector.testedBy.push(service.discoveredBy);
    tracker.testedVectors++;
  }
  
  if (service.vulnerabilities.length > 0) {
    vector.findings = service.vulnerabilities;
    vector.confidence = Math.min(1, vector.confidence + 0.1);
  }
  
  tracker.coveragePercent = tracker.totalVectors > 0 
    ? Math.round((tracker.testedVectors / tracker.totalVectors) * 100) 
    : 0;
  tracker.lastUpdated = Date.now();
}

// ─── CREDENTIAL STORE ────────────────────────────────────────────────────

export function addCredentialRecord(record: Omit<CredentialRecord, 'id' | 'discoveredAt'>): string {
  if (!currentContext()) return '';
  
  const id = `cred-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const fullRecord: CredentialRecord = {
    ...record,
    id,
    discoveredAt: Date.now(),
  };
  
  currentContext()!.credentialStore.push(fullRecord);
  logInfo(MODULE_NAME, `Added credential: ${record.type} - ${record.username} (${record.accessLevel})`);
  return id;
}

export function getCredentialsByType(type: CredentialRecord['type']): CredentialRecord[] {
  if (!currentContext()) return [];
  return currentContext()!.credentialStore.filter(c => c.type === type);
}

export function getValidCredentialsForHost(host: string): CredentialRecord[] {
  if (!currentContext()) return [];
  return currentContext()!.credentialStore.filter(c => c.validOn.includes(host));
}

export function markCredentialTested(credentialId: string, host: string, success: boolean): void {
  if (!currentContext()) return;
  const cred = currentContext()!.credentialStore.find(c => c.id === credentialId);
  if (cred) {
    if (success && !cred.validOn.includes(host)) {
      cred.validOn.push(host);
    }
    if (!cred.testedOn.includes(host)) {
      cred.testedOn.push(host);
    }
    cred.lastUsed = Date.now();
  }
}

// ─── HYPOTHESIS TRACKING ──────────────────────────────────────────────────

export function addHypothesis(hypothesis: Omit<Hypothesis, 'id' | 'createdAt' | 'updatedAt'>): string {
  if (!currentContext()) return '';
  
  const id = `hyp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const fullHypothesis: Hypothesis = {
    ...hypothesis,
    id,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  
  currentContext()!.hypotheses.push(fullHypothesis);
  logInfo(MODULE_NAME, `Added hypothesis: ${hypothesis.statement} (confidence: ${hypothesis.confidence}%)`);
  return id;
}

export function updateHypothesis(hypothesisId: string, updates: Partial<Hypothesis>): void {
  if (!currentContext()) return;
  const hyp = currentContext()!.hypotheses.find(h => h.id === hypothesisId);
  if (hyp) {
    Object.assign(hyp, updates, { updatedAt: Date.now() });
  }
}

export function addTestToHypothesis(hypothesisId: string, test: TestRecord): void {
  if (!currentContext()) return;
  const hyp = currentContext()!.hypotheses.find(h => h.id === hypothesisId);
  if (hyp) {
    hyp.testsRun.push(test);
    hyp.updatedAt = Date.now();
    
    // Update status based on result
    if (test.result === 'success') {
      hyp.status = 'confirmed';
      hyp.confidence = Math.min(95, hyp.confidence + 30);
    } else if (test.result === 'failure') {
      hyp.confidence = Math.max(5, hyp.confidence - 20);
      if (hyp.confidence < 15) hyp.status = 'refuted';
    }
  }
}

export function getOpenHypotheses(): Hypothesis[] {
  if (!currentContext()) return [];
  return currentContext()!.hypotheses.filter(h => h.status === 'open' || h.status === 'testing');
}

export function getConfirmedHypotheses(): Hypothesis[] {
  if (!currentContext()) return [];
  return currentContext()!.hypotheses.filter(h => h.status === 'confirmed');
}

// ─── ATTACK GRAPH ────────────────────────────────────────────────────────

export function addAttackNode(node: Omit<AttackGraphNode, 'id'>): string {
  if (!currentContext()) return '';
  
  const id = `node-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const fullNode: AttackGraphNode = { ...node, id };
  
  currentContext()!.attackGraph.nodes.push(fullNode);
  currentContext()!.attackGraph.lastUpdated = Date.now();
  return id;
}

export function addAttackEdge(edge: AttackGraphEdge): void {
  if (!currentContext()) return;
  currentContext()!.attackGraph.edges.push(edge);
  currentContext()!.attackGraph.lastUpdated = Date.now();
}

export function addCriticalPath(path: AttackGraphPath): void {
  if (!currentContext()) return;
  currentContext()!.attackGraph.criticalPaths.push(path);
  currentContext()!.attackGraph.lastUpdated = Date.now();
}

export function getAttackGraph(): AttackGraphState | null {
  return currentContext()?.attackGraph || null;
}

// ─── MODULE EXECUTION HISTORY ────────────────────────────────────────────

export function recordModuleExecution(execution: Omit<ModuleExecution, 'startTime'>): void {
  if (!currentContext()) return;
  const fullExecution: ModuleExecution = {
    ...execution,
    startTime: Date.now(),
  };
  currentContext()!.moduleHistory.push(fullExecution);
}

export function getModuleHistory(): ModuleExecution[] {
  return currentContext()?.moduleHistory || [];
}

export function getCompletedModules(): ScanModule[] {
  if (!currentContext()) return [];
  return currentContext()!.moduleHistory.map(m => m.module);
}

// ─── PIVOT CHAINS ────────────────────────────────────────────────────────

export function addPivotChain(chain: Omit<PivotChainState, 'id' | 'discoveredAt'>): string {
  if (!currentContext()) return '';
  
  const id = `pivot-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const fullChain: PivotChainState = {
    ...chain,
    id,
    discoveredAt: Date.now(),
  };
  
  currentContext()!.pivotChains.push(fullChain);
  logInfo(MODULE_NAME, `Added pivot chain: ${chain.steps.length} steps, probability: ${(chain.totalProbability * 100).toFixed(0)}%`);
  return id;
}

export function updatePivotChain(chainId: string, updates: Partial<PivotChainState>): void {
  if (!currentContext()) return;
  const chain = currentContext()!.pivotChains.find(c => c.id === chainId);
  if (chain) {
    Object.assign(chain, updates);
  }
}

export function getPivotChains(): PivotChainState[] {
  return currentContext()?.pivotChains || [];
}

// ─── COVERAGE REPORTING ──────────────────────────────────────────────────

export function getCoverageReport(): { 
  targetType: string; 
  coveragePercent: number; 
  tested: number; 
  total: number; 
  untestedVectors: CoverageVector[];
  topGaps: CoverageVector[];
} | null {
  if (!currentContext()) return null;
  
  const tracker = currentContext()!.coverageTracker;
  const untested = tracker.vectors.filter(v => v.applicable && !v.tested);
  const topGaps = untested
    .sort((a, b) => b.priority - a.priority)
    .slice(0, 10);
  
  return {
    targetType: tracker.targetType,
    coveragePercent: tracker.coveragePercent,
    tested: tracker.testedVectors,
    total: tracker.totalVectors,
    untestedVectors: untested,
    topGaps,
  };
}

export function getContextSummary(): string {
  if (!currentContext()) return 'No active scan context';
  
  const ctx = currentContext()!;
  return `
Scan Context Summary (${ctx.scanId})
Domain: ${ctx.domain} (${ctx.targetType})
Phase: ${ctx.currentPhase}
Duration: ${((Date.now() - ctx.scanStartTime) / 1000).toFixed(0)}s

Network: ${ctx.networkSegments.length} segments, ${ctx.trustRelationships.length} trust relationships
Services: ${ctx.serviceInventory.length} discovered, ${ctx.serviceInventory.filter(s => s.tested).length} tested
  Credentials: ${ctx.credentialStore.length} stored, ${ctx.credentialStore.filter(c => c.validOn.length > 0).length} validated
  Hypotheses: ${ctx.hypotheses.length} total, ${ctx.hypotheses.filter(h => h.status === 'confirmed').length} confirmed
  Attack Graph: ${ctx.attackGraph.nodes.length} nodes, ${ctx.attackGraph.edges.length} edges, ${ctx.attackGraph.criticalPaths.length} critical paths
  Coverage: ${ctx.coverageTracker.coveragePercent}% (${ctx.coverageTracker.testedVectors}/${ctx.coverageTracker.totalVectors})
  Pivot Chains: ${ctx.pivotChains.length} discovered
  Modules Run: ${ctx.moduleHistory.length}
  `.trim();
}

// ─── INITIALIZE COVERAGE FOR TARGET TYPE ────────────────────────────────────
// Initializes the coverage tracker with all possible attack vectors for the target type

export function initializeCoverageForTargetType(targetType: string): void {
  const context = getScanContext();
  if (!context) return;

  // Define attack vectors per target type
  const vectorsByType: Record<string, Omit<CoverageVector, 'id' | 'tested' | 'testedBy' | 'findings' | 'confidence' | 'priority'>[]> = {
    web: [
      { category: 'web', technique: 'T1190', title: 'Exploit Public-Facing Application', applicable: true },
      { category: 'web', technique: 'T1193', title: 'Spearphishing Attachment', applicable: true },
      { category: 'web', technique: 'T1189', title: 'Drive-by Compromise', applicable: true },
      { category: 'web', technique: 'T1059.007', title: 'Command Injection', applicable: true },
      { category: 'web', technique: 'T1059.006', title: 'SQL Injection', applicable: true },
      { category: 'web', technique: 'T1505.003', title: 'Web Shell', applicable: true },
      { category: 'web', technique: 'T1552.001', title: 'Credentials in Files', applicable: true },
      { category: 'web', technique: 'T1552.002', title: 'Credentials in Registry', applicable: true },
      { category: 'web', technique: 'T1552.003', title: 'Credentials in Config', applicable: true },
      { category: 'web', technique: 'T1040', title: 'Network Sniffing', applicable: true },
      { category: 'web', technique: 'T1557', title: 'MITM', applicable: true },
      { category: 'web', technique: 'T1185', title: 'Browser Session Hijacking', applicable: true },
      { category: 'web', technique: 'T1550.001', title: 'Application Access Token', applicable: true },
      { category: 'web', technique: 'T1606', title: 'Forge Web Credentials', applicable: true },
      { category: 'web', technique: 'T1556', title: 'Modify Authentication Process', applicable: true },
    ],
    activeDirectory: [
      { category: 'activeDirectory', technique: 'T1558.003', title: 'Kerberoasting', applicable: true },
      { category: 'activeDirectory', technique: 'T1558.004', title: 'AS-REP Roasting', applicable: true },
      { category: 'activeDirectory', technique: 'T1208', title: 'Kerberos Delegation Abuse', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.001', title: 'LSASS Memory', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.006', title: 'DCSync', applicable: true },
      { category: 'activeDirectory', technique: 'T1003.004', title: 'NTDS.dit', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.002', title: 'Pass the Hash', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.003', title: 'Pass the Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.004', title: 'Pass the Hash (SMB)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.006', title: 'Remote Services (WinRM)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.003', title: 'Remote Services (DCOM)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.002', title: 'Remote Services (SMB)', applicable: true },
      { category: 'activeDirectory', technique: 'T1021.005', title: 'Remote Services (WMI)', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.001', title: 'Golden Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1550.004', title: 'Silver Ticket', applicable: true },
      { category: 'activeDirectory', technique: 'T1556.002', title: 'Password Filter', applicable: true },
      { category: 'activeDirectory', technique: 'T1484.001', title: 'Group Policy Modification', applicable: true },
      { category: 'activeDirectory', technique: 'T1505.003', title: 'Web Shell (AD CS)', applicable: true },
      { category: 'activeDirectory', technique: 'T1098', title: 'Account Manipulation', applicable: true },
    ],
    linux: [
      { category: 'linux', technique: 'T1068', title: 'Exploitation for Privilege Escalation', applicable: true },
      { category: 'linux', technique: 'T1548.003', title: 'Sudo and Sudo Caching', applicable: true },
      { category: 'linux', technique: 'T1543.002', title: 'Systemd Service', applicable: true },
      { category: 'linux', technique: 'T1053.003', title: 'Cron', applicable: true },
      { category: 'linux', technique: 'T1574.001', title: 'LD_PRELOAD', applicable: true },
      { category: 'linux', technique: 'T1556.003', title: 'Pluggable Authentication Modules', applicable: true },
      { category: 'linux', technique: 'T1021.004', title: 'Pass the Hash (SSH Keys)', applicable: true },
      { category: 'linux', technique: 'T1021.003', title: 'Remote Services (SSH)', applicable: true },
      { category: 'linux', technique: 'T1021.005', title: 'Remote Services (Docker)', applicable: true },
      { category: 'linux', technique: 'T1611', title: 'Escape to Host', applicable: true },
      { category: 'linux', technique: 'T1552.001', title: 'Credentials in Files', applicable: true },
      { category: 'linux', technique: 'T1552.004', title: 'Private Keys', applicable: true },
      { category: 'linux', technique: 'T1083', title: 'File and Directory Discovery', applicable: true },
      { category: 'linux', technique: 'T1082', title: 'System Information Discovery', applicable: true },
      { category: 'linux', technique: 'T1135', title: 'Network Share Discovery', applicable: true },
    ],
    windows: [
      { category: 'windows', technique: 'T1068', title: 'Exploitation for Privilege Escalation', applicable: true },
      { category: 'windows', technique: 'T1548.002', title: 'Bypass User Account Control', applicable: true },
      { category: 'windows', technique: 'T1543.003', title: 'Windows Service', applicable: true },
      { category: 'windows', technique: 'T1053.005', title: 'Scheduled Task', applicable: true },
      { category: 'windows', technique: 'T1574.002', title: 'DLL Search Order Hijacking', applicable: true },
      { category: 'windows', technique: 'T1556.002', title: 'Password Filter', applicable: true },
      { category: 'windows', technique: 'T1003.001', title: 'LSASS Memory', applicable: true },
      { category: 'windows', technique: 'T1550.002', title: 'Pass the Hash', applicable: true },
      { category: 'windows', technique: 'T1021.006', title: 'WinRM', applicable: true },
      { category: 'windows', technique: 'T1021.003', title: 'DCOM', applicable: true },
      { category: 'windows', technique: 'T1021.002', title: 'SMB', applicable: true },
      { category: 'windows', technique: 'T1021.005', title: 'WMI', applicable: true },
      { category: 'windows', technique: 'T1562.001', title: 'Disable or Modify Tools', applicable: true },
      { category: 'windows', technique: 'T1562.002', title: 'Disable Windows Event Logging', applicable: true },
      { category: 'windows', technique: 'T1059.001', title: 'PowerShell', applicable: true },
    ],
    network: [
      { category: 'network', technique: 'T1595.001', title: 'Active Scanning: Scan IP Blocks', applicable: true },
      { category: 'network', technique: 'T1595.002', title: 'Active Scanning: Vulnerability Scanning', applicable: true },
      { category: 'network', technique: 'T1595.003', title: 'Active Scanning: Wordlist Scanning', applicable: true },
      { category: 'network', technique: 'T1046', title: 'Network Service Scanning', applicable: true },
      { category: 'network', technique: 'T1069.002', title: 'Permission Groups Discovery', applicable: true },
      { category: 'network', technique: 'T1018', title: 'Remote System Discovery', applicable: true },
      { category: 'network', technique: 'T1016', title: 'System Network Configuration Discovery', applicable: true },
      { category: 'network', technique: 'T1040', title: 'Network Sniffing', applicable: true },
      { category: 'network', technique: 'T1557', title: 'MITM', applicable: true },
      { category: 'network', technique: 'T1021.001', title: 'Remote Services (RDP)', applicable: true },
      { category: 'network', technique: 'T1021.004', title: 'SMB', applicable: true },
      { category: 'network', technique: 'T1021.003', title: 'DCOM', applicable: true },
      { category: 'network', technique: 'T1021.005', title: 'WMI', applicable: true },
      { category: 'network', technique: 'T1590.005', title: 'Active Directory Reconnaissance', applicable: true },
    ],
    mixed: [],
    cloud: [],
    database: [],
    email: [],
  };

  const vectors = (vectorsByType[targetType] || []).map((v, i) => ({
    ...v,
    id: `cov-${v.technique}-${targetType}`,
    tested: false,
    testedBy: [],
    findings: [],
    confidence: 0.7,
    priority: Math.max(1, 10 - i),
  }));

  context.coverageTracker = {
    targetType,
    vectors,
    totalVectors: vectors.length,
    testedVectors: 0,
    coveragePercent: 0,
    lastUpdated: Date.now(),
  };

  logInfo(MODULE_NAME, `Initialized coverage tracker for ${targetType}: ${vectors.length} vectors`);
}