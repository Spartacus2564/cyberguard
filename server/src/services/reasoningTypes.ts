import { Finding, Severity, ScanModule, ScanResult } from '../types';

export type TargetType = 'web' | 'activeDirectory' | 'linux' | 'windows' | 'network' | 'mixed';

export interface HostInfo {
  ip: string;
  hostname?: string;
  os?: string;
  services: ServiceRecord[];
  targetTypes: string[];
  compromiseLevel: 'none' | 'recon' | 'foothold' | 'user' | 'admin' | 'system' | 'domain-admin';
  credentials: string[];
  pivotPotential: string[];
}

export interface NetworkSegment {
  cidr: string;
  hosts: (string | HostInfo)[];
  type: 'dmz' | 'internal' | 'management' | 'database' | 'unknown';
  segmentation: 'none' | 'firewall' | 'vlan' | 'acl';
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
  vulnerabilities: string[];
  credentials: string[];
  attackSurface: string[];
}

export type CredentialType = 
  | 'domain' 
  | 'local' 
  | 'database' 
  | 'api' 
  | 'ssh' 
  | 'web' 
  | 'certificate' 
  | 'token' 
  | 'hash';

export type CredentialAccessLevel = 
  | 'user' 
  | 'admin' 
  | 'system' 
  | 'domain-admin' 
  | 'enterprise-admin';

export interface CredentialRecord {
  id: string;
  type: CredentialType;
  username: string;
  secret?: string;
  hash?: string;
  source: string;
  accessLevel: CredentialAccessLevel;
  validOn: string[];
  testedOn: string[];
  discoveredAt: number;
  lastUsed?: number;
  confidence: number;
}

export interface Credential {
  type: CredentialType;
  username: string;
  password?: string;
  hash?: string;
  source: string;
  accessLevel: CredentialAccessLevel;
}

export interface DetectedService {
  host: string;
  port: number;
  protocol: string;
  service: string;
  version?: string;
  banner?: string;
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

// Type aliases for backward compatibility
export type AttackNode = AttackGraphNode;
export type AttackEdge = AttackGraphEdge;
export type AttackPath = AttackGraphPath;

export interface MitreCoverage {
  covered: string[];
  missing: string[];
  coveragePercent: number;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  entryPoints: string[];
  criticalPaths: AttackGraphPath[];
  mitreCoverage: MitreCoverage;
}

export interface AttackGraphContext {
  domain: string;
  targetType: string;
  target: AttackSurfaceTarget;
  findings: Finding[];
  techStack: string[];
  openPorts: number[];
  services: DetectedService[];
  credentials: Credential[];
  networkMap: NetworkSegment[];
  mitreTechniques: string[];
}

export interface AttackGraphState {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  entryPoints: string[];
  criticalPaths: AttackGraphPath[];
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
  findings: string[];
  confidence: number;
  priority: number;
}

export interface CoverageTracker {
  targetType: string;
  vectors: CoverageVector[];
  totalVectors: number;
  testedVectors: number;
  coveragePercent: number;
  lastUpdated: number;
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

export interface PivotChainState {
  id: string;
  steps: PivotStepState[];
  totalProbability: number;
  finalAccess: { type: string; host: string; level: string };
  mitrePath: string[];
  status: 'hypothesized' | 'testing' | 'confirmed' | 'failed';
  discoveredAt: number;
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

export type ScanPhase = 'recon' | 'classification' | 'attack' | 'adaptive' | 'triage' | 'complete';

export interface PivotContext {
  currentAccess: { type: string; host: string; credentials: Credential[] };
  networkMap: NetworkSegment[];
  allFindings: Finding[];
  targetTypes: string[];
}

export interface PivotChain {
  steps: PivotStep[];
  totalProbability: number;
  finalAccess: { type: string; host: string; level: string };
  mitrePath: string[];
}

export interface PivotStep {
  from: { type: string; host: string };
  to: { type: string; host: string };
  technique: string;
  method: string;
  requirements: string[];
  confidence: number;
}

export interface ValidationContext {
  finding: Finding;
  target: AttackGraphContext['target'];
  attackGraph: AttackGraph;
  originalEvidence: string;
}

export interface ValidationResult {
  validated: boolean;
  confidence: number;
  additionalEvidence: string[];
  falsePositiveIndicators: string[];
  recommendedRetest: RetestPlan[];
}

export interface RetestPlan {
  module: ScanModule;
  payload: string;
  context: string;
  reason: string;
}

export interface RetestResult {
  plan: RetestPlan;
  result: 'success' | 'failure' | 'error' | 'inconclusive';
  output: string;
  evidence: string;
  timestamp: number;
}

export interface RetestSummary {
  findingId: string;
  findingTitle: string;
  retestPlans: RetestPlan[];
  results: RetestResult[];
  finalStatus: 'confirmed' | 'refuted' | 'inconclusive';
  confidence: number;
}

export interface ChecklistContext {
  findings: Finding[];
  credentials: Credential[];
  networkAccess: NetworkSegment[];
  timeBudget: number;
}

export interface PreExploitChecklist {
  targetType: TargetType;
  phases: ChecklistPhase[];
  totalChecks: number;
  completed: number;
}

export interface ChecklistPhase {
  name: string;
  description: string;
  checks: ChecklistItem[];
}

export interface ChecklistItem {
  id: string;
  description: string;
  mitreTechnique: string;
  module: ScanModule;
  payload: string;
  prerequisites: string[];
  completed: boolean;
  evidence?: string;
  execute?: (domain: string, context: ChecklistContext) => Promise<Finding | null>;
}

export interface ReasoningContext {
  domain: string;
  targetType: string;
  currentFindings: Finding[];
  attackGraph: AttackGraph;
  completedSteps: string[];
  availableCredentials: Credential[];
  networkAccess: NetworkSegment[];
  timeBudget: number;
  riskTolerance: 'low' | 'medium' | 'high';
}

export interface ReasoningAction {
  type: 'scan' | 'exploit' | 'enumerate' | 'pivot' | 'credential-access' | 'lateral-move' | 'exfiltrate' | 'persist';
  module: ScanModule;
  target: string;
  parameters: Record<string, unknown>;
  reasoning: string;
  mitreTechnique: string;
  priority: number;
  estimatedTime: number;
  prerequisites: string[];
}

export interface ReasoningResult {
  nextActions: ReasoningAction[];
  updatedHypotheses: Hypothesis[];
  pivotOpportunities: PivotOpportunity[];
  riskAssessment: string;
  confidence: number;
}

export interface Hypothesis {
  id: string;
  statement: string;
  confidence: number;
  status: 'open' | 'testing' | 'confirmed' | 'refuted' | 'stale';
  evidence: string[];
  testsRun: string[];
}

export interface PivotOpportunity {
  from: { type: string; host: string; evidence: string };
  to: { type: string; host: string; evidence: string };
  technique: string;
  requirements: string[];
  confidence: number;
}

export interface AttackSurfaceTarget {
  domain: string;
  targetType: string;
  ip: string;
  openPorts: number[];
  services: DetectedService[];
  techStack: string[];
  osInfo: string;
  networkContext: NetworkSegment[];
}

export interface AttackVector {
  id: string;
  category: 'network' | 'web' | 'ad' | 'linux' | 'windows' | 'cloud' | 'database' | 'email' | 'physical';
  technique: string;
  title: string;
  description: string;
  prerequisites: string[];
  applicable: boolean;
  confidence: number;
  module: ScanModule;
  payloads: string[];
  expectedEvidence: string[];
}

export interface PriorityVector {
  vectorId: string;
  priority: number;
  reason: string;
  estimatedEffort: 'low' | 'medium' | 'high';
  potentialImpact: 'critical' | 'high' | 'medium' | 'low';
}

export interface AttackSurfaceMap {
  vectors: AttackVector[];
  coverage: { tested: string[]; untested: string[]; coveragePercent: number };
  priorities: PriorityVector[];
}