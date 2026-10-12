import { Request } from 'express';

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO',
}

export enum AssessmentStatus {
  PENDING = 'PENDING',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  FAILED = 'FAILED',
}

export enum UserRole {
  ADMIN = 'ADMIN',
  MEMBER = 'MEMBER',
}

export type ScanModule =
  | 'dns'
  | 'tls'
  | 'headers'
  | 'webConfig'
  | 'technology'
  | 'subdomains'
  | 'emailSecurity'
  | 'portScan'
  | 'cveCorrelation'
  | 'activeVuln'
  | 'dnsDeep'
  | 'tlsDeep'
  | 'osFingerprint'
  | 'subdomainTakeover'
  | 'siteCrawl'
  | 'serviceAudit'
  | 'advancedAttacks'
  | 'brokenAuth'
  | 'httpMethods'
  | 'apiSecurity'
  | 'supplyChain'
  | 'cloudSecurity'
  | 'clientSecurity'
  | 'kaliTools'
  | 'businessLogic'
  | 'activeDirectory'
  | 'networkPentest'
  | 'windowsSystem'
  | 'linuxSystem'
  | 'behavioral'
  | 'supplyChainIntel'
  | 'sourceAnalysis'
  | 'liveCve'
  | 'modernAttacks'
  | 'exploitChain'
  | 'exploitation'
  | 'smarterRecon'
  | 'correlation'
  | 'deepDiscovery'
  | 'adaptiveReasoning'
  | 'aiCveResearch'
  | 'autonomousPentester'
  | 'universalAttackSurface'
  | 'attackGraph'
  | 'crossTargetPivot'
  | 'coverageTracker'
  | 'preExploitChecklist'
  | 'findingValidationLoop'
  | 'raceCondition';

export type TargetType = 'web' | 'activeDirectory' | 'linux' | 'windows' | 'network' | 'mixed';

export interface ScanContext {
  domain: string;
  techStack: string[];
  openPorts: number[];
  subdomains: string[];
  hasLoginForm: boolean;
  hasAPI: boolean;
  wafDetected: boolean;
  cloudProvider: string | null;
  framework: string | null;
  database: string | null;
  findings: Finding[];
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  cvssScore?: number;
  affectedAsset: string;
  evidence: string;
  impact: string;
  remediation: string;
  references: string[];
  detectedAt: Date;
  confidence: number; // 0.0 - 1.0, how confident we are this is a real finding
}

export interface Assessment {
  id: string;
  domain: string;
  status: AssessmentStatus;
  organizationId: string;
  findings: Finding[];
  createdAt: Date;
  completedAt?: Date;
}

export interface AuthRequest extends Request {
  userId: string;
  organizationId: string;
  email: string;
  role: UserRole;
}

export interface ScanResult {
  module: ScanModule;
  findings: Finding[];
  duration: number;
  errors: string[];
}

export interface ReportData {
  assessmentId: string;
  domain: string;
  organizationId: string;
  organizationName: string;
  generatedAt: Date;
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    riskScore: number;
  };
  findings: Finding[];
  recommendations: string[];
  executiveSummary: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  organizationId: string;
  role: UserRole;
  exp?: number;
}

// ─── Incident Response Types ───

export type IRPhase = 'collection' | 'preservation' | 'analysis' | 'containment' | 'eradication' | 'recovery' | 'lessons-learned';
export type EvidenceType = 'disk-image' | 'memory-dump' | 'log-files' | 'pcap' | 'registry' | 'file-system' | 'volatile-data' | 'malware-sample';
export type EvidenceStatus = 'collected' | 'preserved' | 'analyzing' | 'analyzed' | 'archived';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed';
export type IOCType = 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'registry-key' | 'file-path' | 'mutex' | 'cve' | 'mitre-technique';

export interface Evidence {
  id: string;
  caseId: string;
  type: EvidenceType;
  source: string;
  path: string;
  hash: { md5: string; sha1: string; sha256: string };
  size: number;
  collectedAt: number;
  collectedBy: string;
  status: EvidenceStatus;
  chainOfCustody: CustodyEntry[];
  metadata: Record<string, unknown>;
}

export interface CustodyEntry {
  timestamp: number;
  action: 'collected' | 'transferred' | 'analyzed' | 'stored' | 'verified';
  actor: string;
  location: string;
  hashVerified: boolean;
  notes?: string;
}

export interface TimelineEvent {
  id: string;
  caseId: string;
  timestamp: number;
  source: string;
  eventType: string;
  description: string;
  severity: Severity;
  mitreTechniques: string[];
  relatedEvidence: string[];
  rawData: Record<string, unknown>;
}

export interface IOC {
  id: string;
  caseId: string;
  type: IOCType;
  value: string;
  description: string;
  confidence: number;
  source: string;
  firstSeen: number;
  lastSeen: number;
  mitreTechniques: string[];
  tags: string[];
  relatedFindings: string[];
}

export interface ContainmentAction {
  id: string;
  caseId: string;
  type: 'network-block' | 'host-isolate' | 'account-disable' | 'process-kill' | 'file-quarantine' | 'registry-delete' | 'custom';
  target: string;
  parameters: Record<string, unknown>;
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'rolled-back';
  executedAt?: number;
  executedBy?: string;
  result?: string;
  rollbackInfo?: Record<string, unknown>;
}

export interface IRCase {
  id: string;
  name: string;
  description: string;
  status: IncidentStatus;
  severity: Severity;
  createdAt: number;
  updatedAt: number;
  assignedTo: string[];
  evidence: Evidence[];
  timeline: TimelineEvent[];
  iocs: IOC[];
  containmentActions: ContainmentAction[];
  findings: Finding[];
  mitreCoverage: { covered: string[]; missing: string[] };
  reportPath?: string;
}

export interface IRModuleResult {
  evidence?: Evidence[];
  timelineEvents?: TimelineEvent[];
  iocs?: IOC[];
  containmentActions?: ContainmentAction[];
  findings?: Finding[];
  errors: string[];
}

export interface IRScanContext {
  caseId: string;
  targetScope: string[];
  evidencePaths: string[];
  timeBudget: number;
  riskTolerance: 'low' | 'medium' | 'high';
}
