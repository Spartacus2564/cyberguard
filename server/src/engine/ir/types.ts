// Import main types first
import { Finding, Severity, ScanModule, ScanResult, ScanContext, JWTPayload, UserRole, AssessmentStatus } from '../../../types';

// Re-export main types
export { Finding, Severity, ScanModule, ScanResult, ScanContext, JWTPayload, UserRole, AssessmentStatus };

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