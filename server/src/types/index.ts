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
