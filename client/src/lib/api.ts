import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  organizationId: string;
  organization?: { id: string; name: string };
}

export interface Assessment {
  id: string;
  domain: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  startedAt?: string;
  findings?: Finding[];
  report?: Report;
  _count?: { findings: number };
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  cvssScore?: number;
  affectedAsset: string;
  evidence: string;
  impact: string;
  remediation: string;
  references: string;
  detectedAt: string;
}

export interface VulnerabilityChain {
  title: string;
  description: string;
  severity: string;
  findings: string[];
  attackPath: string[];
  impact: string;
  severityRationale?: string;
}

export interface RemediationPhase {
  phase: string;
  timeframe: string;
  findings: string[];
  actions: string[];
  riskReduction: string;
}

export interface ReportContent {
  summary?: {
    totalFindings: number;
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
    riskScore: number;
    grade: string;
    gradeLabel: string;
    riskLevel: string;
  };
  findings?: { id: string; title: string; severity: string; category: string; affectedAsset: string }[];
  categoryScores?: Record<string, { score: number; findings: number; weightedDeduction: number }>;
  complianceMapping?: Record<string, { passed: boolean; total: number; percentage: number }>;
  complianceFrameworkResults?: Record<string, Record<string, { passed: boolean; findings: any[] }>>;
  scoringBreakdown?: { title: string; severity: string; deduction: number; adjustedDeduction: number; cumulativeScore: number }[];
  attackNarrative?: string;
  vulnerabilityChains?: VulnerabilityChain[];
  remediationPlan?: RemediationPhase[];
  executiveSummary?: string;
  modulesRun?: { name: string; duration: number; findings: number }[];
  generatedAt?: string;
}

export interface ScanProgress {
  status: string;
  activeModule: string | null;
  moduleIndex: number;
  totalModules: number;
  startedAt: string | null;
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

export interface ScanLogsResponse {
  logs: ScanLogEntry[];
  status: string;
}

export interface ScanComparison {
  hasPrevious: boolean;
  previous?: {
    id: string;
    domain: string;
    completedAt: string;
    score: number;
    totalFindings: number;
    severityCounts: Record<string, number>;
  };
  current?: {
    score: number;
    totalFindings: number;
    severityCounts: Record<string, number>;
  };
  delta?: {
    scoreChange: number;
    findingsChange: number;
    newFindings: { title: string; severity: string }[];
    resolvedFindings: { title: string; severity: string }[];
  };
}

export interface Report {
  id: string;
  assessmentId: string;
  content: string;
  executiveSummary?: string;
  createdAt: string;
}

export interface Asset {
  id: string;
  domain: string;
  createdAt: string;
}

export interface AssessmentStats {
  total: number;
  completed: number;
  running: number;
  pending: number;
  failed: number;
  recent: Assessment[];
  findingsBySeverity: { severity: string; count: number }[];
}

export interface SecurityScore {
  score: number;
  grade: string;
  breakdown: { critical: number; high: number; medium: number; low: number; info: number };
}

export interface Screenshot {
  id: string;
  assessmentId: string;
  url: string;
  domain: string;
  screenshotPath: string;
  title?: string;
  statusCode?: number;
  technologies?: string;
  securityHeaders?: string;
  createdAt: string;
}

export interface ScanSchedule {
  id: string;
  assessmentId: string;
  domain: string;
  organizationId: string;
  interval: string;
  enabled: boolean;
  lastRun?: string;
  nextRun?: string;
  createdAt: string;
}

export interface FixPR {
  id: string;
  assessmentId: string;
  title: string;
  description: string;
  branch: string;
  changes: FixPRChange[];
  status: string;
  createdAt: string;
}

export interface FixPRChange {
  file: string;
  type: string;
  description: string;
  additions: string[];
  deletions: string[];
}

export interface Review {
  id: string;
  findingId: string;
  assessmentId: string;
  status: ReviewStatus;
  reviewerId?: string;
  reviewerName?: string;
  comments: ReviewComment[];
  statusHistory: StatusTransition[];
  createdAt: string;
  updatedAt: string;
}

export type ReviewStatus = 'PENDING' | 'IN_REVIEW' | 'APPROVED' | 'ESCALATED' | 'DISMISSED' | 'FIXED';

export interface ReviewComment {
  id: string;
  authorId: string;
  authorName: string;
  content: string;
  createdAt: string;
}

export interface StatusTransition {
  from: string;
  to: string;
  by: string;
  at: string;
  reason?: string;
}

export interface ReviewStats {
  total: number;
  byStatus: Record<ReviewStatus, number>;
  bySeverity: Record<string, number>;
  avgTimeToReview: number;
  avgTimeToResolution: number;
  topReviewers: Array<{ name: string; count: number }>;
}

export interface ComplianceReport {
  framework: string;
  controls: ComplianceControl[];
  complianceScore?: number;
  summary: string;
  recommendations: string[];
}

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'fail' | 'partial' | 'not_applicable';
  findings: string[];
  recommendations: string[];
}

export interface AuditLog {
  id: string;
  userId?: string;
  organizationId?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  details?: string;
  ipAddress?: string;
  createdAt: string;
}

export interface AuditLogResponse {
  logs: AuditLog[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}
