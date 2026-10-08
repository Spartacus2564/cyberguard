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
