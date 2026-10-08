import { AssessmentStatus } from '@prisma/client';
import prisma from '../lib/prisma';
import { calculateSecurityScore } from '../engine/riskScoring';
import { Finding } from '../types';

export async function createAssessment(
  domain: string,
  organizationId: string,
  assetId?: string
) {
  return prisma.assessment.create({
    data: {
      domain,
      organizationId,
      assetId,
      status: AssessmentStatus.PENDING,
    },
  });
}

export async function getAssessmentById(id: string, organizationId: string) {
  return prisma.assessment.findFirst({
    where: { id, organizationId },
    include: { findings: true, report: true },
  });
}

export async function getAssessmentsByOrganization(
  organizationId: string,
  page: number = 1,
  limit: number = 10
) {
  const skip = (page - 1) * limit;

  const [assessments, total] = await Promise.all([
    prisma.assessment.findMany({
      where: { organizationId },
      include: { findings: true },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.assessment.count({ where: { organizationId } }),
  ]);

  return {
    assessments,
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  };
}

export async function updateAssessmentStatus(
  id: string,
  status: AssessmentStatus,
  riskScore?: number
) {
  const data: { status: AssessmentStatus; startedAt?: Date; completedAt?: Date; riskScore?: number } = { status };

  if (status === AssessmentStatus.RUNNING) {
    data.startedAt = new Date();
  }

  if (status === AssessmentStatus.COMPLETED || status === AssessmentStatus.FAILED) {
    data.completedAt = new Date();
  }

  if (riskScore !== undefined) {
    data.riskScore = riskScore;
  }

  return prisma.assessment.update({
    where: { id },
    data,
  });
}

export async function deleteAssessment(id: string, organizationId: string) {
  const assessment = await prisma.assessment.findFirst({
    where: { id, organizationId },
  });

  if (!assessment) {
    throw new Error('Assessment not found or access denied');
  }

  if (assessment.status === AssessmentStatus.RUNNING || assessment.status === AssessmentStatus.PENDING) {
    throw new Error('Cannot delete a running assessment');
  }

  return prisma.assessment.delete({ where: { id } });
}

export async function getAssessmentStats(organizationId: string) {
  const [total, byStatus, recent, severityAgg] = await Promise.all([
    prisma.assessment.count({ where: { organizationId } }),
    prisma.assessment.groupBy({
      by: ['status'],
      where: { organizationId },
      _count: { status: true },
    }),
    prisma.assessment.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      take: 5,
      include: { findings: true },
    }),
    prisma.finding.groupBy({
      by: ['severity'],
      where: { assessment: { organizationId } },
      _count: { severity: true },
    }),
  ]);

  const statusCounts: Record<string, number> = {};
  byStatus.forEach((item) => {
    statusCounts[item.status] = item._count.status;
  });

  const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  severityAgg.forEach((item) => {
    severityCounts[item.severity] = item._count.severity;
  });

  const findingsBySeverity = Object.entries(severityCounts).map(([severity, count]) => ({
    severity,
    count,
  }));

  const running = (statusCounts['RUNNING'] || 0) + (statusCounts['PENDING'] || 0);
  const criticalFindings = severityCounts['CRITICAL'] || 0;

  let securityScore = 100;
  securityScore -= severityCounts['CRITICAL'] * 25;
  securityScore -= severityCounts['HIGH'] * 15;
  securityScore -= severityCounts['MEDIUM'] * 8;
  securityScore -= severityCounts['LOW'] * 3;
  securityScore = Math.max(0, Math.min(100, securityScore));

  const recentAssessments = recent.map((a) => {
    const findings = a.findings as unknown as Finding[];
    const riskResult = calculateSecurityScore(findings);
    return {
      id: a.id,
      domain: a.domain,
      status: a.status,
      createdAt: a.createdAt,
      findingsCount: findings.length,
      score: riskResult.score,
    };
  });

  return {
    securityScore: Math.round(securityScore),
    totalAssets: total,
    activeAssessments: running,
    criticalFindings,
    findingsBySeverity,
    recentAssessments,
  };
}

export { prisma };
