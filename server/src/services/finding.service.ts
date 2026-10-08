import { Severity } from '../types';
import prisma from '../lib/prisma';

export async function createFinding(data: {
  assessmentId: string;
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
  compliance?: Record<string, string>;
}) {
  return prisma.finding.create({
    data: {
      ...data,
      references: JSON.stringify(data.references),
      compliance: data.compliance ? JSON.stringify(data.compliance) : null,
      detectedAt: new Date(),
    },
  });
}

export async function createFindingsBulk(
  findings: Array<{
    assessmentId: string;
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
    compliance?: Record<string, string>;
  }>
) {
  // Deduplicate by title — keep the highest severity version
  const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const deduped = new Map<string, typeof findings[0]>();
  for (const f of findings) {
    const key = f.title.toLowerCase().trim();
    const existing = deduped.get(key);
    if (!existing || (sevOrder[f.severity] ?? 5) < (sevOrder[existing.severity] ?? 5)) {
      deduped.set(key, f);
    }
  }
  const unique = [...deduped.values()];

  return prisma.finding.createMany({
    data: unique.map(f => ({
      ...f,
      references: JSON.stringify(f.references),
      compliance: f.compliance ? JSON.stringify(f.compliance) : null,
      detectedAt: new Date(),
    })),
  });
}

export async function getFindingsByAssessment(
  assessmentId: string,
  organizationId: string,
  page: number = 1,
  limit: number = 50,
  severity?: string
) {
  const assessment = await prisma.assessment.findFirst({
    where: { id: assessmentId, organizationId },
  });

  if (!assessment) {
    throw new Error('Assessment not found or access denied');
  }

  const where: any = { assessmentId };
  if (severity) {
    where.severity = severity;
  }

  const [findings, total] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.finding.count({ where }),
  ]);

  // Parse JSON fields that are stored as strings
  const parsedFindings = findings.map(f => ({
    ...f,
    references: (() => { try { return typeof f.references === 'string' ? JSON.parse(f.references) : (f.references || []); } catch { return []; } })(),
    compliance: (() => { try { return typeof f.compliance === 'string' ? JSON.parse(f.compliance) : f.compliance; } catch { return null; } })(),
  }));

  return {
    findings: parsedFindings,
    total,
    page,
    limit,
    totalPages: Math.ceil(total / limit),
  };
}

export async function getFindingsSummary(organizationId: string) {
  const agg = await prisma.finding.groupBy({
    by: ['severity'],
    where: { assessment: { organizationId } },
    _count: { severity: true },
  });

  const counts: Record<string, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };

  let total = 0;
  agg.forEach((item) => {
    counts[item.severity] = item._count.severity;
    total += item._count.severity;
  });

  return { total, bySeverity: counts };
}

export { prisma };
