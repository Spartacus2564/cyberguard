import prisma from '../lib/prisma';
import { Finding } from '../types';

export interface ComparisonResult {
  previousAssessmentId: string | null;
  previousDate: Date | null;
  newFindings: Finding[];
  fixedFindings: Finding[];
  unchangedFindings: Finding[];
  regressionDetected: boolean;
  improvementDetected: boolean;
  summary: string;
}

export async function compareWithPreviousScan(
  domain: string,
  organizationId: string,
  currentFindings: Finding[]
): Promise<ComparisonResult> {
  const previous = await prisma.assessment.findFirst({
    where: {
      domain,
      organizationId,
      status: 'COMPLETED',
    },
    orderBy: { completedAt: 'desc' },
  });

  if (!previous) {
    return {
      previousAssessmentId: null,
      previousDate: null,
      newFindings: currentFindings,
      fixedFindings: [],
      unchangedFindings: [],
      regressionDetected: false,
      improvementDetected: false,
      summary: 'First scan for this target. No historical data available for comparison.',
    };
  }

  const previousFindingRecords = await prisma.finding.findMany({
    where: { assessmentId: previous.id },
  });

  const prevTitles = new Set(previousFindingRecords.map(f => f.title.toLowerCase().trim()));
  const currTitles = new Set(currentFindings.map(f => f.title.toLowerCase().trim()));

  const newFindings = currentFindings.filter(f => !prevTitles.has(f.title.toLowerCase().trim()));
  const fixedFindings = previousFindingRecords
    .filter(f => !currTitles.has(f.title.toLowerCase().trim()))
    .map(f => ({
      id: f.id,
      title: f.title,
      description: f.description,
      severity: f.severity as Finding['severity'],
      category: f.category,
      affectedAsset: f.affectedAsset,
      evidence: f.evidence,
      impact: f.impact,
      remediation: f.remediation,
      references: (() => { try { return typeof f.references === 'string' ? JSON.parse(f.references) : (f.references || []); } catch { return []; } })(),
      detectedAt: f.detectedAt,
      confidence: 0.7,
    }));
  const unchangedFindings = currentFindings.filter(f => prevTitles.has(f.title.toLowerCase().trim()));

  const criticalNew = newFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
  const criticalFixed = fixedFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
  const regressionDetected = criticalNew > criticalFixed;
  const improvementDetected = criticalFixed > criticalNew;

  let summary = `Compared with previous scan (${previous.completedAt?.toISOString().split('T')[0] || 'unknown date'}): `;
  summary += `${newFindings.length} new finding(s), ${fixedFindings.length} fixed finding(s), ${unchangedFindings.length} unchanged.`;
  if (regressionDetected) summary += ' REGRESSION DETECTED: More critical/high vulnerabilities found than fixed.';
  if (improvementDetected) summary += ' IMPROVEMENT: More critical/high vulnerabilities fixed than found.';

  return {
    previousAssessmentId: previous.id,
    previousDate: previous.completedAt || null,
    newFindings,
    fixedFindings,
    unchangedFindings,
    regressionDetected,
    improvementDetected,
    summary,
  };
}
