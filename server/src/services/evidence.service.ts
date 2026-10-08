// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE SERVICE — Capture, store, and retrieve audit evidence
// ═══════════════════════════════════════════════════════════════════════════════

import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CreateEvidenceInput {
  findingId?: string;
  assessmentId: string;
  type: string;                // 'tool_output', 'screenshot', 'http_request', 'command_output'
  title: string;
  content: string;
  contentType?: string;
  metadata?: Record<string, unknown>;
}

export interface EvidenceRecord {
  id: string;
  findingId: string | null;
  assessmentId: string;
  type: string;
  title: string;
  content: string;
  contentType: string | null;
  metadata: string | null;
  createdAt: Date;
}

// ─── Evidence CRUD ───────────────────────────────────────────────────────────

export async function createEvidence(input: CreateEvidenceInput): Promise<EvidenceRecord> {
  const evidence = await prisma.evidence.create({
    data: {
      findingId: input.findingId || null,
      assessmentId: input.assessmentId,
      type: input.type,
      title: input.title,
      content: input.content.substring(0, 100000),
      contentType: input.contentType || 'text/plain',
      metadata: input.metadata ? JSON.stringify(input.metadata) : null,
    },
  });

  logger.info(`[Evidence] Captured: ${input.type} for finding ${input.findingId || 'N/A'}`);
  return evidence as EvidenceRecord;
}

export async function getEvidenceByFinding(findingId: string): Promise<EvidenceRecord[]> {
  return prisma.evidence.findMany({
    where: { findingId },
    orderBy: { createdAt: 'asc' },
  }) as Promise<EvidenceRecord[]>;
}

export async function getEvidenceByAssessment(assessmentId: string): Promise<(EvidenceRecord & { finding: { id: string; title: string; severity: string } | null })[]> {
  return prisma.evidence.findMany({
    where: { assessmentId },
    include: {
      finding: {
        select: { id: true, title: true, severity: true },
      },
    },
    orderBy: { createdAt: 'desc' },
  }) as any;
}

// ─── Bulk Evidence from Tool Output ──────────────────────────────────────────

export async function captureToolEvidence(
  findingId: string | undefined,
  assessmentId: string,
  toolName: string,
  stdout: string,
  stderr: string,
  command: string,
  exitCode: number,
  durationMs: number,
): Promise<void> {
  if (stdout.trim()) {
    await createEvidence({
      findingId,
      assessmentId,
      type: 'tool_output',
      title: `${toolName} output`,
      content: stdout.substring(0, 50000),
      contentType: 'text/plain',
      metadata: { command, exitCode, durationMs, stream: 'stdout' },
    });
  }

  if (stderr.trim() && stderr.length > 10) {
    await createEvidence({
      findingId,
      assessmentId,
      type: 'tool_output',
      title: `${toolName} stderr`,
      content: stderr.substring(0, 10000),
      contentType: 'text/plain',
      metadata: { command, exitCode, stream: 'stderr' },
    });
  }
}

// ─── Evidence Statistics ─────────────────────────────────────────────────────

export async function getEvidenceStats(organizationId: string) {
  const [totalFindings, findingsWithEvidence, totalEvidence] = await Promise.all([
    prisma.finding.count({
      where: { assessment: { organizationId } },
    }),
    prisma.finding.count({
      where: {
        assessment: { organizationId },
        evidences: { some: {} },
      },
    }),
    prisma.evidence.count({
      where: {
        assessment: { organizationId },
      },
    }),
  ]);

  return {
    totalFindings,
    findingsWithEvidence,
    findingsWithoutEvidence: totalFindings - findingsWithEvidence,
    totalEvidenceRecords: totalEvidence,
    evidenceCoverage: totalFindings > 0
      ? Math.round((findingsWithEvidence / totalFindings) * 100)
      : 0,
  };
}
