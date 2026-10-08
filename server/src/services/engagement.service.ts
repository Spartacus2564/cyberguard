// ═══════════════════════════════════════════════════════════════════════════════
// ENGAGEMENT SERVICE — CRUD + lifecycle management for engagements
// ═══════════════════════════════════════════════════════════════════════════════

import { EngagementStatus } from '@prisma/client';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CreateEngagementInput {
  name: string;
  domain?: string;
  description?: string;
  organizationId: string;
  scopeRules?: { type: string; targetType: string; value: string; description?: string }[];
  config?: Record<string, unknown>;
}

export interface EngagementWithScope {
  id: string;
  name: string;
  domain: string | null;
  description: string | null;
  status: EngagementStatus;
  organizationId: string;
  startedAt: Date | null;
  completedAt: Date | null;
  config: string | null;
  createdAt: Date;
  updatedAt: Date;
  scopeRules: {
    id: string;
    type: string;
    targetType: string;
    value: string;
    description: string | null;
  }[];
  _count: {
    discoveredAssets: number;
    discoveredServices: number;
    attackPaths: number;
    hypotheses: number;
    toolExecutions: number;
  };
}

// ─── CRUD Operations ─────────────────────────────────────────────────────────

export async function createEngagement(input: CreateEngagementInput): Promise<EngagementWithScope> {
  const engagement = await prisma.engagement.create({
    data: {
      name: input.name,
      domain: input.domain || null,
      description: input.description || null,
      organizationId: input.organizationId,
      config: input.config ? JSON.stringify(input.config) : null,
      scopeRules: {
        create: (input.scopeRules || []).map(rule => ({
          type: rule.type,
          targetType: rule.targetType,
          value: rule.value,
          description: rule.description || null,
        })),
      },
    },
    include: {
      scopeRules: true,
      _count: {
        select: {
          discoveredAssets: true,
          discoveredServices: true,
          attackPaths: true,
          hypotheses: true,
          toolExecutions: true,
        },
      },
    },
  });

  logger.info(`[Engagement] Created: ${engagement.name} (${engagement.id})`);
  return engagement as unknown as EngagementWithScope;
}

export async function getEngagement(id: string, organizationId: string): Promise<EngagementWithScope | null> {
  return prisma.engagement.findFirst({
    where: { id, organizationId },
    include: {
      scopeRules: true,
      _count: {
        select: {
          discoveredAssets: true,
          discoveredServices: true,
          attackPaths: true,
          hypotheses: true,
          toolExecutions: true,
        },
      },
    },
  }) as Promise<EngagementWithScope | null>;
}

export async function listEngagements(
  organizationId: string,
  page = 1,
  limit = 20,
): Promise<{ engagements: EngagementWithScope[]; total: number; page: number; totalPages: number }> {
  const [engagements, total] = await Promise.all([
    prisma.engagement.findMany({
      where: { organizationId },
      include: {
        scopeRules: true,
        _count: {
          select: {
            discoveredAssets: true,
            discoveredServices: true,
            attackPaths: true,
            hypotheses: true,
            toolExecutions: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.engagement.count({ where: { organizationId } }),
  ]);

  return {
    engagements: engagements as unknown as EngagementWithScope[],
    total,
    page,
    totalPages: Math.ceil(total / limit),
  };
}

export async function updateEngagementStatus(
  id: string,
  organizationId: string,
  status: EngagementStatus,
): Promise<void> {
  const updateData: Record<string, unknown> = { status };

  if (status === EngagementStatus.ACTIVE) {
    updateData.startedAt = new Date();
  } else if (status === EngagementStatus.COMPLETED || status === EngagementStatus.FAILED) {
    updateData.completedAt = new Date();
  }

  await prisma.engagement.updateMany({
    where: { id, organizationId },
    data: updateData,
  });

  logger.info(`[Engagement] ${id} status → ${status}`);
}

export async function deleteEngagement(id: string, organizationId: string): Promise<void> {
  const engagement = await prisma.engagement.findFirst({
    where: { id, organizationId },
  });

  if (!engagement) {
    throw new Error('Engagement not found');
  }

  if (engagement.status === EngagementStatus.ACTIVE) {
    throw new Error('Cannot delete an active engagement');
  }

  await prisma.engagement.delete({ where: { id } });
  logger.info(`[Engagement] Deleted: ${id}`);
}

// ─── Scope Management ────────────────────────────────────────────────────────

export async function addScopeRule(
  engagementId: string,
  organizationId: string,
  rule: { type: string; targetType: string; value: string; description?: string },
): Promise<void> {
  const engagement = await prisma.engagement.findFirst({
    where: { id: engagementId, organizationId },
  });
  if (!engagement) throw new Error('Engagement not found');

  await prisma.scopeRule.create({
    data: {
      engagementId,
      type: rule.type,
      targetType: rule.targetType,
      value: rule.value,
      description: rule.description || null,
    },
  });

  logger.info(`[Engagement] Scope rule added to ${engagementId}: ${rule.type} ${rule.targetType}=${rule.value}`);
}

export async function removeScopeRule(
  ruleId: string,
  organizationId: string,
): Promise<void> {
  const rule = await prisma.scopeRule.findFirst({
    where: { id: ruleId, engagement: { organizationId } },
  });
  if (!rule) throw new Error('Scope rule not found');

  await prisma.scopeRule.delete({ where: { id: ruleId } });
  logger.info(`[Engagement] Scope rule removed: ${ruleId}`);
}

// ─── Engagement Statistics ───────────────────────────────────────────────────

export async function getEngagementStats(organizationId: string) {
  const [total, active, completed, totalAssets, totalServices, totalPaths, totalFindings] = await Promise.all([
    prisma.engagement.count({ where: { organizationId } }),
    prisma.engagement.count({ where: { organizationId, status: EngagementStatus.ACTIVE } }),
    prisma.engagement.count({ where: { organizationId, status: EngagementStatus.COMPLETED } }),
    prisma.discoveredAsset.count({ where: { engagement: { organizationId } } }),
    prisma.discoveredService.count({ where: { engagement: { organizationId } } }),
    prisma.attackPath.count({ where: { engagement: { organizationId } } }),
    prisma.finding.count({
      where: {
        assessment: { organizationId },
      },
    }),
  ]);

  return {
    totalEngagements: total,
    activeEngagements: active,
    completedEngagements: completed,
    totalDiscoveredAssets: totalAssets,
    totalDiscoveredServices: totalServices,
    totalAttackPaths: totalPaths,
    totalFindings,
  };
}
