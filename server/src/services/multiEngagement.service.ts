import { PrismaClient, Engagement, EngagementStatus } from '@prisma/client';
import logger from '../utils/logger';

const prisma = new PrismaClient();

export interface EngagementSummary {
  id: string;
  name: string;
  status: EngagementStatus;
  target: string;
  createdAt: Date;
  assetCount: number;
  hypothesisCount: number;
  confirmedHypotheses: number;
  knowledgeCount: number;
  avgConfidence: number;
}

export interface CrossEngagementStats {
  totalEngagements: number;
  activeEngagements: number;
  completedEngagements: number;
  totalAssets: number;
  totalHypotheses: number;
  totalConfirmed: number;
  totalKnowledge: number;
  sharedPatterns: { pattern: string; engagements: string[]; count: number }[];
}

export class MultiEngagementService {
  async getEngagementSummaries(organizationId: string): Promise<EngagementSummary[]> {
    const engagements = await prisma.engagement.findMany({
      where: { organizationId },
      include: {
        _count: {
          select: {
            discoveredAssets: true,
            hypotheses: true,
            knowledge: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    const summaries: EngagementSummary[] = [];
    for (const eng of engagements) {
      const [confirmed, avgConf] = await Promise.all([
        prisma.hypothesis.count({ where: { engagementId: eng.id, status: 'CONFIRMED' } }),
        prisma.hypothesis.aggregate({ where: { engagementId: eng.id }, _avg: { confidence: true } }),
      ]);
      summaries.push({
        id: eng.id,
        name: eng.name,
        status: eng.status,
        target: eng.description || '',
        createdAt: eng.createdAt,
        assetCount: eng._count.discoveredAssets,
        hypothesisCount: eng._count.hypotheses,
        confirmedHypotheses: confirmed,
        knowledgeCount: eng._count.knowledge,
        avgConfidence: avgConf._avg.confidence ?? 0,
      });
    }
    return summaries;
  }

  async getCrossEngagementStats(organizationId: string): Promise<CrossEngagementStats> {
    const engagements = await prisma.engagement.findMany({
      where: { organizationId },
      include: {
        _count: {
          select: {
            discoveredAssets: true,
            hypotheses: true,
            knowledge: true,
          },
        },
      },
    });

    const totalEngagements = engagements.length;
    const activeEngagements = engagements.filter(e => e.status === 'ACTIVE').length;
    const completedEngagements = engagements.filter(e => e.status === 'COMPLETED').length;
    const totalAssets = engagements.reduce((sum, e) => sum + e._count.discoveredAssets, 0);
    const totalHypotheses = engagements.reduce((sum, e) => sum + e._count.hypotheses, 0);
    const totalKnowledge = engagements.reduce((sum, e) => sum + e._count.knowledge, 0);

    let totalConfirmed = 0;
    for (const eng of engagements) {
      totalConfirmed += await prisma.hypothesis.count({ where: { engagementId: eng.id, status: 'CONFIRMED' } });
    }

    const sharedPatterns = await this.findSharedKnowledgePatterns(organizationId);

    return {
      totalEngagements,
      activeEngagements,
      completedEngagements,
      totalAssets,
      totalHypotheses,
      totalConfirmed,
      totalKnowledge,
      sharedPatterns,
    };
  }

  async findSharedKnowledgePatterns(organizationId: string): Promise<{ pattern: string; engagements: string[]; count: number }[]> {
    const engagements = await prisma.engagement.findMany({
      where: { organizationId },
      select: { id: true },
    });

    const engIds = engagements.map(e => e.id);
    if (engIds.length === 0) return [];

    const knowledge = await prisma.engagementKnowledge.findMany({
      where: { engagementId: { in: engIds } },
      select: { category: true, key: true, engagementId: true },
    });

    const keyToEngagements = new Map<string, Set<string>>();
    for (const k of knowledge) {
      const patternKey = `${k.category}:${k.key}`;
      const set = keyToEngagements.get(patternKey) || new Set();
      set.add(k.engagementId);
      keyToEngagements.set(patternKey, set);
    }

    const shared: { pattern: string; engagements: string[]; count: number }[] = [];
    for (const [pattern, engSet] of keyToEngagements) {
      if (engSet.size > 1) {
        shared.push({
          pattern,
          engagements: Array.from(engSet),
          count: engSet.size,
        });
      }
    }

    return shared.sort((a, b) => b.count - a.count);
  }

  async copyKnowledgeBetweenEngagements(fromEngagementId: string, toEngagementId: string, category?: string): Promise<number> {
    const where: any = { engagementId: fromEngagementId };
    if (category) where.category = category;

    const entries = await prisma.engagementKnowledge.findMany({ where });
    let count = 0;

    for (const entry of entries) {
      try {
        const existing = await prisma.engagementKnowledge.findUnique({
          where: { engagementId_category_key: { engagementId: toEngagementId, category: entry.category, key: entry.key } },
        });

        if (existing) {
          if (entry.confidence > existing.confidence) {
            await prisma.engagementKnowledge.update({
              where: { id: existing.id },
              data: { value: entry.value, confidence: entry.confidence, source: entry.source },
            });
          }
        } else {
          await prisma.engagementKnowledge.create({
            data: {
              engagementId: toEngagementId,
              category: entry.category,
              key: entry.key,
              value: entry.value,
              confidence: entry.confidence,
              source: entry.source,
            },
          });
        }
        count++;
      } catch (e) {
        logger.warn('Failed to copy knowledge entry', { key: entry.key, error: (e as Error).message });
      }
    }
    return count;
  }

  async getEngagementTimeline(engagementId: string): Promise<{ date: string; events: { type: string; detail: string }[] }[]> {
    const [hypotheses, tools, knowledge] = await Promise.all([
      prisma.hypothesis.findMany({
        where: { engagementId },
        select: { createdAt: true, hypothesis: true, status: true },
        orderBy: { createdAt: 'asc' },
      }),
      prisma.toolExecution.findMany({
        where: { engagementId },
        select: { startedAt: true, toolName: true, status: true },
        orderBy: { startedAt: 'asc' },
      }),
      prisma.engagementKnowledge.findMany({
        where: { engagementId },
        select: { createdAt: true, category: true, key: true },
        orderBy: { createdAt: 'asc' },
      }),
    ]);

    const dateMap = new Map<string, { type: string; detail: string }[]>();

    for (const h of hypotheses) {
      const date = h.createdAt.toISOString().split('T')[0];
      const events = dateMap.get(date) || [];
      events.push({ type: 'hypothesis', detail: `[${h.status}] ${h.hypothesis.slice(0, 100)}` });
      dateMap.set(date, events);
    }

    for (const t of tools) {
      const date = t.startedAt.toISOString().split('T')[0];
      const events = dateMap.get(date) || [];
      events.push({ type: 'tool', detail: `${t.toolName} - ${t.status}` });
      dateMap.set(date, events);
    }

    for (const k of knowledge) {
      const date = k.createdAt.toISOString().split('T')[0];
      const events = dateMap.get(date) || [];
      events.push({ type: 'knowledge', detail: `[${k.category}] ${k.key}` });
      dateMap.set(date, events);
    }

    return Array.from(dateMap.entries())
      .map(([date, events]) => ({ date, events }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }
}

export const multiEngagementService = new MultiEngagementService();
