import { PrismaClient, Hypothesis, HypothesisStatus } from '@prisma/client';
import logger from '../utils/logger';

const prisma = new PrismaClient();

export interface CreateHypothesisInput {
  engagementId: string;
  hypothesis: string;
  reasoning: string;
  confidence?: number;
  testAction?: string;
  parentHypothesisId?: string;
}

export interface UpdateHypothesisInput {
  status?: HypothesisStatus;
  confidence?: number;
  testResult?: string;
  evidence?: string;
}

export interface HypothesisChain {
  root: Hypothesis;
  children: Hypothesis[];
  totalConfidence: number;
  depth: number;
}

export class HypothesisPersistenceService {
  async create(input: CreateHypothesisInput): Promise<Hypothesis> {
    return prisma.hypothesis.create({
      data: {
        engagementId: input.engagementId,
        hypothesis: input.hypothesis,
        reasoning: input.reasoning,
        confidence: input.confidence ?? 0.5,
        testAction: input.testAction,
        parentHypothesisId: input.parentHypothesisId,
      },
    });
  }

  async update(id: string, input: UpdateHypothesisInput): Promise<Hypothesis> {
    return prisma.hypothesis.update({
      where: { id },
      data: input,
    });
  }

  async getById(id: string): Promise<Hypothesis | null> {
    return prisma.hypothesis.findUnique({ where: { id } });
  }

  async getByEngagement(engagementId: string, status?: HypothesisStatus): Promise<Hypothesis[]> {
    const where: any = { engagementId };
    if (status) where.status = status;
    return prisma.hypothesis.findMany({
      where,
      orderBy: [{ confidence: 'desc' }, { createdAt: 'desc' }],
    });
  }

  async getTopHypotheses(engagementId: string, limit: number = 10): Promise<Hypothesis[]> {
    return prisma.hypothesis.findMany({
      where: { engagementId, status: { not: 'ABANDONED' } },
      orderBy: { confidence: 'desc' },
      take: limit,
    });
  }

  async getConfirmed(engagementId: string): Promise<Hypothesis[]> {
    return prisma.hypothesis.findMany({
      where: { engagementId, status: 'CONFIRMED' },
      orderBy: { confidence: 'desc' },
    });
  }

  async getChain(hypothesisId: string): Promise<HypothesisChain> {
    const root = await prisma.hypothesis.findUnique({
      where: { id: hypothesisId },
      include: {
        childHypotheses: {
          include: { childHypotheses: true },
          orderBy: { confidence: 'desc' },
        },
      },
    });
    if (!root) throw new Error('Hypothesis not found');

    const flatten = (h: Hypothesis, depth: number = 0): { hypothesis: Hypothesis; depth: number }[] => {
      let results = [{ hypothesis: h, depth }];
      const children = (h as any).childHypotheses || [];
      for (const child of children) {
        results = results.concat(flatten(child, depth + 1));
      }
      return results;
    };

    const allNodes = flatten(root);
    const maxDepth = Math.max(...allNodes.map(n => n.depth), 0);
    const avgConfidence = allNodes.reduce((sum, n) => sum + n.hypothesis.confidence, 0) / allNodes.length;

    return {
      root,
      children: allNodes.filter(n => n.depth > 0).map(n => n.hypothesis),
      totalConfidence: avgConfidence,
      depth: maxDepth,
    };
  }

  async getStats(engagementId: string): Promise<{
    total: number;
    proposed: number;
    testing: number;
    confirmed: number;
    refuted: number;
    avgConfidence: number;
  }> {
    const [total, proposed, testing, confirmed, refuted, avg] = await Promise.all([
      prisma.hypothesis.count({ where: { engagementId } }),
      prisma.hypothesis.count({ where: { engagementId, status: 'PROPOSED' } }),
      prisma.hypothesis.count({ where: { engagementId, status: 'TESTING' } }),
      prisma.hypothesis.count({ where: { engagementId, status: 'CONFIRMED' } }),
      prisma.hypothesis.count({ where: { engagementId, status: 'REFUTED' } }),
      prisma.hypothesis.aggregate({ where: { engagementId }, _avg: { confidence: true } }),
    ]);
    return {
      total,
      proposed,
      testing,
      confirmed,
      refuted,
      avgConfidence: avg._avg.confidence ?? 0,
    };
  }

  async delete(id: string): Promise<void> {
    await prisma.hypothesis.delete({ where: { id } });
  }

  async deleteByEngagement(engagementId: string): Promise<number> {
    const result = await prisma.hypothesis.deleteMany({ where: { engagementId } });
    return result.count;
  }
}

export const hypothesisPersistenceService = new HypothesisPersistenceService();
