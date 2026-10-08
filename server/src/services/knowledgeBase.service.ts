import { PrismaClient, EngagementKnowledge } from '@prisma/client';
import logger from '../utils/logger';

const prisma = new PrismaClient();

export interface CreateKnowledgeInput {
  engagementId: string;
  category: string;
  key: string;
  value: string;
  confidence?: number;
  source?: string;
}

export interface KnowledgeQuery {
  engagementId: string;
  category?: string;
  keyPattern?: string;
  minConfidence?: number;
  search?: string;
}

export class KnowledgeBaseService {
  async upsert(input: CreateKnowledgeInput): Promise<EngagementKnowledge> {
    const existing = await prisma.engagementKnowledge.findUnique({
      where: { engagementId_category_key: { engagementId: input.engagementId, category: input.category, key: input.key } },
    });

    if (existing) {
      const confidence = input.confidence ?? existing.confidence;
      if (confidence >= existing.confidence) {
        return prisma.engagementKnowledge.update({
          where: { id: existing.id },
          data: { value: input.value, confidence, source: input.source ?? existing.source },
        });
      }
      return existing;
    }

    return prisma.engagementKnowledge.create({
      data: {
        engagementId: input.engagementId,
        category: input.category,
        key: input.key,
        value: input.value,
        confidence: input.confidence ?? 1.0,
        source: input.source,
      },
    });
  }

  async upsertBatch(inputs: CreateKnowledgeInput[]): Promise<number> {
    let count = 0;
    for (const input of inputs) {
      try {
        await this.upsert(input);
        count++;
      } catch (e) {
        logger.warn('Failed to upsert knowledge entry', { key: input.key, error: (e as Error).message });
      }
    }
    return count;
  }

  async query(q: KnowledgeQuery): Promise<EngagementKnowledge[]> {
    const where: any = { engagementId: q.engagementId };
    if (q.category) where.category = q.category;
    if (q.minConfidence) where.confidence = { gte: q.minConfidence };
    if (q.keyPattern) where.key = { contains: q.keyPattern };
    if (q.search) {
      where.OR = [
        { key: { contains: q.search } },
        { value: { contains: q.search } },
      ];
    }
    return prisma.engagementKnowledge.findMany({
      where,
      orderBy: [{ confidence: 'desc' }, { updatedAt: 'desc' }],
    });
  }

  async getByCategory(engagementId: string, category: string): Promise<EngagementKnowledge[]> {
    return prisma.engagementKnowledge.findMany({
      where: { engagementId, category },
      orderBy: { confidence: 'desc' },
    });
  }

  async getById(id: string): Promise<EngagementKnowledge | null> {
    return prisma.engagementKnowledge.findUnique({ where: { id } });
  }

  async delete(id: string): Promise<void> {
    await prisma.engagementKnowledge.delete({ where: { id } });
  }

  async deleteByEngagement(engagementId: string): Promise<number> {
    const result = await prisma.engagementKnowledge.deleteMany({ where: { engagementId } });
    return result.count;
  }

  async getCategories(engagementId: string): Promise<{ category: string; count: number }[]> {
    const result = await prisma.engagementKnowledge.groupBy({
      by: ['category'],
      where: { engagementId },
      _count: true,
    });
    return result.map(r => ({ category: r.category, count: r._count }));
  }

  async getStats(engagementId: string): Promise<{ totalEntries: number; categories: number; avgConfidence: number }> {
    const [total, categories, avg] = await Promise.all([
      prisma.engagementKnowledge.count({ where: { engagementId } }),
      prisma.engagementKnowledge.groupBy({ by: ['category'], where: { engagementId } }),
      prisma.engagementKnowledge.aggregate({ where: { engagementId }, _avg: { confidence: true } }),
    ]);
    return {
      totalEntries: total,
      categories: categories.length,
      avgConfidence: avg._avg.confidence ?? 0,
    };
  }

  async findPatterns(engagementId: string, category?: string): Promise<Map<string, EngagementKnowledge[]>> {
    const where: any = { engagementId };
    if (category) where.category = category;
    const entries = await prisma.engagementKnowledge.findMany({ where, orderBy: { confidence: 'desc' } });
    const grouped = new Map<string, EngagementKnowledge[]>();
    for (const entry of entries) {
      const group = grouped.get(entry.category) || [];
      group.push(entry);
      grouped.set(entry.category, group);
    }
    return grouped;
  }

  async exportKnowledge(engagementId: string): Promise<string> {
    const entries = await prisma.engagementKnowledge.findMany({
      where: { engagementId },
      orderBy: [{ category: 'asc' }, { confidence: 'desc' }],
    });
    return JSON.stringify(entries, null, 2);
  }

  async importKnowledge(engagementId: string, data: string): Promise<number> {
    const entries: CreateKnowledgeInput[] = JSON.parse(data);
    let count = 0;
    for (const entry of entries) {
      await this.upsert({ ...entry, engagementId });
      count++;
    }
    return count;
  }
}

export const knowledgeBaseService = new KnowledgeBaseService();
