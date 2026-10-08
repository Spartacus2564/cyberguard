import { Router, Request, Response } from 'express';
import { knowledgeBaseService } from '../services/knowledgeBase.service';
import { hypothesisPersistenceService } from '../services/hypothesisPersistence.service';
import { multiEngagementService } from '../services/multiEngagement.service';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

const router = Router();

router.use(authenticate);

async function verifyEngagementOwnership(engagementId: string, organizationId: string): Promise<boolean> {
  const engagement = await prisma.engagement.findFirst({ where: { id: engagementId, organizationId } });
  return !!engagement;
}

// ═══════════════════════════════════════════════════════════════════════════════
// KNOWLEDGE BASE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/engagements/:id/knowledge', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const { category, minConfidence, search, keyPattern } = req.query;
    const entries = await knowledgeBaseService.query({
      engagementId: req.params.id,
      category: category as string | undefined,
      minConfidence: minConfidence ? parseFloat(minConfidence as string) : undefined,
      search: search as string | undefined,
      keyPattern: keyPattern as string | undefined,
    });
    res.json({ data: entries, total: entries.length });
  } catch (error) {
    logger.error('Failed to fetch knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch knowledge' });
  }
});

router.post('/engagements/:id/knowledge', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const entry = await knowledgeBaseService.upsert({
      engagementId: req.params.id,
      ...req.body,
    });
    res.status(201).json(entry);
  } catch (error) {
    logger.error('Failed to upsert knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to upsert knowledge' });
  }
});

router.post('/engagements/:id/knowledge/batch', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const count = await knowledgeBaseService.upsertBatch(
      req.body.entries.map((e: any) => ({ engagementId: req.params.id, ...e }))
    );
    res.json({ imported: count });
  } catch (error) {
    logger.error('Failed to batch upsert knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to batch upsert knowledge' });
  }
});

router.get('/engagements/:id/knowledge/categories', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const categories = await knowledgeBaseService.getCategories(req.params.id);
    res.json({ data: categories });
  } catch (error) {
    logger.error('Failed to fetch knowledge categories', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch knowledge categories' });
  }
});

router.get('/engagements/:id/knowledge/stats', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const stats = await knowledgeBaseService.getStats(req.params.id);
    res.json(stats);
  } catch (error) {
    logger.error('Failed to fetch knowledge stats', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch knowledge stats' });
  }
});

router.get('/engagements/:id/knowledge/patterns', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const { category } = req.query;
    const patterns = await knowledgeBaseService.findPatterns(req.params.id, category as string | undefined);
    const result: Record<string, any[]> = {};
    patterns.forEach((value, key) => { result[key] = value; });
    res.json({ data: result });
  } catch (error) {
    logger.error('Failed to fetch knowledge patterns', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch knowledge patterns' });
  }
});

router.get('/engagements/:id/knowledge/export', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const data = await knowledgeBaseService.exportKnowledge(req.params.id);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="knowledge-${req.params.id}.json"`);
    res.send(data);
  } catch (error) {
    logger.error('Failed to export knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to export knowledge' });
  }
});

router.post('/engagements/:id/knowledge/import', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const count = await knowledgeBaseService.importKnowledge(req.params.id, JSON.stringify(req.body.entries));
    res.json({ imported: count });
  } catch (error) {
    logger.error('Failed to import knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to import knowledge' });
  }
});

router.delete('/engagements/:id/knowledge/:knowledgeId', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    await knowledgeBaseService.delete(req.params.knowledgeId);
    res.json({ deleted: true });
  } catch (error) {
    logger.error('Failed to delete knowledge', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to delete knowledge' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HYPOTHESIS PERSISTENCE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/engagements/:id/hypotheses', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const { status } = req.query;
    const hypotheses = await hypothesisPersistenceService.getByEngagement(
      req.params.id,
      status as any
    );
    res.json({ data: hypotheses, total: hypotheses.length });
  } catch (error) {
    logger.error('Failed to fetch hypotheses', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch hypotheses' });
  }
});

router.post('/engagements/:id/hypotheses', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const hypothesis = await hypothesisPersistenceService.create({
      engagementId: req.params.id,
      ...req.body,
    });
    res.status(201).json(hypothesis);
  } catch (error) {
    logger.error('Failed to create hypothesis', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to create hypothesis' });
  }
});

router.put('/engagements/:id/hypotheses/:hypothesisId', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const hypothesis = await hypothesisPersistenceService.update(req.params.hypothesisId, req.body);
    res.json(hypothesis);
  } catch (error) {
    logger.error('Failed to update hypothesis', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to update hypothesis' });
  }
});

router.get('/engagements/:id/hypotheses/top', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;
    const hypotheses = await hypothesisPersistenceService.getTopHypotheses(req.params.id, limit);
    res.json({ data: hypotheses });
  } catch (error) {
    logger.error('Failed to fetch top hypotheses', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch top hypotheses' });
  }
});

router.get('/engagements/:id/hypotheses/confirmed', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const hypotheses = await hypothesisPersistenceService.getConfirmed(req.params.id);
    res.json({ data: hypotheses });
  } catch (error) {
    logger.error('Failed to fetch confirmed hypotheses', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch confirmed hypotheses' });
  }
});

router.get('/engagements/:id/hypotheses/stats', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const stats = await hypothesisPersistenceService.getStats(req.params.id);
    res.json(stats);
  } catch (error) {
    logger.error('Failed to fetch hypothesis stats', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch hypothesis stats' });
  }
});

router.get('/engagements/:id/hypotheses/:hypothesisId/chain', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const chain = await hypothesisPersistenceService.getChain(req.params.hypothesisId);
    res.json(chain);
  } catch (error) {
    logger.error('Failed to fetch hypothesis chain', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch hypothesis chain' });
  }
});

router.delete('/engagements/:id/hypotheses/:hypothesisId', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    await hypothesisPersistenceService.delete(req.params.hypothesisId);
    res.json({ deleted: true });
  } catch (error) {
    logger.error('Failed to delete hypothesis', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to delete hypothesis' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// MULTI-ENGAGEMENT ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/multi/summaries', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const orgId = authReq.organizationId;
    if (!orgId) return res.status(401).json({ error: 'Unauthorized' });
    const summaries = await multiEngagementService.getEngagementSummaries(orgId);
    res.json({ data: summaries });
  } catch (error) {
    logger.error('Failed to fetch engagement summaries', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch engagement summaries' });
  }
});

router.get('/multi/cross-stats', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const orgId = authReq.organizationId;
    if (!orgId) return res.status(401).json({ error: 'Unauthorized' });
    const stats = await multiEngagementService.getCrossEngagementStats(orgId);
    res.json(stats);
  } catch (error) {
    logger.error('Failed to fetch cross-engagement stats', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch cross-engagement stats' });
  }
});

router.post('/multi/copy-knowledge/:fromId/:toId', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.fromId, authReq.organizationId) ||
        !await verifyEngagementOwnership(req.params.toId, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const { category } = req.query;
    const count = await multiEngagementService.copyKnowledgeBetweenEngagements(
      req.params.fromId,
      req.params.toId,
      category as string | undefined
    );
    res.json({ copied: count });
  } catch (error) {
    logger.error('Failed to copy knowledge between engagements', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to copy knowledge between engagements' });
  }
});

router.get('/multi/timeline/:id', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    if (!await verifyEngagementOwnership(req.params.id, authReq.organizationId)) {
      return res.status(404).json({ error: 'Engagement not found' });
    }
    const timeline = await multiEngagementService.getEngagementTimeline(req.params.id);
    res.json({ data: timeline });
  } catch (error) {
    logger.error('Failed to fetch engagement timeline', { error: (error as Error).message });
    res.status(500).json({ error: 'Failed to fetch engagement timeline' });
  }
});

export default router;
