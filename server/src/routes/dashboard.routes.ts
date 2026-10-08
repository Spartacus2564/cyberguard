import { Router, Request, Response } from 'express';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

const router = Router();
router.use(authenticate);

router.get('/dashboard/stats', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const orgId = authReq.organizationId;

    const [engagements, findings, assets] = await Promise.all([
      prisma.engagement.findMany({
        where: { organizationId: orgId },
        select: { id: true, name: true, domain: true, status: true, createdAt: true },
        orderBy: { createdAt: 'desc' },
        take: 20,
      }),
      prisma.finding.groupBy({
        by: ['severity'],
        where: { assessment: { organizationId: orgId } },
        _count: true,
      }),
      prisma.asset.count({ where: { organizationId: orgId } }),
    ]);

    const findingsBySeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => {
      const found = findings.find(f => f.severity === sev);
      return { severity: sev, count: found ? found._count : 0 };
    });

    const totalFindings = findingsBySeverity.reduce((s, f) => s + f.count, 0);
    const criticalFindings = (findingsBySeverity.find(f => f.severity === 'CRITICAL')?.count || 0) +
      (findingsBySeverity.find(f => f.severity === 'HIGH')?.count || 0);

    const securityScore = totalFindings === 0 ? 100 : Math.max(0, 100 - (criticalFindings * 10) - (totalFindings * 2));

    const recentAssessments = engagements.map(e => ({
      id: e.id,
      domain: e.domain || e.name,
      status: e.status,
      score: null as number | null,
      findingsCount: 0,
      createdAt: e.createdAt,
    }));

    res.json({
      securityScore,
      totalAssets: assets,
      activeAssessments: engagements.filter(e => e.status === 'ACTIVE' || e.status === 'DRAFT').length,
      criticalFindings,
      totalEngagements: engagements.length,
      findingsBySeverity,
      recentAssessments,
    });
  } catch (error) {
    logger.error('Dashboard stats error:', { error: String(error) });
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

export default router;
