import { Router, Request, Response } from 'express';
import { param, query } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import * as findingService from '../services/finding.service';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const router = Router();

router.use(authenticate);

router.get(
  '/summary',
  async (req: Request, res: Response) => {
    try {
      const { organizationId } = req as AuthRequest;
      const summary = await findingService.getFindingsSummary(organizationId);
      res.json(summary);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch findings summary' });
    }
  }
);

router.get(
  '/assessments/:assessmentId/findings',
  validate([
    param('assessmentId').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('severity').optional().isIn(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).withMessage('Invalid severity'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 50;
      const severity = req.query.severity as string | undefined;
      const result = await findingService.getFindingsByAssessment(
        req.params.assessmentId,
        authReq.organizationId,
        page,
        limit,
        severity
      );
      res.json(result);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to fetch findings';
      if (message.includes('not found')) {
        res.status(404).json({ message });
      } else {
        res.status(500).json({ message: 'Failed to fetch findings' });
      }
    }
  }
);

export default router;
