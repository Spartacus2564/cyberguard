import { Router, Request, Response } from 'express';
import { query } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import { getAuditLogs } from '../services/audit.service';

const router = Router();

router.use(authenticate);

router.get(
  '/',
  validate([
    query('limit').optional().isInt({ min: 1, max: 200 }),
    query('offset').optional().isInt({ min: 0 }),
    query('action').optional().isString(),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const limit = parseInt(req.query.limit as string) || 50;
      const offset = parseInt(req.query.offset as string) || 0;
      const action = req.query.action as string | undefined;

      const result = await getAuditLogs(authReq.organizationId, { limit, offset, action });
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch audit logs' });
    }
  }
);

export default router;
