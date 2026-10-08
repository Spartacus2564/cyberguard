import { Router, Request, Response } from 'express';
import { body, query, param } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { ssrfProtection } from '../middleware/ssrfProtection';
import { AuthRequest } from '../types';
import * as assessmentService from '../services/assessment.service';
import { logAudit } from '../services/audit.service';
import { addScanJob, scanQueue } from '../queue';
import { getAvailableModules } from '../engine';
import { generateReport, generatePdfReport, generateJsonReport, generateCsvReport } from '../services/report.service';
import { scanLimiter } from '../middleware/rateLimiter';
import { AssessmentStatus, ScanJobStatus } from '@prisma/client';
import prisma from '../lib/prisma';
import fs from 'fs';
import path from 'path';
import { config } from '../config';
import redis from '../lib/redis';
import logger from '../utils/logger';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const router = Router();

router.use(authenticate);

router.get(
  '/stats',
  async (req: Request, res: Response) => {
    try {
      const { organizationId } = req as AuthRequest;
      const stats = await assessmentService.getAssessmentStats(organizationId);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch assessment stats' });
    }
  }
);

router.post(
  '/',
  validate([
    body('domain')
      .notEmpty().withMessage('Domain is required')
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)
      .withMessage('Invalid domain format'),
  ]),
  ssrfProtection,
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { domain } = req.body;
      const assessment = await assessmentService.createAssessment(domain.trim().toLowerCase(), authReq.organizationId);
      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'assessment.create',
        resource: 'assessment',
        resourceId: assessment.id,
        details: `Created assessment for ${domain}`,
        ipAddress: req.ip,
      });
      res.status(201).json(assessment);
    } catch (error) {
      res.status(500).json({ message: 'Failed to create assessment' });
    }
  }
);

router.get(
  '/',
  validate([
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const result = await assessmentService.getAssessmentsByOrganization(authReq.organizationId, page, limit);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch assessments' });
    }
  }
);

router.get(
  '/:id',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await assessmentService.getAssessmentById(req.params.id, authReq.organizationId);
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }
      res.json(assessment);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch assessment' });
    }
  }
);

router.delete(
  '/:id',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      await assessmentService.deleteAssessment(req.params.id, authReq.organizationId);
      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'assessment.delete',
        resource: 'assessment',
        resourceId: req.params.id,
        ipAddress: req.ip,
      });
      res.status(204).send();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to delete assessment';
      if (message.includes('not found')) {
        res.status(404).json({ message });
      } else if (message.includes('running')) {
        res.status(409).json({ message });
      } else {
        res.status(500).json({ message: 'Failed to delete assessment' });
      }
    }
  }
);

router.post(
  '/:id/run',
  scanLimiter,
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await assessmentService.getAssessmentById(req.params.id, authReq.organizationId);
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      if (assessment.status === AssessmentStatus.RUNNING) {
        res.status(409).json({ message: 'Assessment is already running' });
        return;
      }

      // Accept optional module selection in body
      const allModules = getAvailableModules();
      const modules = (req.body?.modules && Array.isArray(req.body.modules))
        ? req.body.modules.filter((m: string) => allModules.includes(m as any))
        : allModules;

      await addScanJob({
        assessmentId: req.params.id,
        domain: assessment.domain,
        organizationId: authReq.organizationId,
        modules: modules.length > 0 ? modules : allModules,
      });

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'assessment.run',
        resource: 'assessment',
        resourceId: req.params.id,
        details: `Started scan with ${modules.length} modules`,
        ipAddress: req.ip,
      });

      res.json({ message: 'Assessment execution queued', assessmentId: req.params.id });
    } catch (error) {
      res.status(500).json({ message: 'Failed to trigger assessment' });
    }
  }
);

// ─── CANCEL ASSESSMENT ───────────────────────────────────────────────────────
router.post(
  '/:id/cancel',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
      });
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      if (assessment.status !== AssessmentStatus.RUNNING && assessment.status !== AssessmentStatus.PENDING) {
        res.status(409).json({ message: 'Assessment is not running' });
        return;
      }

      // Cancel the Bull queue job
      const jobs = await scanQueue.getJobs(['active', 'waiting', 'delayed']);
      for (const job of jobs) {
        if (job.data.assessmentId === req.params.id) {
          await job.remove();
          break;
        }
      }

      // Update status to CANCELLED
      await prisma.assessment.update({
        where: { id: req.params.id },
        data: { status: AssessmentStatus.CANCELLED, completedAt: new Date() },
      });

      // Cancel any active scan jobs
      await prisma.scanJob.updateMany({
        where: { assessmentId: req.params.id, status: { in: [ScanJobStatus.QUEUED, ScanJobStatus.PROCESSING] } },
        data: { status: ScanJobStatus.CANCELLED },
      });

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'assessment.cancel',
        resource: 'assessment',
        resourceId: req.params.id,
        ipAddress: req.ip,
      });

      res.json({ message: 'Assessment cancelled' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to cancel assessment' });
    }
  }
);

router.get(
  '/:id/report/download',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;

      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
      });

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      let report = await prisma.report.findFirst({
        where: { assessmentId: req.params.id, organizationId: authReq.organizationId },
      });

      if (!report) {
        report = await generateReport(req.params.id, authReq.organizationId);
      }

      const reportsDir = path.resolve(config.reportsDir);

      if (report.pdfPath) {
        const resolvedPath = path.resolve(report.pdfPath);
        if (!resolvedPath.startsWith(reportsDir)) {
          res.status(400).json({ message: 'Invalid report path' });
          return;
        }
        if (fs.existsSync(resolvedPath)) {
          res.setHeader('Content-Type', 'application/pdf');
          res.setHeader('Content-Disposition', `attachment; filename="report-${assessment.domain}.pdf"`);
          fs.createReadStream(resolvedPath).pipe(res);
          return;
        }
      }

      const pdfPath = await generatePdfReport(report.id);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="report-${assessment.domain}.pdf"`);
      fs.createReadStream(pdfPath).pipe(res);
    } catch (error: unknown) {
      logger.error('Report download error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to download report' });
    }
  }
);

// ─── JSON EXPORT ──────────────────────────────────────────────────────────────
router.get(
  '/:id/report/json',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const json = await generateJsonReport(req.params.id, authReq.organizationId);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="report-${req.params.id.slice(0, 8)}.json"`);
      res.json(json);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to export report';
      if (message.includes('not found')) {
        res.status(404).json({ message });
      } else {
        res.status(500).json({ message: 'Failed to export report' });
      }
    }
  }
);

// ─── CSV EXPORT ───────────────────────────────────────────────────────────────
router.get(
  '/:id/report/csv',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const csv = await generateCsvReport(req.params.id, authReq.organizationId);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="findings-${req.params.id.slice(0, 8)}.csv"`);
      res.send(csv);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to export report';
      if (message.includes('not found')) {
        res.status(404).json({ message });
      } else {
        res.status(500).json({ message: 'Failed to export report' });
      }
    }
  }
);

// ─── SCAN PROGRESS ────────────────────────────────────────────────────────────
router.get(
  '/:id/progress',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: (req as AuthRequest).organizationId },
      });
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const progressKey = `scan:${req.params.id}:progress`;
      const [activeModule, moduleIndex, totalModules] = await Promise.all([
        redis.get(`${progressKey}:activeModule`),
        redis.get(`${progressKey}:moduleIndex`),
        redis.get(`${progressKey}:totalModules`),
      ]);

      res.json({
        status: assessment.status,
        activeModule: activeModule || null,
        moduleIndex: moduleIndex ? parseInt(moduleIndex) : 0,
        totalModules: totalModules ? parseInt(totalModules) : 0,
        startedAt: assessment.startedAt?.toISOString() || null,
      });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch progress' });
    }
  }
);

// ─── SCAN LOGS ───────────────────────────────────────────────────────────────
router.get(
  '/:id/logs',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: (req as AuthRequest).organizationId },
      });
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const logsKey = `scan:${req.params.id}:logs`;
      const rawLogs = await redis.lrange(logsKey, 0, -1);
      const logs = rawLogs.map((r) => {
        try { return JSON.parse(r); } catch { return null; }
      }).filter(Boolean);

      res.json({ logs, status: assessment.status });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch scan logs' });
    }
  }
);

// ─── PREVIOUS SCAN COMPARISON ────────────────────────────────────────────────
router.get(
  '/:id/compare',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
      });
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      // Find previous completed scan for same domain
      const previous = await prisma.assessment.findFirst({
        where: {
          organizationId: authReq.organizationId,
          domain: assessment.domain,
          status: AssessmentStatus.COMPLETED,
          id: { not: req.params.id },
        },
        orderBy: { completedAt: 'desc' },
        include: { findings: true },
      });

      if (!previous) {
        res.json({ hasPrevious: false });
        return;
      }

      const prevFindings = previous.findings;
      const currFindings = await prisma.finding.findMany({ where: { assessmentId: req.params.id } });

      const prevSevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      const currSevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      prevFindings.forEach(f => { prevSevCounts[f.severity as keyof typeof prevSevCounts]++; });
      currFindings.forEach(f => { currSevCounts[f.severity as keyof typeof currSevCounts]++; });

      const prevScore = previous.riskScore || 0;
      const currScore = assessment.riskScore || 0;

      // Find new and resolved findings using category+keyword matching (not exact title)
      // This prevents false "resolved" when the same issue gets a slightly different title
      function normalizeForComparison(title: string): string {
        return title.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 40);
      }
      
      const prevKeys = new Set(prevFindings.map(f => normalizeForComparison(f.title)));
      const currKeys = new Set(currFindings.map(f => normalizeForComparison(f.title)));
      
      // Also build category-based sets for fuzzy matching
      const prevByCategory = new Map<string, typeof prevFindings[0]>();
      for (const f of prevFindings) {
        const cat = f.category || '';
        if (!prevByCategory.has(cat)) prevByCategory.set(cat, f);
      }
      const currByCategory = new Map<string, typeof currFindings[0]>();
      for (const f of currFindings) {
        const cat = f.category || '';
        if (!currByCategory.has(cat)) currByCategory.set(cat, f);
      }
      
      const newFindings = currFindings.filter(f => {
        const norm = normalizeForComparison(f.title);
        // Consider "new" only if not matched by normalized title OR category
        return !prevKeys.has(norm) && !prevByCategory.has(f.category || '');
      }).map(f => ({ title: f.title, severity: f.severity }));
      
      const resolvedFindings = prevFindings.filter(f => {
        const norm = normalizeForComparison(f.title);
        // Consider "resolved" only if not matched by normalized title OR category
        return !currKeys.has(norm) && !currByCategory.has(f.category || '');
      }).map(f => ({ title: f.title, severity: f.severity }));

      res.json({
        hasPrevious: true,
        previous: {
          id: previous.id,
          domain: previous.domain,
          completedAt: previous.completedAt?.toISOString(),
          score: prevScore,
          totalFindings: prevFindings.length,
          severityCounts: prevSevCounts,
        },
        current: {
          score: currScore,
          totalFindings: currFindings.length,
          severityCounts: currSevCounts,
        },
        delta: {
          scoreChange: currScore - prevScore,
          findingsChange: currFindings.length - prevFindings.length,
          newFindings,
          resolvedFindings,
        },
      });
    } catch (error) {
      res.status(500).json({ message: 'Failed to compare scans' });
    }
  }
);

export default router;
