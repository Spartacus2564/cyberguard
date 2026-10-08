import { Router, Request, Response } from 'express';
import { param } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import { captureWebsite, captureMultiplePages } from '../services/screenshot.service';
import { scheduleScan, stopSchedule, getSchedules } from '../services/scheduler.service';
import { generateFixPR, generateFixDiff } from '../services/autofix.service';
import { generateGitHubActionsWorkflow, generateGitLabCI, generateWebhookPayload } from '../services/cicd.service';
import { createReview, addComment, updateStatus, getPendingReviews, getReviewStats, getReviewsByAssessment, ReviewStatus } from '../services/review.service';
import { generateSOC2Report, generateISO27001Report } from '../services/compliance.service';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import fs from 'fs';
import path from 'path';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const router = Router();

router.use(authenticate);

// ─── SCREENSHOT ENDPOINTS ────────────────────────────────────────────────────

// Capture website screenshot
router.post(
  '/:id/screenshot',
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

      const url = `https://${assessment.domain}`;
      const screenshot = await captureWebsite(url, assessment.domain);

      // Save screenshot to database
      const dbScreenshot = await prisma.screenshot.create({
        data: {
          assessmentId: assessment.id,
          url: screenshot.url,
          domain: assessment.domain,
          screenshotPath: screenshot.screenshotPath,
          title: screenshot.title,
          statusCode: screenshot.statusCode,
          technologies: JSON.stringify(screenshot.technologies),
          securityHeaders: JSON.stringify(screenshot.securityHeaders),
        },
      });

      res.json({
        id: dbScreenshot.id,
        url: screenshot.url,
        screenshotPath: screenshot.screenshotPath,
        title: screenshot.title,
        statusCode: screenshot.statusCode,
        technologies: screenshot.technologies,
        securityHeaders: screenshot.securityHeaders,
        performanceMetrics: screenshot.performanceMetrics,
        forms: screenshot.forms,
        links: screenshot.links.length,
      });
    } catch (error) {
      logger.error('Screenshot capture error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to capture screenshot' });
    }
  }
);

// Get screenshots for assessment
router.get(
  '/:id/screenshots',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      // Verify assessment ownership
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
      });
      if (!assessment) return res.status(404).json({ message: 'Assessment not found' });
      
      const screenshots = await prisma.screenshot.findMany({
        where: { assessmentId: req.params.id },
        orderBy: { createdAt: 'desc' },
      });

      res.json(screenshots);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch screenshots' });
    }
  }
);

// Serve screenshot image
router.get(
  '/screenshot/:filename',
  async (req: Request, res: Response) => {
    try {
      // Sanitize filename: only allow alphanumeric, hyphens, underscores, dots
      const safeFilename = req.params.filename.replace(/[^a-zA-Z0-9._-]/g, '');
      if (safeFilename !== req.params.filename || safeFilename.includes('..')) {
        return res.status(400).json({ message: 'Invalid filename' });
      }
      const screenshotsDir = path.join(process.cwd(), 'reports', 'screenshots');
      const filePath = path.join(screenshotsDir, safeFilename);
      
      // Verify path stays within screenshots directory
      if (!path.resolve(filePath).startsWith(path.resolve(screenshotsDir))) {
        return res.status(400).json({ message: 'Invalid filename' });
      }
      
      if (!fs.existsSync(filePath)) {
        res.status(404).json({ message: 'Screenshot not found' });
        return;
      }

      res.setHeader('Content-Type', 'image/png');
      fs.createReadStream(filePath).pipe(res);
    } catch (error) {
      res.status(500).json({ message: 'Failed to serve screenshot' });
    }
  }
);

// ─── SCHEDULE ENDPOINTS ──────────────────────────────────────────────────────

// Create schedule
router.post(
  '/:id/schedule',
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

      const { interval, modules } = req.body;
      if (!interval || !['hourly', 'daily', 'weekly', 'monthly'].includes(interval)) {
        res.status(400).json({ message: 'Invalid interval. Must be hourly, daily, weekly, or monthly' });
        return;
      }

      await scheduleScan({
        assessmentId: assessment.id,
        domain: assessment.domain,
        organizationId: authReq.organizationId,
        interval,
        enabled: true,
        modules: modules || [],
      });

      res.json({ message: `Scheduled ${interval} scan for ${assessment.domain}` });
    } catch (error) {
      logger.error('Schedule creation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to create schedule' });
    }
  }
);

// Stop schedule
router.delete(
  '/:id/schedule',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      await stopSchedule(req.params.id);
      res.json({ message: 'Schedule stopped' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to stop schedule' });
    }
  }
);

// Get schedules for organization
router.get(
  '/schedules',
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const schedules = await getSchedules(authReq.organizationId);
      res.json(schedules);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch schedules' });
    }
  }
);

// ─── AUTO-FIX ENDPOINTS ─────────────────────────────────────────────────────

// Generate fix PR
router.post(
  '/:id/fix-pr',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
        include: { findings: true },
      });

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const fixPR = generateFixPR(assessment.findings as any, assessment.domain);

      // Save to database
      const dbPR = await prisma.fixPR.create({
        data: {
          assessmentId: assessment.id,
          title: fixPR.title,
          description: fixPR.description,
          branch: fixPR.branch,
          changes: JSON.stringify(fixPR.changes),
          status: 'pending',
        },
      });

      res.json({
        id: dbPR.id,
        title: fixPR.title,
        description: fixPR.description,
        branch: fixPR.branch,
        findingsCount: fixPR.findings.length,
        changesCount: fixPR.changes.length,
        changes: fixPR.changes,
        diff: generateFixDiff(fixPR.changes),
      });
    } catch (error) {
      logger.error('Fix PR generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate fix PR' });
    }
  }
);

// Get fix PRs for assessment
router.get(
  '/:id/fix-prs',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.id, organizationId: authReq.organizationId },
      });
      if (!assessment) return res.status(404).json({ message: 'Assessment not found' });

      const prs = await prisma.fixPR.findMany({
        where: { assessmentId: req.params.id },
        orderBy: { createdAt: 'desc' },
      });

      res.json(prs.map(pr => ({
        ...pr,
        changes: JSON.parse(pr.changes),
      })));
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch fix PRs' });
    }
  }
);

// Update fix PR status
router.patch(
  '/:assessmentId/fix-pr/:prId',
  validate([
    param('assessmentId').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
    param('prId').matches(UUID_REGEX).withMessage('Invalid PR ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { status } = req.body;
      if (!status || !['pending', 'applied', 'rejected'].includes(status)) {
        res.status(400).json({ message: 'Invalid status' });
        return;
      }

      // Verify assessment ownership
      const assessment = await prisma.assessment.findFirst({
        where: { id: req.params.assessmentId, organizationId: authReq.organizationId },
      });
      if (!assessment) return res.status(404).json({ message: 'Assessment not found' });

      const pr = await prisma.fixPR.update({
        where: { id: req.params.prId, assessmentId: req.params.assessmentId },
        data: { status },
      });

      res.json(pr);
    } catch (error) {
      res.status(500).json({ message: 'Failed to update fix PR' });
    }
  }
);

// ─── CI/CD ENDPOINTS ────────────────────────────────────────────────────────

// Generate GitHub Actions workflow
router.post(
  '/cicd/github',
  async (req: Request, res: Response) => {
    try {
      const { domain, apiUrl, schedule } = req.body;
      if (!domain || !apiUrl) {
        res.status(400).json({ message: 'domain and apiUrl are required' });
        return;
      }
      const yaml = generateGitHubActionsWorkflow({ domain, apiUrl, schedule });
      res.json({ yaml, domain });
    } catch (error) {
      logger.error('GitHub Actions workflow generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate GitHub Actions workflow' });
    }
  }
);

// Generate GitLab CI/CD config
router.post(
  '/cicd/gitlab',
  async (req: Request, res: Response) => {
    try {
      const { domain, apiUrl, schedule } = req.body;
      if (!domain || !apiUrl) {
        res.status(400).json({ message: 'domain and apiUrl are required' });
        return;
      }
      const yaml = generateGitLabCI({ domain, apiUrl, schedule });
      res.json({ yaml, domain });
    } catch (error) {
      logger.error('GitLab CI generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate GitLab CI config' });
    }
  }
);

// Generate webhook payload
router.post(
  '/cicd/webhook',
  async (req: Request, res: Response) => {
    try {
      const { assessmentId } = req.body;
      if (!assessmentId) {
        res.status(400).json({ message: 'assessmentId is required' });
        return;
      }

      const authReq = req as AuthRequest;
      const assessment = await prisma.assessment.findFirst({
        where: { id: assessmentId, organizationId: authReq.organizationId },
        include: { findings: true },
      });

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const payload = generateWebhookPayload(assessment as any);
      res.json(payload);
    } catch (error) {
      logger.error('Webhook payload generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate webhook payload' });
    }
  }
);

// ─── REVIEW ENDPOINTS ───────────────────────────────────────────────────────

// Create review for finding
router.post(
  '/:id/reviews',
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

      const { findingId, reviewerId, reviewerName } = req.body;
      if (!findingId) {
        res.status(400).json({ message: 'findingId is required' });
        return;
      }

      const review = await createReview(
        findingId,
        assessment.id,
        reviewerId || authReq.userId,
        reviewerName || authReq.email,
      );

      res.status(201).json(review);
    } catch (error) {
      logger.error('Review creation error:', { error: String(error) });
      res.status(500).json({ message: String(error) || 'Failed to create review' });
    }
  }
);

// Update review status
router.patch(
  '/:id/reviews/:reviewId',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
    param('reviewId').matches(UUID_REGEX).withMessage('Invalid review ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const { status, reason } = req.body;
      if (!status || !Object.values(ReviewStatus).includes(status)) {
        res.status(400).json({
          message: `Invalid status. Must be one of: ${Object.values(ReviewStatus).join(', ')}`,
        });
        return;
      }

      const authReq = req as AuthRequest;
      const review = await updateStatus(
        req.params.reviewId,
        status,
        authReq.userId,
        authReq.email,
        reason,
      );

      res.json(review);
    } catch (error) {
      logger.error('Review status update error:', { error: String(error) });
      res.status(500).json({ message: String(error) || 'Failed to update review' });
    }
  }
);

// Get reviews for assessment
router.get(
  '/:id/reviews',
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

      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;

      const [reviews, stats] = await Promise.all([
        getReviewsByAssessment(assessment.id),
        getReviewStats(assessment.id),
      ]);

      res.json({ reviews, stats, page, limit });
    } catch (error) {
      logger.error('Review fetch error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to fetch reviews' });
    }
  }
);

// ─── COMPLIANCE ENDPOINTS ───────────────────────────────────────────────────

// Generate SOC 2 report
router.post(
  '/compliance/soc2',
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { assessmentId } = req.body;
      if (!assessmentId) {
        res.status(400).json({ message: 'assessmentId is required' });
        return;
      }

      const assessment = await prisma.assessment.findFirst({
        where: { id: assessmentId, organizationId: authReq.organizationId },
        include: { findings: true },
      });

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const report = generateSOC2Report(assessment.findings as any, assessment);
      res.json(report);
    } catch (error) {
      logger.error('SOC 2 report generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate SOC 2 report' });
    }
  }
);

// Generate ISO 27001 report
router.post(
  '/compliance/iso27001',
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { assessmentId } = req.body;
      if (!assessmentId) {
        res.status(400).json({ message: 'assessmentId is required' });
        return;
      }

      const assessment = await prisma.assessment.findFirst({
        where: { id: assessmentId, organizationId: authReq.organizationId },
        include: { findings: true },
      });

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const report = generateISO27001Report(assessment.findings as any, assessment);
      res.json(report);
    } catch (error) {
      logger.error('ISO 27001 report generation error:', { error: String(error) });
      res.status(500).json({ message: 'Failed to generate ISO 27001 report' });
    }
  }
);

export default router;
