import { Router, Request, Response } from 'express';
import { param } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { AuthRequest } from '../types';
import * as assessmentService from '../services/assessment.service';
import * as findingService from '../services/finding.service';
import { generateReport, generatePdfReport } from '../services/report.service';
import prisma from '../lib/prisma';
import fs from 'fs';
import path from 'path';
import { config } from '../config';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const router = Router();

router.use(authenticate);

router.get(
  '/',
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const reports = await prisma.report.findMany({
        where: { assessment: { organizationId: authReq.organizationId } },
        include: { assessment: { select: { id: true, domain: true, status: true } } },
        orderBy: { createdAt: 'desc' },
        take: 50,
      });
      res.json({ reports });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch reports' });
    }
  }
);

router.post(
  '/generate/:assessmentId',
  validate([
    param('assessmentId').matches(UUID_REGEX).withMessage('Invalid assessment ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { assessmentId } = req.params;
      const assessment = await assessmentService.getAssessmentById(assessmentId, authReq.organizationId);

      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const report = await generateReport(assessmentId, authReq.organizationId);
      res.status(201).json({ message: 'Report generated', report });
    } catch (error) {
      res.status(500).json({ message: 'Failed to generate report' });
    }
  }
);

router.get(
  '/:id',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid report ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const report = await prisma.report.findFirst({
        where: {
          id: req.params.id,
          assessment: { organizationId: authReq.organizationId },
        },
        include: { assessment: true },
      });

      if (!report) {
        res.status(404).json({ message: 'Report not found' });
        return;
      }

      res.json(report);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch report' });
    }
  }
);

router.get(
  '/:id/download',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid report ID format'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const report = await prisma.report.findFirst({
        where: {
          id: req.params.id,
          assessment: { organizationId: authReq.organizationId },
        },
        include: { assessment: true },
      });

      if (!report) {
        res.status(404).json({ message: 'Report not found' });
        return;
      }

      if (report.pdfPath) {
        const reportsDir = path.resolve(config.reportsDir);
        const resolvedPath = path.resolve(report.pdfPath);
        if (resolvedPath.startsWith(reportsDir) && fs.existsSync(resolvedPath)) {
          res.setHeader('Content-Type', 'application/pdf');
          res.setHeader('Content-Disposition', `attachment; filename="report-${report.assessment.domain}.pdf"`);
          fs.createReadStream(resolvedPath).pipe(res);
          return;
        }
      }

      const pdfPath = await generatePdfReport(report.id);
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="report-${report.assessment.domain}.pdf"`);
      fs.createReadStream(pdfPath).pipe(res);
    } catch (error) {
      res.status(500).json({ message: 'Failed to download report' });
    }
  }
);

export default router;
