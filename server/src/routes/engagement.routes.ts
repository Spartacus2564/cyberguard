// ═══════════════════════════════════════════════════════════════════════════════
// ENGAGEMENT ROUTES — CRUD + scope management + statistics
// ═══════════════════════════════════════════════════════════════════════════════

import { Router, Request, Response } from 'express';
import { body, query, param } from 'express-validator';
import { validate } from '../middleware/validate';
import { authenticate } from '../middleware/auth';
import { ssrfProtection } from '../middleware/ssrfProtection';
import { AuthRequest } from '../types';
import * as engagementService from '../services/engagement.service';
import { logAudit } from '../services/audit.service';
import prisma from '../lib/prisma';
import { Severity } from '../types';
import redis from '../lib/redis';
import logger from '../utils/logger';
import { AssessmentStatus } from '@prisma/client';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const router = Router();

router.use(authenticate);

// ─── List Engagements ────────────────────────────────────────────────────────

router.get(
  '/',
  validate([
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 20;
      const result = await engagementService.listEngagements(authReq.organizationId, page, limit);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch engagements' });
    }
  }
);

// ─── Get Engagement Stats ────────────────────────────────────────────────────

router.get('/stats', async (req: Request, res: Response) => {
  try {
    const authReq = req as AuthRequest;
    const stats = await engagementService.getEngagementStats(authReq.organizationId);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch engagement stats' });
  }
});

// ─── Create Engagement ───────────────────────────────────────────────────────

router.post(
  '/',
  validate([
    body('name').notEmpty().withMessage('Engagement name is required'),
    body('target').optional().isString(),
    body('description').optional().isString(),
    body('scopeRules').optional().isArray(),
    body('scopeRules.*.type').optional().isIn(['allow', 'deny']),
    body('scopeRules.*.targetType').optional().isIn(['domain', 'cidr', 'ip', 'url', 'regex']),
    body('scopeRules.*.value').optional().isString(),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { name, description, target, scopeRules, config } = req.body;

      // Dedup: only block if there's an ACTIVE (running) engagement for same domain
      if (target) {
        const activeExisting = await prisma.engagement.findFirst({
          where: { domain: target, organizationId: authReq.organizationId, status: 'ACTIVE' },
          orderBy: { createdAt: 'desc' },
        });
        if (activeExisting) {
          res.status(200).json(activeExisting);
          return;
        }
        // Clean up stale DRAFT engagements for same domain
        await prisma.engagement.deleteMany({
          where: { domain: target, organizationId: authReq.organizationId, status: 'DRAFT' },
        });
      }

      const rules = scopeRules || [];
      if (target && !scopeRules) {
        rules.push({ type: 'allow', targetType: 'domain', value: target });
      }

      const engagement = await engagementService.createEngagement({
        name,
        domain: target,
        description: description || target || '',
        organizationId: authReq.organizationId,
        scopeRules: rules,
        config,
      });

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.create',
        resource: 'engagement',
        resourceId: engagement.id,
        details: `Created engagement: ${name}`,
        ipAddress: req.ip,
      });

      res.status(201).json(engagement);
    } catch (error) {
      res.status(500).json({ message: 'Failed to create engagement' });
    }
  }
);

// ─── Get Engagement ──────────────────────────────────────────────────────────

router.get(
  '/:id',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }
      res.json(engagement);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch engagement' });
    }
  }
);

// ─── Update Engagement Status ────────────────────────────────────────────────

router.post(
  '/:id/status',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    body('status').isIn(['DRAFT', 'ACTIVE', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED']).withMessage('Invalid status'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      await engagementService.updateEngagementStatus(
        req.params.id,
        authReq.organizationId,
        req.body.status,
      );

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.status',
        resource: 'engagement',
        resourceId: req.params.id,
        details: `Status changed to ${req.body.status}`,
        ipAddress: req.ip,
      });

      res.json({ message: 'Engagement status updated' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to update engagement status' });
    }
  }
);

// ─── Delete Engagement ───────────────────────────────────────────────────────

router.delete(
  '/:id',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      await engagementService.deleteEngagement(req.params.id, authReq.organizationId);

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.delete',
        resource: 'engagement',
        resourceId: req.params.id,
        ipAddress: req.ip,
      });

      res.status(204).send();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to delete engagement';
      if (message.includes('not found')) {
        res.status(404).json({ message });
      } else if (message.includes('active')) {
        res.status(409).json({ message });
      } else {
        res.status(500).json({ message: 'Failed to delete engagement' });
      }
    }
  }
);

// ─── Add Scope Rule ──────────────────────────────────────────────────────────

router.post(
  '/:id/scope',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    body('type').isIn(['allow', 'deny']).withMessage('Type must be allow or deny'),
    body('targetType').isIn(['domain', 'cidr', 'ip', 'url', 'regex']).withMessage('Invalid target type'),
    body('value').notEmpty().withMessage('Value is required'),
    body('description').optional().isString(),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      await engagementService.addScopeRule(req.params.id, authReq.organizationId, req.body);

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.scope.add',
        resource: 'engagement',
        resourceId: req.params.id,
        details: `Added scope rule: ${req.body.type} ${req.body.targetType}=${req.body.value}`,
        ipAddress: req.ip,
      });

      res.status(201).json({ message: 'Scope rule added' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to add scope rule' });
    }
  }
);

// ─── Remove Scope Rule ───────────────────────────────────────────────────────

router.delete(
  '/:id/scope/:ruleId',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    param('ruleId').matches(UUID_REGEX).withMessage('Invalid rule ID'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      await engagementService.removeScopeRule(req.params.ruleId, authReq.organizationId);

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.scope.remove',
        resource: 'engagement',
        resourceId: req.params.id,
        details: `Removed scope rule: ${req.params.ruleId}`,
        ipAddress: req.ip,
      });

      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: 'Failed to remove scope rule' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// AUTONOMOUS SCAN TRIGGER
// ═══════════════════════════════════════════════════════════════════════════════

router.post(
  '/:id/scan',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    body('domain').optional().isString(),
    body('modules').optional().isArray(),
  ]),
  ssrfProtection,
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { domain: reqDomain, modules } = req.body;

      // Verify engagement exists
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      // Use domain from body, or fall back to scope rule
      let domain = reqDomain;
      if (!domain && engagement.scopeRules && engagement.scopeRules.length > 0) {
        const allowRule = engagement.scopeRules.find((r: any) => r.type === 'allow' && r.targetType === 'domain');
        if (allowRule) domain = allowRule.value;
      }
      if (!domain) {
        res.status(400).json({ message: 'Domain is required (provide in body or via scope rule)' });
        return;
      }

      // Create assessment
      const assessment = await prisma.assessment.create({
        data: {
          domain,
          organizationId: authReq.organizationId,
          status: 'PENDING',
        },
      });

      // Queue engagement-aware scan
      const { addEngagementScanJob } = await import('../queue/engagementQueue');
      await addEngagementScanJob({
        assessmentId: assessment.id,
        domain,
        organizationId: authReq.organizationId,
        modules: modules || [
          'dns', 'tls', 'headers', 'webConfig', 'technology', 'portScan',
          'osFingerprint', 'dnsDeep', 'emailSecurity', 'activeVuln',
          'kaliTools', 'businessLogic', 'advancedAttacks',
        ],
        engagementId: req.params.id,
      });

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.scan.trigger',
        resource: 'engagement',
        resourceId: req.params.id,
        details: `Triggered autonomous scan for ${domain}`,
        ipAddress: req.ip,
      });

      res.status(202).json({
        message: 'Autonomous scan queued',
        assessmentId: assessment.id,
        engagementId: req.params.id,
      });
    } catch (error) {
      res.status(500).json({ message: 'Failed to trigger scan' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// CANCEL SCAN
// ═══════════════════════════════════════════════════════════════════════════════

router.post(
  '/:id/cancel',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      // If no domain or engagement is DRAFT, just mark it as cancelled
      const domain = (engagement as { domain?: string }).domain;
      if (!domain || (engagement as { status?: string }).status === 'DRAFT') {
        await engagementService.updateEngagementStatus(req.params.id, authReq.organizationId, 'FAILED');
        res.json({ message: 'Scan cancelled' });
        return;
      }

      const assessment = await prisma.assessment.findFirst({
        where: { domain, organizationId: authReq.organizationId, status: { in: ['RUNNING', 'PENDING'] } },
        orderBy: { createdAt: 'desc' },
      });
      if (!assessment) {
        // Check if there's a recent assessment that might be stuck
        const recent = await prisma.assessment.findFirst({
          where: { domain, organizationId: authReq.organizationId },
          orderBy: { createdAt: 'desc' },
        });
        if (recent && recent.status !== 'COMPLETED' && recent.status !== 'CANCELLED') {
          await prisma.assessment.update({ where: { id: recent.id }, data: { status: AssessmentStatus.CANCELLED, completedAt: new Date() } });
          await engagementService.updateEngagementStatus(req.params.id, authReq.organizationId, 'FAILED');
          res.json({ message: 'Scan cancelled (force)' });
          return;
        }
        // No active scan, but still mark engagement as cancelled
        await engagementService.updateEngagementStatus(req.params.id, authReq.organizationId, 'FAILED');
        res.json({ message: 'Scan cancelled' });
        return;
      }

      const { cancelScan } = await import('../queue/engagementQueue');
      const cancelled = await cancelScan(assessment.id);

      await prisma.assessment.update({ where: { id: assessment.id }, data: { status: AssessmentStatus.CANCELLED, completedAt: new Date() } });
      await engagementService.updateEngagementStatus(req.params.id, authReq.organizationId, 'FAILED');

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.scan.cancel',
        resource: 'engagement',
        resourceId: req.params.id,
        details: 'Scan cancelled by user',
        ipAddress: req.ip,
      });

      res.json({ message: 'Scan cancelled' });
    } catch (error) {
      res.status(500).json({ message: 'Failed to cancel scan' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK GRAPH
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/attack-graph',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { getGraphData } = await import('../engine/attackGraph');
      const graph = await getGraphData(req.params.id);
      res.json(graph);
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch attack graph' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERED ASSETS
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/assets',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { getAssetsByEngagement, getAssetSummary } = await import('../services/assetInventory.service');
      const [assets, summary] = await Promise.all([
        getAssetsByEngagement(req.params.id),
        getAssetSummary(req.params.id),
      ]);

      res.json({ assets, summary });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch assets' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// EVIDENCE
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/evidence',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      // Get evidence from assessments linked to this engagement
      const assessments = await prisma.assessment.findMany({
        where: { organizationId: authReq.organizationId },
        select: { id: true },
      });

      const assessmentIds = assessments.map(a => a.id);
      const evidence = await prisma.evidence.findMany({
        where: { assessmentId: { in: assessmentIds } },
        include: {
          finding: { select: { id: true, title: true, severity: true } },
        },
        orderBy: { createdAt: 'desc' },
        take: 100,
      });

      res.json({ evidence });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch evidence' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL EXECUTIONS
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/tool-executions',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const executions = await prisma.toolExecution.findMany({
        where: { engagementId: req.params.id },
        orderBy: { startedAt: 'desc' },
        take: 50,
      });

      res.json({ executions });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch tool executions' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// FINDINGS — load from assessment linked by domain
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/findings',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const domain = (engagement as any).domain;
      if (!domain) {
        res.json({ data: [] });
        return;
      }

      // Find assessment with findings (prefer completed ones)
      let assessment = await prisma.assessment.findFirst({
        where: { domain, organizationId: authReq.organizationId, status: 'COMPLETED' },
        orderBy: { createdAt: 'desc' },
      });
      if (!assessment) {
        assessment = await prisma.assessment.findFirst({
          where: { domain, organizationId: authReq.organizationId },
          orderBy: { createdAt: 'desc' },
        });
      }
      if (!assessment) {
        res.json({ data: [] });
        return;
      }

      const findings = await prisma.finding.findMany({
        where: { assessmentId: assessment.id },
        orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
      });

      res.json({ data: findings, assessmentId: assessment.id });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch findings' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// DELTA COMPARISON — compare with previous scan
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/delta',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const domain = (engagement as { domain?: string }).domain;
      if (!domain) {
        res.status(400).json({ message: 'No domain associated with this engagement' });
        return;
      }

      const assessment = await prisma.assessment.findFirst({
        where: { domain, organizationId: authReq.organizationId, status: 'COMPLETED' },
        orderBy: { createdAt: 'desc' },
      });
      if (!assessment) {
        res.status(404).json({ message: 'No completed assessment found' });
        return;
      }

      const { compareWithPreviousScan } = await import('../services/historyComparison.service');
      const findings = await prisma.finding.findMany({ where: { assessmentId: assessment.id } });
      const comparison = await compareWithPreviousScan(domain, authReq.organizationId, findings.map(f => ({
        id: f.id,
        title: f.title,
        description: f.description,
        severity: f.severity as Severity,
        category: f.category,
        affectedAsset: f.affectedAsset,
        evidence: f.evidence,
        impact: f.impact,
        remediation: f.remediation,
        references: (f.references || '').split(',').filter(Boolean),
        detectedAt: f.detectedAt,
        confidence: 0.7,
      })));

      res.json(comparison);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Failed to get delta';
      res.status(500).json({ message });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// AI CHAT — continuous pentest assistant
// ═══════════════════════════════════════════════════════════════════════════════

router.post(
  '/:id/chat',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { message } = req.body;
      if (!message || typeof message !== 'string') {
        res.status(400).json({ message: 'Message is required' });
        return;
      }

      const domain = (engagement as any).domain;

      // Gather context
      const [findings, assets, hyps, aps, tools] = await Promise.all([
        domain ? prisma.finding.findMany({
          where: { assessment: { domain, organizationId: authReq.organizationId } },
          orderBy: { severity: 'asc' },
          take: 50,
        }) : [],
        prisma.discoveredAsset.findMany({ where: { engagementId: req.params.id } }),
        prisma.hypothesis.findMany({ where: { engagementId: req.params.id } }),
        prisma.attackPath.findMany({ where: { engagementId: req.params.id } }),
        prisma.toolExecution.findMany({ where: { engagementId: req.params.id }, orderBy: { startedAt: 'desc' }, take: 20 }),
      ]);

      const context = {
        domain,
        status: engagement.status,
        findingsCount: findings.length,
        findings: findings.map((f: any) => ({ title: f.title, severity: f.severity, description: f.description, remediation: f.remediation })),
        assets: assets.map((a: any) => ({ hostname: a.hostname, type: a.assetType, ip: a.ipAddress })),
        hypotheses: hyps.map((h: any) => ({ hypothesis: h.hypothesis, confidence: h.confidence, status: h.status })),
        attackPaths: aps.map((p: any) => ({ title: p.title, riskScore: p.riskScore })),
        toolsRun: tools.map((t: any) => ({ tool: t.toolName, status: t.status, findings: t.findingsCount })),
      };

      const { getAI } = await import('../services/ai.service');
      const ai = getAI();

      const systemPrompt = `You are CyberGuard AI, an autonomous pentesting assistant. You have just completed a security assessment of ${domain || 'the target'}.

CURRENT ASSESSMENT CONTEXT:
${JSON.stringify(context, null, 2)}

You can:
- Analyze findings and explain their business impact
- Suggest deeper investigation areas
- Recommend specific remediation steps
- Explain attack chains and how vulnerabilities chain together
- Identify which findings are false positives vs real risks
- Suggest additional scan modules to run

Be concise, direct, and actionable. Use plain text (no markdown headers, no bold).`;

      const response = await ai.chat([
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message },
      ]);

      res.json({ response, context: { findingsCount: findings.length, assetsCount: assets.length } });
    } catch (error: any) {
      res.status(500).json({ message: 'Chat failed: ' + (error.message || 'Unknown error') });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN LOGS
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/logs',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const assessment = await prisma.assessment.findFirst({
        where: { domain: engagement.domain || '', organizationId: authReq.organizationId },
        orderBy: { createdAt: 'desc' },
      });
      if (!assessment) {
        res.json({ logs: [] });
        return;
      }

      const logsKey = `scan:${assessment.id}:logs`;
      const rawLogs = await redis.lrange(logsKey, 0, -1);
      const logs = rawLogs.map((r) => {
        try { return JSON.parse(r); } catch { return null; }
      }).filter(Boolean);
      res.json({ logs });
    } catch (error) {
      res.status(500).json({ message: 'Failed to fetch scan logs' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN PROGRESS (SSE)

router.get(
  '/:id/progress',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const engagement = await engagementService.getEngagement(req.params.id, authReq.organizationId);
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders();

      const engagementId = req.params.id;
      const progressKey = 'engagement:' + engagementId + ':progress';
      const channel = 'engagement:' + engagementId + ':events';

      const sendSSE = (data: Record<string, unknown>) => {
        res.write('data: ' + JSON.stringify(data) + '\n\n');
      };

      const currentProgress = await redis.get(progressKey);
      if (currentProgress) {
        try { sendSSE(JSON.parse(currentProgress)); } catch {}
      }

      const subscriber = redis.duplicate();
      subscriber.subscribe(channel, (err) => {
        if (err) {
          logger.warn('[EngagementProgress] Redis subscribe error: ' + err);
        }
      });
      subscriber.on('message', (_ch: string, message: string) => {
        try {
          const data = JSON.parse(message);
          sendSSE(data);
        } catch {}
      });

      req.on('close', () => {
        subscriber.unsubscribe(channel);
        subscriber.quit();
      });

      const heartbeat = setInterval(() => {
        res.write(':heartbeat\n\n');
      }, 15000);

      req.on('close', () => clearInterval(heartbeat));
    } catch (error) {
      logger.error('[EngagementProgress] SSE error: ' + error);
      res.status(500).json({ message: 'Failed to establish progress stream' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

router.get(
  '/:id/export/:format',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid assessment ID'),
    param('format').isIn(['json', 'csv', 'sarif', 'junit']).withMessage('Invalid format. Use: json, csv, sarif, junit'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { id, format } = req.params;

      const assessment = await prisma.assessment.findFirst({
        where: { id, organizationId: authReq.organizationId },
      });
      if (!assessment) {
        res.status(404).json({ message: 'Assessment not found' });
        return;
      }

      const findings = (assessment as any).findings as any[];
      if (!findings || findings.length === 0) {
        res.status(404).json({ message: 'No findings found for this assessment' });
        return;
      }

      const { exportFindings } = await import('../services/export.service');
      const output = exportFindings(findings, format as any, assessment.domain, assessment.id);

      const contentTypes: Record<string, string> = {
        json: 'application/json',
        csv: 'text/csv',
        sarif: 'application/sarif+json',
        junit: 'application/xml',
      };

      const extensions: Record<string, string> = {
        json: 'json',
        csv: 'csv',
        sarif: 'sarif.json',
        junit: 'xml',
      };

      res.setHeader('Content-Type', contentTypes[format] || 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="cyberguard-${assessment.domain}-report.${extensions[format] || 'json'}"`);
      res.send(output);
    } catch (error) {
      res.status(500).json({ message: 'Export failed' });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
// AUTHENTICATED SCANNING CREDENTIALS
// ═══════════════════════════════════════════════════════════════════════════════

router.post(
  '/:id/credentials',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    body('name').notEmpty().withMessage('Credential name is required'),
    body('type')
      .isIn(['basic', 'form', 'cookie', 'header'])
      .withMessage('Type must be basic, form, cookie, or header'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { id } = req.params;

      const engagement = await engagementService.getEngagement(
        id,
        authReq.organizationId
      );
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { storeCredential } = await import(
        '../services/credential.service'
      );
      const credential = await storeCredential(
        id,
        req.body.name,
        req.body.type,
        {
          username: req.body.username,
          password: req.body.password,
          cookies: req.body.cookies,
          headers: req.body.headers,
          loginUrl: req.body.loginUrl,
          loginSelector: req.body.loginSelector,
          passwordSelector: req.body.passwordSelector,
          submitSelector: req.body.submitSelector,
          successIndicator: req.body.successIndicator,
        }
      );

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.credential.store',
        resource: 'engagement',
        resourceId: id,
        details: `Stored credential: ${req.body.name} (${req.body.type})`,
        ipAddress: req.ip,
      });

      res.status(201).json(credential);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to store credential';
      res.status(500).json({ message });
    }
  }
);

router.get(
  '/:id/credentials',
  validate([param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID')]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { id } = req.params;

      const engagement = await engagementService.getEngagement(
        id,
        authReq.organizationId
      );
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { listCredentials } = await import(
        '../services/credential.service'
      );
      const credentials = await listCredentials(id);

      res.json(credentials);
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Failed to list credentials';
      res.status(500).json({ message });
    }
  }
);

router.delete(
  '/:id/credentials/:credentialId',
  validate([
    param('id').matches(UUID_REGEX).withMessage('Invalid engagement ID'),
    param('credentialId')
      .matches(UUID_REGEX)
      .withMessage('Invalid credential ID'),
  ]),
  async (req: Request, res: Response) => {
    try {
      const authReq = req as AuthRequest;
      const { id, credentialId } = req.params;

      const engagement = await engagementService.getEngagement(
        id,
        authReq.organizationId
      );
      if (!engagement) {
        res.status(404).json({ message: 'Engagement not found' });
        return;
      }

      const { deleteCredential } = await import(
        '../services/credential.service'
      );
      await deleteCredential(credentialId, id);

      await logAudit({
        userId: authReq.userId,
        organizationId: authReq.organizationId,
        action: 'engagement.credential.delete',
        resource: 'engagement',
        resourceId: id,
        details: `Deleted credential: ${credentialId}`,
        ipAddress: req.ip,
      });

      res.json({ message: 'Credential deleted' });
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : 'Failed to delete credential';
      res.status(500).json({ message });
    }
  }
);

export default router;
