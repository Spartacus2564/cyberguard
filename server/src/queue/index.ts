import Bull from 'bull';
import { AssessmentStatus, ScanJobStatus } from '@prisma/client';
import { config } from '../config';
import { runAssessment, getModulesRun } from '../engine';
import { setScanContext, clearScanContext, scanLog } from '../engine/scanLogger';
import { calculateSecurityScore } from '../engine/riskScoring';
import { createFindingsBulk } from '../services/finding.service';
import { generateReport } from '../services/report.service';
import { updateAssessmentStatus } from '../services/assessment.service';
import { ScanModule } from '../types';
import prisma from '../lib/prisma';
import logger from '../utils/logger';
import redis from '../lib/redis';

export interface ScanJobData {
  assessmentId: string;
  domain: string;
  organizationId: string;
  modules: string[];
}

const scanQueue = new Bull<ScanJobData>('cyberguard-scans', config.redisUrl, {
  defaultJobOptions: {
    attempts: 1,
    removeOnComplete: 100,
    removeOnFail: 50,
    timeout: 1800000, // 30 minutes
  },
  settings: {
    stalledInterval: 120000, // 2 min
    lockDuration: 1800000,   // 30 min lock
    maxStalledCount: 1,
  },
});

scanQueue.process(async (job) => {
  const { assessmentId, domain, organizationId, modules } = job.data;

  let scanJob: { id: string } | null = null;
  try {
    scanJob = await prisma.scanJob.create({
      data: {
        assessmentId,
        status: ScanJobStatus.PROCESSING,
        modulesToRun: JSON.stringify(modules),
      },
    });

    await updateAssessmentStatus(assessmentId, AssessmentStatus.RUNNING);
    setScanContext(assessmentId);
    scanLog({ level: 'info', module: 'queue', message: `Scan queued for ${domain} — ${modules.length} modules selected` });
    await job.progress(5);

    // Track active module in Redis for real-time progress
    const progressKey = `scan:${assessmentId}:progress`;
    const logsKey = `scan:${assessmentId}:logs`;
    const modulesRun: { name: string; duration: number; findings: number }[] = [];

    // Wrap the entire scan in a safety timeout (25 min — leaves time for post-processing)
    const SCAN_SAFETY_TIMEOUT = 1500000;
    const scanResults = await Promise.race([
      runAssessment(domain, modules as ScanModule[], (moduleName, index, total) => {
        redis.set(`${progressKey}:activeModule`, moduleName, 'EX', 600).catch(() => {});
        redis.set(`${progressKey}:moduleIndex`, index.toString(), 'EX', 600).catch(() => {});
        redis.set(`${progressKey}:totalModules`, total.toString(), 'EX', 600).catch(() => {});
      }, (entry) => {
        // Write each log entry to a Redis list (max 200 entries, 15 min TTL)
        // NOTE: PROBE entries are already filtered out by scanLog()
        redis.rpush(logsKey, JSON.stringify(entry)).catch(() => {});
        redis.ltrim(logsKey, -200, -1).catch(() => {});
        redis.expire(logsKey, 900).catch(() => {});
      }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`Scan safety timeout after ${SCAN_SAFETY_TIMEOUT / 60000} minutes`)), SCAN_SAFETY_TIMEOUT)),
    ]);

    // Destructure the new AI-enriched result shape
    const { results: scanModuleResults, aiEnriched, aiTriageResult, classification } = scanResults;

    // Store completed module info
    for (const result of scanModuleResults) {
      modulesRun.push({
        name: result.module,
        duration: result.duration,
        findings: result.findings.length,
      });
    }

    // Store modules run, AI triage metadata, and classification in Redis for the report
    await redis.set(`${progressKey}:modulesRun`, JSON.stringify(modulesRun), 'EX', 600);
    if (classification) {
      await redis.set(`${progressKey}:classification`, JSON.stringify({
        primary: classification.primary,
        confidence: classification.confidence,
        services: classification.services,
        webTech: classification.webTech,
        osGuess: classification.osGuess,
        openPorts: classification.openPorts,
        reasons: classification.reasons,
      }), 'EX', 600);
    }
    if (aiTriageResult) {
      await redis.set(`${progressKey}:aiChains`, JSON.stringify(aiTriageResult.chains || []), 'EX', 600);
      await redis.set(`${progressKey}:attackNarrative`, aiTriageResult.attackNarrative || '', 'EX', 600);
      await redis.set(`${progressKey}:remediationPlan`, JSON.stringify(aiTriageResult.remediationPlan || []), 'EX', 600);
    }
    logger.info(`[Queue] Scan complete for ${domain}: type=${classification?.primary || 'unknown'}, aiEnriched=${aiEnriched}, triageChains=${aiTriageResult?.chains?.length ?? 0}`);

    // Clear active module
    await redis.del(`${progressKey}:activeModule`);
    await job.progress(70);

    const allFindings = scanModuleResults.flatMap((r) => r.findings);

    if (allFindings.length > 0) {
      await createFindingsBulk(
        allFindings.map((f) => ({
          assessmentId,
          title: f.title,
          description: f.description,
          severity: f.severity,
          category: f.category,
          cvssScore: f.cvssScore,
          affectedAsset: f.affectedAsset,
          evidence: f.evidence,
          impact: f.impact,
          remediation: f.remediation,
          references: f.references,
        }))
      );
    }

    await job.progress(80);

    const riskResult = calculateSecurityScore(allFindings);

    await generateReport(assessmentId, organizationId, modules as ScanModule[], modulesRun);

    await prisma.scanJob.update({
      where: { id: scanJob.id },
      data: { status: ScanJobStatus.COMPLETED, progress: 100 },
    });

    await updateAssessmentStatus(assessmentId, AssessmentStatus.COMPLETED, riskResult.score);
    await job.progress(100);

    // Clean up progress keys
    await redis.del(progressKey);
    clearScanContext();

    return { assessmentId, findingsCount: allFindings.length, riskScore: riskResult.score };
  } catch (error) {
    clearScanContext();
    logger.error(`Scan job failed for assessment ${assessmentId}:`, { error: String(error) });

    // Use short timeouts for DB updates so the catch block doesn't hang
    // when the background scan is still consuming the Prisma connection pool
    try {
      if (scanJob) {
        await Promise.race([
          prisma.scanJob.update({
            where: { id: scanJob.id },
            data: { status: ScanJobStatus.FAILED },
          }),
          new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 5000)),
        ]);
      }
    } catch { /* best effort */ }

    try {
      await Promise.race([
        updateAssessmentStatus(assessmentId, AssessmentStatus.FAILED),
        new Promise<'timeout'>((r) => setTimeout(() => r('timeout'), 5000)),
      ]);
    } catch { /* best effort */ }

    // Don't re-throw — Bull already knows the job failed via timeout rejection.
    // Re-throwing causes unhandled rejection noise.
  }
});

// ─── ORPHAN RECOVERY ON STARTUP ─────────────────────────────────────────────
// If the container was killed mid-scan, scan jobs get stuck as PROCESSING in the
// DB but the Bull job is lost. This resets them to FAILED on startup.
async function recoverOrphanedJobs() {
  try {
    const orphaned = await prisma.scanJob.updateMany({
      where: { status: 'PROCESSING' },
      data: { status: 'FAILED' },
    });
    if (orphaned.count > 0) {
      // Also reset any assessments stuck as RUNNING
      await prisma.assessment.updateMany({
        where: { status: 'RUNNING' },
        data: { status: 'FAILED', completedAt: new Date() },
      });
      logger.warn(`[Queue] Recovered ${orphaned.count} orphaned scan job(s) from previous run`);
    }
  } catch (e) {
    logger.error('[Queue] Orphan recovery failed', { error: String(e) });
  }
}

recoverOrphanedJobs();

scanQueue.on('completed', (job, result) => {
  logger.info(`Scan job ${job.id} completed`, result);
});

scanQueue.on('failed', (job, err) => {
  logger.error(`Scan job ${job?.id} failed`, { error: err.message });
});

export async function addScanJob(data: ScanJobData): Promise<Bull.Job<ScanJobData>> {
  return scanQueue.add(data, {
    priority: 1,
    delay: 0,
  });
}

async function gracefulShutdown() {
  logger.info('Shutting down scan queue...');
  await scanQueue.close();
  await prisma.$disconnect();
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

export { scanQueue };
