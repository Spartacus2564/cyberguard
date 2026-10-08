import Bull from 'bull';
import { AssessmentStatus } from '@prisma/client';
import { config } from '../config';
import { addScanJob, ScanJobData } from '../queue';
import prisma from '../lib/prisma';
import logger from '../utils/logger';

export interface ScheduleConfig {
  assessmentId: string;
  domain: string;
  organizationId: string;
  interval: 'hourly' | 'daily' | 'weekly' | 'monthly';
  enabled: boolean;
  lastRun?: Date;
  nextRun?: Date;
  modules: string[];
}

const scheduleQueue = new Bull('schedule-queue', config.redisUrl, {
  defaultJobOptions: {
    attempts: 3,
    removeOnComplete: 50,
    removeOnFail: 20,
  },
});

// Process scheduled scans
scheduleQueue.process(async (job) => {
  const { assessmentId, domain, organizationId, modules } = job.data;
  
  try {
    logger.info(`[Scheduler] Running scheduled scan for ${domain}`);
    
    // Check if assessment exists and is not running
    const assessment = await prisma.assessment.findUnique({
      where: { id: assessmentId },
    });
    
    if (!assessment || assessment.status === AssessmentStatus.RUNNING) {
      logger.warn(`[Scheduler] Skipping scan for ${domain} - assessment not found or already running`);
      return;
    }
    
    // Create new assessment for scheduled scan
    const newAssessment = await prisma.assessment.create({
      data: {
        domain,
        organizationId,
        status: AssessmentStatus.PENDING,
      },
    });
    
    // Queue the scan
    await addScanJob({
      assessmentId: newAssessment.id,
      domain,
      organizationId,
      modules: modules.length > 0 ? modules : undefined,
    });
    
    logger.info(`[Scheduler] Queued scheduled scan for ${domain} - assessment ${newAssessment.id}`);
    
    // Update last run time
    await prisma.scanSchedule.updateMany({
      where: { assessmentId },
      data: { lastRun: new Date() },
    });
    
  } catch (error) {
    logger.error(`[Scheduler] Failed to run scheduled scan for ${domain}:`, { error: String(error) });
  }
});

// Schedule a recurring scan
export async function scheduleScan(config: ScheduleConfig): Promise<void> {
  const { assessmentId, domain, organizationId, interval, modules } = config;
  
  // Calculate interval in milliseconds
  const intervalMs = {
    hourly: 60 * 60 * 1000,
    daily: 24 * 60 * 60 * 1000,
    weekly: 7 * 24 * 60 * 60 * 1000,
    monthly: 30 * 24 * 60 * 60 * 1000,
  }[interval];
  
  // Add recurring job
  await scheduleQueue.add(
    { assessmentId, domain, organizationId, modules },
    {
      repeat: {
        every: intervalMs,
      },
      jobId: `schedule-${assessmentId}`,
    }
  );
  
  // Save schedule to database
  await prisma.scanSchedule.upsert({
    where: { assessmentId },
    update: {
      interval,
      enabled: true,
      nextRun: new Date(Date.now() + intervalMs),
    },
    create: {
      assessmentId,
      domain,
      organizationId,
      interval,
      enabled: true,
      nextRun: new Date(Date.now() + intervalMs),
    },
  });
  
  logger.info(`[Scheduler] Scheduled ${interval} scan for ${domain}`);
}

// Stop a scheduled scan
export async function stopSchedule(assessmentId: string): Promise<void> {
  const jobs = await scheduleQueue.getJobs(['waiting', 'active', 'delayed']);
  for (const job of jobs) {
    if (job.data.assessmentId === assessmentId) {
      await job.remove();
      break;
    }
  }
  
  await prisma.scanSchedule.updateMany({
    where: { assessmentId },
    data: { enabled: false },
  });
  
  logger.info(`[Scheduler] Stopped schedule for assessment ${assessmentId}`);
}

// Get all schedules for an organization
export async function getSchedules(organizationId: string): Promise<any[]> {
  return prisma.scanSchedule.findMany({
    where: { organizationId },
    orderBy: { nextRun: 'asc' },
  });
}

// Initialize scheduler on startup
export async function initializeScheduler(): Promise<void> {
  try {
    // Find all enabled schedules
    const schedules = await prisma.scanSchedule.findMany({
      where: { enabled: true },
    });
    
    for (const schedule of schedules) {
      await scheduleScan({
        assessmentId: schedule.assessmentId,
        domain: schedule.domain,
        organizationId: schedule.organizationId,
        interval: schedule.interval as any,
        enabled: true,
        modules: [],
      });
    }
    
    logger.info(`[Scheduler] Initialized ${schedules.length} scheduled scans`);
  } catch (error) {
    logger.error(`[Scheduler] Failed to initialize:`, { error: String(error) });
  }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('[Scheduler] Shutting down...');
  await scheduleQueue.close();
});

export { scheduleQueue };
