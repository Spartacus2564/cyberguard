const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
(async () => {
  // Get all assessments for this domain
  const all = await p.assessment.findMany({
    where: { domain: 'tekup-student.educated.tn' },
    orderBy: { createdAt: 'desc' },
    select: { id: true, status: true, createdAt: true }
  });
  console.log('All assessments:', all.length);
  for (const a of all) {
    console.log('  ' + a.id + ' | ' + a.status + ' | ' + a.createdAt.toISOString().substring(0, 19));
  }

  // Keep only the most recent COMPLETED one, cancel/delete the rest
  const completed = all.filter(a => a.status === 'COMPLETED');
  const running = all.filter(a => a.status === 'RUNNING' || a.status === 'PENDING');
  const failed = all.filter(a => a.status === 'FAILED' || a.status === 'CANCELLED');

  console.log('\nCompleted:', completed.length);
  console.log('Running:', running.length);
  console.log('Failed/Cancelled:', failed.length);

  // Cancel any running assessments
  for (const a of running) {
    await p.assessment.update({ where: { id: a.id }, data: { status: 'CANCELLED', completedAt: new Date() } });
    console.log('Cancelled:', a.id);
  }

  // Clean up old scan jobs
  const oldJobs = await p.scanJob.findMany({
    where: { assessmentId: { in: all.map(a => a.id) } },
    select: { id: true, assessmentId: true, status: true }
  });
  console.log('\nScan jobs found:', oldJobs.length);
  for (const j of oldJobs) {
    if (j.status === 'PROCESSING' || j.status === 'QUEUED') {
      await p.scanJob.update({ where: { id: j.id }, data: { status: 'CANCELLED' } });
      console.log('  Cancelled job:', j.id);
    }
  }

  // Clean up Redis keys
  const redis = require('ioredis');
  const r = new redis(process.env.REDIS_URL || 'redis://localhost:6379');
  for (const a of all) {
    await r.del('engagement:' + a.id + ':progress');
    await r.del('scan:' + a.id + ':cancelled');
  }
  await r.quit();

  console.log('\nDone. Cleaned up ' + all.length + ' assessments.');
  await p.$disconnect();
})();
