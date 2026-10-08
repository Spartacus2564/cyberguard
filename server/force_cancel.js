const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
(async () => {
  const engagements = await p.engagement.findMany({
    select: { id: true, status: true, domain: true },
    orderBy: { createdAt: 'desc' },
    take: 5
  });
  console.log('ENGAGEMENTS:');
  for (const e of engagements) console.log('  ' + e.status + ' | ' + e.domain + ' | ' + e.id);

  const assessments = await p.assessment.findMany({
    select: { id: true, status: true, domain: true, createdAt: true },
    orderBy: { createdAt: 'desc' },
    take: 5
  });
  console.log('ASSESSMENTS:');
  for (const a of assessments) console.log('  ' + a.status + ' | ' + a.domain + ' | ' + a.id);

  // Force-cancel any stuck assessments
  const stuck = await p.assessment.updateMany({
    where: { status: { in: ['RUNNING', 'PENDING'] } },
    data: { status: 'CANCELLED', completedAt: new Date() }
  });
  console.log('Force-cancelled stuck assessments:', stuck.count);

  // Also cancel stuck scan jobs
  const stuckJobs = await p.scanJob.updateMany({
    where: { status: { in: ['QUEUED', 'PROCESSING'] } },
    data: { status: 'CANCELLED', completedAt: new Date() }
  });
  console.log('Force-cancelled stuck scan jobs:', stuckJobs.count);

  await p.$disconnect();
})();
