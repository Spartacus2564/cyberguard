const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
(async () => {
  // Check for orphaned ToolExecution records
  const orphaned = await prisma.$queryRaw`
    SELECT te.id, te."engagementId", te."toolName", te."createdAt"
    FROM "ToolExecution" te
    LEFT JOIN "Engagement" e ON te."engagementId" = e.id
    WHERE e.id IS NULL
    ORDER BY te."createdAt" DESC
    LIMIT 10
  `;
  console.log('Orphaned ToolExecutions:', orphaned.length);
  for (const o of orphaned) {
    console.log(' ', o.engagementId, o.toolName, o.createdAt);
  }

  // Check for stale engagements
  const stale = await prisma.engagement.findMany({
    where: { status: { in: ['ACTIVE', 'DRAFT'] } },
    select: { id: true, domain: true, status: true, createdAt: true }
  });
  console.log('\nActive/Draft engagements:', stale.length);
  for (const s of stale) console.log(' ', s.id.slice(0,8), s.domain, s.status, s.createdAt);

  // Check assessment tool executions for each engagement
  for (const s of stale) {
    const assessments = await prisma.assessment.findMany({
      where: { domain: s.domain },
      select: { id: true, status: true }
    });
    for (const a of assessments) {
      const tools = await prisma.toolExecution.findMany({
        where: { assessmentId: a.id },
        select: { id: true, toolName: true, findingsCount: true }
      });
      if (tools.length > 0) {
        console.log('  Assessment', a.id.slice(0,8), ':', tools.length, 'tools,', tools.reduce((s,t) => s + t.findingsCount, 0), 'findings');
      }
    }
  }

  await prisma.$disconnect();
})();
