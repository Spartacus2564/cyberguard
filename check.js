const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
(async () => {
  // Check latest engagement
  const eng = await prisma.engagement.findFirst({ orderBy: { createdAt: 'desc' } });
  console.log('Latest:', eng.id.slice(0,8), eng.domain, eng.status);
  
  const tools = await prisma.toolExecution.findMany({ where: { engagementId: eng.id }, select: { toolName: true, status: true, findingsCount: true, durationMs: true } });
  console.log('\nModules:', tools.length);
  for (const t of tools) console.log(' ', t.toolName.padEnd(20), t.status.padEnd(10), 'findings=' + t.findingsCount, 'time=' + ((t.durationMs || 0) / 1000).toFixed(1) + 's');
  
  const assessment = await prisma.assessment.findFirst({ where: { domain: eng.domain, organizationId: eng.organizationId }, orderBy: { createdAt: 'desc' } });
  if (assessment) {
    const findings = await prisma.finding.findMany({ where: { assessmentId: assessment.id }, select: { title: true, severity: true, category: true } });
    console.log('\nFindings:', findings.length);
    for (const f of findings) console.log(' ', f.severity.padEnd(8), f.title.substring(0,55), '[' + f.category + ']');
  }
  
  await prisma.$disconnect();
})();
