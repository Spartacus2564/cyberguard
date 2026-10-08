const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
(async () => {
  const all = await p.assessment.findMany({
    where: { domain: 'tekup-student.educated.tn' },
    orderBy: { createdAt: 'desc' },
    select: { id: true, status: true, createdAt: true }
  });
  console.log('Assessments:', all.length);
  for (const a of all) console.log('  ' + a.status + ' | ' + a.id.substring(0, 8));
  const ids = all.map(a => a.id);
  await p.assessment.deleteMany({ where: { id: { in: ids } } });
  console.log('Deleted', ids.length, 'assessments');
  await p.$disconnect();
})();
